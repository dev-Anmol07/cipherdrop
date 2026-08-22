"""
CipherDrop backend — Flask.

The server only ever sees ciphertext and opaque metadata. A drop record
contains:
  - kem_ct     : ML-KEM-512 ciphertext (server-opaque, 768 bytes)
  - salt       : 8 random bytes used to derive per-chunk AES-GCM nonces
  - header_ct  : AES-256-GCM ciphertext of {filename, mimetype, size} —
                 metadata is encrypted client-side; the server never sees
                 the filename or MIME type in the clear.
  - chunks     : JSON array of base64 AES-256-GCM ciphertext chunks, each
                 cryptographically bound (via AES-GCM associated data) to
                 its position and the total chunk count, so chunks can't
                 be reordered/dropped/spliced without breaking auth.
  - expires_at : epoch-ms deadline; a background sweep purges anything
                 past this even if it was never opened, and a fetch of an
                 expired-but-not-yet-swept record is rejected the same way.
  - vault_id   : optional — set only for "Send to a Vault" drops (see below).

Two ways a file gets encrypted, both using the exact same AES-256-GCM /
chunking / AAD-binding logic — they differ only in WHOSE ML-KEM keypair
gets used and WHERE the decapsulation key ends up:

  Quick Send (default): the sender generates a fresh, one-time ML-KEM-512
  keypair, encapsulates against their OWN public key, and puts the
  decapsulation key (dk) directly in the link's URL fragment. Convenient,
  works with anyone, no setup — but the link itself is a bearer secret,
  so it doesn't meaningfully benefit from ML-KEM's quantum resistance:
  whoever holds the link can decrypt, with or without a quantum computer.

  Send to a Vault: the RECIPIENT generates one long-term ML-KEM-512
  keypair, ONCE, and publishes the public half (ek) to this server's
  identity directory under a chosen Vault ID. Senders look that ek up
  and encapsulate against it. The resulting link carries NO key at all —
  just a pointer to ciphertext plus the target vault id. Only a device
  holding that vault's private key (dk), which never leaves the
  recipient's own storage, can ever decrypt it. This is what actually
  defends against harvest-now-decrypt-later: there's now a real public
  key traveling over real network traffic, and ML-KEM (unlike RSA/ECDH)
  has no known efficient quantum attack against it.

No encryption keys are ever transmitted to or stored by this server —
identities store only PUBLIC keys, same as a PGP keyserver.

Routes:
  POST   /api/upload             -> store ciphertext + encrypted metadata, return a UUID + one-time revoke token
  GET    /api/drop/<id>          -> return ciphertext, then atomically delete it
                                     (404 if never existed/already used, 410 if expired)
  DELETE /api/drop/<id>          -> revoke a drop early, given its revoke token (204 either way —
                                     see revoke_drop() for why a missing drop isn't treated as an error here)
  GET    /api/drop/<id>/status   -> delivery confirmation: 'opened' (+ timestamp), 'pending', or 'not_found'
  POST   /api/vault/register     -> claim a Vault ID, publish its ML-KEM-512 public key
  GET    /api/vault/<id>/pubkey  -> look up a Vault ID's public key before sending to it
  GET    /, /drop/<id>           -> serve the single-page frontend

Production notes (see README for the full checklist):
  - Set ALLOWED_ORIGINS if the frontend is ever served from a different
    origin than this API. By default (unset), no cross-origin requests
    are allowed — same-origin only, which is all this app needs since it
    serves its own frontend.
  - Run behind gunicorn/waitress (see Procfile), not `python app.py`,
    for anything beyond local testing. FLASK_DEBUG must stay unset/0.
  - The rate limiter here uses in-process memory storage, which is fine
    for a single instance but resets on restart and doesn't share state
    across multiple worker processes. For real multi-worker deployment,
    point flask-limiter at Redis instead (one-line change, see below).
  - Vault IDs are first-come-first-served and immutable once registered
    (no update endpoint) — that's deliberate, since allowing updates
    without proof of private-key ownership would let anyone hijack an
    existing Vault ID by re-registering it with a different public key.
    Lose your local private key with no backup, and the fix is the same
    as losing a PGP key: pick a new Vault ID.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cipherdrop.db"
STATIC_DIR = BASE_DIR / "static"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Demo cap: 100 MB of plaintext per upload (client encrypts in 4 MB chunks;
# ciphertext is plaintext size + a small fixed per-chunk overhead).
MAX_UPLOAD_BYTES = 100 * 1024 * 1024

# Allowed TTLs a client may request, in milliseconds. Anything else is
# rejected rather than silently clamped, so a buggy/malicious client can't
# quietly get an unbounded lifetime.
ALLOWED_TTL_MS = {5 * 60_000, 15 * 60_000, 60 * 60_000, 24 * 60 * 60_000}

SWEEP_INTERVAL_SECONDS = 30

# How long an "opened" receipt sticks around for the sender to poll
# before it's swept away too. This is metadata only (a timestamp) — never
# the file, the key, or even the filename — but it's still deliberately
# short-lived rather than permanent, since "when files get opened" is
# still usage data worth not accumulating forever by default.
RECEIPT_TTL_MS = 24 * 60 * 60_000

VAULT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,40}$")

# Single source of truth for schema — used by BOTH get_db() (the
# request-handling connection) and the background sweep thread's own,
# separate connection. These previously drifted out of sync (the sweep
# thread's copy was missing the vault_id column), and because whichever
# connection creates the table first "wins" the CREATE TABLE IF NOT
# EXISTS race, that silently broke uploads whenever the sweep thread's
# first tick beat the first HTTP request to it. Never duplicate this SQL
# again — import it instead.
DROPS_SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS drops (
        id                TEXT PRIMARY KEY,
        kem_ct            BLOB NOT NULL,
        salt              BLOB NOT NULL,
        header_ct         BLOB NOT NULL,
        chunks            TEXT NOT NULL,   -- JSON array of base64 strings
        created_at        INTEGER NOT NULL,
        expires_at        INTEGER NOT NULL,
        vault_id          TEXT,             -- NULL for Quick Send drops
        revoke_token_hash TEXT              -- SHA-256 hex of the sender's revoke token
    )
"""
IDENTITIES_SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS identities (
        vault_id   TEXT PRIMARY KEY,
        ek         BLOB NOT NULL,     -- public key only, never a secret
        created_at INTEGER NOT NULL
    )
"""
# Deliberately separate from `drops`, not a column on it: a receipt is
# written the moment a drop is opened, in the SAME transaction that
# deletes the ciphertext row — so the strict "atomic delete on first
# access" property for ciphertext is completely unaffected by this
# feature. A receipt holds nothing but a timestamp.
RECEIPTS_SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS receipts (
        id                 TEXT PRIMARY KEY,
        opened_at          INTEGER NOT NULL,
        receipt_expires_at INTEGER NOT NULL
    )
"""


def _ensure_column(conn, table, column, coltype):
    """Add a column to an existing table if it's not already there.

    CREATE TABLE IF NOT EXISTS is a no-op against a table that already
    exists with an older schema — it does NOT add new columns. We already
    hit this exact bug once (vault_id silently missing on a pre-existing
    DB file); this helper exists so adding a new column is never again a
    footgun for anyone running against a DB created by an older version
    of this file.
    """
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

# No origin configured -> same-origin only (this app serves its own
# frontend, so that's all it needs by default). Set ALLOWED_ORIGINS as a
# comma-separated list to allow a separately-hosted frontend.
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]

# Rate limiting storage. "memory://" is fine for a single process; for a
# real multi-worker deployment, set RATELIMIT_STORAGE_URI to a shared
# backend, e.g. "redis://localhost:6379".
RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

# The client base64-encodes ciphertext before it ever hits this route,
# which inflates size by ~4/3 (100 MB plaintext -> ~133 MB on the wire).
# The old "+4 MiB" slack here was sized off the PLAINTEXT cap, not what
# actually arrives in the request body, so a legitimate ~90-100 MB file
# got killed by Flask's automatic 413 before upload()'s own, friendlier
# "file too large" check ever ran. Size this off the base64'd ciphertext
# instead, plus slack for the GCM tag per chunk and JSON structure
# overhead (quotes/commas/other fields), which is small but non-zero.
MAX_CONTENT_LENGTH = 4 * ((MAX_UPLOAD_BYTES + 2) // 3) + 8 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Render (like most PaaS) puts this app behind a reverse proxy. Without
# this, request.remote_addr resolves to the PROXY's address for every
# request, not the visitor's — which would silently turn the per-IP rate
# limits below into one shared global limit for the entire site. Trusts
# exactly one hop of X-Forwarded-For/-Proto/-Host, matching a single
# reverse proxy in front of the app (Render's setup); raise x_for if
# there's ever more than one proxy hop in front of this.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

if ALLOWED_ORIGINS:
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})
# else: no CORS() call at all — cross-origin requests to /api/* are
# blocked by the browser's default same-origin policy, which is correct
# for a same-origin-only deployment.

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=RATELIMIT_STORAGE_URI,
    default_limits=[],  # only the routes below are limited
)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, timeout=10)
        # WAL mode lets readers/writers avoid blocking each other, and the
        # busy_timeout makes any remaining lock contention retry instead of
        # immediately raising "database is locked" — important here because
        # the background sweep thread (below) writes to this same file on
        # its own connection, concurrently with request handling.
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA busy_timeout=10000")
        db.execute(DROPS_SCHEMA_SQL)
        _ensure_column(db, "drops", "vault_id", "TEXT")
        _ensure_column(db, "drops", "revoke_token_hash", "TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_drops_expires_at ON drops(expires_at)")
        db.execute(IDENTITIES_SCHEMA_SQL)
        db.execute(RECEIPTS_SCHEMA_SQL)
        db.commit()
    return db


@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _from_b64(s: str) -> bytes:
    return base64.b64decode(s)


def _new_revoke_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hex). The raw token is handed to the
    client exactly once, in the upload response, and never stored — only
    its hash is kept, same principle as password storage. Revoking later
    means presenting the raw token again; the server never needs to (and
    can't) show it to anyone a second time."""
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
    return raw, digest


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------
# Background expiry sweep
# ---------------------------------------------------------------------------
# A drop that's never opened would otherwise sit in the database forever.
# This periodically reclaims anything past its expiry, independent of
# whether a GET /api/drop/<id> ever happens for it.

def _sweep_expired_forever():
    # _start_sweep_thread_once() fires at import time — on free-tier
    # hosting, that's the same moment a cold start wakes the instance to
    # serve its first real request. Give that request a short head start
    # before this thread's own connection joins in and competes for the
    # SQLite write lock; busy_timeout absorbs the rest.
    time.sleep(5)
    while True:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute(DROPS_SCHEMA_SQL)
            conn.execute(RECEIPTS_SCHEMA_SQL)
            _ensure_column(conn, "drops", "vault_id", "TEXT")
            _ensure_column(conn, "drops", "revoke_token_hash", "TEXT")
            now_ms = int(time.time() * 1000)
            deleted = conn.execute("DELETE FROM drops WHERE expires_at <= ?", (now_ms,)).rowcount
            deleted_receipts = conn.execute("DELETE FROM receipts WHERE receipt_expires_at <= ?", (now_ms,)).rowcount
            conn.commit()
            conn.close()
            if deleted:
                app.logger.info("expiry sweep: reclaimed %d expired drop(s)", deleted)
            if deleted_receipts:
                app.logger.info("expiry sweep: reclaimed %d expired receipt(s)", deleted_receipts)
        except Exception as exc:  # pragma: no cover - defensive, sweep must never crash the process
            app.logger.warning("expiry sweep failed: %s", exc)
        time.sleep(SWEEP_INTERVAL_SECONDS)


def _start_sweep_thread_once():
    # Under the Flask reloader (debug mode), the module loads twice — once
    # in the watcher process, once in the actual server process (which
    # sets WERKZEUG_RUN_MAIN=true). Only start the sweep in the process
    # that's actually serving requests. Under gunicorn there's no
    # reloader, so WERKZEUG_RUN_MAIN is simply unset and this always
    # starts, once per worker — harmless, since the DELETE is idempotent.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        t = threading.Thread(target=_sweep_expired_forever, daemon=True)
        t.start()


_start_sweep_thread_once()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/api/upload")
@limiter.limit("5 per minute")
def upload():
    body = request.get_json(silent=True)
    if not body:
        return jsonify(error="expected JSON body"), 400

    required = ("kemCipherText", "salt", "headerCt", "chunks", "ttlMs")
    missing = [k for k in required if k not in body]
    if missing:
        return jsonify(error=f"missing fields: {', '.join(missing)}"), 400

    ttl_ms = body["ttlMs"]
    if not isinstance(ttl_ms, int) or ttl_ms not in ALLOWED_TTL_MS:
        return jsonify(error="ttlMs must be one of: " + ", ".join(str(t) for t in sorted(ALLOWED_TTL_MS))), 400

    # Optional: this drop was encapsulated against a Vault ID's persistent
    # public key rather than a throwaway one. Purely a label for display /
    # error-messaging on the receiving end — the server can't verify the
    # sender actually used that vault's key (that would require doing
    # crypto server-side, which this app deliberately never does); a
    # mislabeled drop just fails to decrypt on the receiving end instead
    # of leaking anything.
    vault_id = body.get("vaultId")
    if vault_id is not None:
        if not isinstance(vault_id, str) or not VAULT_ID_RE.match(vault_id):
            return jsonify(error="invalid vaultId"), 400

    try:
        kem_ct = _from_b64(body["kemCipherText"])
        salt = _from_b64(body["salt"])
        header_ct = _from_b64(body["headerCt"])
        chunks = body["chunks"]
        if not isinstance(chunks, list) or not chunks or not all(isinstance(c, str) for c in chunks):
            return jsonify(error="chunks must be a non-empty array of base64 strings"), 400
        # validate each chunk decodes and tally plaintext-equivalent size
        total_ct_bytes = 0
        for c in chunks:
            decoded = _from_b64(c)
            total_ct_bytes += len(decoded)
    except Exception:
        return jsonify(error="fields must be valid base64"), 400

    if len(kem_ct) != 768:
        return jsonify(error="unexpected KEM ciphertext size"), 400
    if len(salt) != 8:
        return jsonify(error="unexpected salt size"), 400
    if total_ct_bytes == 0 or total_ct_bytes > MAX_UPLOAD_BYTES + 16 * len(chunks):
        # +16 bytes/chunk slack for the AES-GCM auth tag on each chunk
        return jsonify(error="file too large or empty"), 400

    drop_id = uuid.uuid4().hex
    now_ms = int(time.time() * 1000)
    expires_at = now_ms + ttl_ms
    revoke_token, revoke_token_hash = _new_revoke_token()

    try:
        db = get_db()
        db.execute(
            "INSERT INTO drops (id, kem_ct, salt, header_ct, chunks, created_at, expires_at, vault_id, revoke_token_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (drop_id, kem_ct, salt, header_ct, json.dumps(chunks), now_ms, expires_at, vault_id, revoke_token_hash),
        )
        db.commit()
    except Exception:
        app.logger.exception("upload: database write failed")
        return jsonify(error="storage error, please try again"), 500

    # revokeToken is returned exactly once, here. The server only ever
    # keeps its hash — same principle as password storage — so this is
    # the sender's only chance to receive it. Lose it, and the drop can
    # no longer be revoked early; it still expires normally on its own.
    return jsonify(id=drop_id, expiresAt=expires_at, revokeToken=revoke_token)


@app.get("/api/drop/<drop_id>")
def fetch_drop(drop_id):
    try:
        db = get_db()
        cur = db.execute(
            "SELECT kem_ct, salt, header_ct, chunks, expires_at, vault_id FROM drops WHERE id = ?",
            (drop_id,),
        )
        row = cur.fetchone()
        if row is None:
            return jsonify(error="not_found"), 404

        kem_ct, salt, header_ct, chunks_json, expires_at, vault_id = row
        now_ms = int(time.time() * 1000)
        is_expired = expires_at <= now_ms

        # Atomic one-time-access delete: happens in the same transaction as
        # the SELECT, before the response is built, so a second request for
        # this id can't race a first — regardless of whether this turns out
        # to be a normal fetch or an expired one below. A delivery receipt
        # (timestamp only, never content) is written in this SAME
        # transaction — but only when this is a genuine delivery, not an
        # expired-but-not-yet-swept fetch that never actually handed
        # anything to anyone.
        db.execute("DELETE FROM drops WHERE id = ?", (drop_id,))
        if not is_expired:
            db.execute(
                "INSERT OR REPLACE INTO receipts (id, opened_at, receipt_expires_at) VALUES (?, ?, ?)",
                (drop_id, now_ms, now_ms + RECEIPT_TTL_MS),
            )
        db.commit()
    except Exception:
        app.logger.exception("fetch_drop: database error")
        return jsonify(error="storage error, please try again"), 500

    if is_expired:
        return jsonify(error="expired"), 410

    return jsonify(
        kemCipherText=_b64(kem_ct),
        salt=_b64(salt),
        headerCt=_b64(header_ct),
        chunks=json.loads(chunks_json),
        vaultId=vault_id,
    )


@app.delete("/api/drop/<drop_id>")
@limiter.limit("20 per minute")
def revoke_drop(drop_id):
    body = request.get_json(silent=True) or {}
    token = body.get("revokeToken")
    if not isinstance(token, str) or not token:
        return jsonify(error="missing revokeToken"), 400

    try:
        db = get_db()
        row = db.execute("SELECT revoke_token_hash FROM drops WHERE id = ?", (drop_id,)).fetchone()
        if row is None:
            # Already gone (opened, expired, or already revoked) — a
            # revoke attempt on a link that no longer exists isn't an
            # error worth distinguishing from "successfully revoked";
            # either way, nothing is retrievable through this id anymore.
            return "", 204

        stored_hash = row[0]
        # A drop with no stored hash predates this feature (or was
        # inserted some other way) — refuse rather than silently allow
        # deletion with no proof of ownership at all.
        if not stored_hash or not hmac.compare_digest(stored_hash, _hash_token(token)):
            return jsonify(error="invalid revokeToken"), 403

        db.execute("DELETE FROM drops WHERE id = ?", (drop_id,))
        db.commit()
    except Exception:
        app.logger.exception("revoke_drop: database error")
        return jsonify(error="storage error, please try again"), 500

    return "", 204


@app.get("/api/drop/<drop_id>/status")
@limiter.limit("60 per minute")
def drop_status(drop_id):
    db = get_db()
    receipt = db.execute(
        "SELECT opened_at FROM receipts WHERE id = ?", (drop_id,)
    ).fetchone()
    if receipt is not None:
        return jsonify(status="opened", openedAt=receipt[0])

    still_pending = db.execute("SELECT 1 FROM drops WHERE id = ?", (drop_id,)).fetchone()
    if still_pending is not None:
        return jsonify(status="pending")

    # Not in either table: never existed, expired-and-swept before being
    # opened, or revoked. All three look identical from here on purpose —
    # this endpoint only ever answers "did this get delivered," and a
    # sender already knows locally (their own Activity tab) if THEY
    # revoked it, so no separate case is needed for that.
    return jsonify(status="not_found")


@app.post("/api/vault/register")
@limiter.limit("10 per hour")
def vault_register():
    body = request.get_json(silent=True)
    if not body:
        return jsonify(error="expected JSON body"), 400

    vault_id = body.get("vaultId")
    ek_b64 = body.get("ek")
    if not isinstance(vault_id, str) or not VAULT_ID_RE.match(vault_id):
        return jsonify(error="vaultId must be 3-40 characters: letters, numbers, - or _"), 400
    if not isinstance(ek_b64, str):
        return jsonify(error="missing ek"), 400
    try:
        ek = _from_b64(ek_b64)
    except Exception:
        return jsonify(error="ek must be valid base64"), 400
    if len(ek) != 800:
        return jsonify(error="unexpected public key size"), 400

    db = get_db()
    existing = db.execute("SELECT 1 FROM identities WHERE vault_id = ?", (vault_id,)).fetchone()
    if existing is not None:
        # Immutable by design — see module docstring for why there's no
        # update path. A taken vault_id just means picking another one.
        return jsonify(error="vaultId already taken"), 409

    try:
        db.execute(
            "INSERT INTO identities (vault_id, ek, created_at) VALUES (?, ?, ?)",
            (vault_id, ek, int(time.time() * 1000)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Lost a race with a concurrent registration of the same id.
        return jsonify(error="vaultId already taken"), 409
    except Exception:
        app.logger.exception("vault_register: database write failed")
        return jsonify(error="storage error, please try again"), 500

    return jsonify(vaultId=vault_id), 201


@app.get("/api/vault/<vault_id>/pubkey")
@limiter.limit("30 per minute")
def vault_pubkey(vault_id):
    if not VAULT_ID_RE.match(vault_id):
        return jsonify(error="invalid vaultId"), 400
    db = get_db()
    row = db.execute("SELECT ek FROM identities WHERE vault_id = ?", (vault_id,)).fetchone()
    if row is None:
        return jsonify(error="not_found"), 404
    return jsonify(vaultId=vault_id, ek=_b64(row[0]))


@app.get("/api/health")
def health():
    return jsonify(status="ok", time=int(time.time() * 1000))


@app.get("/")
@app.get("/drop/<drop_id>")
def index(drop_id=None):
    # Single-page frontend; app.js reads window.location to decide
    # whether it's rendering the "send" or "receive" view.
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    # Local development only. FLASK_DEBUG must stay unset (or "0") for
    # anything that isn't strictly your own machine — the Werkzeug
    # debugger it enables allows remote code execution if ever reachable
    # from outside localhost. For anything beyond local testing, run via
    # the Procfile (gunicorn) instead of this __main__ block.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=debug, port=port)
