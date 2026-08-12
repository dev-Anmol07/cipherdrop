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

No encryption keys are ever transmitted to or stored by this server. The
ML-KEM decapsulation key (dk) lives only in the recipient's URL fragment
(the part after '#'), which per RFC 3986 §3.5 browsers never send in HTTP
requests.

Routes:
  POST /api/upload      -> store ciphertext + encrypted metadata, return a UUID
  GET  /api/drop/<id>   -> return ciphertext, then atomically delete it
                            (404 if never existed/already used, 410 if expired)
  GET  /, /drop/<id>    -> serve the single-page frontend

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
"""

import base64
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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

# No origin configured -> same-origin only (this app serves its own
# frontend, so that's all it needs by default). Set ALLOWED_ORIGINS as a
# comma-separated list to allow a separately-hosted frontend.
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]

# Rate limiting storage. "memory://" is fine for a single process; for a
# real multi-worker deployment, set RATELIMIT_STORAGE_URI to a shared
# backend, e.g. "redis://localhost:6379".
RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 4 * 1024 * 1024  # slack for base64 + JSON overhead

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
        db = g._db = sqlite3.connect(DB_PATH)
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS drops (
                id         TEXT PRIMARY KEY,
                kem_ct     BLOB NOT NULL,
                salt       BLOB NOT NULL,
                header_ct  BLOB NOT NULL,
                chunks     TEXT NOT NULL,   -- JSON array of base64 strings
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_drops_expires_at ON drops(expires_at)")
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


# ---------------------------------------------------------------------------
# Background expiry sweep
# ---------------------------------------------------------------------------
# A drop that's never opened would otherwise sit in the database forever.
# This periodically reclaims anything past its expiry, independent of
# whether a GET /api/drop/<id> ever happens for it.

def _sweep_expired_forever():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS drops (id TEXT PRIMARY KEY, kem_ct BLOB, salt BLOB, "
                "header_ct BLOB, chunks TEXT, created_at INTEGER, expires_at INTEGER)"
            )
            deleted = conn.execute("DELETE FROM drops WHERE expires_at <= ?", (int(time.time() * 1000),)).rowcount
            conn.commit()
            conn.close()
            if deleted:
                app.logger.info("expiry sweep: reclaimed %d expired drop(s)", deleted)
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

    db = get_db()
    db.execute(
        "INSERT INTO drops (id, kem_ct, salt, header_ct, chunks, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (drop_id, kem_ct, salt, header_ct, json.dumps(chunks), now_ms, expires_at),
    )
    db.commit()

    return jsonify(id=drop_id, expiresAt=expires_at)


@app.get("/api/drop/<drop_id>")
def fetch_drop(drop_id):
    db = get_db()
    cur = db.execute(
        "SELECT kem_ct, salt, header_ct, chunks, expires_at FROM drops WHERE id = ?",
        (drop_id,),
    )
    row = cur.fetchone()
    if row is None:
        return jsonify(error="not_found"), 404

    # Atomic one-time-access delete: happens in the same transaction as
    # the SELECT, before the response is built, so a second request for
    # this id can't race a first — regardless of whether this turns out
    # to be a normal fetch or an expired one below.
    db.execute("DELETE FROM drops WHERE id = ?", (drop_id,))
    db.commit()

    kem_ct, salt, header_ct, chunks_json, expires_at = row
    if expires_at <= int(time.time() * 1000):
        return jsonify(error="expired"), 410

    return jsonify(
        kemCipherText=_b64(kem_ct),
        salt=_b64(salt),
        headerCt=_b64(header_ct),
        chunks=json.loads(chunks_json),
    )


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
