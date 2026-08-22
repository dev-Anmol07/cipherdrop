# CipherDrop

Quantum-safe, one-time file sharing. Files, filenames, and file types are
all encrypted **in the browser** with ML-KEM-512 (NIST FIPS 203) +
AES-256-GCM before anything leaves your machine — the server only ever
stores and forwards ciphertext.

**Live:** https://cipherdrop-rtc1.onrender.com
*(free-tier hosting — sleeps after 15 min of inactivity, first request
after that can take 30–50s to wake it back up)*

## Quick start (local)

```bash
pip install -r requirements.txt --break-system-packages   # or use a venv
python app.py
```

Open **http://localhost:5000**, drop a file, pick how long the link
should live if nobody opens it, and share the link it gives you. Open
that link to decrypt and download — it works exactly once, and expires
on its own if it's never opened.

No `npm install` is required to run the app — the crypto module is
already pre-built at `static/js/mlkem.bundle.js`. You only need Node if
you want to modify `src/mlkem-entry.js` and rebuild it (`npm install &&
npm run build`).

**Note:** `python app.py` only binds to `localhost` — it's reachable from
your own machine, not from anyone else's, including a client on the same
WiFi. See **Deploying** below for a real, shareable link.

## UI

- **Secure Vault / Activity / Keys** nav tabs. Vault is the send/receive
  flow described above. Activity is a local, in-memory log of what
  *this browser tab* has sent — never transmitted anywhere, which is
  why it's the one place a filename is visible in the clear (only the
  sender can see it, and it resets on reload). Keys is a static panel
  explaining exactly what `ek`/`dk`/session keys are and aren't — including
  the harvest-now-decrypt-later limitation, stated plainly in the product
  itself, not just in the pitch deck.
- **Send / Receive toggle.** A direct shared link (`/drop/<id>#<dk>`)
  still auto-decrypts immediately on load, same as before. The toggle
  adds a second path in: switch to Receive and paste a full link (e.g.
  one someone sent you over Slack) to trigger the same decrypt flow
  manually, without needing to click a live hyperlink.
- **Settings** (gear icon) sets a default self-destruct timer for your
  next upload, kept only in this tab's memory. **About** (profile icon)
  links to the source repo. **API Status** in the footer does a real
  fetch to `/api/health` and reports actual round-trip latency, not a
  placeholder.

## What's fixed in this build

Earlier versions of this project had five known gaps. All five are now
handled server-side, not just in a demo:

1. **Metadata privacy.** Filename, MIME type, and size are encrypted
   client-side into a small ciphertext blob before upload. The server's
   database has no cleartext filename column — verified by inspecting
   the raw API response.
2. **Expiry.** The sender picks a TTL (5 min / 15 min / 1 hr / 24 hr).
   A background thread sweeps expired-but-unopened drops every 30
   seconds, independent of whether anyone ever requests them. A fetch
   that lands in the gap between "expired" and "swept" still correctly
   returns `410 Gone` rather than serving stale data.
3. **Rate limiting.** `POST /api/upload` is capped at 5 requests/minute
   per IP via `flask-limiter`, returning `429` once exceeded.
4. **CORS.** No `Access-Control-Allow-Origin` header is sent unless you
   explicitly set `ALLOWED_ORIGINS`. By default, only same-origin
   requests work — which is all this app needs, since it serves its own
   frontend.
5. **Chunked, tamper-bound encryption.** Files are encrypted in 4 MB
   chunks instead of one buffer. Each chunk's ciphertext is
   cryptographically bound (via AES-GCM associated data) to its position
   and the total chunk count, so a tampered vault entry — reordered,
   dropped, or spliced chunks — fails decryption instead of silently
   producing corrupted output. Cap raised to 100 MB.

Also fixed as part of making this deployable at all:
- `debug=False` by default (`FLASK_DEBUG=1` opts in explicitly, for
  local dev only — the Werkzeug debugger it enables is a remote code
  execution risk if it's ever reachable from outside your own machine).
- A `Procfile` + `gunicorn` for running behind a real WSGI server instead
  of Flask's built-in dev server.

One small UI fix: the **Download** button disables itself and changes to
"Downloaded ✓" after first use. This is cosmetic only — the real one-time
enforcement already happened server-side the moment `GET /api/drop/<id>`
was answered — but it makes the UI reflect what's already true instead of
leaving a live, clickable button sitting there after the file's been
delivered.

## Two ways to send: Quick Link vs. Vault

Earlier versions of this project had one honest, unresolved gap: **the
ML-KEM step didn't defend against "harvest now, decrypt later."** The
sender generated a fresh keypair per upload, encapsulated against their
own public key, and discarded it — never transmitted anywhere. No public
key in transit means nothing for a future quantum computer to have
harvested; that mode was cryptographically equivalent to just generating
32 random bytes directly.

That's fixed now, but the fix is a genuinely different mode, not a patch
to the old one — both exist side by side because they make different
tradeoffs:

- **Quick Link** (the original behavior, still the default) — the sender
  generates a one-time keypair and puts the decapsulation key directly
  in the link's URL fragment. Zero setup, works with anyone. But the
  link itself is a bearer secret: whoever holds it can decrypt, with or
  without a quantum computer. Fine for convenience; doesn't meaningfully
  benefit from ML-KEM's quantum resistance.

- **Vault** (new) — the *recipient* generates one long-term ML-KEM-512
  keypair, once, via Settings → Vault Identity, and publishes the public
  half to this server's identity directory under a chosen Vault ID (`POST
  /api/vault/register`). The private half never leaves their device
  (optionally passphrase-protected with PBKDF2 + AES-256-GCM before it
  even touches localStorage). Senders look up that public key (`GET
  /api/vault/<id>/pubkey`) and encapsulate against it instead of a
  throwaway key. The resulting link carries **no key at all** — just a
  pointer plus which vault it's addressed to. This is what actually
  defends against harvest-now-decrypt-later: there's now a real public
  key traveling over real network traffic, and ML-KEM (unlike RSA/ECDH)
  has no known efficient quantum attack against it.

Vault identities are exportable/importable as a JSON backup (Settings →
Export/Import) so a recipient isn't locked to one device — and
deliberately **immutable once registered**: there's no update endpoint,
because allowing one without proof of private-key ownership would let
anyone hijack an existing Vault ID by re-registering it with a different
public key. Lose your device and your backup, and the fix is the same as
losing a PGP key — pick a new Vault ID.

## Link revocation

A sender can cancel a Quick Link or Vault link before anyone opens it —
Activity tab → Cancel. Mechanism: `/api/upload` returns a `revokeToken`
alongside the drop id, once, in that response only. The server never
stores the raw token — only its SHA-256 hash, same principle as password
storage — so revoking later means presenting the raw token again via
`DELETE /api/drop/<id>`, checked with a constant-time comparison
(`hmac.compare_digest`) to avoid timing side-channels. The token lives
only in the sender's local Activity log entry; losing it just means the
link can no longer be canceled early, it still expires normally on its
own.

## Delivery confirmation

The Activity tab polls `GET /api/drop/<id>/status` every 15s for
anything still locally pending, and flips "sent" to "opened" (with a
real server timestamp) once it is. Implementation is a separate
`receipts` table — deliberately not a column on `drops` — so the strict
"ciphertext deleted atomically on first access" property is completely
unaffected: the receipt (a timestamp, nothing else) is written in the
*same transaction* as the ciphertext delete, and only for genuine
deliveries, not expired-but-unswept fetches. Receipts self-expire after
24h.

**Precise semantic, worth being exact about:** "opened" means the
ciphertext was successfully *fetched* from the server — that's the most
the server can ever know, since decryption happens entirely client-side
and the server has no visibility into whether it then succeeded. In
practice these are almost always the same event, with one real exception:
opening a Vault link on a device that doesn't hold the matching identity
still consumes the one-time link (fetch happens, ciphertext is gone) even
though decryption then fails locally. Same tradeoff email read receipts
make — "delivered" isn't "comprehended."

## Vault key fingerprints

Every Vault identity has a fingerprint (first 16 bytes of SHA-256(`ek`),
grouped hex) — shown in Settings for your own identity, and shown to a
sender the moment they look up a recipient's key, before encryption
starts. This is the mitigation for Vault ID registration having no
proof-of-ownership (see below): it can't stop someone from squatting a
name, but it makes an impersonation attempt *detectable* if the two
parties compare the fingerprint out-of-band — the same trust model
Signal and PGP use in production. Deliberately **not** implemented:
cryptographic proof-of-possession at registration, which would require
this server to execute ML-KEM operations against the submitted public
key. That's a narrow, safe operation (no secret material involved), but
it would still contradict this app's core claim that the Flask backend
runs zero cryptographic code — so the trade wasn't made, and the gap is
named rather than quietly patched over.

## What's still out of scope, on purpose

Persistent audit trails, database redundancy/backups, and disk-backed
streaming uploads (100 MB is still buffered in memory on both ends —
fine for a demo, not arbitrary file sizes at real scale). Vault ID
registration remains first-come-first-served with no proof-of-ownership
beyond immutability (mitigated, not solved, by the fingerprint display
above) — anyone can see that a Vault ID exists and its public key (by
design, same as a PGP keyserver), and there's no rate-limit-independent
Sybil resistance on who can *claim* IDs beyond the existing per-IP rate
limiter.

## Deploying (tested end to end on Render's free tier)

The live link above was deployed exactly this way:

1. **Push the code to GitHub.** If you use GitHub's web upload instead of
   `git push`, drag the `static` and `src` **folders themselves** into the
   uploader — dragging individual files instead flattens the folder
   structure, which breaks Flask's `static/...` paths and produces a 404
   on every page. Confirm afterward that the repo shows nested paths like
   `static/js/app.js`, not `app.js` sitting at the root.
2. On [render.com](https://render.com), **New +** → **Web Service** →
   connect the repo.
3. Configure:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 2 --threads 4 --bind 0.0.0.0:$PORT`
   - **Instance Type:** Free
   - Leave environment variables empty (no `ALLOWED_ORIGINS` needed —
     frontend and API share an origin here).
4. Deploy, then **test from a genuinely different device** — phone on
   cellular data, not the same WiFi — since that's the only way to
   confirm it isn't secretly still local-only.

For platforms other than Render (Railway, Fly.io, etc.), the same
`Procfile` start command works — just paste it into whatever field that
platform uses for a start command.

For anything beyond a demo deployment, also consider:
- `RATELIMIT_STORAGE_URI=redis://...` — the default in-memory rate
  limiter doesn't share state across multiple gunicorn workers or
  survive a restart. Fine for a single small instance; a real deployment
  with multiple workers needs Redis.
- SQLite works for a demo; a real deployment should use Postgres for
  concurrent-write safety and durability.

## Project layout

```
app.py                     Flask backend: upload/drop/health routes, Vault identity directory, expiry sweep, rate limiting
Procfile                   gunicorn start command for deployment
requirements.txt           Flask, flask-cors, flask-limiter, gunicorn
static/index.html          Single-page app (Send/Receive, Activity, Keys tabs), CSP hardened
static/css/style.css       Styling
static/js/app.js           Crypto core (Quick Link + Vault), Vault identity storage, UI logic
static/js/mlkem.bundle.js  Pre-built ML-KEM-512 (bundled from @noble/post-quantum)
src/mlkem-entry.js         Source for the bundle above
package.json               `npm run build` to regenerate the bundle after editing src/
```

## Manual verification

```bash
python app.py &
# Upload a file, pick a short TTL, copy the link.
# Open the link — file downloads.
# Open the *same* link again — "already been used".
# Wait out the TTL without opening it — link 410s, then disappears
#   from the database within ~30s even without being fetched.
# Fire off 6 uploads within a minute — the 6th gets rate-limited.
```
