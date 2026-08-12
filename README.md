# CipherDrop

Quantum-safe, one-time file sharing. Files, filenames, and file types are
all encrypted **in the browser** with ML-KEM-512 (NIST FIPS 203) +
AES-256-GCM before anything leaves your machine — the server only ever
stores and forwards ciphertext.

**Live:** https://cipherdrop-ajww.onrender.com
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

## What's still an open, known limitation (by design, not oversight)

**The ML-KEM step does not yet defend against "harvest now, decrypt
later."** The sender generates a fresh keypair per upload, encapsulates
against their own public key, and discards it — it's never transmitted
anywhere. That means there's no public key in transit for a future
quantum computer to have "harvested." Right now this system is
cryptographically equivalent to generating 32 random bytes directly.

Fixing this for real requires **persistent recipient identities** (a
published, long-lived `ek` per user — closer to how PGP or Signal
prekeys work) so the sender encapsulates against a key that genuinely
travels over the network today and would genuinely need breaking later.
That's a materially bigger product than this one and is out of scope
here — flagging it explicitly rather than letting the pitch imply
otherwise.

Also out of scope on purpose: link revocation, delivery confirmation,
persistent audit trails, database redundancy/backups, and
disk-backed streaming uploads (100 MB is still buffered in memory on
both ends — fine for a demo, not for arbitrary file sizes at real
scale).

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
app.py                     Flask backend: /api/upload, /api/drop/<id>, expiry sweep, rate limiting
Procfile                   gunicorn start command for deployment
requirements.txt           Flask, flask-cors, flask-limiter, gunicorn
static/index.html          Single-page app (send view + receive view), CSP hardened
static/css/style.css       Styling
static/js/app.js           Upload/download flow, chunked WebCrypto AES-GCM, TTL selection
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
