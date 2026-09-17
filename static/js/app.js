// CipherDrop — frontend crypto workflow, talking to a real Flask backend.
//
// SEND:    keygen (ek, dk) -> encaps(ek) -> (kemCipherText, sharedSecret)
//          -> encrypt an encrypted metadata "header" (filename/mimetype/size)
//          -> AES-256-GCM encrypt the file in 4 MB chunks, each bound via
//             associated data (AAD) to its position + total chunk count
//          -> POST {kemCipherText, salt, headerCt, chunks, ttlMs} to the server
//          -> link = origin/drop/<id>#<dk>   (dk NEVER sent to the server)
//
// RECEIVE: read dk (from location.hash on a direct link, or parsed out of
//          a pasted link in the Receive pane) -> GET /api/drop/<id>
//          (server deletes the record as part of answering this request;
//           returns 410 if it was already expired, 404 if unknown/used)
//          -> decaps(kemCipherText, dk) -> sharedSecret
//          -> decrypt header -> {filename, mimetype}
//          -> decrypt each chunk -> reassemble -> trigger download
//
// The server never sees a filename, MIME type, or plaintext byte at any
// point — only ciphertext, a salt, and an expiry timestamp.
//
// Everything below the crypto core (tabs, activity log, settings, paste-
// to-receive, health check) is UI/UX around that unchanged pipeline.

(() => {
  'use strict';

  const CHUNK_BYTES = 4 * 1024 * 1024; // 4 MB per AES-GCM chunk — must match backend's expectations
  const MAX_BYTES = 100 * 1024 * 1024; // 100 MB per file (mirrors server-side MAX_UPLOAD_BYTES)
  const HEADER_INDEX_SENTINEL = 0xffffffff;

  // ---------- byte <-> base64url helpers ----------

  function bytesToB64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function b64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  function bytesToB64Url(bytes) {
    return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64UrlToBytes(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return b64ToBytes(b64);
  }

  // ---------- Vault key fingerprint (for out-of-band verification) ----------
  // Real cryptographic proof-of-possession for a KEM key would require
  // the SERVER to run ML-KEM operations against the submitted public key
  // — which would directly contradict this app's core claim that the
  // Flask backend executes zero cryptographic code. Rather than quietly
  // break that guarantee for one feature, this does what Signal and PGP
  // actually do in practice: a fingerprint of the public key, computed
  // entirely client-side, that two people can compare out-of-band (read
  // it aloud, post it somewhere, etc.) before trusting a Vault ID. It
  // doesn't stop someone from registering a name before its rightful
  // owner does, but it makes an impersonation attempt DETECTABLE instead
  // of invisible — the same tradeoff every public-key directory makes.
  async function ekFingerprint(ekBytes) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', ekBytes));
    const hex = Array.from(digest.slice(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
    return hex.toUpperCase().match(/.{1,4}/g).join(' ');
  }

  // ---------- chunked AES-256-GCM with per-chunk IV + AAD ----------
  // IV = 8-byte random salt + 4-byte big-endian counter (0 reserved for
  // the metadata header, i+1 for chunk i); AAD binds each ciphertext to
  // its index and the total chunk count so tampering (reordering /
  // dropping / splicing) breaks authentication instead of silently
  // corrupting output.

  function makeIv(salt8, counter) {
    const iv = new Uint8Array(12);
    iv.set(salt8, 0);
    new DataView(iv.buffer).setUint32(8, counter, false);
    return iv;
  }
  function makeAad(index, total) {
    const aad = new Uint8Array(8);
    const view = new DataView(aad.buffer);
    view.setUint32(0, index, false);
    view.setUint32(4, total, false);
    return aad;
  }
  async function importAesKey(keyBytes, usage) {
    return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, [usage]);
  }
  async function aesEncryptWithAad(key, iv, aad, plaintextBytes) {
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintextBytes);
    return new Uint8Array(ct);
  }
  async function aesDecryptWithAad(key, iv, aad, ciphertextBytes) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertextBytes);
    return new Uint8Array(pt);
  }

  // ---------- progress UI ----------

  function setStep(container, stepName, state, label) {
    const el = container.querySelector(`[data-step="${stepName}"]`);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (state) el.classList.add(state);
    if (label) el.textContent = label;
  }

  // setStep() only ever overwrites text when a label is passed, so a
  // dynamic label from one run (e.g. Vault mode's "Looking up
  // recipient's Vault key…" on the shared 'keygen' step) was sticking
  // around on the NEXT run — including after switching modes — because
  // nothing ever restored the original static text. captureStepDefaults()
  // snapshots each step's markup text once at startup; resetStep() puts
  // it back, so every fresh attempt starts from a clean, correct label.
  function captureStepDefaults(container) {
    const defaults = {};
    if (!container) return defaults;
    container.querySelectorAll('[data-step]').forEach((el) => {
      defaults[el.dataset.step] = el.textContent;
    });
    return defaults;
  }
  function resetStep(container, stepName, defaults) {
    const el = container.querySelector(`[data-step="${stepName}"]`);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (defaults && defaults[stepName] !== undefined) el.textContent = defaults[stepName];
  }

  // ---------- tiny toast ----------

  let toastTimer = null;
  function showToast(text, kind) {
    const toast = document.getElementById('toast');
    const dot = document.getElementById('toast-dot');
    const textEl = document.getElementById('toast-text');
    textEl.textContent = text;
    dot.className = 'toast-dot' + (kind ? ' ' + kind : '');
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 3200);
  }

  // ================= Vault Identity =================
  // A LONG-LIVED ML-KEM-512 keypair, generated once per device (or
  // imported from a backup), used for "Send to a Vault" instead of the
  // throwaway per-file keypair Quick Send uses. This is what makes the
  // quantum-resistance claim actually meaningful: ek is genuinely public
  // and genuinely travels over the network to whoever wants to send here;
  // dk never does, not even inside a link.
  //
  // Stored in localStorage only — never transmitted. Optionally wrapped
  // with a passphrase (PBKDF2 -> AES-256-GCM) so the raw private key
  // isn't sitting in cleartext on shared/untrusted machines. Losing both
  // the device and any exported backup means losing the identity
  // permanently — there is deliberately no server-side recovery, because
  // a recovery path would mean the server could reconstruct dk, which
  // defeats the entire point.

  const IDENTITY_STORAGE_KEY = 'cipherdrop_vault_identity';
  const KDF_ITERATIONS = 210000;

  function loadIdentity() {
    try {
      const raw = localStorage.getItem(IDENTITY_STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }
  function saveIdentity(identity) {
    localStorage.setItem(IDENTITY_STORAGE_KEY, JSON.stringify(identity));
  }
  function clearIdentity() {
    localStorage.removeItem(IDENTITY_STORAGE_KEY);
  }

  async function deriveWrappingKey(passphrase, saltBytes) {
    const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: KDF_ITERATIONS, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function wrapDkWithPassphrase(dkBytes, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveWrappingKey(passphrase, salt);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dkBytes));
    return { ct: bytesToB64(ct), salt: bytesToB64(salt), iv: bytesToB64(iv) };
  }

  async function unwrapDkWithPassphrase(wrapped, passphrase) {
    const key = await deriveWrappingKey(passphrase, b64ToBytes(wrapped.salt));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(wrapped.iv) }, key, b64ToBytes(wrapped.ct));
    return new Uint8Array(pt);
  }

  // Resolves an identity's usable dk, prompting for a passphrase if the
  // stored copy is wrapped. Throws if the passphrase is wrong/declined.
  async function getUsableDk(identity) {
    if (identity.dk) return b64ToBytes(identity.dk);
    const passphrase = window.prompt(`Enter the passphrase for Vault "${identity.vaultId}" to decrypt:`);
    if (!passphrase) throw new Error('A passphrase is required to unlock this Vault identity.');
    try {
      return await unwrapDkWithPassphrase(identity.dkWrapped, passphrase);
    } catch {
      throw new Error('Incorrect passphrase for this Vault identity.');
    }
  }

  async function renderIdentityPanel() {
    const identity = loadIdentity();
    const noneEl = document.getElementById('identity-none');
    const existsEl = document.getElementById('identity-exists');
    if (!noneEl || !existsEl) return;
    if (identity) {
      noneEl.classList.add('hidden');
      existsEl.classList.remove('hidden');
      document.getElementById('identity-vault-id').textContent = identity.vaultId;
      document.getElementById('identity-protected-note').classList.toggle('hidden', !identity.dkWrapped);
      const fpEl = document.getElementById('identity-fingerprint');
      if (fpEl) fpEl.textContent = await ekFingerprint(b64ToBytes(identity.ek));
    } else {
      noneEl.classList.remove('hidden');
      existsEl.classList.add('hidden');
    }
  }

  function initVaultIdentity() {
    renderIdentityPanel();

    document.getElementById('create-identity-btn').addEventListener('click', async () => {
      const vaultIdInput = document.getElementById('create-vault-id-input');
      const passInput = document.getElementById('create-vault-pass-input');
      const errEl = document.getElementById('identity-error');
      errEl.classList.add('hidden');

      const vaultId = vaultIdInput.value.trim();
      if (!/^[A-Za-z0-9_-]{3,40}$/.test(vaultId)) {
        errEl.textContent = 'Vault ID must be 3–40 characters: letters, numbers, - or _.';
        errEl.classList.remove('hidden');
        return;
      }

      try {
        const { ek, dk } = window.MLKEM512.keygen();
        const res = await fetch('/api/vault/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ vaultId, ek: bytesToB64(ek) }),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.error || `registration failed (${res.status})`);
        }

        const passphrase = passInput.value;
        const identity = passphrase
          ? { vaultId, ek: bytesToB64(ek), dkWrapped: await wrapDkWithPassphrase(dk, passphrase) }
          : { vaultId, ek: bytesToB64(ek), dk: bytesToB64(dk) };
        saveIdentity(identity);
        renderIdentityPanel();
        vaultIdInput.value = '';
        passInput.value = '';
        showToast(`Vault "${vaultId}" created on this device`, 'ok');
      } catch (err) {
        errEl.textContent = err.message || 'Could not create this Vault identity.';
        errEl.classList.remove('hidden');
      }
    });

    document.getElementById('export-identity-btn').addEventListener('click', () => {
      const identity = loadIdentity();
      if (!identity) return;
      const blob = new Blob([JSON.stringify(identity, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cipherdrop-vault-${identity.vaultId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });

    document.getElementById('forget-identity-btn').addEventListener('click', () => {
      clearIdentity();
      renderIdentityPanel();
      showToast('Identity removed from this device', 'ok');
    });

    document.getElementById('import-identity-input').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const errEl = document.getElementById('identity-error');
      errEl.classList.add('hidden');
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        if (!parsed.vaultId || !parsed.ek || !(parsed.dk || parsed.dkWrapped)) {
          throw new Error('That file doesn\'t look like a CipherDrop Vault identity export.');
        }
        saveIdentity(parsed);
        renderIdentityPanel();
        showToast(`Vault "${parsed.vaultId}" imported`, 'ok');
      } catch (err) {
        errEl.textContent = err.message || 'Could not import that identity file.';
        errEl.classList.remove('hidden');
      }
      e.target.value = '';
    });
  }

  // ================= NAV: tabs =================

  function initTabs() {
    const tabs = document.querySelectorAll('.nav-tab');
    const panels = {
      vault: document.getElementById('tab-vault'),
      activity: document.getElementById('tab-activity'),
      keys: document.getElementById('tab-keys'),
    };

    function activate(tabName) {
      tabs.forEach((t) => {
        const isActive = t.dataset.tab === tabName;
        t.classList.toggle('active', isActive);
        t.setAttribute('aria-selected', String(isActive));
      });
      Object.entries(panels).forEach(([name, el]) => el.classList.toggle('hidden', name !== tabName));
    }

    tabs.forEach((t) => t.addEventListener('click', () => activate(t.dataset.tab)));

    document.getElementById('nav-send-btn').addEventListener('click', () => {
      activate('vault');
      setMode('send');
      document.getElementById('dropzone').focus();
    });

    document.getElementById('footer-protocol-link').addEventListener('click', (e) => {
      e.preventDefault();
      activate('keys');
    });

    return { activate };
  }

  // ================= Send / Receive mode toggle =================

  function setMode(mode) {
    const sendBtn = document.getElementById('mode-send-btn');
    const receiveBtn = document.getElementById('mode-receive-btn');
    const sendPane = document.getElementById('send-view');
    const receivePane = document.getElementById('receive-view');

    const isSend = mode === 'send';
    sendBtn.classList.toggle('active', isSend);
    sendBtn.setAttribute('aria-selected', String(isSend));
    receiveBtn.classList.toggle('active', !isSend);
    receiveBtn.setAttribute('aria-selected', String(!isSend));
    sendPane.classList.toggle('hidden', !isSend);
    receivePane.classList.toggle('hidden', isSend);
  }

  function initModeToggle() {
    document.getElementById('mode-send-btn').addEventListener('click', () => setMode('send'));
    document.getElementById('mode-receive-btn').addEventListener('click', () => setMode('receive'));
  }

  // ================= Profile / Settings dropdowns =================

  function initDropdowns() {
    const pairs = [
      ['profile-btn', 'profile-dropdown'],
      ['settings-btn', 'settings-dropdown'],
    ];
    const dropdownEls = pairs.map(([, dropId]) => document.getElementById(dropId));

    function closeAll(except) {
      dropdownEls.forEach((el) => { if (el !== except) el.classList.add('hidden'); });
    }

    pairs.forEach(([btnId, dropId]) => {
      const btn = document.getElementById(btnId);
      const drop = document.getElementById(dropId);
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const willOpen = drop.classList.contains('hidden');
        closeAll();
        if (willOpen) drop.classList.remove('hidden');
      });
    });

    document.addEventListener('click', () => closeAll());
    dropdownEls.forEach((el) => el.addEventListener('click', (e) => e.stopPropagation()));

    // Settings: default TTL applies immediately to the visible send-view control.
    document.getElementById('default-ttl-select').addEventListener('change', (e) => {
      document.getElementById('ttl-select').value = e.target.value;
    });
  }

  // ================= Terms panel + API status (footer) =================

  function initFooter() {
    const termsPanel = document.getElementById('terms-panel');
    document.getElementById('footer-terms-link').addEventListener('click', (e) => {
      e.preventDefault();
      termsPanel.classList.remove('hidden');
    });
    document.getElementById('terms-close-btn').addEventListener('click', () => {
      termsPanel.classList.add('hidden');
    });

    document.getElementById('footer-status-link').addEventListener('click', async (e) => {
      e.preventDefault();
      const start = performance.now();
      try {
        const res = await fetch('/api/health');
        const ms = Math.round(performance.now() - start);
        if (res.ok) showToast(`API Status: Operational (${ms}ms)`, 'ok');
        else showToast(`API Status: Unexpected response (${res.status})`, 'bad');
      } catch {
        showToast('API Status: Unreachable', 'bad');
      }
    });
  }

  // ================= Activity log (sender-side, in-memory only) =================
  // Never transmitted anywhere — this is the one place a filename is
  // visible in the clear, because it's the sender's own browser
  // remembering what it already knew before encrypting.

  const activityLog = [];

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  function addActivityEntry(entry) {
    // status starts 'pending'; flips to 'expired' (by time, computed at
    // render) or 'revoked' (explicitly, via the Cancel button below).
    activityLog.unshift({ status: 'pending', ...entry });
    renderActivityLog();
  }

  async function revokeActivityEntry(entry, badgeEl, cancelBtn) {
    cancelBtn.disabled = true;
    cancelBtn.textContent = 'Canceling…';
    try {
      const res = await fetch(`/api/drop/${encodeURIComponent(entry.dropId)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revokeToken: entry.revokeToken }),
      });
      if (res.status === 204) {
        entry.status = 'revoked';
        renderActivityLog();
        showToast('Link revoked — no longer retrievable', 'ok');
      } else {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `revoke failed (${res.status})`);
      }
    } catch (err) {
      cancelBtn.disabled = false;
      cancelBtn.textContent = 'Cancel';
      showToast(err.message || 'Could not revoke this link', 'bad');
    }
  }

  function renderActivityLog() {
    const list = document.getElementById('activity-list');
    const now = Date.now();
    if (activityLog.length === 0) {
      list.innerHTML = '<div class="activity-empty">Nothing sent yet in this session.</div>';
      return;
    }
    list.innerHTML = '';
    for (const entry of activityLog) {
      const timedOut = entry.expiresAt <= now;
      // 'revoked' and 'opened' are sticky (both come from an explicit
      // event, not the clock); otherwise derive pending/expired from the
      // clock every render.
      const displayStatus =
        entry.status === 'revoked' || entry.status === 'opened' ? entry.status : (timedOut ? 'expired' : 'pending');

      const row = document.createElement('div');
      row.className = 'activity-item';

      const icon = document.createElement('span');
      icon.className = 'activity-item-icon';
      icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';

      const main = document.createElement('div');
      main.className = 'activity-item-main';
      const name = document.createElement('div');
      name.className = 'activity-item-name';
      name.textContent = entry.filename;
      name.title = entry.filename;
      const meta = document.createElement('div');
      meta.className = 'activity-item-meta';
      if (displayStatus === 'revoked') {
        meta.textContent = `${formatBytes(entry.sizeBytes)} · revoked by you`;
      } else if (displayStatus === 'opened') {
        meta.textContent = `${formatBytes(entry.sizeBytes)} · opened ${new Date(entry.openedAt).toLocaleTimeString()}`;
      } else if (displayStatus === 'expired') {
        meta.textContent = `${formatBytes(entry.sizeBytes)} · expired`;
      } else {
        meta.textContent = `${formatBytes(entry.sizeBytes)} · one-time link, expires ${new Date(entry.expiresAt).toLocaleTimeString()} if unopened`;
      }
      main.append(name, meta);

      const badge = document.createElement('span');
      badge.className = `status-badge ${displayStatus}`;
      badge.textContent = displayStatus === 'pending' ? 'sent' : displayStatus;

      row.append(icon, main, badge);

      if (displayStatus === 'pending' && entry.dropId && entry.revokeToken) {
        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'activity-cancel-btn';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.addEventListener('click', () => revokeActivityEntry(entry, badge, cancelBtn));
        row.appendChild(cancelBtn);
      }

      list.appendChild(row);
    }
  }

  // Polls delivery status for anything still locally 'pending', so "sent"
  // can flip to "opened" (with a real timestamp from the server) without
  // the sender needing to do anything. Never touches revoked/expired
  // entries — those are already resolved, no point asking the server
  // again. A drop's ciphertext is still gone the instant it's fetched,
  // same as always; this only reads a separate, short-lived receipt
  // timestamp — see app.py's receipts table for why that's a safe
  // separation to make.
  async function pollActivityStatuses() {
    const now = Date.now();
    const pending = activityLog.filter(
      (e) => e.status !== 'revoked' && e.status !== 'opened' && e.expiresAt > now && e.dropId
    );
    if (pending.length === 0) return;

    let changed = false;
    await Promise.all(pending.map(async (entry) => {
      try {
        const res = await fetch(`/api/drop/${encodeURIComponent(entry.dropId)}/status`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.status === 'opened') {
          entry.status = 'opened';
          entry.openedAt = data.openedAt;
          changed = true;
        }
      } catch {
        // Network hiccup — just try again on the next poll tick.
      }
    }));
    if (changed) renderActivityLog();
  }

  // Re-render periodically so "sent" flips to "expired" without needing a
  // reload, and poll for delivery confirmation on whatever's still pending.
  setInterval(() => {
    if (activityLog.length) renderActivityLog();
    pollActivityStatuses();
  }, 15000);

  // ================= SEND =================

  let sendToVaultMode = false;

  function initSendModeToggle() {
    const quickBtn = document.getElementById('send-quick-btn');
    const vaultBtn = document.getElementById('send-vault-btn');
    const vaultRow = document.getElementById('send-vault-id-row');
    if (!quickBtn || !vaultBtn) return;

    function setSendMode(toVault) {
      sendToVaultMode = toVault;
      quickBtn.classList.toggle('active', !toVault);
      vaultBtn.classList.toggle('active', toVault);
      vaultRow.classList.toggle('hidden', !toVault);
    }

    quickBtn.addEventListener('click', () => setSendMode(false));
    vaultBtn.addEventListener('click', () => setSendMode(true));
  }

  function initSendView() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const progress = document.getElementById('progress');
    const result = document.getElementById('result');
    const errorBox = document.getElementById('error');
    const resultLink = document.getElementById('result-link');
    const copyBtn = document.getElementById('copy-btn');
    const resetBtn = document.getElementById('reset-btn');
    const ttlSelect = document.getElementById('ttl-select');
    const expiryNote = document.getElementById('expiry-note');
    const sendStepDefaults = captureStepDefaults(progress);

    dropzone.tabIndex = 0;
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
    });
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length) handleFile(fileInput.files[0]);
    });

    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(resultLink.value);
        copyBtn.textContent = 'Copied';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1400);
      } catch {
        // Clipboard permission denied, insecure context, unfocused
        // document, etc. — fall back to manual selection so the user
        // still has a way to get the link, instead of a silent no-op.
        resultLink.select();
        showToast('Could not copy automatically — link is selected, press Ctrl/Cmd+C', 'bad');
      }
    });

    resetBtn.addEventListener('click', () => {
      dropzone.classList.remove('hidden');
      progress.classList.add('hidden');
      result.classList.add('hidden');
      errorBox.classList.add('hidden');
      fileInput.value = '';
      const fpEl = document.getElementById('send-vault-fingerprint');
      if (fpEl) fpEl.classList.add('hidden');
      ['keygen', 'encaps', 'encrypt', 'upload'].forEach((s) => resetStep(progress, s, sendStepDefaults));
    });

    async function handleFile(file) {
      errorBox.classList.add('hidden');
      // Reset every step to its real default before a fresh attempt —
      // covers retrying after an error too, not just the explicit
      // "Share another file" button, since that path had the same bug.
      ['keygen', 'encaps', 'encrypt', 'upload'].forEach((s) => resetStep(progress, s, sendStepDefaults));

      if (file.size > MAX_BYTES) {
        showError(`"${file.name}" is ${(file.size / (1024 * 1024)).toFixed(1)} MB — this instance caps uploads at 100 MB.`);
        return;
      }
      if (file.size === 0) {
        showError(`"${file.name}" is empty — nothing to encrypt.`);
        return;
      }

      dropzone.classList.add('hidden');
      progress.classList.remove('hidden');

      try {
        let ek, dk, vaultId = null, recipientFingerprint = null;

        if (sendToVaultMode) {
          // Vault mode: no keypair of our own — encapsulate against the
          // RECIPIENT's long-lived public key instead. dk stays undefined;
          // there's nothing of ours to embed in the link, because the
          // decrypting key already lives permanently on the recipient's
          // device.
          const vaultIdInput = document.getElementById('send-vault-id-input');
          const targetVaultId = vaultIdInput.value.trim();
          if (!targetVaultId) throw new Error("Enter the recipient's Vault ID first.");

          setStep(progress, 'keygen', 'active', "Looking up recipient's Vault key…");
          const lookupRes = await fetch(`/api/vault/${encodeURIComponent(targetVaultId)}/pubkey`);
          if (!lookupRes.ok) {
            throw new Error(lookupRes.status === 404
              ? `No Vault found with ID "${targetVaultId}".`
              : `Could not look up that Vault (${lookupRes.status}).`);
          }
          const { ek: recipientEkB64 } = await lookupRes.json();
          ek = b64ToBytes(recipientEkB64);
          vaultId = targetVaultId;
          recipientFingerprint = await ekFingerprint(ek);
          const fpEl = document.getElementById('send-vault-fingerprint');
          if (fpEl) {
            fpEl.textContent = `Key fingerprint: ${recipientFingerprint} — verify this with the recipient out-of-band before trusting it.`;
            fpEl.classList.remove('hidden');
          }
          setStep(progress, 'keygen', 'done', "Found recipient's Vault key");
        } else {
          // Quick Send: fresh, one-time ML-KEM-512 keypair for this upload only.
          setStep(progress, 'keygen', 'active');
          ({ ek, dk } = window.MLKEM512.keygen());
          setStep(progress, 'keygen', 'done');
        }

        // Encapsulate — derive a session key against whichever ek is in
        // play (our own throwaway one, or the recipient's persistent one).
        setStep(progress, 'encaps', 'active');
        const { kemCipherText, sharedSecret } = window.MLKEM512.encapsulate(ek);
        setStep(progress, 'encaps', 'done');

        // Encrypt metadata header + file in chunks, all bound via AAD.
        setStep(progress, 'encrypt', 'active', 'Encrypting file with AES-256-GCM…');
        const fileBytes = new Uint8Array(await file.arrayBuffer());
        const numChunks = Math.max(1, Math.ceil(fileBytes.length / CHUNK_BYTES));
        const salt = crypto.getRandomValues(new Uint8Array(8));
        const aesKey = await importAesKey(sharedSecret, 'encrypt');

        const headerPlaintext = new TextEncoder().encode(
          JSON.stringify({ filename: file.name, mimetype: file.type || 'application/octet-stream', size: fileBytes.length })
        );
        const headerCt = await aesEncryptWithAad(
          aesKey, makeIv(salt, 0), makeAad(HEADER_INDEX_SENTINEL, numChunks), headerPlaintext
        );

        const chunks = [];
        for (let i = 0; i < numChunks; i++) {
          const start = i * CHUNK_BYTES;
          const slice = fileBytes.subarray(start, Math.min(start + CHUNK_BYTES, fileBytes.length));
          const ct = await aesEncryptWithAad(aesKey, makeIv(salt, i + 1), makeAad(i, numChunks), slice);
          chunks.push(bytesToB64(ct));
          setStep(progress, 'encrypt', 'active', `Encrypting file with AES-256-GCM… ${Math.round(((i + 1) / numChunks) * 100)}%`);
        }
        setStep(progress, 'encrypt', 'done', 'Encrypted file with AES-256-GCM');

        // Upload ciphertext + encrypted metadata only. ek (whether ours or
        // the recipient's) is never needed again after this point. dk (if
        // this was Quick Send) never leaves the browser except inside the
        // link's fragment.
        setStep(progress, 'upload', 'active');
        const ttlMs = parseInt(ttlSelect.value, 10);
        const uploadBody = {
          kemCipherText: bytesToB64(kemCipherText),
          salt: bytesToB64(salt),
          headerCt: bytesToB64(headerCt),
          chunks,
          ttlMs,
        };
        if (vaultId) uploadBody.vaultId = vaultId;

        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(uploadBody),
        });
        if (!res.ok) {
          const errBody = await res.json().catch(() => ({}));
          if (res.status === 429) throw new Error('Rate limit reached — try again in a minute.');
          throw new Error(errBody.error || `upload failed (${res.status})`);
        }
        const { id, expiresAt, revokeToken } = await res.json();
        setStep(progress, 'upload', 'done');

        // Vault links carry no key at all — just a pointer plus which
        // vault it's addressed to, for a clearer error if opened on the
        // wrong device. Quick Send links carry dk in the fragment, same
        // as before.
        const link = vaultId
          ? `${location.origin}/drop/${id}?vault=${encodeURIComponent(vaultId)}`
          : `${location.origin}/drop/${id}#${bytesToB64Url(dk)}`;

        progress.classList.add('hidden');
        resultLink.value = link;
        expiryNote.textContent = vaultId
          ? `Sent to Vault "${vaultId}" (fingerprint ${recipientFingerprint}). Expires at ${new Date(expiresAt).toLocaleTimeString()} if never opened.`
          : `Expires at ${new Date(expiresAt).toLocaleTimeString()} if never opened.`;
        result.classList.remove('hidden');

        addActivityEntry({ filename: file.name, sizeBytes: file.size, expiresAt, dropId: id, revokeToken });
      } catch (err) {
        progress.classList.add('hidden');
        dropzone.classList.remove('hidden');
        showError(err.message || 'Something went wrong while encrypting or uploading.');
      }
    }

    function showError(msg) {
      errorBox.textContent = msg;
      errorBox.classList.remove('hidden');
    }
  }

  // Captured once, at load — before any receive attempt has had a
  // chance to overwrite the static default text in this container. See
  // the comment on captureStepDefaults()/resetStep() above for why this
  // can't just be captured lazily inside receiveDrop() itself.
  const receiveStepDefaults = captureStepDefaults(document.getElementById('receive-progress'));

  // ================= RECEIVE (shared by direct link + paste-to-receive) =================

  // Given the fetched record and whatever dk (if any) came from the URL,
  // works out the actual decapsulation key to use. Quick Send drops carry
  // dk in the link; Vault-addressed drops carry none — the key has to
  // come from this device's own stored identity instead.
  async function resolveDkForRecord(record, providedDkB64) {
    if (!record.vaultId) {
      if (!providedDkB64) {
        throw new Error('This link is missing its decryption key. Make sure you copied the full URL, including everything after the "#".');
      }
      return b64UrlToBytes(providedDkB64);
    }
    const identity = loadIdentity();
    if (!identity) {
      throw new Error(`This file was sent to Vault "${record.vaultId}". Set up or import that Vault's identity on this device (Settings), then open the link again.`);
    }
    if (identity.vaultId !== record.vaultId) {
      throw new Error(`This file was sent to Vault "${record.vaultId}", but this device's identity is "${identity.vaultId}". Import the correct identity to decrypt it.`);
    }
    return getUsableDk(identity);
  }

  async function receiveDrop(dropId, dkB64) {
    const progress = document.getElementById('receive-progress');
    const result = document.getElementById('receive-result');
    const errorBox = document.getElementById('receive-error');
    const filenameEl = document.getElementById('receive-filename');
    const downloadBtn = document.getElementById('download-btn');
    const subEl = document.getElementById('receive-hint');

    errorBox.classList.add('hidden');
    result.classList.add('hidden');
    progress.classList.remove('hidden');
    ['fetch', 'decaps', 'decrypt'].forEach((s) => resetStep(progress, s, receiveStepDefaults));

    let chunkPlaintexts, filename, mimetype;

    try {
      setStep(progress, 'fetch', 'active');
      const res = await fetch(`/api/drop/${encodeURIComponent(dropId)}`);
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        if (res.status === 410) throw new Error('This link expired before it was opened and has been deleted.');
        if (res.status === 404) throw new Error('This link has already been used, or never existed.');
        throw new Error(errBody.error || `fetch failed (${res.status})`);
      }
      const record = await res.json();
      setStep(progress, 'fetch', 'done');

      setStep(progress, 'decaps', 'active', record.vaultId ? 'Unlocking with your Vault identity…' : 'Decapsulating session key…');
      const dk = await resolveDkForRecord(record, dkB64);
      const kemCipherText = b64ToBytes(record.kemCipherText);
      const sharedSecret = window.MLKEM512.decapsulate(kemCipherText, dk);
      setStep(progress, 'decaps', 'done');

      setStep(progress, 'decrypt', 'active', 'Decrypting with AES-256-GCM…');
      const aesKey = await importAesKey(sharedSecret, 'decrypt');
      const salt = b64ToBytes(record.salt);
      const numChunks = record.chunks.length;

      const headerPlaintext = await aesDecryptWithAad(
        aesKey, makeIv(salt, 0), makeAad(HEADER_INDEX_SENTINEL, numChunks), b64ToBytes(record.headerCt)
      );
      const header = JSON.parse(new TextDecoder().decode(headerPlaintext));
      filename = header.filename;
      mimetype = header.mimetype;

      chunkPlaintexts = [];
      for (let i = 0; i < numChunks; i++) {
        const pt = await aesDecryptWithAad(aesKey, makeIv(salt, i + 1), makeAad(i, numChunks), b64ToBytes(record.chunks[i]));
        chunkPlaintexts.push(pt);
        setStep(progress, 'decrypt', 'active', `Decrypting with AES-256-GCM… ${Math.round(((i + 1) / numChunks) * 100)}%`);
      }
      setStep(progress, 'decrypt', 'done', 'Decrypted with AES-256-GCM');
    } catch (err) {
      progress.classList.add('hidden');
      showError(err.message || 'Decryption failed. The link may be malformed or already used.');
      return;
    }

    progress.classList.add('hidden');
    if (subEl) subEl.textContent = 'Decrypted successfully. The link is now permanently gone from the server.';
    filenameEl.textContent = filename;
    result.classList.remove('hidden');

    const newBtn = downloadBtn.cloneNode(true); // strip any previous listener if this runs twice
    downloadBtn.replaceWith(newBtn);
    newBtn.addEventListener('click', () => {
      const blob = new Blob(chunkPlaintexts, { type: mimetype });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      // Cosmetic only — the real one-time enforcement already happened
      // server-side the moment GET /api/drop/<id> was answered.
      newBtn.disabled = true;
      newBtn.textContent = 'Downloaded ✓';
    });

    function showError(msg) {
      errorBox.textContent = msg;
      errorBox.classList.remove('hidden');
    }
  }

  // Parses either a full CipherDrop link or just the "/drop/<id>..."
  // portion of one, pasted by the user into the Receive pane. Quick Send
  // links carry a key in the fragment; Vault links carry none — the
  // server's own response later confirms which kind this is.
  function parsePastedLink(text) {
    const trimmed = text.trim();
    const idMatch = trimmed.match(/\/drop\/([a-f0-9]{32})/);
    if (!idMatch) return null;
    const fragMatch = trimmed.match(/#([A-Za-z0-9\-_]+)/);
    return { id: idMatch[1], dk: fragMatch ? fragMatch[1] : null };
  }

  function initPasteToReceive() {
    const input = document.getElementById('receive-link-input');
    const btn = document.getElementById('receive-decrypt-btn');
    const errorBox = document.getElementById('receive-error');

    function submit() {
      const parsed = parsePastedLink(input.value);
      if (!parsed) {
        errorBox.textContent = 'That doesn\'t look like a CipherDrop link — check you copied the whole thing.';
        errorBox.classList.remove('hidden');
        return;
      }
      receiveDrop(parsed.id, parsed.dk);
    }

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  }

  // ================= ROUTING =================

  function main() {
    initTabs();
    initModeToggle();
    initDropdowns();
    initFooter();
    initSendModeToggle();
    initSendView();
    initPasteToReceive();
    initVaultIdentity();

    // A direct shared link auto-decrypts immediately, same as before —
    // the paste flow above is an *additional* way in, for when someone
    // lands on the plain "/" page instead. Works for both link kinds:
    // Quick Send carries dk in the hash fragment; Vault links carry none
    // (dk comes from this device's stored identity instead, resolved
    // once the server confirms which vault the drop is addressed to).
    const match = location.pathname.match(/^\/drop\/([a-f0-9]{32})\/?$/);
    if (match) {
      setMode('receive');
      document.getElementById('receive-paste-row').classList.add('hidden');
      document.getElementById('receive-hint').classList.add('hidden');
      const dkB64 = location.hash.slice(1) || null;
      receiveDrop(match[1], dkB64);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', main);
  } else {
    main();
  }
})();
