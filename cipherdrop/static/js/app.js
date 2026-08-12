// CipherDrop — frontend crypto workflow, talking to a real Flask backend.
//
// SEND:    keygen (ek, dk) -> encaps(ek) -> (kemCipherText, sharedSecret)
//          -> encrypt an encrypted metadata "header" (filename/mimetype/size)
//          -> AES-256-GCM encrypt the file in 4 MB chunks, each bound via
//             associated data (AAD) to its position + total chunk count
//          -> POST {kemCipherText, salt, headerCt, chunks, ttlMs} to the server
//          -> link = origin/drop/<id>#<dk>   (dk NEVER sent to the server)
//
// RECEIVE: read dk from location.hash -> GET /api/drop/<id>
//          (server deletes the record as part of answering this request;
//           returns 410 if it was already expired, 404 if unknown/used)
//          -> decaps(kemCipherText, dk) -> sharedSecret
//          -> decrypt header -> {filename, mimetype}
//          -> decrypt each chunk -> reassemble -> trigger download
//
// The server never sees a filename, MIME type, or plaintext byte at any
// point — only ciphertext, a salt, and an expiry timestamp.

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

  // ---------- chunked AES-256-GCM with per-chunk IV + AAD ----------
  // See the standalone build's comments for the full rationale — same
  // scheme here: IV = 8-byte random salt + 4-byte big-endian counter
  // (0 reserved for the metadata header, i+1 for chunk i); AAD binds
  // each ciphertext to its index and the total chunk count so tampering
  // (reordering/dropping/splicing) breaks authentication instead of
  // silently corrupting output.

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

  // ================= SEND VIEW =================

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
      await navigator.clipboard.writeText(resultLink.value);
      copyBtn.textContent = 'Copied';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1400);
    });

    resetBtn.addEventListener('click', () => {
      dropzone.classList.remove('hidden');
      progress.classList.add('hidden');
      result.classList.add('hidden');
      errorBox.classList.add('hidden');
      fileInput.value = '';
      ['keygen', 'encaps', 'encrypt', 'upload'].forEach((s) => setStep(progress, s, null));
    });

    async function handleFile(file) {
      errorBox.classList.add('hidden');

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
        // 1. Keygen — fresh ML-KEM-512 keypair for this upload only.
        setStep(progress, 'keygen', 'active');
        const { ek, dk } = window.MLKEM512.keygen();
        setStep(progress, 'keygen', 'done');

        // 2. Encapsulate — derive a session key against our own ek.
        setStep(progress, 'encaps', 'active');
        const { kemCipherText, sharedSecret } = window.MLKEM512.encapsulate(ek);
        setStep(progress, 'encaps', 'done');

        // 3. Encrypt metadata header + file in chunks, all bound via AAD.
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

        // 4. Upload ciphertext + encrypted metadata only. ek is
        //    discarded — it's never needed again. dk never leaves the
        //    browser.
        setStep(progress, 'upload', 'active');
        const ttlMs = parseInt(ttlSelect.value, 10);
        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            kemCipherText: bytesToB64(kemCipherText),
            salt: bytesToB64(salt),
            headerCt: bytesToB64(headerCt),
            chunks,
            ttlMs,
          }),
        });
        if (!res.ok) {
          const errBody = await res.json().catch(() => ({}));
          if (res.status === 429) throw new Error('Rate limit reached — try again in a minute.');
          throw new Error(errBody.error || `upload failed (${res.status})`);
        }
        const { id, expiresAt } = await res.json();
        setStep(progress, 'upload', 'done');

        const link = `${location.origin}/drop/${id}#${bytesToB64Url(dk)}`;
        progress.classList.add('hidden');
        resultLink.value = link;
        expiryNote.textContent = `Expires at ${new Date(expiresAt).toLocaleTimeString()} if never opened.`;
        result.classList.remove('hidden');
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

  // ================= RECEIVE VIEW =================

  async function initReceiveView(dropId) {
    const progress = document.getElementById('receive-progress');
    const result = document.getElementById('receive-result');
    const errorBox = document.getElementById('receive-error');
    const filenameEl = document.getElementById('receive-filename');
    const downloadBtn = document.getElementById('download-btn');
    const subEl = document.getElementById('receive-sub');

    const dkB64 = location.hash.slice(1);
    if (!dkB64) {
      progress.classList.add('hidden');
      showError('This link is missing its decryption key. Make sure you copied the full URL, including everything after the "#".');
      return;
    }

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

      setStep(progress, 'decaps', 'active');
      const dk = b64UrlToBytes(dkB64);
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
    subEl.textContent = 'Decrypted successfully. The link is now permanently gone from the server.';
    filenameEl.textContent = filename;
    result.classList.remove('hidden');

    downloadBtn.addEventListener('click', () => {
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
      // server-side the moment GET /api/drop/<id> was answered. This
      // just makes the UI reflect that the file has been delivered,
      // instead of leaving a live "Download" button sitting there.
      downloadBtn.disabled = true;
      downloadBtn.textContent = 'Downloaded ✓';
    });

    function showError(msg) {
      errorBox.textContent = msg;
      errorBox.classList.remove('hidden');
    }
  }

  // ================= ROUTING =================

  function main() {
    const match = location.pathname.match(/^\/drop\/([a-f0-9]{32})\/?$/);
    if (match) {
      document.getElementById('send-view').classList.add('hidden');
      document.getElementById('receive-view').classList.remove('hidden');
      initReceiveView(match[1]);
    } else {
      initSendView();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', main);
  } else {
    main();
  }
})();
