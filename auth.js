/*
  Single 4-digit code gate + client-side encryption for the surgical case log
  suite. The code is never stored — it's run through PBKDF2 to derive an
  AES-GCM key, which is what actually encrypts the case data in localStorage.

  There is no server, so this only protects against casual/local access. Note
  that a 4-digit code has only 10,000 possible values, so unlike a real
  password it offers little resistance to anyone willing to brute-force it
  offline against the encrypted data — treat it as a screen lock, not strong
  encryption. There is also no code recovery — forgetting it means the
  encrypted case data cannot be decrypted again; only a full reset (which
  erases all case data) is possible.
*/
(function () {
  const PIN_KEY = 'caseLogPin';
  const SESSION_KEY_B64 = 'caseLogSessionKeyB64';
  const PBKDF2_ITERATIONS = 150000;
  const DATA_KEY_BASES = ['cardiacCases_enc', 'thoracicCases_enc', 'vascularCases_enc'];

  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function getPinRecord() {
    try {
      return JSON.parse(localStorage.getItem(PIN_KEY) || 'null');
    } catch (e) {
      return null;
    }
  }
  function hasPin() {
    return !!getPinRecord();
  }

  async function deriveKey(code, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptString(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return { ivB64: bufToB64(iv), ctB64: bufToB64(ct) };
  }

  async function decryptString(key, ivB64, ctB64) {
    const iv = new Uint8Array(b64ToBuf(ivB64));
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, b64ToBuf(ctB64));
    return new TextDecoder().decode(ptBuf);
  }

  async function encryptJSON(key, obj) {
    const { ivB64, ctB64 } = await encryptString(key, JSON.stringify(obj));
    return ivB64 + '.' + ctB64;
  }

  async function decryptJSON(key, str) {
    if (!str) return null;
    const parts = str.split('.');
    if (parts.length !== 2) return null;
    try {
      return JSON.parse(await decryptString(key, parts[0], parts[1]));
    } catch (e) {
      return null;
    }
  }

  async function createPin(code) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(code, salt);
    const verifier = await encryptString(key, 'CASELOG_OK');
    localStorage.setItem(PIN_KEY, JSON.stringify({
      saltB64: bufToB64(salt),
      verifierIvB64: verifier.ivB64,
      verifierCtB64: verifier.ctB64,
    }));
    await persistSession(key);
    return key;
  }

  async function verifyPin(code) {
    const record = getPinRecord();
    if (!record) throw new Error('No code set up yet.');
    const salt = new Uint8Array(b64ToBuf(record.saltB64));
    const key = await deriveKey(code, salt);
    try {
      const check = await decryptString(key, record.verifierIvB64, record.verifierCtB64);
      if (check !== 'CASELOG_OK') throw new Error('bad');
    } catch (e) {
      throw new Error('Incorrect code.');
    }
    await persistSession(key);
    return key;
  }

  async function persistSession(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    localStorage.setItem(SESSION_KEY_B64, bufToB64(raw));
  }

  async function restoreSession() {
    const b64 = localStorage.getItem(SESSION_KEY_B64);
    if (!b64) return null;
    try {
      return await crypto.subtle.importKey('raw', b64ToBuf(b64), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    } catch (e) {
      return null;
    }
  }

  function lock() {
    localStorage.removeItem(SESSION_KEY_B64);
    location.reload();
  }

  function resetPin() {
    localStorage.removeItem(PIN_KEY);
    localStorage.removeItem(SESSION_KEY_B64);
    DATA_KEY_BASES.forEach((base) => localStorage.removeItem(base));
    location.reload();
  }

  function injectBaseStyles() {
    const style = document.createElement('style');
    style.textContent = `
      body.cla-locked > .wrap { display: none !important; }
      .cla-gate {
        position: fixed; inset: 0; z-index: 1000;
        display: flex; align-items: center; justify-content: center;
        background: var(--bg, #ffffff);
        padding: 24px;
      }
      .cla-gate-card {
        background: var(--card, #fff);
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 16px;
        padding: 32px;
        width: 300px;
        max-width: 100%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        text-align: center;
      }
      .cla-gate-card h2 {
        margin: 0 0 4px;
        font-size: 18px;
        color: var(--text, #0f172a);
      }
      .cla-gate-sub {
        font-size: 12px;
        color: var(--muted, #64748b);
        margin-bottom: 22px;
      }
      .cla-pin-row {
        display: flex;
        justify-content: center;
        gap: 10px;
        margin-bottom: 18px;
      }
      .cla-pin-row input {
        width: 44px;
        height: 52px;
        text-align: center;
        font-size: 22px;
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 8px;
        font-family: inherit;
        background: transparent;
        color: var(--text, #0f172a);
      }
      .cla-pin-row input:focus {
        outline: none;
        border-color: var(--accent, #e11d48);
      }
      .cla-pin-label {
        font-size: 12px;
        font-weight: 600;
        color: var(--muted, #64748b);
        margin-bottom: 10px;
      }
      .cla-gate-error {
        color: #b3261e;
        font-size: 12px;
        margin: -8px 0 14px;
        min-height: 14px;
      }
      .cla-gate-reset {
        margin-top: 4px;
        font-size: 12px;
        color: var(--muted, #64748b);
      }
      .cla-gate-reset a {
        color: var(--accent, #e11d48);
        text-decoration: none;
        font-weight: 600;
        cursor: pointer;
      }
      .cla-badge {
        position: fixed;
        top: 14px;
        right: 16px;
        z-index: 900;
        display: flex;
        align-items: center;
        gap: 8px;
        background: var(--card, #fff);
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 999px;
        padding: 6px 12px;
        font-size: 12px;
        color: var(--muted, #64748b);
        box-shadow: 0 4px 14px rgba(0,0,0,0.06);
      }
      .cla-badge button {
        background: none;
        border: none;
        color: var(--accent, #e11d48);
        font-weight: 700;
        font-size: 12px;
        cursor: pointer;
        padding: 0;
      }
    `;
    document.head.appendChild(style);
  }

  function renderBadge() {
    const existing = document.querySelector('.cla-badge');
    if (existing) existing.remove();
    const badge = document.createElement('div');
    badge.className = 'cla-badge';
    badge.innerHTML = `<span>Unlocked</span><button type="button">Lock</button>`;
    badge.querySelector('button').addEventListener('click', lock);
    document.body.appendChild(badge);
  }

  function buildPinInputs(container) {
    const inputs = [...container.querySelectorAll('input')];
    inputs.forEach((input, i) => {
      input.addEventListener('input', () => {
        input.value = input.value.replace(/[^0-9]/g, '').slice(-1);
        if (input.value && i < inputs.length - 1) inputs[i + 1].focus();
        container.dispatchEvent(new CustomEvent('cla-pin-change'));
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !input.value && i > 0) inputs[i - 1].focus();
      });
    });
    return {
      value: () => inputs.map((i) => i.value).join(''),
      isComplete: () => inputs.every((i) => i.value !== ''),
      clear: () => {
        inputs.forEach((i) => (i.value = ''));
        inputs[0].focus();
      },
      focus: () => inputs[0].focus(),
    };
  }

  function pinRowHtml(idPrefix) {
    return `
      <div class="cla-pin-row" id="${idPrefix}">
        <input type="tel" inputmode="numeric" maxlength="1">
        <input type="tel" inputmode="numeric" maxlength="1">
        <input type="tel" inputmode="numeric" maxlength="1">
        <input type="tel" inputmode="numeric" maxlength="1">
      </div>
    `;
  }

  function renderGate(onUnlocked) {
    document.body.classList.add('cla-locked');
    const overlay = document.createElement('div');
    overlay.className = 'cla-gate';
    document.body.appendChild(overlay);

    const creating = !hasPin();

    overlay.innerHTML = `
      <div class="cla-gate-card">
        <h2>${creating ? 'Create a Code' : 'Enter Code'}</h2>
        <div class="cla-gate-sub">${creating ? 'Choose a 4-digit code to protect this device\'s case log.' : 'Enter your 4-digit code to unlock the case log.'}</div>
        <div class="cla-pin-label">${creating ? 'New code' : 'Code'}</div>
        ${pinRowHtml('claPin1')}
        ${creating ? '<div class="cla-pin-label">Confirm code</div>' + pinRowHtml('claPin2') : ''}
        <div class="cla-gate-error" id="claError"></div>
        ${!creating ? '<div class="cla-gate-reset"><a id="claReset">Forgot your code? Reset &amp; erase all data</a></div>' : ''}
      </div>
    `;

    const errorEl = overlay.querySelector('#claError');
    const pin1 = buildPinInputs(overlay.querySelector('#claPin1'));
    const pin2 = creating ? buildPinInputs(overlay.querySelector('#claPin2')) : null;

    async function finish(key) {
      overlay.remove();
      document.body.classList.remove('cla-locked');
      onUnlocked(key);
    }

    if (creating) {
      overlay.querySelector('#claPin1').addEventListener('cla-pin-change', () => {
        if (pin1.isComplete()) overlay.querySelector('#claPin2 input').focus();
      });
      overlay.querySelector('#claPin2').addEventListener('cla-pin-change', async () => {
        if (!pin2.isComplete()) return;
        errorEl.textContent = '';
        if (pin1.value() !== pin2.value()) {
          errorEl.textContent = 'Codes do not match. Try again.';
          pin1.clear();
          pin2.clear();
          pin1.focus();
          return;
        }
        const key = await createPin(pin1.value());
        finish(key);
      });
      pin1.focus();
    } else {
      overlay.querySelector('#claPin1').addEventListener('cla-pin-change', async () => {
        if (!pin1.isComplete()) return;
        errorEl.textContent = '';
        try {
          const key = await verifyPin(pin1.value());
          finish(key);
        } catch (err) {
          errorEl.textContent = err.message;
          pin1.clear();
        }
      });
      pin1.focus();

      overlay.querySelector('#claReset').addEventListener('click', () => {
        if (confirm('This will permanently erase the code and all case data on this device. Continue?')) {
          resetPin();
        }
      });
    }
  }

  async function protect(onReady) {
    injectBaseStyles();
    const existingKey = await restoreSession();
    if (existingKey) {
      await onReady(existingKey);
      renderBadge();
      return;
    }
    document.body.classList.add('cla-locked');
    renderGate(async (key) => {
      await onReady(key);
      renderBadge();
    });
  }

  window.CaseLogAuth = {
    protect,
    encryptJSON,
    decryptJSON,
  };
})();
