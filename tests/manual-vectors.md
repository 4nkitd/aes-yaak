# Manual AES-128 Test Vectors & Verification Guide

This document helps you manually verify the `encryptAes128` / `decryptAes128` template helpers in the Yaak AES plugin against known / reproducible vectors.

The goal: give you reproducible inputs (key, IV, plaintext) and a Node.js script to compute the expected ciphertexts so you can cross-check what the plugin returns inside Yaak.

---

## 1. Important Notes

1. The plugin currently enforces a 16‑byte IV for all modes (including GCM).  
   - Standards: AES-GCM commonly uses a 12‑byte (96-bit) IV; the plugin’s simplification means you must adapt official 96-bit GCM vectors (cannot use them verbatim).  
   - If you need strict compliance with 12‑byte GCM IVs, extend the plugin (relax IV length check & adjust WebCrypto call).
2. CBC default padding is PKCS7. Use `{ padding: "None" }` to reproduce *no padding* test vectors.
3. CTR & CBC (no padding) provide no integrity/authentication—only GCM does.
4. The plugin zero-pads for `padding: "None"` when the plaintext length is not a multiple of 16.

---

## 2. Minimal Node.js Helper Script

Save as `vectors.js` (outside Yaak if you like) and run:  
`node vectors.js`

It prints expected ciphertexts for a few deterministic inputs using Node’s `crypto` (which the plugin mirrors in Node environments).

```js
// vectors.js
const crypto = require('crypto');

function hex(str) { return Buffer.from(str, 'hex'); }

function aesCbcNoPadEnc(keyHex, ivHex, ptHex) {
  const key = hex(keyHex);
  const iv = hex(ivHex);
  const pt = hex(ptHex);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  cipher.setAutoPadding(false); // no PKCS7
  const out = Buffer.concat([cipher.update(pt), cipher.final()]);
  return out.toString('hex');
}

function aesCbcPkcs7Enc(keyHex, ivHex, utf8Plain) {
  const key = hex(keyHex);
  const iv = hex(ivHex);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  const out = Buffer.concat([cipher.update(Buffer.from(utf8Plain, 'utf8')), cipher.final()]);
  return out.toString('base64');
}

function aesCtrEnc(keyHex, ivHex, utf8Plain) {
  const key = hex(keyHex);
  const iv = hex(ivHex);
  const cipher = crypto.createCipheriv('aes-128-ctr', key, iv);
  const out = Buffer.concat([cipher.update(utf8Plain, 'utf8'), cipher.final()]);
  return out.toString('hex');
}

function aesGcmEnc(keyHex, ivHex, utf8Plain) {
  const key = hex(keyHex);
  const iv = hex(ivHex); // 16 bytes here to match plugin
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv, { authTagLength: 16 });
  const ct = Buffer.concat([cipher.update(utf8Plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ctBase64: ct.toString('base64'),
    tagBase64: tag.toString('base64'),
    pluginCombined: `${ct.toString('base64')}.${tag.toString('base64')}`
  };
}

// --- Test Vectors ---

// 2.1 AES-128-CBC No Padding (Classic NIST Block)
// From SP 800-38A Example F.2.1 (Key, IV, first block)
const CBC_NP_KEY = '2b7e151628aed2a6abf7158809cf4f3c';
const CBC_NP_IV  = '000102030405060708090a0b0c0d0e0f';
const CBC_NP_PT1 = '6bc1bee22e409f96e93d7e117393172a'; // single 16-byte block
const cbcNoPadCt = aesCbcNoPadEnc(CBC_NP_KEY, CBC_NP_IV, CBC_NP_PT1);
// Expected: 7649abac8119b246cee98e9b12e9197d

// 2.2 AES-128-CBC PKCS7 Padding (UTF-8 message)
const CBC_P_KEY = CBC_NP_KEY;
const CBC_P_IV  = CBC_NP_IV;
const CBC_P_MSG = 'Hello World'; // 11 bytes -> pad 0x05 * 5
const cbcPkcs7CtB64 = aesCbcPkcs7Enc(CBC_P_KEY, CBC_P_IV, CBC_P_MSG);

// 2.3 AES-128-CTR (Deterministic with fixed IV)
const CTR_KEY = CBC_NP_KEY;
const CTR_IV  = CBC_NP_IV; // 16 bytes used directly as counter initial value
const CTR_MSG = 'Streaming Mode Test';
const ctrCtHex = aesCtrEnc(CTR_KEY, CTR_IV, CTR_MSG);

// 2.4 AES-128-GCM (Non-standard 16-byte IV for plugin parity)
const GCM_KEY = CBC_NP_KEY;
const GCM_IV  = CBC_NP_IV; // 16 bytes (plugin requirement)
const GCM_MSG = 'Authenticate Me';
const gcm = aesGcmEnc(GCM_KEY, GCM_IV, GCM_MSG);

// Print
console.log('--- AES-128 Test Vector Outputs ---');
console.log('CBC NoPad Ciphertext (hex):', cbcNoPadCt);
console.log('  (Expected NIST):          7649abac8119b246cee98e9b12e9197d');
console.log('');
console.log('CBC PKCS7 Ciphertext (base64):', cbcPkcs7CtB64);
console.log('  Plaintext:', JSON.stringify(CBC_P_MSG));
console.log('');
console.log('CTR Ciphertext (hex):', ctrCtHex);
console.log('  Plaintext:', JSON.stringify(CTR_MSG));
console.log('');
console.log('GCM Ciphertext Base64:', gcm.ctBase64);
console.log('GCM Tag Base64:       ', gcm.tagBase64);
console.log('Plugin Combined:      ', gcm.pluginCombined);
```

---

## 3. Matching Inside Yaak

Set environment variables (example):

```
AES_KEY=2b7e151628aed2a6abf7158809cf4f3c
AES_IV=000102030405060708090a0b0c0d0e0f
```

### 3.1 CBC No Padding

Expression:
```
{{ encryptAes128('6bc1bee22e409f96e93d7e117393172a' , env.AES_KEY, env.AES_IV, { mode: 'CBC', padding: 'None', output: 'hex' }) }}
```

Result should equal:
```
7649abac8119b246cee98e9b12e9197d
```

Then decrypt to verify round-trip (still hex input):
```
{{ decryptAes128('7649abac8119b246cee98e9b12e9197d', env.AES_KEY, env.AES_IV, { mode: 'CBC', padding: 'None', inputEncoding: 'hex' }) }}
```
You will get the block decoded as raw bytes interpreted UTF-8. Since it’s hex-like ASCII input encrypted as *binary*, the decrypted bytes will map back to the original 16-byte sequence—display may not match the hex string. For *semantic* validation prefer binary comparison or switch to an ASCII plaintext.

### 3.2 CBC PKCS7 (Human String)

```
{{ encryptAes128('Hello World', env.AES_KEY, env.AES_IV) }}
```

Compare base64 against `cbcPkcs7CtB64` from the script.

Decrypt:
```
{{ decryptAes128(<cipher-from-above>, env.AES_KEY, env.AES_IV) }}
```
Expect: `Hello World`

### 3.3 CTR

```
{{ encryptAes128('Streaming Mode Test', env.AES_KEY, env.AES_IV, { mode: 'CTR', output: 'hex' }) }}
```

Match the hex with `ctrCtHex`.

Decrypt:
```
{{ decryptAes128(<ctr-hex>, env.AES_KEY, env.AES_IV, { mode: 'CTR', inputEncoding: 'hex' }) }}
```
Expect: `Streaming Mode Test`

### 3.4 GCM

```
{{ encryptAes128('Authenticate Me', env.AES_KEY, env.AES_IV, { mode: 'GCM' }) }}
```

Should produce: `<cipherBase64>.<tagBase64>` which equals `pluginCombined` from script.

Decrypt:
```
{{ decryptAes128(<combined>, env.AES_KEY, env.AES_IV, { mode: 'GCM' }) }}
```
Expect: `Authenticate Me`

If you want to split components:
```
{{ decryptAes128(cipherPart, env.AES_KEY, env.AES_IV, { mode: 'GCM', tag: tagPart }) }}
```

---

## 4. Adding Your Own Vectors

To add more:

1. Choose mode & padding.
2. Fix key + IV for determinism (do NOT reuse in production).
3. Generate ciphertext with Node’s `crypto`.
4. Record triple: (mode, key, iv, plaintext, ciphertext, [tag]).
5. Test both encrypt and decrypt template functions.

Template snippet for structured notes:

```
Mode: CBC / GCM / CTR
Padding: PKCS7 | None
Key (hex): ...
IV  (hex): ...
Plaintext: ...
Ciphertext (base64|hex): ...
Tag (if GCM): ...
```

---

## 5. Caveats When Comparing

| Scenario | Cause | Action |
|----------|-------|--------|
| Ciphertext differs from expectation | Different IV, padding, output encoding, or plaintext mismatch | Double-check each parameter |
| GCM decrypt error (tag length) | Tag truncated or wrong encoding | Ensure 16-byte tag base64/hex decodes to 16 bytes |
| Extra characters after CBC no-padding decrypt | Zero padding removed improperly or plaintext not block-aligned | Use PKCS7 or ensure exactly 16-byte multiples |
| WebCrypto vs Node difference (CTR) | CTR not supported in WebCrypto path in plugin | Use Node environment or restrict to CBC/GCM |

---

## 6. Extending Test Coverage

Potential additions (not included yet):

- Multiple-block CBC PKCS7 example
- CBC zero-padding explicit test where plaintext already block-aligned
- Negative test: tampered GCM tag causing failure (plugin currently returns `[aes-error] ...`)
- Randomized IV tests (must store produced IV alongside ciphertext)

---

## 7. Quick Integrity Checklist (Manual)

For each mode:

- CBC: Flip 1 ciphertext byte; decrypted plaintext changes predictably (no error).
- CTR: Flip 1 byte; only corresponding plaintext segment flips (no error).
- GCM: Flip 1 byte; decryption should error (authentication failure).

(Current implementation returns `[aes-error]` message if decryption fails.)

---

## 8. When to Automate

If you need regression safeguards:

- Wrap these vectors into a lightweight Node script that `require`s the plugin file directly.
- Call the exported template runner functions (or invoke the inner encryption functions if you expose them).
- Assert equality with `assert` module.

Pseudo-outline:

```js
const plugin = require('../src/plugin');
const enc = plugin.templates.find(t => t.name === 'encryptAes128').run;
const dec = plugin.templates.find(t => t.name === 'decryptAes128').run;
// Provide dummy context object if needed (currently unused).
```

(If you restructure to export raw helpers, you can call them directly.)

---

## 9. To Do (Vectors)

- Add official NIST GCM vectors (requires adapting plugin to accept 12-byte IV).
- Include AES-256 variants if plugin expanded.
- Provide deterministic HKDF-derived key examples.

---

## 10. Summary

This file gives:

- Deterministic baseline vectors (CBC no-pad, CBC PKCS7, CTR, GCM).
- A generator script to recompute expected outputs.
- Step-by-step guidance for validating inside Yaak.

Use these to confirm that changes to the plugin (refactors, padding tweaks, mode additions) do not silently break functionality.

---

Happy testing & stay cryptographically cautious.