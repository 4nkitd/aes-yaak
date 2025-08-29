# Yaak AES-128 Plugin

Adds two template helper functions to Yaak:

- `encryptAes128(plaintext, key, iv, options?)`
- `decryptAes128(ciphertext, key, iv, options?)`

Supports AES‑128 in CBC, GCM, CTR, and ECB modes (CBC default) for selectively encrypting / decrypting content inside Yaak request bodies, headers, variables, and environment values. (ECB is provided only for legacy interoperability and SHOULD NOT be used for new designs.)

> Core intent: Bridge Yaak's internal ChaCha20-Poly1305 secret storage with an external system that mandates AES‑128.

---

## Contents

1. Quick Start
2. Installation
3. Usage in Yaak
4. Function Signatures
5. Options Reference
6. Key & IV Handling
7. Output / Input Conventions
8. GCM Auth Tag Handling
9. Examples
10. Error Handling
11. Security Considerations
12. Troubleshooting
13. Roadmap
14. License / Disclaimer

---

## 1. Quick Start

1. Put `plugin.js` (this project’s `src/plugin.js`) in a directory.
2. In Yaak: `Settings` > `Plugins` > `Load Folder…` and select the directory that contains the file.
3. Define environment variables (recommended):
   - `AES_KEY` (16 bytes via hex / base64 / utf8)
   - `AES_IV`  (16 bytes via hex / base64 / utf8)
4. Use inside a request body:
   ```
   {
     "secureField": "{{ encryptAes128('Hello', env.AES_KEY, env.AES_IV) }}"
   }
   ```
5. Decrypt a response field similarly (e.g. in a test, or derived variable):
   ```
   {{ decryptAes128(body.secureField, env.AES_KEY, env.AES_IV) }}
   ```

---

## 2. Installation

Two ways:

### A. Direct (simplest)

- Clone / copy this folder
- Ensure `plugin.js` is at the project root or inside a folder you will load
- Load the folder in Yaak’s Plugin settings

### B. Via `yaakcli` (if you want scaffolding)

1. Install CLI (if available on your system; if not, skip to A):
   ```
   npm i -g yaakcli
   ```
2. Generate a plugin scaffold:
   ```
   yaakcli plugin create yaak-aes
   ```
3. Replace the generated `plugin.js` with the provided one here (or merge changes).
4. Reload in Yaak.

Yaak auto-reloads plugins when the backing files change (if not, disable/enable again in Settings).

---

## 3. Usage in Yaak

Anywhere you can use a template expression:

- Request body (JSON / text)
- Headers
- Query parameters
- Environment variable definitions
- Pre-request scripting contexts returning strings
- Tests / derived variables

Examples:
```
Authorization: Encrypted {{ encryptAes128(env.API_TOKEN, env.AES_KEY, env.AES_IV) }}
```

---

## 4. Function Signatures

```
encryptAes128(plaintext, key, iv, options?)
decryptAes128(ciphertext, key, iv, options?)
```

Arguments:

| Arg        | Type    | Required | Description |
|------------|---------|----------|-------------|
| plaintext / ciphertext | string | Yes | Data to encrypt or decrypt |
| key        | string  | Yes | 16-byte material (hex/base64/utf8; see below) |
| iv         | string  | Yes | 16-byte IV / nonce (CBC & GCM need 16 bytes; CTR also uses 16 here) |
| options    | object  | No | Mode + formatting overrides |

Returns a string (ciphertext or plaintext). On failure returns a marker string starting with `[aes-error]`.

---

## 5. Options Reference

```
{
  mode: "CBC" | "GCM" | "CTR" | "ECB"  // default "CBC"  (ECB has no IV and provides no semantic security)
  padding: "PKCS7" | "None"           // CBC only; default "PKCS7"
  output: "base64" | "hex" | "binary" // ENCRYPT only; default "base64"
  inputEncoding: "auto" | "base64" | "hex" | "binary" // DECRYPT only; default "auto"
  tag: "<auth tag>"                   // DECRYPT GCM only (if ciphertext does not embed)
}
```

Notes:

- For `GCM` encryption the plugin emits: `<ciphertext><sep><tag>` where `<sep>` is `.` (or `:` if you split manually). Both parts are encoded with the chosen `output`.
- For `GCM` decryption you can supply combined format OR pass `options.tag`.
- `CTR` has no padding or authentication.
- `CBC` with `padding: "None"` zero‑pads (NOT standard PKCS#7) — only use if the remote system expects that.

---

## 6. Key & IV Handling

The plugin normalizes:

- 32 hex chars  → 16 bytes
- 24 base64 chars (plus padding) → 16 bytes
- Any other string → UTF‑8 bytes (must produce length 16)

If final length ≠ 16, an error is thrown.

Recommended: use base64 or hex environment variables:

```
AES_KEY=00112233445566778899AABBCCDDEEFF   # hex
AES_IV=0102030405060708090A0B0C0D0E0F10     # hex
```

Or base64:
```
AES_KEY=ABEiM0RVZneImaq7zN3u/w==
AES_IV=AQIDBAUGBwgJCgsMDQ4PEA==
```

Avoid raw human words like `mysecretkey1234` unless for quick testing only.

---

## 7. Output / Input Conventions

Encryption output (default): base64

Decryption input:

- If `inputEncoding: "auto"` (default):
  1. Tries base64 decode
  2. If hex-like, uses hex
  3. Else treats as UTF-8 (typically only for plaintext-like test)
- You can force a decoding with `inputEncoding`.

Binary output is rarely useful inside JSON; prefer base64 / hex.

---

## 8. GCM Auth Tag Handling

On encrypt (GCM):
```
ciphertext.tag   (e.g., "mZk...==.Q1h...==")
```

On decrypt (GCM) you can:

A) Provide combined:
```
{{ decryptAes128(body.encField, env.AES_KEY, env.AES_IV, { mode: "GCM" }) }}
```

B) Supply separate components:
```
{{ decryptAes128(body.ctOnly, env.AES_KEY, env.AES_IV, { mode: "GCM", tag: body.tagOnly }) }}
```

Auth tag must be 16 bytes post-decoding.

---

## 9. Examples

### Basic CBC (default)

```
{{ encryptAes128("Hello World", env.AES_KEY, env.AES_IV) }}
```

Produces base64 ciphertext, e.g. `k1KcT...==` (value will differ by key/iv).

Decrypt:
```
{{ decryptAes128(body.secureField, env.AES_KEY, env.AES_IV) }}
```

### CBC No Padding (zero-pad)

```
{{ encryptAes128("ABC", env.AES_KEY, env.AES_IV, { padding: "None" }) }}
```

Make sure the remote side also expects zero padding or already block-aligned data.

### GCM

```
{{ encryptAes128(json.user.ssn, env.AES_KEY, env.AES_IV, { mode: "GCM", output: "hex" }) }}
```

Might yield:
```
<hex-ciphertext>.<hex-tag>
```

Decrypting hex:
```
{{ decryptAes128(body.enc, env.AES_KEY, env.AES_IV, { mode: "GCM", inputEncoding: "hex" }) }}
```

### CTR (stateless stream-like)

```
{{ encryptAes128(env.PAYLOAD, env.AES_KEY, env.AES_IV, { mode: "CTR" }) }}
```

(Remember: CTR gives no integrity protection.)

### Embedding in JSON

```
{
  "user": "{{ encryptAes128(json.userPlain, env.AES_KEY, env.AES_IV, { mode: 'GCM' }) }}"
}
```

### Piping a Response Value Back

If a response field `data.token` is AES encrypted:

```
Decrypted token: {{ decryptAes128(body.data.token, env.AES_KEY, env.AES_IV) }}
```

---

## 10. Error Handling

Errors return a string:

```
[aes-error] <message>
```

Common causes:

- Wrong key/iv length
- Invalid base64/hex input
- Missing GCM tag
- Mode unsupported in the active runtime (WebCrypto path currently excludes CTR)
- Incorrect padding (CBC)

If you see `[aes-error]`, fix input rather than sending the broken value onward.

---

## 11. Security Considerations

- AES-CBC & CTR do NOT authenticate: attacks can alter ciphertext. Prefer GCM when possible.
- Never reuse (key, IV) pairs for GCM / CTR across different plaintexts.
- If system mandates static IV, document the risk; consider wrapping with an HMAC layer externally.
- Store keys in Yaak environment secrets or external secret managers (not in version control).
- Avoid logging decrypted sensitive data in shared logs.
- Validate decrypted outputs (length, charset) before trusting them.

---

## 12. Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `[aes-error] key must be exactly 16 bytes` | Input decoded to wrong length | Provide proper hex/base64 or adjust utf8 |
| Garbage characters after decrypt (CBC None) | Zero padding trimmed leaving binary remnants | Use PKCS7 (default) or ensure original blocks |
| GCM decrypt error | Missing or wrong tag | Ensure ciphertext includes `.tag` or pass `options.tag` |
| Different ciphertext each time (CBC/GCM) | Changing IV or data (expected for random IV) | For deterministic output you must keep same IV (but be aware of security impact) |
| Mode not supported error | Using CTR under WebCrypto environment | Switch to Node runtime or use CBC/GCM |

---

## 13. Roadmap

Planned / potential improvements:

- Deterministic test harness + published vectors
- Optional random IV generation helper `generateAesIv()`
- Key derivation helper (PBKDF2 / HKDF)
- Support additional tag sizes (GCM)
- Configurable zero/ISO10126 padding variants

Open to contributions.

---

## 14. License / Disclaimer

MIT License (add a LICENSE file if distributing).

This plugin is provided “as is” with no warranty. Validate independently for regulatory or high-assurance contexts.

---

## Appendix: Choosing a Mode

| Mode | Integrity | Needs Unique IV? | Typical Use |
|------|-----------|------------------|-------------|
| CBC  | No        | Recommended      | Legacy interoperability |
| GCM  | Yes (AEAD)| Yes (critical)   | Preferred modern use |
| CTR  | No        | Yes (critical)   | Streaming / partial encryption |
| ECB  | No        | N/A (no IV)      | Only for strict legacy systems; avoid otherwise |

If the remote system permits GCM, choose GCM.

---

## Appendix: Generating Keys / IV Quickly

Node.js:
```
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

Base64:
```
node -e "console.log(require('crypto').randomBytes(16).toString('base64'))"
```

---

## FAQ

Q: Why only 128-bit keys?
A: This plugin targets a system that strictly requires AES-128. Extending to 192/256 is straightforward (modify validation + algorithm strings) if needed.

Q: Can I provide a 32-char ASCII key?
A: Only if it decodes/normalizes to 16 bytes. A 32 ASCII char string will be 32 bytes and rejected unless it is hex (32 hex chars = 16 bytes).

Q: How do I separate ciphertext and tag for GCM manually?
A: Use `const [ct, tag] = value.split('.')` (or `:` if you chose that yourself).

---

## 15. TypeScript Integration & Build

The project now includes a TypeScript entry point at `src/index.ts` which:

- Imports the CommonJS AES implementation from `src/plugin.js`.
- Adapts its template helpers (`encryptAes128`, `decryptAes128`) to Yaak’s `templateFunctions` API shape.
- Exposes them alongside an example `httpRequestActions` action.

How it works:

1. `src/plugin.js` (CommonJS) still contains the core encryption logic.
2. `src/index.ts` requires that file, iterates its exported `templates` array, and maps each to a Yaak Template Function Plugin object with an `onRender` method that invokes the original `run`.
3. All arguments are currently treated as plain text inputs; you can later enrich arg metadata (types, required flags, descriptions).

Building:

- Run: `npm run build` (calls `yaakcli build`).
- Output artifacts are placed in `build/` per Yaak CLI defaults.
- Load the resulting plugin folder (project root or `build`) in Yaak: Settings > Plugins > Load Folder…

Development loop:

1. Edit `src/plugin.js` or `src/index.ts`.
2. (Optional) Run `npm run build` if you want a clean output bundle.
3. Reload the plugin in Yaak (if auto‑reload doesn’t trigger).

Testing:

- Current automated tests are minimal (`src/index.test.ts` with Vitest).
- For cryptographic correctness, rely on `tests/manual-vectors.md`.
- You can add a TypeScript test that imports `src/plugin.js` directly and asserts vectors.

Extending:

- Add additional template helpers by pushing new definitions into the `templates` array in `plugin.js` (they are automatically surfaced by `index.ts`).
- Or create pure TS helpers and merge them into `templateFunctions` directly in `index.ts`.

Versioning:

- Keep the version constant in `plugin.js` (`VERSION`) synchronized with `package.json` if you start publishing the package.

Happy encrypting. Keep your keys safe.

---

### Troubleshooting Addendum: Template Function Not Suggested / Rendered as Plain Text

If `{{ encryptAes128(...) }}` (or `decryptAes128`) shows up literally in the rendered request or does not appear in Yaak's template auto‑complete:

1. Confirm plugin load
   - Open Settings > Plugins and verify the folder containing this README plus `src/index.ts` (and `src/plugin.js`) is loaded.
   - If you pointed Yaak at a `build/` directory, ensure the build actually contains the plugin bundle.

2. Reload / hot reload
   - Toggle the plugin off/on or remove and re-add the folder after changes to `index.ts` or `plugin.js`.
   - Some template registries only refresh on (re)load.

3. Ensure TypeScript bridge is present
   - `src/index.ts` must export `plugin` with a `templateFunctions` array (the file in this project maps the CommonJS `plugin.templates` from `plugin.js`).
   - If you removed or renamed `src/plugin.js`, update `index.ts` to require the new path.

4. Check environment variable spelling
   - Template suggestions start populating once the function name is typed correctly: `encryptAes128(`.
   - A missing closing `}}` or extra braces will cause Yaak to treat it as plain text.

5. Mode / argument count
   - The mapped template function expects up to 4 arguments (plaintext, key, iv, options). Supplying an unmatched `{` inside may break parsing and suppress suggestions.

6. Debug logging
   - Start Yaak with environment variable `YAAK_AES_DEBUG=1` (or set it in your shell) before launching. You should see a console log:  
     `[yaak-aes-plugin] Loaded templates: encryptAes128, decryptAes128`
   - If absent, the CommonJS module may not be loading.

7. Build artifacts
   - If using `yaakcli build`, confirm the output directory actually includes the JS that defines `templateFunctions`.
   - Running only TypeScript (no emit) with an outdated build can leave Yaak seeing an older version without the AES helpers.

8. Conflicting plugin name
   - If you duplicated this project and loaded both, name collisions could hide one set. Ensure only one AES plugin is active or give them distinct names.

9. Minimal reproduction
   - Create a new request and type exactly: `{{ encryptAes128("test", "00112233445566778899AABBCCDDEEFF", "000102030405060708090A0B0C0D0E0F") }}`
   - If it still renders literally, the function was never registered.

10. Fallback check
   - Open the developer tools / logs (if available in your Yaak build) to see if any runtime errors mention the plugin file.

If after these steps the function is still not recognized, verify that:
- No syntax errors were introduced into `src/index.ts`.
- The Node.js version meets the requirement (>=16) if you're relying on the Node crypto path.

Feel free to extend this section with any environment-specific quirks you discover.