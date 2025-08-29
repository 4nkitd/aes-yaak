# Yaak AES Plugin (TypeScript)
AES-128 & AES-256 utilities for the [Yaak](https://yaak.app) API client.
Provides template helper functions to encrypt and decrypt values inline in requests, environment variables, tests, and derived fields.

> Supports modes: CBC, GCM, CTR, ECB (ECB & CTR require the Node crypto backend; WebCrypto only supports CBC & GCM).
> Authenticated encryption is ONLY provided by GCM. Prefer GCM whenever the remote system supports it.

---


## 1. Overview

This plugin bridges systems that require AES (128 or 256) encryption with Yaak’s flexible templating environment.
You can selectively encrypt or decrypt portions of request bodies, headers, query parameters, secrets, or test scripts without external tooling.

---

## 2. Features

- AES‑128 and AES‑256 (auto-detects key length; optional explicit `keySize`).
- Modes: CBC, GCM, CTR, ECB.
  - CBC / GCM work in Node and WebCrypto contexts.
  - CTR / ECB supported only when Node’s `crypto` module is available.
- Rich encoding controls for keys, IVs, plaintext, ciphertext and output.
- GCM combined output (`cipher.tag`) or separate components.
- Zero-padding option (`padding: "None"`) for legacy CBC/ECB interoperability.
- TypeScript-first implementation (no runtime transpilation needed if your environment supports TS build).
- Helpful `[aes-error] <message>` return markers instead of silent failures.
- Backward-compatible aliases: `encryptAes128` / `decryptAes128` (now also accept 256-bit keys).

---

## 3. Quick Start

1. Clone repository (or copy folder containing `src/index.ts` + `src/aesPlugin.ts`).
2. In Yaak: `Settings` → `Plugins` → `Load Folder…` → choose the project root (or the build output if you compile).
3. Define environment variables (example, hex-encoded):
   ```
   AES_KEY=00112233445566778899AABBCCDDEEFF        # 16 bytes = AES-128
   AES_IV =0102030405060708090A0B0C0D0E0F10        # 16-byte IV
   ```
4. Use in a request body:
   ```
   {
     "secureField": "{{ encryptAes('Hello World', env.AES_KEY, env.AES_IV) }}"
   }
   ```
5. Decrypt some returned field:
   ```
   {{ decryptAes(body.secureField, env.AES_KEY, env.AES_IV) }}
   ```

---

## 4. Installation / Loading in Yaak

### A. Direct Use
- Ensure the folder contains the built JS or the TypeScript source (depending on Yaak’s loader support).
- Load the folder via plugin settings.

### B. Using `yaakcli` Scaffold (Optional)
```
npm i -g yaakcli
yaakcli plugin create yaak-aes
# Replace generated plugin contents with this repo
```
Reload plugin in Yaak (toggle disable/enable if hot reload doesn’t trigger).

---

## 5. Functions & Signatures

Primary (generic for AES-128/256):
```
encryptAes(plaintext, key, iv, options?)
decryptAes(ciphertext, key, iv, options?)
```

Legacy aliases (still work; honor 256-bit keys):
```
encryptAes128(plaintext, key, iv, options?)
decryptAes128(ciphertext, key, iv, options?)
```

Return value: String (ciphertext or plaintext).
On failure: string beginning with `[aes-error]`.

---

## 6. Options Reference

```
{
  mode: "CBC" | "GCM" | "CTR" | "ECB"         // default "CBC"
  padding: "PKCS7" | "None"                   // CBC/ECB only; default "PKCS7"
  keySize: 128 | 256                          // optional, inferred from key if omitted
  keyEncoding: "auto" | "hex" | "base64" | "utf8"    // default "auto"
  ivEncoding:  "auto" | "hex" | "base64" | "utf8"    // default "auto"
  plaintextEncoding: "utf8" | "hex" | "base64"       // ENCRYPT; default "utf8"
  output: "base64" | "hex"                           // ENCRYPT; default "base64"
  inputEncoding: "auto" | "base64" | "hex"           // DECRYPT; default "auto"
  decryptedOutputEncoding: "utf8" | "hex" | "base64" // DECRYPT; default "utf8"
  tag: "<auth tag>"                                  // DECRYPT GCM if not combined
  backend: "auto" | "node" | "web"                   // default "auto"
}
```

Ignored fields on encrypt / decrypt are simply disregarded; they won’t error unless invalid.

---

## 7. Supported Modes

| Mode | Authenticated? | IV Required | Notes |
|------|----------------|------------|-------|
| CBC  | No             | Yes (16B)  | PKCS7 (default) or zero-padding |
| GCM  | Yes (AEAD)     | Yes (16B)* | Combined `cipher.tag` output |
| CTR  | No             | Yes (16B)  | Node backend only |
| ECB  | No             | No         | Node backend only; legacy only |

*Standard GCM often uses 12-byte IVs; this plugin currently standardizes on 16 bytes. Roadmap includes 12-byte allowance.

---

## 8. Key & IV Handling (128 vs 256)

- Key is decoded according to `keyEncoding` (or auto-detected).
- Length 16 bytes → AES-128; length 32 bytes → AES-256.
- `keySize` (optional) enforces expectation and errors if mismatch.
- IV must be 16 bytes for all IV-using modes (CBC/GCM/CTR). Ignored for ECB.
- Auto-decoding rules when `encoding: "auto"`:
  - Exact length*2 hex string → hex decode
  - Base64-looking → base64 decode
  - Else utf8

Examples (hex):
```
AES_KEY_128=00112233445566778899AABBCCDDEEFF
AES_KEY_256=00112233445566778899AABBCCDDEEFF0011223344556677
AES_IV     =0102030405060708090A0B0C0D0E0F10
```

---

## 9. Encoding (Input / Output)

Encryption:
- `plaintextEncoding` converts your supplied plaintext into bytes (utf8 by default).
- `output` chooses ciphertext encoding (base64 default).

Decryption:
- `inputEncoding` tells plugin how to decode ciphertext (force this if you know the format; avoids auto mis-detection).
- `decryptedOutputEncoding` controls final plaintext representation (utf8/hex/base64).

---

## 10. GCM Auth Tag Handling

Encryption output (GCM):
```
<cipher>.<tag>
```
(Separator is `.`; any `.` inside base64 is rare but supported by splitting on the last period.)

Decryption paths:
A) Combined:
```
{{ decryptAes(body.payload, env.AES_KEY, env.AES_IV, { "mode":"GCM" }) }}
```
B) Separate:
```
{{ decryptAes(body.ctOnly, env.AES_KEY, env.AES_IV, { "mode":"GCM", "tag": body.tagOnly }) }}
```

Tag must decode to 16 bytes.

---

## 11. Examples

### AES-128 (CBC default)
```
{{ encryptAes("Hello World", env.AES_KEY, env.AES_IV) }}
{{ decryptAes(body.secureField, env.AES_KEY, env.AES_IV) }}
```

### AES-256 (CBC hex output)
```
{{ encryptAes("Hi256", env.AES_KEY_256, env.AES_IV,
  {"mode":"CBC","keyEncoding":"hex","ivEncoding":"hex","output":"hex"} ) }}
```

### GCM (base64 → base64)
```
{{ encryptAes(json.secret, env.AES_KEY, env.AES_IV, {"mode":"GCM"} ) }}
{{ decryptAes(body.secret, env.AES_KEY, env.AES_IV, {"mode":"GCM"} ) }}
```

### CTR (Node backend)
```
{{ encryptAes(env.STREAM_DATA, env.AES_KEY, env.AES_IV,
  {"mode":"CTR","keyEncoding":"hex","ivEncoding":"hex","output":"hex"} ) }}
```

### Zero Padding (CBC)
```
{{ encryptAes("ABC", env.AES_KEY, env.AES_IV,
  {"mode":"CBC","padding":"None"} ) }}
```
(Ensure plaintext length is acceptable to the remote system.)

### Explicit decrypt encodings
```
{{ decryptAes(body.ctHex, env.AES_KEY, env.AES_IV,
  {"mode":"CBC","keyEncoding":"hex","ivEncoding":"hex","inputEncoding":"hex"} ) }}
```

---

## 12. Error Handling

All failures return:
```
[aes-error] <message>
```

Frequent causes:
| Message fragment | Reason |
|------------------|--------|
| key must be 16 or 32 bytes | Encoded form not expected length |
| iv required | Mode uses IV but you passed blank |
| GCM auth tag must be 16 bytes | Tag wrong length |
| unsupported in WebCrypto | Using CTR/ECB with only WebCrypto backend |
| bad decrypt / invalid tag | Wrong key / IV / mode / padding or tampered data |

---

## 13. Security Considerations

- Prefer GCM over CBC / CTR / ECB.
- Never reuse (key, IV) pairs for GCM or CTR.
- CBC zero-padding is NOT interoperable with standard PKCS7; only use if mandated.
- Don’t use the same value for key and IV.
- Consider external authentication (HMAC) if using a non-AEAD mode (CBC/CTR/ECB).
- Don’t log full plaintext or keys in multi-user environments.

---

## 14. Troubleshooting Cheat Sheet

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `[aes-error] bad decrypt` | Wrong key, IV, mode, or padding | Verify all; force inputEncoding |
| Random UTF8 junk | Wrong decoding (hex vs base64) | Set explicit inputEncoding |
| GCM decrypt fails | Wrong/missing tag | Use combined `cipher.tag` or supply `tag` |
| Mode unsupported | Forced web backend for CTR/ECB | Switch to Node or change mode |
| Key size mismatch | Provided 16B key but keySize=256 | Align keySize or key material |

---

## 15. Migration (Old AES-128 JS → This TS)

Old names:
- `encryptAes128`, `decryptAes128`

New generic additions:
- `encryptAes`, `decryptAes`

No breaking changes: old names still work, but they now accept 32-byte keys (AES-256). If you depended on a strict 16-byte check, add `"keySize":128` in options.

---

## 16. Development & Build

Scripts:
```
npm install
npm run build   # runs yaakcli build (ensure yaakcli installed)
```

TypeScript source:
- Main logic: `src/aesPlugin.ts`
- Yaak entry: `src/index.ts` (adapts template functions to Yaak API)

Testing (basic):
- `src/index.test.ts` (expand with vitest for vectors).
- Add more deterministic vectors in `tests/`.

Suggested improvement: add automated multi-mode test suite with known vectors (see Roadmap).

---

## 17. Test Vectors

Manual reference file: `tests/manual-vectors.md` (AES‑128 examples).
For AES‑256, replicate the same scripts with a 32-byte key.
Add future PRs with standardized NIST GCM + CBC multi-block vectors (adapted to 16-byte IV where necessary).

---

## 18. Roadmap

- Allow standard 12-byte GCM nonce (with GH issue tracking).
- Add random IV generator helper: `generateAesIv(length=16)`.
- Optional HKDF / PBKDF2 key derivation helpers.
- Debug mode returning structured JSON diagnostics.
- More test vectors (AES-256 GCM, tamper tests).
- Optional streaming interface for very large payloads.

---

## 19. Contributing

1. Fork + branch (feature/..., fix/...).
2. Add / update tests when altering crypto logic.
3. Keep README and Options section in sync with code.
4. Run lint / tests before opening PR.
5. Describe interoperability scenario if adding a legacy option (e.g. 12-byte IV).

Issues & PRs welcome—focus on security clarity and backward compatibility.

---

## 20. License

MIT License (see LICENSE file).
Provided “as is” with no warranty. Independently validate for regulated or high-assurance deployments.

---

## FAQ

**Q: Why no AES-192?**
A: Simplifies API; rarely mandated. Can be added (PRs welcome).

**Q: Why fixed 16-byte IV requirement?**
A: Simplicity + parity across modes. 12-byte GCM is planned (better performance & standard compliance).

**Q: How do I force AES-128 when I accidentally have a 32-byte key?**
A: You can’t—supply a 16-byte key or set `keySize:128` and provide matching length.

**Q: I get `[aes-error] bad decrypt` in ECB—why?**
A: Probably ciphertext was produced with CBC or wrong key; confirm mode and key.

**Q: Can I omit IV for CBC if remote system uses static one?**
A: You must supply something; CBC requires an IV. If the remote uses a static IV, pass that value (but note the security risk).

---

Happy encrypting. Use authenticated encryption where possible. Contributions encouraged!
