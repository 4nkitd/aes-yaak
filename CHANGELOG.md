# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CHANGELOG.md` and `CONTRIBUTING.md`

---

## [0.0.1] — initial

Pre-release. No git tag yet.

### Added
- Yaak template plugin for AES encryption / decryption
- AES-128 and AES-256 (auto-detects key length; optional explicit `keySize`)
- Modes: CBC, GCM, CTR, ECB
  - CBC + GCM work in both Node and WebCrypto backends
  - CTR + ECB are Node-backend-only
- Encoding controls: `keyEncoding`, `ivEncoding`, `plaintextEncoding`, `output`, `inputEncoding`, `decryptedOutputEncoding`
- GCM combined `cipher.tag` output, or separate components
- Zero-padding option (`padding: "None"`) for legacy CBC/ECB interop
- Helpful `[aes-error] <message>` markers instead of silent failures
- Backward-compatible aliases: `encryptAes128` / `decryptAes128`
- Manual NIST-style vector reference under `tests/manual-vectors.md`
- TypeScript-first implementation
- MIT license

### Known issues
- `vitest` test setup currently fails to start because `src/index.test.ts` imports `src/index.ts`, which calls `module.exports = plugin` at module load. Refactor needed: extract pure crypto helpers into a separate file to allow direct testing.

[Unreleased]: https://github.com/4nkitd/aes-yaak/compare/HEAD...HEAD
