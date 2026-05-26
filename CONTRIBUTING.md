# Contributing to aes-yaak

A [Yaak](https://yaak.app) API-client plugin providing AES-128 / AES-256 encryption and decryption template helpers (CBC, GCM, CTR, ECB modes).

## Dev setup

Prereqs:

- Node.js 20+
- (Optional) [`yaakcli`](https://www.npmjs.com/package/yaakcli) for the plugin build target

```bash
git clone https://github.com/4nkitd/aes-yaak.git
cd aes-yaak
npm install
npm run build
```

`npm run build` invokes `yaakcli build`. Output lands in `build/`.

## Loading in Yaak

In Yaak: `Settings` → `Plugins` → `Load Folder…` and choose this project root (or the `build/` output if you built it).

## Running tests

```bash
npx vitest run
```

**Heads up — the test setup is currently broken**: `src/index.test.ts` imports `src/index.ts`, which calls `module.exports = plugin` at module-load time. Vitest doesn't like that. The fix is to extract the pure crypto helpers from `src/aesPlugin.ts` (already mostly factored) into a file that has no Yaak side-effects and to import that from the test. A first PR doing this refactor + adding vector-based tests is welcome.

Manual reference vectors live in `tests/manual-vectors.md`.

## Project layout

```
aes-yaak/
├── src/
│   ├── index.ts        # Yaak plugin entry; registers template helpers
│   ├── aesPlugin.ts    # core encrypt/decrypt logic
│   └── index.test.ts   # (broken; see above)
├── tests/
│   └── manual-vectors.md
├── build/              # yaakcli output (gitignored if you set that up)
└── README.md           # extensive — usage, options, modes, FAQ, roadmap
```

## Adding a feature

The README has a Roadmap section listing planned work (12-byte GCM nonce, IV generator, HKDF/PBKDF2 helpers, debug mode, streaming interface, AES-192). To pick one up:

1. Open a GitHub issue describing the change and any back-compat concerns
2. Implement in `src/aesPlugin.ts` (keep the Yaak-facing API in `src/index.ts` thin)
3. Add test vectors under `tests/` and reference them from the test file (once the test setup is fixed)
4. Update README + CHANGELOG
5. PR

## Security PRs

Crypto bugs are exempt from the "open an issue first" rule. Send a fix directly with a clear explanation of the threat and a test vector demonstrating it. For sensitive disclosure, see `SECURITY.md` (when added).

## Branches and commits

- Branch from `master`: `feat/<name>`, `fix/<name>`, `docs/<name>`.
- Conventional Commits encouraged.

## PR checklist

- [ ] `npm run build` succeeds
- [ ] Tests pass (once the test setup is fixed)
- [ ] README updated if user-facing
- [ ] `CHANGELOG.md` entry under `## [Unreleased]`
- [ ] If altering crypto logic, include test vectors (NIST or self-generated round-trip)

## Releases

Maintainers only. Tag `v0.x.y`, push, attach the `build/` output to the GitHub Release.

## Reporting issues

[GitHub issues](https://github.com/4nkitd/aes-yaak/issues).
