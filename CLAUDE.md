# eGuard for Windows (desktop agent)

**Start here in every session: read [docs/STATUS.md](docs/STATUS.md)** (what's done, what's next, decisions waiting
on the owner, gotchas).

- **Spec (source of truth):** `C:\Users\corew\eguard\docs\desktop-agent-spec.md`
- **Build prompt (phases, non-negotiables, "ask me first" list):** `C:\Users\corew\eguard\docs\desktop-agent-prompt.md`
- **Open questions:** `C:\Users\corew\eguard\docs\desktop-agent-open-questions.md`
- **Wire reference:** `C:\Users\corew\eguard\docs\mobile-api.md` Part C, and the server code in
  `C:\Users\corew\eguard\src\app\api\device\v1\`

## How this repo is worked on

- One phase per session. At the end of a phase: update docs/STATUS.md, commit, and stop. The next phase starts in a
  new session from docs/STATUS.md.
- Don't change the server (`~/eguard`). If it's wrong or missing something, say which file and what you'd change.
- Things on the prompt's "ask me first" list wait for the owner (server/wire/spec changes, security changes on this
  PC, code signing, self-update, crates that need the network or run code at install time).

## Layout

- `crates/eguard-core`: platform-neutral (no `windows` crate). Wire types, rules, time accounting, trusted clock,
  signatures, removal codes, offline queue, sync state. `#![forbid(unsafe_code)]` via workspace lints.
- `fixtures/server/`: real server responses, captured by `node tools/capture-fixtures.mjs` (needs ~/eguard's dev DB
  and a dev server; it deletes its test family afterwards). `fixtures/canonical-vectors.json`: made by
  `node tools/canonical-vectors.mjs`. Never hand-edit either.

## Commands

```sh
cargo test -p eguard-core
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
node tools/capture-fixtures.mjs        # refresh fixtures (EGUARD_URL defaults to http://localhost:3000)
```

## Conventions

- Comments say why, in plain words, like the server's. Doc comments on every public item.
- `unsafe` only at FFI boundaries in the platform crate, wrapped in small safe functions with a `SAFETY` comment.
- Fail closed: no error, 401, timeout or bad signature ever lowers protection.
- Secrets (device token, removal secret) never reach logs: `Debug` impls redact them.
