# Pinned dependency versions: libsignal, libp2p & rusqlite

Phase 0 foundations decision (PLAN.md §6, row "Pin `libsignal`/`libp2p` versions"), extended in the
Phase 2 "Storage" story to also cover `rusqlite`/SQLCipher. This document records the exact versions
pinned, why they were chosen, what crypto/transport/storage capabilities they provide, and how the
supply chain is protected against tampering.

## libsignal

- **Crate:** `libsignal-protocol`
- **Source:** git, not crates.io — Signal does not publish `libsignal` to crates.io.
- **Pinned ref:** commit `38428a7bb70509910d72b3f78208c1daf33774d8`, the exact commit tag `v0.96.2`
  pointed to at the time of pinning. Pinned by `rev` rather than `tag` in `Cargo.toml` — tags are
  mutable on the upstream repo (can be force-moved), while a `rev` is immutable independent of
  `Cargo.lock` or the `--locked` flag.
- **License:** AGPL-3.0-only (already accounted for in `CONTRIBUTING.md` / `LICENSE`, PLAN.md §7/§10).
- **MSRV:** Rust 1.88 (workspace toolchain is 1.96, satisfied).
- **Consumed by:** `core/crypto` (`core/crypto/Cargo.toml`).

### PQXDH availability

**Confirmed available** at tag `v0.96.2`. `rust/protocol/src/pqxdh.rs` exists in the pinned tree, and
`libsignal-protocol`'s manifest depends on `libcrux-ml-kem` with the `mlkem1024` feature, which backs
PQXDH's post-quantum KEM step. The pinned version also ships `double_ratchet.rs` / `triple_ratchet.rs`,
`sender_keys.rs` + `group_cipher.rs` (Signal Sender Keys for groups), and `sealed_sender.rs` — covering
every crypto capability PLAN.md §2 calls for (X3DH/PQXDH, Double Ratchet, Sender Keys, Sealed Sender).

Per PLAN.md §6 ("Crypto" row): "X3DH (or PQXDH, post-quantum, if available in the pinned version)" —
**decision: use PQXDH**, since it is available.

## libp2p

- **Crate:** `libp2p` (meta-crate)
- **Source:** crates.io
- **Pinned version:** `0.56.0` (latest stable at time of pinning).
- **License:** MIT
- **MSRV:** Rust 1.83.0 (workspace toolchain is 1.96, satisfied).
- **Consumed by:** `core/transport` (`core/transport/Cargo.toml`).

This story pins the **version only**, with default features. Feature selection (`noise`, `quic`,
`tcp`, `kad`, `relay`, `gossipsub`, async runtime choice, etc. — the protocols named in PLAN.md §2's
architecture diagram) is deferred to the Phase 3 "Transport (online)" story, where the runtime/executor
decision actually needs to be made. Pinning the version now is sufficient for `Cargo.lock` to record an
exact, reproducible dependency graph for everything `libp2p` depends on.

## rusqlite (SQLCipher)

- **Crate:** `rusqlite`
- **Source:** crates.io
- **Pinned version:** `0.40.1`
- **Feature:** `bundled-sqlcipher-vendored-openssl` — statically links a vendored SQLCipher amalgamation
  *and* a vendored OpenSSL (libcrypto, for SQLCipher's cipher provider) into the binary. Chosen over
  the plain `bundled-sqlcipher` feature (which links a vendored SQLCipher against the *system*
  OpenSSL) so a dev machine or CI runner needs no system SQLCipher/OpenSSL install to build the
  workspace — `cargo build --locked` is sufficient on a clean checkout.
- **License:** MIT (`rusqlite`); SQLCipher's community edition is BSD-style with attribution and is
  bundled, not separately downloaded, by the `libsqlite3-sys` build script.
- **Consumed by:** `core/storage` (`core/storage/Cargo.toml`), implementing PLAN.md §2/§6's
  "Storage (SQLCipher) ... encrypted at rest" layer.
- **Why a raw key, not a passphrase:** `core/storage` passes SQLCipher a raw 256-bit key via the
  `PRAGMA key = "x'<hex>'"` literal form rather than a passphrase. Key derivation (PBKDF2/Argon2 from
  a user secret) is a separate concern owned by whatever caller constructs the key; `rusqlite`/SQLCipher
  here only consumes already-strong key material, so there's no redundant/weaker KDF pass inside the
  store itself.

## How the pin is enforced

Both dependencies are declared once in `[workspace.dependencies]` in the root `Cargo.toml` and
referenced via `.workspace = true` from the crates that use them, so there is a single source of
truth for the version/ref.

`Cargo.lock` is committed to the repository. It pins:
- `libp2p` (and its ~240 transitive crates.io dependencies) to **exact versions with SHA-256
  checksums** recorded in the `checksum = "..."` field of each `[[package]]` entry.
- `libsignal-protocol` (and its sibling workspace crates `libsignal-debug`, `libsignal-core`,
  `signal-crypto`) to the **exact git commit** `38428a7b...` pinned via `rev` in `Cargo.toml`.

`libsignal-protocol` itself pulls in a second git dependency transitively:
`spqr` (Signal's `SparsePostQuantumRatchet`, tag `v1.5.1`, also from the `signalapp` GitHub org). It
is in the same trust domain as libsignal and its commit is likewise locked in `Cargo.lock`, but unlike
the top-level libsignal dependency we don't control its manifest — it is pinned by Signal's own
`libsignal` repo, not by us, so an upstream libsignal version bump could also change which `spqr`
commit gets pulled in. Re-pinning libsignal (see "Re-pinning in the future" below) should include
checking what `spqr` ref the new libsignal version requires.

## Supply-chain check: build fails closed on checksum mismatch

Cargo verifies the `checksum` field in `Cargo.lock` against the actual bytes fetched from the
registry before it will compile a crate. If a registry crate's published content ever changed
without a version bump (a substituted/tampered package), the recorded checksum would no longer
match and the build fails closed — it does not silently use the tampered code.

Verified directly against this workspace:

```
$ sed -i.bak 's/^checksum = "ce71348bf5838e46449ae240631117b487073d5f347c06d434caddcb91dceb5a"$/checksum = "0000000000000000000000000000000000000000000000000000000000000000"/' Cargo.lock
$ cargo check -p transport --locked
error: checksum for `libp2p v0.56.0` changed between lock files

this could be indicative of a few possible errors:

    * the lock file is corrupt
    * a replacement source in use (e.g., a mirror) returned a different checksum
    * the source itself may be corrupt in one way or another

unable to verify that `libp2p v0.56.0` is the same as when the lockfile was generated

$ mv Cargo.lock.bak Cargo.lock   # restore
```

The build aborts rather than proceeding with mismatched content — the negative/fail-closed case
this story's acceptance criteria require.

For the **git** dependency (`libsignal-protocol`), there is no separate `checksum` field — integrity
instead comes from git's content-addressed object hashing: `Cargo.lock` records the exact commit SHA
resolved from the tag, and `cargo build --locked` will refuse to silently re-resolve to a different
commit if the tag is later moved/force-pushed upstream. Re-pinning to a new libsignal release must be
a deliberate, reviewed change to this file and `Cargo.lock`, not an automatic update.

`cargo build --locked` (or `cargo check --locked`, as used above) must be the command CI runs, so an
out-of-date or tampered `Cargo.lock` fails the build instead of silently re-resolving versions.

## Re-pinning in the future

Bumping either dependency is a deliberate action, not automatic:
1. Update the version/tag in `[workspace.dependencies]` in the root `Cargo.toml`.
2. Run `cargo update -p libp2p` or `cargo update -p libsignal-protocol` (not a blanket `cargo update`).
3. Re-verify PQXDH/Sender Keys/Sealed Sender availability in the new libsignal tag if bumping it.
4. Commit the updated `Cargo.lock` alongside the manifest change, through the normal review gate
   (libsignal touches crypto/identity — security-engineer review required per CLAUDE.md).
