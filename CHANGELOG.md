# Changelog

All notable changes to Veridiff are documented in this file, in [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/) format. Versioning
follows [Semantic Versioning](https://semver.org/); pre-1.0, a minor bump
may include breaking changes, per semver's own pre-1.0 carve-out.

## [0.2.3] - 2026-09-17

### Fixed
- `hex_decode` (Rust) silently dropped a malformed byte pair (odd length,
  non-hex characters) instead of erroring, so a malformed `bytes` field in
  a `disassembleRange` response would have passed through `parse_instruction`
  as a shorter-than-expected `raw_bytes` rather than the loud
  `MalformedResponse` every other field in that function already gets.
  Fixed by cross-checking the decoded length against the agent-reported
  `size`. Found in the same review pass that added `MalformedResponse`
  itself, for consistency -- never observed to actually happen. Python's
  `bytes.fromhex()` already raised `ValueError` on the same malformed
  input, so only the Rust side needed this.

### Added
- **Live ARM64 verification, closing the gap v0.2.2 left open.** Both
  engines, real hardware (POCO F7 Ultra, Android 16, `arm64-v8a`),
  identical results to each other and structurally identical to the
  existing x86 proof: `examples/licensecheck.c`, cross-compiled with the
  Android NDK instead of the host's `gcc` (no source changes), `spawn()`ed
  and traced over `adb`/USB. `b.ne` (ARM64's conditional branch, where x86
  uses `jne`) correctly identified as the deciding instruction by the same
  `is_conditional_branch` classifier introduced in 0.2.0 as mock-tested
  only. Full reproducible recipe in `CLAUDE.md`'s Testing section.
  Getting here took two failed attempts, both documented (README Field
  Notes, `CLAUDE.md`): Frida cannot inject into a statically-linked ELF
  binary (fixed by building with the NDK, dynamically linked, instead),
  and hooking a function inside hardened Bionic `libc.so` crashes the
  target process while hooking a normal app's own native library doesn't
  (sidestepped by tracing the test binary's own code rather than a system
  library function). Neither was a Veridiff bug.

### Changed
- README and `CLAUDE.md`'s ARM64 sections rewritten throughout to reflect
  the successful result -- the "not yet successful end to end" framing
  from 0.2.2 is gone; the two real technical findings that framing was
  protecting are kept, since they're still true and still useful to
  whoever touches this next.

## [0.2.2] - 2026-09-17

### Added
- `CLAUDE.md`: durable, repo-committed project instructions (versioning
  policy, commit policy, testing policy, scope pointer to "The Law").
- `CHANGELOG.md` (this file), backfilled to 0.1.0.

### Changed
- `README.md`'s version callout now describes only the current release,
  with full history moved here. Previously it accumulated a summary per
  version indefinitely.

### Investigated
- Live ARM64 testing against a real rooted Android device (POCO F7 Ultra,
  Android 16, arm64-v8a). Result: **not yet successful end-to-end** --
  documented honestly rather than claimed. Two real findings, neither a
  Veridiff bug:
  - Frida cannot inject into a statically-linked ELF binary on this
    device -- confirmed for both `spawn()` and `attach()`, identical
    "bootstrapper crashed with signal 11" failure. A Frida injection-layer
    limitation (dlopen-based injection needs a dynamic linker in the
    target), not specific to this engine.
  - Hooking a function inside hardened Bionic `libc.so` (`strcmp`) crashed
    the target process, twice, reproducibly. Hooking a function inside a
    normal app's own bundled native library (Chrome Beta) worked cleanly.
    Likely cause: ARM64 control-flow hardening (PAC/BTI/CFI) on system
    libraries on a current Android build conflicting with inline hooking --
    a reasonable hypothesis given the evidence, not confirmed to the same
    standard as the static-binary finding.
  - The engine's own device-selection design held up without changes:
    Python's `VeridiffEngine(device=...)` already accepted an arbitrary
    Frida device, and Rust's engine not owning a `Device` meant the same
    USB-vs-local switch needed zero engine code changes on either side.
  - See `CLAUDE.md`'s Testing section and README Field Notes for the full
    writeup and what the next attempt should try differently.

## [0.2.1] - 2026-09-17

### Fixed
- **`resync_confirmed` compared a candidate resync point against itself
  instead of against the blocks after it.** Since a candidate's `bj` is
  only ever found because `b[bj] == a[p]` already holds, the leading
  element of the old comparison window was a trivial self-match by
  construction. Whenever either trace happened to end exactly at the
  candidate, the confirmation window collapsed to just that tautology --
  a resync could be accepted with zero real evidence, in precisely the
  single-block-fly-by case `MIN_CONFIRM` (added in 0.2.0) exists to
  reject. The most serious bug found in this project's history: it
  silently defeated the tuned-resync feature in exactly the scenario it
  was built for, the same day it shipped. Fixed semantics: both traces
  exhausted together at the candidate is legitimate and still confirms
  (nothing left in either to disagree with); one exhausted while the
  other continues is rejected (the bug above). Found by an independent
  review pass, not by the test suite that existed at the time.
- Warm-up mode's untraced pre-call shared the same allocated argument
  buffer as the traced call that followed it. For a `'string'` argument,
  both calls pointed at one allocation -- a target that decodes or
  transforms its argument in place (routine for obfuscated checks) would
  have the untraced warm-up call mutate the buffer the traced call then
  read. Fixed by giving the warm-up call its own allocation. Not
  live-verified against a self-mutating target specifically.
- `RelayHandler::on_message`'s "meta" handler (Rust) silently fabricated
  plausible-looking defaults (`module_base: 0`, `pointer_size: 8`, ...) on
  an incomplete payload instead of failing visibly. Fixed to log and drop
  the trace instead -- an empty, obviously-wrong result instead of a
  subtly-wrong one. Deliberately does not panic: this runs inside the C
  callback dispatching Frida's "message" signal, where an unwinding panic
  would abort the whole host process, not just this call.
- `disassemble_block` (Rust) panicked (`.expect()`) on a malformed
  `disassembleRange` response instead of returning the `Result` it already
  declares. Unlike the fix above, panicking here was technically safe
  (runs on the caller's own thread) -- but it's a `pub fn` on an embeddable
  library, and a panic there takes the embedder's process down for what
  should be recoverable. Extracted a standalone `parse_instruction()`
  returning `Result`, with a new `MalformedResponse` error variant. Ported
  the same extraction to Python (`_parse_instruction()`) for symmetry,
  though Python's existing direct-dict-indexing behavior was already
  correct, just untested and inline.

### Changed
- `VeridiffEngine::find_divergence_regions`' documented complexity
  corrected: typical case is O(N + regions * resync_window) as before, but
  worst case (a value recurring throughout the resync window, e.g. a
  dispatcher hit on every loop iteration) is O(N + regions *
  resync_window^2). Left as a documented, accepted bound rather than adding
  comparison-budget machinery for a cost that has not mattered in practice.
- `VeridiffError` marked `#[non_exhaustive]`. Adding `MalformedResponse`
  in this release was, strictly, a breaking change for any exhaustive
  match on the enum; a 0.x patch release shouldn't be forced to respect
  that distinction going forward.
- Closed a real test-coverage gap (not a bug): `Arg::Int`/`Uint`/`Pointer`
  had been part of the API since 0.1.0 but only the `Str`/`'string'`
  variant had ever been live-verified as a call argument. Verified
  end-to-end against a throwaway three-argument test target -- correct,
  no bug found, but now proven rather than assumed.

### Added
- `python/test_main.py`: a real, committed pytest suite mirroring the Rust
  `#[cfg(test)]` suite test-for-test. Previous Python coverage was ad hoc
  scratch scripts, never committed.

## [0.2.0] - 2026-09-17

### Added
- **Warm-up mode**: `trace_call(..., warm_up=True)` /
  `TraceCallOptions { warm_up: true }` calls the target once, untraced,
  with the same arguments immediately before the traced call, to resolve
  PLT/GOT dynamic-linker lazy binding ahead of the run being measured.
  Live-proven against a real, reproducible false positive (two identical
  arguments diverging at `strcmp@plt`): the divergence reproduces with
  `warm_up=False` and is eliminated with `warm_up=True`, on the same test
  binary, in both engines. Off by default -- an extra call before tracing
  isn't safe for a target with side effects or other non-idempotent state.
- **Cross-architecture branch classification**: `Instruction.is_conditional_branch`
  (Python property / Rust method) on every disassembled instruction,
  covering x86 `jCC` mnemonics and ARM64 `b.cond`/`cbz`/`cbnz`/`tbz`/`tbnz`
  forms. `Instruction.parse` itself needed no changes -- Capstone via
  frida-gum already decodes every architecture Frida attaches to -- what
  was missing was classification, added host-side (not in the JS agent)
  for testability without live hardware. Verified live against
  `Instruction.groups` first: a real `jne` and the `jmp` two instructions
  later in the same block report identical groups, so classification had
  to be mnemonic-based by evidence, not `.groups`-based by assumption. x86
  half live-verified; ARM64 half verified by mock disassembly-payload unit
  tests only, no ARM64 hardware available at the time.
- **Tuned resync (OLLVM heuristics)**: `find_divergence_regions` now
  requires a candidate resync point to hold up under `MIN_CONFIRM`
  consecutive blocks of continued agreement before accepting it, instead
  of trusting the first shared address found. Fixes the class of false
  positive where OLLVM-flattened (or any commonly-helper-calling) code
  routes different logical paths through the same dispatcher block, which
  a naive first-match rule would misread as a real merge.

### Changed
- Hot-path allocation reuse (Rust): `find_divergence_regions` reuses one
  scratch hashmap across every region found in a call instead of
  allocating fresh per region; trace assembly (`TraceBuilder::absorb`)
  reserves Vec/HashMap capacity from each incoming chunk's upper-bound
  event count instead of growing incrementally. `find_first_divergence`
  and the raw `GumEvent` decode were already allocation-free -- stated
  plainly rather than implying they were newly optimized. An unsafe
  `&[GumEvent]` transmute of the raw event buffer was considered and
  rejected: IPC byte buffers carry no alignment guarantee, making that
  undefined behavior regardless of whether it happens to work on a given
  CPU.

## [0.1.0] - 2026-09-16

### Added
- Initial release: Python (`python/main.py`, single file) and Rust
  (`rust/` -- `src/lib.rs` as a real importable library, `src/main.rs` as
  a thin usage-example binary) engines for finding the exact basic block
  where two Frida-traced executions of the same native function first
  diverge.
- Core diff algorithm: longest-common-prefix scan (`find_first_divergence`),
  deliberately not a Myers/LCS-style diff -- after a real branch splits two
  paths, they routinely rejoin a shared library call or common epilogue,
  which an edit-distance algorithm would misread as "unchanged" instead of
  reporting the first real split. `find_divergence_regions` adds a
  bounded-lookahead resync for checks that run multiple independent
  conditionals in sequence.
- Raw `GumEvent` buffers forwarded via `send()` as-is (no
  `Stalker.parse()`, no per-event JS object) and decoded host-side
  (struct/bytes, O(N)), for throughput on multi-million-block traces.
  Layout verified against a live target, pinned to Frida 17.16.4's
  internal ABI (`gumevent.h`) at time of writing.
- Disassembly delegated entirely to the agent's own `Instruction.parse()`
  (Capstone via frida-gum) -- neither host carries a disassembler
  dependency, and decoding is always guaranteed to match the live target's
  actual architecture and mode.
- Published to GitHub (github.com/Veridiff/Veridiff), Apache License 2.0.

### Fixed
- `Stalker.follow()` silently produces zero events when called from a
  plain `rpc.exports` handler and then invoking a `NativeFunction`
  directly -- it only engages from genuine native execution context.
  Worked around with a throwaway `Interceptor.attach` bracketing the
  traced call purely to get Stalker to engage.
- The published `frida` Rust crate (0.17.2 on crates.io) has a real
  soundness bug in `Script::handle_message` (casts `user_data` to the
  wrong pointer type; UB for any handler with real state -- matches
  upstream issue #189). `rust/Cargo.toml` pins a git revision with the fix
  instead of the crates.io release.
