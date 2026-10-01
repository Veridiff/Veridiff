# Changelog

All notable changes to Veridiff are documented in this file, in [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/) format. Versioning
follows [Semantic Versioning](https://semver.org/); pre-1.0, a minor bump
may include breaking changes, per semver's own pre-1.0 carve-out.

## [0.4.0] - 2026-10-01

### Fixed
- **Stalker's event queue silently truncated every trace longer than 16384
  blocks.** Frida's default `queueCapacity` is 16384 *events*, and the queue
  drops events once full without raising anything, so a long trace came back
  short and reported success. The traced call runs synchronously on the
  followed thread, so the queue cannot drain while it runs: the whole trace
  has to fit. Measured against the new `examples/volume.c` on ARM64 at the
  default capacity: a 75050-block trace returned 16384 blocks (78% lost), a
  375250-block trace returned 16384 (96% lost). The ceiling is exactly the
  capacity, to the event (32768 -> 32768, 65536 -> 65536, 1048576 ->
  1048576), which is what makes detection reliable rather than a guess.
  `queueDrainInterval` is irrelevant for the same synchronous-call reason
  (250 ms, 1 ms and 0 measured identical), so it is deliberately not exposed.
  Fixed by having the agent set the capacity, defaulting to 2^21 events, and
  by reporting the capacity and the raw event count back so truncation is
  visible. *Live-verified on ARM64 and x86-64 in both engines: 1500403 blocks
  traced in 1.81 s (Python) / 1.30 s (Rust) with no loss and linear scaling,
  and a deliberately starved capacity correctly flagged as saturated.*
  Capacity costs nothing until used -- the buffer grows with events actually
  recorded, measured at ~32 bytes each (150065 events cost 4.8 MB of target
  RSS whether the capacity was 2^18 or 2^24).

### Added
- `TraceCallOptions::stalker_queue_capacity` (Rust) /
  `trace_call(..., stalker_queue_capacity=...)` (Python), plus
  `DEFAULT_STALKER_QUEUE_CAPACITY` in both.
- `Trace::event_count` / `Trace::queue_capacity` and the derived
  `Trace::queue_saturated()` / `Trace.queue_saturated`: true exactly when the
  event count reached the capacity, i.e. when the trace is truncated. A
  divergence found in a saturated trace is still real, but "no divergence" is
  not trustworthy and neither is the tail.
- **Four new test targets in `examples/`, each proving one claim**, all built
  for both architectures and run through both engines:
  - `flattened.c` -- control-flow flattening in the shape OLLVM's `-fla` pass
    emits (hand-written, not OLLVM output; said plainly because it bounds what
    the result proves). Closes the oldest honesty gap in the README: the
    resync heuristic had only ever been tested against synthetic block
    sequences. Live result on ARM64: three independent conditionals produce
    exactly three regions, each resyncing at the loop back-edge, with the
    dispatcher visited nine times in both traces; identical arguments produce
    none. The x86-64 build of the same source yields six regions because gcc
    keeps the comparisons as real branches.
  - `branches.c` -- forces real conditional branches of every form the
    classifier claims to know. Eight live-verified on ARM64 (`b.ge`, `b.le`,
    `b.ls`, `b.lt`, `b.ne`, `cbz`, `tbnz`, `tbz`) plus the flattened
    dispatcher's indirect `br` correctly left unmarked, and five on x86-64
    (`ja`, `je`, `jg`, `jl`, `jne`). Previously only `jne`/`b.ne` had ever
    been seen live. `cbnz` is still unproven live -- no build emitted it.
  - `argtypes.c` -- every `Arg` kind in one call, each contributing a distinct
    bit to the return value so a wrong result names the broken kind. Returns
    63 on both architectures. Only the string kind had a committed test
    before.
  - `volume.c` -- the million-block claim, and the target the queue bug was
    found with.

### Changed
- README restructured as well as updated: Quickstart moved ahead of the
  deep-dive sections, a contents list added, breaking changes collected in one
  place, an `examples/` index table added, and the two purely historical bug
  autopsies compressed to point at this file instead. New sections cover
  obfuscated control flow (with the branchless-codegen caveat) and scale.

### Investigated
- **What branchless codegen does to the headline claim.** On the flattened
  ARM64 target the comparison compiles to `subs` + `csel` -- no branch at all
  -- so the decision is a *value*, the two paths only fork later at the
  dispatcher, and the block containing the comparison is one *both* runs
  executed. Veridiff reports the fork correctly, and the two blocks it names
  are legible (`add w8, w8, #1` versus `subs w8, w8, #1`), but the
  `<-- decides here` marker does not fire on a flattened dispatcher, whose
  terminator is an unconditional indirect `br`. Documented in the README
  rather than papered over; the top-of-file claim was reworded to match.
- **Warm-up mode does nothing on Android.** The PLT/GOT lazy-binding confound
  is glibc behaviour; bionic resolves eagerly. Measured: two identical calls
  diverge at `strcmp@plt` on x86-64 without warm-up and do not diverge either
  way on the device. Not a bug, but worth knowing before leaving `warm_up` on
  there.
- **A root module running its own `frida-server` hijacks the USB lookup.** On
  the test device, `get_usb_device()` reached MagiskFrida's server -- which
  runs under a randomised process name, survives `pkill -f frida-server` and
  is invisible to `ps` -- and that server refuses to spawn plain executables
  (`frida.NotSupportedError: only able to spawn apps`). Diagnosed by killing
  "the" server and watching the host stay connected. Worked around by running
  our own on an explicit port and addressing it directly; no engine change was
  needed, since both halves accept any Frida device. Recipe in the README.
- **An intermittent crash creating several remote devices in one Rust
  process.** A harness obtaining a fresh `get_remote_device()` per target
  segfaulted in one run of three; every test passed in isolation and a
  five-round loop never crashed, so it is reported as a teardown race at that
  confidence and no higher, with no claim about which layer owns it. Every
  result from the runs that completed matched the Python engine field for
  field.

## [0.3.0] - 2026-10-01

### Fixed
- **A re-entrant (recursive) target produced a false divergence between two
  identical calls.** The worst bug in this project's history: unlike the
  0.2.1 `resync_confirmed` bug, which broke the resync heuristic, this one
  broke `find_first_divergence` -- the headline function. Two mechanisms,
  one root cause. (a) `Interceptor`'s `onLeave` fires innermost-first, so
  stopping Stalker there cut tracing off while the outer frames were still
  running, losing every outer frame's unwind block. (b) `Stalker.unfollow()`
  does not stop instrumented execution instantly, so those outer frames kept
  emitting block events, delivered *after* `traceCall` returned -- into the
  next call's message stream, where the host prepended them to an unrelated
  trace. Measured on `examples/depth.c` calling `depth(2)` twice with the
  same argument: 9 then 11 blocks, divergence reported at index 0. Fixed by tracking call depth in the agent (follow on the
  outermost entry only, stop on the outermost return only) and by stamping
  every agent message with the id of the `traceCall` that produced it, so
  late events are discarded rather than absorbed by the next listener.
  *Live-verified on x86 in both engines*: identical 11-block traces for
  `depth(2)`, `None` from the diff, and the full block sequence matching one
  derived by hand from `objdump` including the unwind blocks.
- **Tracing a function another thread was calling concurrently hung
  `trace_call` indefinitely.** `Interceptor` hooks are process-wide, not
  per-thread: another thread entering the target ran `Stalker.follow()` for
  *our* thread id from *its* callback, and its `onLeave` stopped stalking
  mid-measurement. Reproduced with `examples/mt.c`, whose background thread
  calls the traced function in a loop -- the first `trace_call` never
  returned (killed at 75s). Fixed by gating both callbacks on the thread id; the same
  target now returns three identical 9-block traces. *Live-verified by the
  symptom disappearing; the precise mechanism of the hang itself was never
  established.*
- **The 0.2.1 `resync_confirmed` fix was incomplete.** It special-cased only
  *zero* blocks remaining after the candidate, while the general
  `min(MIN_CONFIRM, a_remaining, b_remaining)` window still shrank below
  `MIN_CONFIRM` whenever either trace had one or two blocks left -- so
  `a=[...,0x30,0xD0,0xAA]` against `b=[...,0x31,0xD0,0xAA,0xBB,0xBC,0xBD]`
  confirmed `0xD0` on a single matching block while B's three remaining,
  genuinely different blocks went unexamined. The same shape as the original
  bug, one block further along, found the same way: by re-reading the fix
  against the docstring stating what it was supposed to guarantee. The rule
  now states the intent rather than enumerating cases -- a short
  confirmation window is acceptable only when it is short *because both
  traces ran out together*, and then every remaining block must match.
  *Verified by unit test in both engines.*
- **`find_divergence_regions` silently dropped a trailing length
  difference.** When one trace ran out while the other kept going -- either
  at the start (one a strict prefix of the other) or in the tail after an
  accepted resync -- it just stopped and reported nothing, so an empty
  result meant either "identical" or "differs only in length", while
  `find_first_divergence` correctly reported the difference. It is now
  reported as a final region with the exhausted side's branch set to
  `None`. New invariant, now unit-tested in both engines: the region list is
  empty if and only if `find_first_divergence` returns `None`, and the first
  region's fields agree with the divergence point's. *Verified by unit test;
  this is the test that would have caught the gap.*

### Added
- `examples/depth.c` and `examples/mt.c`: the two targets the fixes above
  were found and verified against -- a minimal recursive function and one
  whose background thread calls the traced function in a loop. Committed
  for the same reason `licensecheck.c` is: every claim in this release is
  reproducible from sources in this repository, with the exact build flags
  and resulting symbol addresses in each file's header comment.

### Changed
- **Breaking (Rust):** `DivergenceRegion::branch_a`/`branch_b` are now
  `Option<u64>` rather than `u64`, which is what lets the trailing-difference
  case above be represented at all. Python's annotations became
  `Optional[int]` to match, though nothing there enforced the old ones.
- **Breaking (protocol):** the agent's `traceCall` takes a trailing `callId`
  and echoes it on every message it sends. A host and an `AGENT_SOURCE` from
  different versions must not be mixed; within a release they always match,
  since each engine embeds its own copy.
- `collect_trace` extracted from Rust's `trace_call` as a standalone function
  over the event channel, so stale-event rejection is testable without Frida
  or a live target -- otherwise it is only reachable by racing a real
  re-entrant process.
- README: the ARM64 build recipe is now inline rather than referenced from a
  file that is not part of this repository; `find_divergence_regions`'
  complexity note in "How it works" now matches the docstring's honest
  worst case.

### Known issues
- `close()` hangs if the spawned process was never resumed (observed twice
  out of two; `resume()` then `close()` always worked). Not investigated, not
  fixed. Both demos resume before exiting, so neither exhibits it. See README
  field notes.
- The agent changes are live-verified on **x86 only**. The ARM64 proof in the
  README was produced by the v0.2.3 agent; no ARM64 device was connected for
  this release. The change is architecture-independent (thread ids and call
  depth, no instruction-level assumptions), but that is reasoning, not a
  measurement.

## [0.2.4] - 2026-09-17

### Fixed
- `_parse_instruction` (Python) had the same silent-truncation gap the
  0.2.3 Rust fix closed, missed at the time: `bytes.fromhex()` only raises
  on genuinely malformed hex (odd length, non-hex characters), not on
  well-formed hex that simply disagrees with a separately-reported `size`
  field (`bytes.fromhex("55")` decodes to one valid byte regardless of
  what `size` claims). The 0.2.3 commit message reasoned that Python's
  stdlib already covered this and only fixed Rust; that reasoning covered
  the malformed-hex case but not the wrong-length-well-formed-hex case,
  which is the one the explicit check actually exists for. Found by the
  review that same commit didn't wait for. Both languages
  now cross-check decoded length against `size` identically.
- `disassemble_block` (Rust) returned `VeridiffError::IncompleteTrace` for
  a `disassembleRange` response that wasn't a JSON array -- a real
  failure, but the wrong variant. `IncompleteTrace`'s own doc comment
  defines it as specifically `trace_call`'s channel-closed-or-timed-out
  case; a malformed RPC response is the unrelated failure mode
  `MalformedResponse` exists for, introduced in the same 0.2.3 commit for
  exactly this kind of case one function away. A caller distinguishing
  "transient, maybe retry" from "permanent, don't retry" by matching on
  the variant would have gotten the wrong signal.
- Added a test that was missing for both of the above: the existing 0.2.3
  regression test only covered *malformed* hex ("555", odd length), which
  would keep passing even if the explicit length check were deleted and
  hex-decoding's own error behavior were relied on instead -- masking a
  regression back to the original silent-truncation bug. New tests in both
  languages use well-formed hex that's simply the wrong length ("55" vs a
  declared `size` of 2), which only the explicit check catches.

## [0.2.3] - 2026-09-17

### Fixed
- `hex_decode` (Rust) silently dropped a malformed byte pair (odd length,
  non-hex characters) instead of erroring, so a malformed `bytes` field in
  a `disassembleRange` response would have passed through `parse_instruction`
  as a shorter-than-expected `raw_bytes` rather than the loud
  `MalformedResponse` every other field in that function already gets.
  Fixed by cross-checking the decoded length against the agent-reported
  `size`. Found in the same review that added `MalformedResponse`
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
  only. Full reproducible recipe in the README's field notes.
  Getting here took two failed attempts, both documented there: Frida
  cannot inject into a statically-linked ELF
  binary (fixed by building with the NDK, dynamically linked, instead),
  and hooking a function inside hardened Bionic `libc.so` crashes the
  target process while hooking a normal app's own native library doesn't
  (sidestepped by tracing the test binary's own code rather than a system
  library function). Neither was a Veridiff bug.

### Changed
- The README's ARM64 sections rewritten throughout to reflect
  the successful result -- the "not yet successful end to end" framing
  from 0.2.2 is gone; the two real technical findings that framing was
  protecting are kept, since they're still true and still useful to
  whoever touches this next.

## [0.2.2] - 2026-09-17

### Added
- Written-down maintenance policy for this project (versioning, commits,
  testing, and a scope pointer to "The Law"), kept as maintainer notes
  outside the repository rather than shipped in it.
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
  - See the README's field notes for the full
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
  review, not by the test suite that existed at the time.
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
