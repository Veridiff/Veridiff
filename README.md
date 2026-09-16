════════════════════════════════════════════════════════════════
  VERIDIFF
  the exact instruction where two runs of the same code split
════════════════════════════════════════════════════════════════

Two traces go in. One address comes out: the `cmp` / `jcc` (or
`tst`/`b.cond`, or whatever your architecture calls it) that decided
your two runs weren't going to end the same way.

That's the whole product. Not a framework. Not a platform. An engine.

**v0.2.0** adds four things, in the order they were built: a reused-allocation
pass over the trace-assembly and resync hot paths; an opt-in warm-up call
that eliminates a real, live-reproduced false positive from dynamic-linker
lazy binding; cross-architecture (x86 + ARM64) classification of which
instruction in a block is the actual decision point; and a resync algorithm
that now requires a match to hold up under continued comparison before
trusting it, instead of accepting the first coincidental address it finds --
the difference between correctly walking past an OLLVM dispatcher and being
fooled by it. Each is covered below, with either a live proof or an honest
note about what wasn't (and couldn't be) tested live.

---

## What this actually is

Reverse engineering a license check, an anti-cheat heuristic, or an
OLLVM-flattened dispatcher usually comes down to the same manual loop:
run it once with good input, run it again with bad input, and stare
at two disassembly listings trying to spot where they stopped
agreeing with each other. That loop doesn't scale past a few hundred
basic blocks, and it doesn't survive control-flow flattening at all —
every path already goes through the same dispatcher block, so staring
at addresses tells you nothing.

Veridiff automates the *diffing*, not the reversing. Attach [Frida](https://frida.re)'s
Stalker to a thread, run it twice, and get back the one thing that
actually matters: the last block both runs agreed on, the first block
they didn't, and the disassembly of the instruction that split them.
Millions of basic blocks in, one address out.

It ships as two things, on purpose:

- **`python/main.py`** — one file, `pip install frida`, done.
- **`rust/`** — a real library crate (`src/lib.rs`) plus a thin
  demo binary (`src/main.rs`), for when Python's call overhead is the
  bottleneck instead of Frida's own instrumentation cost.

Both expose the same four calls (`trace_call`, `disassemble_block`,
`find_first_divergence`, `find_divergence_regions`) and produce
byte-identical results against the same target. Neither one has a
single line of CLI, GUI, or presentation logic in it. That's not an
oversight — see **The Law** below.

---

## Proof, Not Promises

No benchmarks against products we've never touched, no "battle-tested
against Denuvo" fantasy claims. Here is a small, deliberately
unremarkable C function — [`examples/licensecheck.c`](examples/licensecheck.c) —
compiled with nothing that makes Frida's job easier, traced twice with
a valid and an invalid key, on this machine, moments before this
paragraph was written:

```
$ gcc -O0 -no-pie -fno-pie -fno-inline -o licensecheck examples/licensecheck.c
$ nm licensecheck | grep check_license
0000000000401146 T check_license

$ python3 python/main.py ./licensecheck 0x401146 VALID-KEY-123 WRONG-KEY
trace A ('VALID-KEY-123'): 9 blocks, returned 1
trace B ('WRONG-KEY'): 6 blocks, returned 0

first divergence at trace index 1
  last common block : 0x114e
  run A took block  : 0x1164
  run B took block  : 0x116a

  disassembly of the deciding block:
    0x40114e  mov qword ptr [rbp - 0x18], rdi
    0x401152  mov dword ptr [rbp - 4], 0
    0x401159  mov rax, qword ptr [rbp - 0x18]
    0x40115d  movzx eax, byte ptr [rax]
    0x401160  cmp al, 0x56
    0x401162  jne 0x40116a  <-- decides here
```

(Trace A is 9 blocks here, not 11 -- v0.1.0's README showed this same run
before warm-up mode existed. See **Warm-up mode** below for what changed
and why. The `<-- decides here` marker is v0.2.0's conditional-branch
classification, covered in **Cross-architecture branch classification**.)

`0x56` is `'V'`. The engine never saw the source. It never saw
`"VALID-KEY-123"` as a string to search for — it doesn't know what a
license key is. It ran two traces, found where they stopped matching,
and handed back the exact comparison, because that's the first byte
the two arguments actually disagree on. That's the entire trick, and
it's the only trick: turn "where did these diverge" into a linear
scan instead of a stare-at-two-listings exercise.

The Rust engine, same binary, same two keys:

```
$ cd rust && cargo run --release -- ../licensecheck 0x401146 VALID-KEY-123 WRONG-KEY
trace A ("VALID-KEY-123"): 9 blocks, returned Some("1")
trace B ("WRONG-KEY"): 6 blocks, returned Some("0")

first divergence at trace index 1
  last common block : 0x114e
  run A took block  : 0x1164
  run B took block  : 0x116a

  disassembly of the deciding block:
    0x40114e  mov qword ptr [rbp - 0x18], rdi
    0x401152  mov dword ptr [rbp - 4], 0
    0x401159  mov rax, qword ptr [rbp - 0x18]
    0x40115d  movzx eax, byte ptr [rax]
    0x401160  cmp al, 0x56
    0x401162  jne 0x40116a  <-- decides here
```

Identical answer. Two independent implementations, two different
language runtimes, one ground truth. Go build `licensecheck` yourself
and run both — the whole point of putting the source in this repo
instead of just the output is that you don't have to take our word
for any of this.

---

## How it works

```
target process                          host (Python / Rust)
───────────────                         ─────────────────────
NativeFunction call, run A   ──►   Interceptor.attach bridges into
  basic blocks execute       ──►   Stalker.follow, which streams the
                                    RAW GumEvent buffer via send() --
                                    no Stalker.parse(), no per-event
                                    JS object, no JSON round-trip
NativeFunction call, run B   ──►   same path, second trace
                                              │
                                              ▼
                              host decodes the fixed-stride GumEvent
                              records directly (struct/bytes, O(N))
                                              │
                                              ▼
                              find_first_divergence(trace_a, trace_b)
                              -- longest-common-prefix scan, O(min(n,m))
                                              │
                                              ▼
                              disassemble just the 1-2 blocks that
                              actually matter, via the agent's own
                              Instruction.parse() (no host-side
                              disassembler dependency, ever)
```

Two design decisions carry the whole thing, and both are deliberate
departures from the obvious approach:

**The diff is a prefix scan, not a Myers/LCS diff.** Text-diff
algorithms solve "what's the minimal edit script between these two
sequences" — the wrong question here. After a real branch splits two
paths, they routinely rejoin a shared library call or a common
epilogue. A minimal-edit-script algorithm reads that coincidental
address match as "unchanged" and hands you a fragmented, misleading
alignment instead of the one thing you actually want: the *first*
point the paths split. A longest-common-prefix scan answers exactly
that question, in O(min(n,m)) with no hashing, instead of O(N·D) for
Myers or O(N log N) for the best hash-assisted variants. `find_divergence_regions`
adds a bounded-lookahead resync on top for the case where a check runs
several independent conditionals in sequence — still not a general
diff, still O(N + regions × window), still answering "where did they
split" rather than "how do these align."

**Disassembly happens inside the agent, not the host.** Frida-gum
already bundles Capstone and exposes it as `Instruction.parse()`. Both
hosts ask the agent to disassemble the handful of blocks that matter
*after* the diff is computed, and get back structured
`{address, mnemonic, opStr}` records — so neither `main.py` nor
`lib.rs` carries a disassembler dependency, and the decode is always
guaranteed to match the live target's actual architecture and mode,
because it's running inside that exact process.

A third, smaller note on the Rust engine specifically: `find_first_divergence`
and the raw `GumEvent` decode were already allocation-free (plain slice
scans, no heap traffic) before v0.2.0 — there was nothing to fix there,
only to state plainly rather than imply otherwise. What v0.2.0 actually
changed is real but narrower: `reserve()`-ing trace-assembly buffers by
each chunk's upper-bound event count instead of growing incrementally, and
reusing one scratch hashmap across every region `find_divergence_regions`
finds instead of allocating one per region. An unsafe transmute of the raw
event buffer into a `&[GumEvent]` slice was considered and rejected: a
`Vec<u8>` arriving over IPC has no alignment guarantee, and reinterpreting
unaligned bytes as a `#[repr(C)]` struct with 8-byte fields is undefined
behavior regardless of whether any given CPU tolerates it in practice.
`from_le_bytes` on a byte slice is the correct idiom and already compiles
to the same loads.

---

## Warm-up mode

A real, reproducible confound, found by actually tracing a process rather
than trusting synthetic data: a target's *first-ever* call to an
externally-linked function (`strcmp`, anything else routed through the
PLT/GOT) takes the dynamic linker's lazy-binding resolver path. Every later
call to that same function skips straight to the now-resolved GOT entry.
Two calls with **identical arguments** can therefore still report a
divergence -- not because your logic differs, but because one of them paid
a one-time linker tax the other didn't.

`trace_call(..., warm_up=True)` (Python) / `TraceCallOptions { warm_up: true }`
(Rust) has the agent call the target once, untraced, with the same
arguments, immediately before the call that's actually measured -- so
whatever GOT entries that code path touches are already resolved by the
time tracing starts. Proof, on the same binary as above, two identical
`"VALID-KEY-123"` calls:

```
warm_up=False: divergence = DivergencePoint(index=4, last_common_block=4160, block_a=4166, block_b=4479)
warm_up=True:  divergence = None
```

That's the actual raw `repr()` of the return value, decimal fields and all
-- `last_common_block=4160` is `0x1040`, `strcmp@plt`. Without warm-up, two
*identical* calls report a divergence there. With it, `find_first_divergence`
correctly returns nothing to report. Off by default -- it means the target
executes an extra time before being traced, which isn't safe for a target
with side effects or other non-idempotent state -- so it's your call to
opt in.

---

## Resync tuning (OLLVM heuristics)

`find_divergence_regions`' old rule was "the first address both traces
share, within the lookahead window, is where they resynced." That's wrong
for exactly the code this tool exists to analyze: OLLVM-flattened control
flow routes many logically-different paths through the *same* dispatcher
block, so that address shows up in both windows almost immediately after
nearly any divergence -- without the two paths having actually merged back
into the same control flow. The old rule would call that a resync. It isn't
one; it's two different paths both passing through shared machinery on
their way to somewhere else.

v0.2.0 requires a candidate to *hold up*: at least three consecutive blocks
must keep agreeing right after the candidate address before it's accepted
as a real merge. A dispatcher fly-by is followed by state-dependent blocks
that differ between the two traces almost every time; a genuine merge keeps
agreeing. Synthetic proof (no live OLLVM-obfuscated binary was available to
test this against, so this is exactly what it looks like -- a targeted
unit test, not a live capture; see `dispatcher_style_coincidental_match_is_rejected`
and its paired acceptance test in both test suites):

```
# same shared block (0xD0) in both cases -- only the outcome differs
a = [0x10, 0x20, 0x30, 0xD0, 0xAA, 0xAB, 0xAC]
b = [0x10, 0x20, 0x31, 0xD0, 0xBB, 0xBC, 0xBD]   # diverges again right after 0xD0
  -> resync_block: None                            # correctly rejected

a = [0x10, 0x20, 0x30, 0xD0, 0xAA, 0xAB, 0xAC]
b = [0x10, 0x20, 0x31, 0xD0, 0xAA, 0xAB, 0xAC]   # genuinely continues identically
  -> resync_block: Some(0xD0)                       # correctly accepted
```

---

## Cross-architecture branch classification

`Instruction.parse` (Capstone, via frida-gum) already decodes every
architecture Frida attaches to, ARM64 included -- there was never any
x86-specific code in the agent to "extend" for `CBZ`/`CBNZ`/`B.cond`/
`TBZ`/`TBNZ`. What both engines now add is `is_conditional_branch` on each
disassembled instruction, so the deciding branch in a block is flagged
instead of left for you to spot by eye (that's the `<-- decides here`
marker in the proof output above).

This has to be mnemonic-based, not `Instruction.groups`-based, and that's
an empirical finding, not a guess: live-captured against the real `jne` in
the proof output above, Capstone reports `groups: ["branch_relative",
"jump"]` -- and the *unconditional* `jmp` two instructions later in the
same block reports the exact same groups. Nothing in `.groups`
distinguishes them. Mnemonic text is the only signal that does, on any
architecture, which is what `is_conditional_branch` actually checks.

Honesty about test coverage, since that empirical finding only covers what
was on hand: the x86 half is live-verified (see above). No ARM64 hardware
or correctly-configured emulation was available in this environment, so the
ARM64 half (`cbz`/`cbnz`/`tbz`/`tbnz`/`b.eq`/`b.ne`/...) is verified by unit
tests against mock disassembly payloads shaped exactly like a real
`disassembleRange` response, not by an end-to-end live ARM64 trace. The
underlying disassembly mechanism is Frida's own well-established multi-arch
Capstone integration, unmodified by this change -- but say so plainly
rather than imply hardware that wasn't touched.

---

## Quickstart

**Python** — one file, one dependency:

```bash
pip install frida
python3 python/main.py <executable> <hex-address-of-target-fn> <arg-a> <arg-b>
```

**Rust** — a real library, importable by path/git from any other crate:

```toml
# your Cargo.toml
[dependencies]
veridiff = { path = "../Veridiff/rust" }
```

```rust
let options = TraceCallOptions { warm_up: true };
let trace = engine.trace_call(&mut script, addr, &args, "int", None, options)?;
let d = VeridiffEngine::find_first_divergence(&trace_a, &trace_b);
```

`src/main.rs` in this repo is nothing but a thin CLI wrapper over that
same API — read it as a usage example, not as the product.

New in v0.2.0, both languages: `trace_call(..., warm_up=True)` / a
`TraceCallOptions { warm_up: true }` argument (see **Warm-up mode**), and
`instruction.is_conditional_branch` / `insn.is_conditional_branch()` on
every `Instruction` returned by `disassemble_block` (see **Cross-architecture
branch classification**). Both are additive on the Python side; the Rust
`trace_call` signature gained a required trailing parameter, which is a
breaking change for existing callers on this pre-1.0 crate -- pass
`TraceCallOptions::default()` for the old behavior.

---

## Field notes (landmines we already stepped on)

Reverse engineering tools should tell you where the bodies are
buried. These cost real debugging time to find; they're documented
inline in both agents, and repeated here because they're the kind of
thing you only learn by actually tracing a real process instead of
trusting synthetic test data.

- **`Stalker.follow()` silently does nothing if you call it from a
  plain `rpc.exports` handler and then invoke a `NativeFunction`
  directly.** No error, no event, `blockCount` stays zero forever. It
  only engages from genuine native execution context — which is why
  `traceCall` brackets the actual call inside a throwaway
  `Interceptor.attach(target, {onEnter, onLeave})` instead of calling
  `Stalker.follow`/`fn()` back to back. If you're extending the agent
  and your event count is mysteriously zero, this is almost certainly
  why.

- **The published `frida` Rust crate (`0.17.2` on crates.io) has a
  real soundness bug** in `Script::handle_message`: it casts the
  signal's `user_data` to the wrong pointer type before calling a
  method through it — undefined behavior for any handler that carries
  real state, matching upstream
  [issue #189](https://github.com/frida/frida-rust/issues/189) (reported
  symptoms: crashes inside atomic ops, garbage field reads, a Windows
  deadlock). Fixed on `main` in commit `080e8a99a5`, not yet in a
  crates.io release — `rust/Cargo.toml` pins a git rev with the full
  reasoning inline. **Check for a `>=0.17.3` release before "helpfully"
  switching that back to a version string.**

- **Two calls with *identical* arguments can still report a spurious
  first divergence**, if the target's first call to some external
  function (`strcmp`, anything else that goes through the PLT) hasn't
  had its GOT entry resolved yet. The first call takes the
  lazy-binding resolver path; every call after it jumps straight to
  the resolved address. `find_first_divergence` will honestly report
  this as a real difference, because it is one — `find_divergence_regions`
  is what shows you it's a single region that immediately resyncs, at
  which point you can recognize a PLT stub address and move on. As of
  v0.2.0 you can also just not have the problem: see **Warm-up mode**.

- **`frida-rust`'s blocking RPC calls have no timeout or dead-session
  detection.** `Exports::call`'s implementation is a bare
  `rx.recv().unwrap()` on an internal channel — if the target process
  exits (including because you called `device.resume()` and its
  `main()` ran to completion) while a call is in flight, or before the
  next one starts, that channel never receives anything and the call
  blocks *forever*, not with an error. Found live: calling
  `disassemble_block` after `device.resume()` hung this engine's own
  demo binary indefinitely. `frida-python`'s equivalent detects this
  and raises `frida.InvalidOperationError: script has been destroyed`
  cleanly instead — this is Rust-specific. The fix isn't a timeout
  wrapper, it's ordering: both demos now do every RPC call (trace,
  diff, disassemble) *before* calling `resume()`, since disassembly
  only needs the target's static, already-mapped code bytes and was
  never dependent on the process actually running. `resume()` is the
  last line in both, purely so the spawned process doesn't get left
  stopped. If you're extending either demo, keep it that way.

---

## The Law

Veridiff is a reference-grade core engine, not an application. Its
entire value is being small, fast, and dependency-light enough to
embed into *anything* — a CLI, a GUI, a Ghidra or IDA plugin, a CI
gate, a Discord bot, whatever the next person building on top of it
needs. Every dependency or abstraction we let into the core is a tax
paid by every single integrator downstream of us, forever — including
the ones who never wanted it.

So the rule is simple, and we intend to enforce it without
exception:

**We welcome, with open arms:**
- Core algorithm improvements — a faster or more accurate divergence
  scan, a smarter resync heuristic, a real reduction in allocations
  or copies on the hot path.
- Memory and correctness fixes, especially ones found the way the
  Stalker/Interceptor bug above was found: by actually tracing a real
  process and proving the fix against real output.
- New architecture support — ARM32/Thumb, MIPS, RISC-V, wherever
  Frida and Capstone already reach and our own classification logic
  (branch-type detection, and whatever comes after it) doesn't yet.
  x86 and ARM64 are covered as of v0.2.0; ARM64 by mock-payload unit
  tests only, since no ARM64 hardware was available to verify live --
  a real device or correctly-configured emulator to actually run that
  verification against is exactly the kind of contribution this
  welcomes.
- Portability fixes for platforms the current code handles badly.

**We will not merge, ever, under any framing:**
- CLI frameworks. No `argparse`, no `clap`, no flag parsing of any
  kind. If you want flags, that's a wrapper, not a patch to this repo.
- GUI code, TUI code, web dashboards, progress bars.
- Colored terminal output, fancy logging frameworks, spinners —
  `print()`/`eprintln!()` or nothing.
- "Convenience" functions that exist only to save a caller three lines
  at the cost of a new dependency for everyone who doesn't need them.
- Config file formats, plugin systems, telemetry, auto-update
  checkers — anything that turns an engine into an application.

This isn't gatekeeping for its own sake — it's the only way a core
engine stays a core engine instead of slowly becoming somebody's
particular CLI with an API bolted on as an afterthought. If you want
a CLI, a GUI, or a Ghidra plugin: **fork the engine, build
`veridiff-cli` or `veridiff-gui` or `veridiff-ida` on top of it as its
own project, and depend on this repo like any other library.** We
mean that as an invitation, not a brush-off — tell us it exists and
we'll link to it from here.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Copyright 2026 Veridiff.
