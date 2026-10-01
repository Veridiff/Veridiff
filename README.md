════════════════════════════════════════════════════════════════
  VERIDIFF
  the exact instruction where two runs of the same code split
════════════════════════════════════════════════════════════════

Two traces go in. One address comes out: the exact basic block where your
two runs stopped agreeing, disassembled, with the branch that split them
marked — `cmp`/`jne` on x86, `subs`/`b.ne` on ARM64, a jump-table dispatcher
if the code is flattened. (When a compiler decides a condition without
branching at all — `csel`, `cmov` — the comparison itself sits in a block
*both* runs executed, and what you get is the block where the paths actually
forked. That distinction is demonstrated, not glossed over: see
**Obfuscated control flow** below.)

That's the whole product. Not a framework. Not a platform. An engine.

**Current release: v0.4.0.** Fixes silent trace truncation: Frida's default
Stalker queue holds 16384 events and drops the rest **without an error**, so
every trace longer than that was quietly incomplete — measured at up to 98%
of blocks lost while reporting success. The engine now sizes the queue itself
(and lets you size it), and every `Trace` carries `queue_saturated` so
truncation can never be silent again. Everything in this README is now
live-verified on **both x86-64 and ARM64/Android**, including control-flow
flattening and a 1.5-million-block trace. Breaking: `trace_call` gained an
option field; see **Quickstart**. Full history in
[`CHANGELOG.md`](CHANGELOG.md).

---

**Contents** — [Quickstart](#quickstart) ·
[Proof, Not Promises](#proof-not-promises) ·
[How it works](#how-it-works) ·
[Warm-up mode](#warm-up-mode) ·
[Obfuscated control flow](#obfuscated-control-flow) ·
[Scale](#scale) ·
[Branch classification](#cross-architecture-branch-classification) ·
[Field notes](#field-notes-landmines-we-already-stepped-on) ·
[The Law](#the-law)

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

### Breaking changes you may have to touch

Pre-1.0, so these come as minor bumps. Both are small.

**v0.4.0** added `stalker_queue_capacity` to `TraceCallOptions`, which breaks
Rust struct-literal construction. Use `..Default::default()` and future knobs
won't break you either:

```rust
let options = TraceCallOptions { warm_up: true, ..Default::default() };
```

`Trace` also gained `event_count` and `queue_capacity`, and with them
`queue_saturated()` / `.queue_saturated` — **check it on any trace long
enough to matter**, because a saturated trace is silently truncated (see
**Field notes**). Python's `trace_call` takes the capacity as a keyword
argument, so nothing there breaks.

**v0.3.0** made `DivergenceRegion`'s `branch_a`/`branch_b` `Option<u64>` in
Rust (`Optional[int]` in Python), so "one trace ran out while the other kept
going" can be reported instead of silently dropped.

The agent and host also exchange a per-call id and a queue capacity, so a host
and an `AGENT_SOURCE` from different versions must not be mixed. Within a
release they always match, since each engine embeds its own copy.

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

Same source file, cross-compiled for Android instead of the host, spawned
and traced on a real rooted phone (POCO F7 Ultra, Android 16, `arm64-v8a`)
over `adb`, same two keys:

```
$ $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang \
    -O0 -fno-inline -o licensecheck-arm64 examples/licensecheck.c
$ adb push licensecheck-arm64 /data/local/tmp/licensecheck-arm64 && adb shell chmod 755 /data/local/tmp/licensecheck-arm64
$ $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm licensecheck-arm64 | grep check_license
0000000000000798 T check_license

trace A ('VALID-KEY-123'): 12 blocks, returned 1
trace B ('WRONG-KEY'): 9 blocks, returned 0

first divergence at trace index 1
  last common block : 0x7a8
  run A took block  : 0x7bc
  run B took block  : 0x7d0

  disassembly of the deciding block:
    0x5b247bc7a8  str wzr, [sp, #0xc]
    0x5b247bc7ac  ldr x8, [sp, #0x10]
    0x5b247bc7b0  ldrb w8, [x8]
    0x5b247bc7b4  subs w8, w8, #0x56
    0x5b247bc7b8  b.ne #0x5b247bc7d0  <-- decides here
```

`0x56` is `'V'`, same as x86 -- `subs`/`b.ne` instead of `cmp`/`jne`, same
decision, correctly identified as the deciding instruction by the exact
same `is_conditional_branch` classifier the x86 proof exercises, on a
completely different instruction set. Both engines produce this same
result (block counts, divergence point, disassembly) against the same
binary -- only the addresses differ, because ASLR gives every run of a
PIE executable a different load address, which is exactly why the module
base gets resolved at trace time rather than assumed. No source change
between this and the x86 build above -- `examples/licensecheck.c` is
untouched; only the compiler target changed. Full walkthrough, including
why this needs `spawn()` (not `attach()` to a system-library hook) and
what didn't work first, is in **Field notes** below.

This capture is re-run on real hardware every release that touches the agent.
The numbers above are v0.4.0's, taken on a POCO F7 Ultra running Android 16,
and they are identical to the ones v0.2.3 first produced — same block counts,
same divergence index, same deciding instruction — with both engines agreeing
on every field. The Android walkthrough below is not a one-off demo either:
six separate targets covering recursion, concurrency, flattened control flow,
every argument kind, the full set of ARM64 conditional-branch forms, and a
1.5-million-block trace all run against this device, and all of them are in
[`examples/`](examples/) so you can repeat them.

### What's in `examples/`

Seven small C files, one claim each, rather than one big binary that proves
nothing in particular. Every one is built for both x86-64 and ARM64, run
through both engines, and carries its exact build flags and resulting symbol
address in its own header comment.

| File | What it is there to prove |
|---|---|
| [`licensecheck.c`](examples/licensecheck.c) | The baseline proof above: find the byte comparison that split two runs. |
| [`depth.c`](examples/depth.c) | A recursive target traces completely and two identical calls do not diverge (the v0.3.0 bug). |
| [`mt.c`](examples/mt.c) | A second thread calling the traced function concurrently neither hangs the trace nor corrupts it. |
| [`flattened.c`](examples/flattened.c) | OLLVM-shaped control-flow flattening: the resync heuristic on real obfuscated code, and what branchless codegen does to the answer. |
| [`branches.c`](examples/branches.c) | `is_conditional_branch` against real compiled branches of every form, not hand-written mnemonics. |
| [`argtypes.c`](examples/argtypes.c) | Every argument kind (`int`, `uint`, `int64`, `uint64`, `pointer`, `string`) arrives intact. |
| [`volume.c`](examples/volume.c) | The million-block claim, and that a truncated trace is detectable. |

`mt.c` deliberately contains a copy of `licensecheck.c`'s function, so the
concurrency test varies the thread and nothing else.

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
diff, still O(N + regions × window) in the typical case (see
`find_divergence_regions`' own docs for the quadratic worst case and why
it's accepted), still answering "where did they split" rather than "how do
these align." As of v0.3.0 it also reports a trailing region when one trace
simply runs out while the other continues, so an empty result means
"identical" and nothing else.

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

## Obfuscated control flow

This is the case the whole resync machinery exists for, and through v0.3.0 it
was the weakest-tested thing in the project: the heuristic was only ever
checked against hand-written block sequences, because no flattened binary was
on hand. [`examples/flattened.c`](examples/flattened.c) fixes that. It is
control-flow flattening written by hand in the shape OLLVM's `-fla` pass
emits — every original basic block becomes a case of one switch, and a single
dispatcher is re-entered between every pair of them — with an opaque predicate
guarding a block that never runs. It is not output from OLLVM itself, which is
stated plainly because it matters for how much the result proves; the
structural property Veridiff has to cope with is identical either way.

`find_divergence_regions`' old rule was "the first address both traces share,
within the lookahead window, is where they resynced." Flattening breaks that
rule completely: the dispatcher shows up in both windows almost immediately
after *any* divergence, without the paths having merged. Since v0.2.0 a
candidate has to *hold up* — at least three consecutive blocks must keep
agreeing after it. Here is what that produces on the real thing, traced on
the phone, three independent conditionals in the source:

```
trace GOOD ('VALID-KEY-123',1): 37 blocks, returned 7
trace BAD  ('WRONG-KEY',0):     37 blocks, returned -7
GOOD most-repeated blocks: [('0x7b8', 9), ('0x7d0', 9), ('0x93c', 8)]
BAD  most-repeated blocks: [('0x7b8', 9), ('0x7d0', 9), ('0x93c', 8)]

region 0: last_common=0x7d0 branch_a=0x81c branch_b=0x834 resync_block=0x93c
region 1: last_common=0x7d0 branch_a=0x86c branch_b=0x884 resync_block=0x93c
region 2: last_common=0x7d0 branch_a=0x8b8 branch_b=0x8d0 resync_block=0x93c
```

Three regions for three conditionals, each one resyncing at the loop
back-edge, with the dispatcher at `0x7d0` visited nine times in both traces —
that repetition is the flattening, and it is exactly what a naive first-match
rule would have tripped over. Change only the third condition and you get one
region; pass identical arguments and you get none at all. Both engines
produce these numbers identically.

### What branchless code does to the answer

Now the part a tool like this has to be honest about. The last common block
is the dispatcher, so disassembling it does **not** show you a comparison:

```
0x7d0  ldr x11, [sp, #8]          <- load the state variable
0x7d4  nop
0x7d8  adr x10, #0x...528         <- jump table
0x7dc  adr x8, #0x...7dc
0x7e0  ldrsw x9, [x10, x11, lsl #2]
0x7e4  add x8, x8, x9
0x7e8  br x8                      <- unconditional, correctly NOT marked
```

The real comparison ran two blocks earlier, in a block **both** runs
executed, and it never branched at all:

```
0x7fc  ldr x8, [sp, #0x20]
0x800  ldrb w10, [x8]             <- key[0]
0x804  mov w9, #3                 <- state 3 (score -= 1)
0x808  mov w8, #2                 <- state 2 (score += 1)
0x80c  subs w10, w10, #0x56       <- compare with 'V'
0x810  csel w8, w8, w9, eq        <- branchless: picks the state as DATA
0x814  str w8, [sp, #0x18]
0x818  b #0x...93c                <- back to the dispatcher
```

So on this target the decision is a value, not a branch, and control flow
forks later, at the dispatcher. Veridiff reports that fork precisely — which
is its actual promise — and the two blocks it hands you are immediately
legible: run A went to `add w8, w8, #1`, run B to `subs w8, w8, #1`, which is
`score += 1` versus `score -= 1` in the source. The `<-- decides here` marker,
however, does not fire on a flattened dispatcher, and chasing the comparison
means walking back through the shared prefix the engine already gave you
(about twenty lines against the public API).

This is not theoretical, and it is not an ARM64 quirk either — it is a
codegen question. The same `examples/flattened.c` built for x86-64 with `gcc
-O0` keeps the comparison as a real branch, so there the deciding block does
end in `cmp al, 0x56` / `jne` with the marker on it, and the branchier code
yields six regions instead of three. Same source, same engine, two different
shapes of answer. Know which one you are looking at.

The synthetic unit tests that came first are still in both suites
(`dispatcher_style_coincidental_match_is_rejected` and its paired acceptance
test), because they pin the exact boundary the live target only exercises
incidentally:

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

## Scale

The claim at the top of this file is "millions of basic blocks in, one address
out." Until v0.4.0 that was never measured, and when it finally was, it turned
out to be false for a reason that had nothing to do with the diff: Frida's
Stalker queue defaults to 16384 events and **drops the rest silently**, so
every long trace came back short and successful. See **Field notes** for the
measurements. With the queue sized properly — which the engine now does by
default — here is [`examples/volume.c`](examples/volume.c) on the phone:

```
    iters     blocks     events   capacity   saturated      s      blocks/s
     1000       7505       7527    2097152       False   0.03       267529
    10000      75023      75045    2097152       False   0.14       546701
    50000     375103     375125    2097152       False   0.49       762960
   200000    1500403    1500425    2097152       False   1.81       829526
```

1.5 million basic blocks off a phone over USB in under two seconds, scaling
linearly, with no events lost. Diffing two traces of that size costs
milliseconds, because the diff is a prefix scan rather than an edit-distance
algorithm:

```
750203 vs 750213 blocks
find_first_divergence:   25.7 ms -> index 750202
find_divergence_regions: 61.2 ms -> 1 region
```

And when the queue *is* too small, that is now visible rather than silent:

```
capacity=16384 -> events=16384  blocks=16364  saturated=True
```

The Rust engine produces the same numbers (1.30 s for the 1.5M-block trace
against Python's 1.81 s, which is the only number in this README where the two
engines differ by design rather than by accident).

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

Through v0.3.0 the live evidence behind that claim was one instruction:
`jne` on x86 and `b.ne` on ARM64. Everything else was a unit test feeding
the classifier strings, which proves the string matching and nothing about
what compilers actually emit. [`examples/branches.c`](examples/branches.c)
closes that: a function shaped to force real branches of every kind — a null
test, single-bit tests, signed and unsigned compares, and a switch. Every
arm calls a `noinline` helper, because an earlier version of that file
without the calls compiled on ARM64 at `-O1` into one `cbz` and a wall of
branchless `csel`, which is its own lesson about this architecture.

Traced on the device, then disassembled and checked instruction by
instruction against what ARM64 actually calls conditional:

```
b      x2   engine=[False] expected=False  OK
b.ge   x1   engine=[True]  expected=True   OK
b.le   x1   engine=[True]  expected=True   OK
b.ls   x1   engine=[True]  expected=True   OK
b.lt   x1   engine=[True]  expected=True   OK
b.ne   x1   engine=[True]  expected=True   OK
bl     x8   engine=[False] expected=False  OK
cbz    x1   engine=[True]  expected=True   OK
ret    x2   engine=[False] expected=False  OK
tbnz   x1   engine=[True]  expected=True   OK
tbz    x2   engine=[True]  expected=True   OK
```

Eight conditional forms live-verified on ARM64 — `b.ge`, `b.le`, `b.ls`,
`b.lt`, `b.ne`, `cbz`, `tbnz`, `tbz` — plus the indirect `br` from the
flattened dispatcher above, correctly left unmarked. On x86-64 the same
target gives `ja`, `je`, `jg`, `jl`, `jne` flagged and `jmp`, `call`, `ret`
not. **`cbnz` is the one form still unproven live:** no build produced it
(clang preferred `cbz` with inverted logic), so it remains covered by unit
test only. Said rather than quietly counted as verified.

The underlying disassembly is still Frida's own multi-arch Capstone
integration, unmodified by any of this — what changed is evidence, not
mechanism.

---

## Field notes (landmines we already stepped on)

Reverse engineering tools should tell you where the bodies are
buried. These cost real debugging time to find; they're documented
inline in both agents, and repeated here because they're the kind of
thing you only learn by actually tracing a real process instead of
trusting synthetic test data.

- **Frida's Stalker drops events once its queue is full, silently, and the
  default queue holds 16384 of them.** This was the worst thing in the
  project when v0.4.0 went looking for it, because the failure mode is a
  trace that is short, wrong, and reports success. The traced call runs
  synchronously on the thread being followed, so the queue cannot drain while
  it runs: the *whole* trace has to fit. Measured against
  [`examples/volume.c`](examples/volume.c) on ARM64, at a default capacity:

  ```
   iters   capacity   events   expected
   10000      16384    16384      75050   -> 78% of the trace lost
   50000      16384    16384     375250   -> 96% lost
  ```

  The ceiling is exactly the capacity, to the event — 32768 gives 32768,
  65536 gives 65536 — which is what makes the fix detectable rather than a
  guess. `Stalker.queueDrainInterval` makes no difference at all (250 ms, 1 ms
  and 0 behaved identically) for the same synchronous-call reason, so the
  engine deliberately does not expose it. What it does expose is the capacity
  (`stalker_queue_capacity`, defaulting to 2²¹ events rather than Frida's
  16384) and `Trace.queue_saturated`, which is true exactly when the event
  count reached the capacity. **If that flag is true, a divergence you found
  is still real, but "no divergence" means nothing and neither does anything
  near the end of the trace.** Capacity is close to free until it is used: the
  buffer grows with events actually recorded, measured at ~32 bytes each on a
  64-bit target (150065 events cost 4.8 MB of target RSS, and the same trace
  cost the same 4.8 MB whether the capacity was 2¹⁸ or 2²⁴).

- **A root module running its own `frida-server` will quietly answer instead
  of yours, and may refuse to spawn anything.** On the Android device used
  here, `frida.get_usb_device()` connected fine and enumerated 363 processes,
  then `spawn()` of a plain executable failed with
  `frida.NotSupportedError: only able to spawn apps`. The server answering was
  not the one started moments earlier: MagiskFrida runs `frida-server` under a
  randomised process name, so it survives `pkill -f frida-server`, is invisible
  to `ps | grep frida`, and wins the USB lookup. Killing "the" server and
  watching the host stay connected is how that gets diagnosed. The fix is to
  stop guessing which server you are talking to: start your own on an explicit
  port and address it directly.

  ```bash
  adb forward tcp:27500 tcp:27500
  adb shell 'su -c "nohup /data/local/tmp/frida-server -l 0.0.0.0:27500 &"'
  # host side: add_remote_device("127.0.0.1:27500") / get_remote_device(...)
  ```

  Nothing in the engine needed to change for this — both halves take whatever
  Frida device you hand them — but it cost real time to work out, and it will
  bite anyone testing on a daily-driver phone with root tooling installed.

- **Warm-up mode does nothing on Android, and that is correct.** The PLT/GOT
  lazy-binding confound that **Warm-up mode** above documents is a glibc
  behaviour. Measured on the device: two identical calls diverge at
  `strcmp@plt` on x86-64 without warm-up, and on Android they do not diverge
  either way, because bionic resolves these eagerly rather than on first call.
  Leaving `warm_up` on costs an extra untraced call and buys nothing there.

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

- **Creating several remote devices in sequence inside one Rust process
  crashed it, intermittently.** Seen while running the ARM64 parity checks:
  a harness that obtained a fresh `get_remote_device()` per test, spawned,
  attached, traced, and dropped everything, segfaulted partway through one run
  in three. Every individual test passed in isolation, and a loop doing
  device + spawn + attach + handler + trace five times over never crashed, so
  this is a race in teardown rather than something reproducible on demand —
  reported at that confidence and no higher, with no claim about which layer
  owns it. The engine is not implicated: every result it produced in the runs
  that completed matched the Python engine field for field. If you drive this
  from Rust over a remote device, obtain the device once and reuse it rather
  than rebuilding the connection per target.

- **`resync_confirmed` confirmed a resync against *itself*, twice over.**
  Condensed, because `CHANGELOG.md` has the full autopsy and the tests now
  pin both halves: the comparison window started *at* the candidate, whose
  first element matches by construction, so a resync could be accepted on
  zero evidence (v0.2.1). The fix special-cased only "zero blocks left",
  while the window still silently shrank below `MIN_CONFIRM` whenever either
  trace had one or two blocks left — the same bug one block further along
  (v0.4.0's predecessor, v0.3.0). Both were found by re-reading the code
  against the docstring stating what it was supposed to guarantee, not by any
  test. The rule now states intent rather than enumerating cases: a short
  confirmation window is acceptable only when it is short *because both traces
  ran out together*, and then every remaining block must match. Worth
  repeating as a general lesson — a fix that enumerates the cases you thought
  of will miss the one you didn't.

- **Warm-up mode's untraced pre-call used to share one argument buffer with
  the traced call.** For a `'string'` argument that meant a target which
  decodes its argument in place — routine in obfuscated checks — would have
  the warm-up call mutate the buffer the traced call then read. Fixed in
  v0.2.1 by giving the warm-up call its own allocation; still not
  live-verified against a self-mutating target, since none was built.

- **Tracing a re-entrant (recursive) target used to produce a false
  divergence between two *identical* calls.** Two mechanisms, one root
  cause, both found by tracing a recursive function rather than by any
  test:

  1. `Interceptor.attach`'s `onLeave` fires **innermost-first**. Stopping
     Stalker there cut tracing off while the outer frames were still
     running, so the trace lost every outer frame's unwind block.
  2. `Stalker.unfollow()` does **not** stop instrumented execution
     instantly. Those outer frames kept running already-generated
     instrumented code and kept emitting block events — delivered *after*
     `traceCall` had returned, i.e. into the **next** call's message stream,
     where the host prepended them to an unrelated trace.

  Measured on [`examples/depth.c`](examples/depth.c) — six lines, recursion
  and nothing else — calling `depth(2)` twice with the same argument: 9
  blocks, then 11 blocks, `find_first_divergence` reporting a divergence at
  **index 0**. For a tool whose entire promise is "the traces differ here",
  silently inventing a difference between two identical runs is as bad as it
  gets. Fixed by tracking call depth in the agent — follow on the outermost entry
  only, stop on the outermost return only — and by stamping every message
  with the id of the `traceCall` that produced it, so late events are
  discarded by construction instead of being absorbed by whoever is
  listening next. After the fix, both engines return byte-identical
  11-block traces for `depth(2)` and `None` for the diff, and the full
  sequence matches the expected one derived by hand from `objdump`, unwind
  blocks included.

- **A function another thread is calling concurrently used to hang
  `trace_call` forever.** `Interceptor` hooks are process-wide, not
  per-thread: another thread entering the target ran `Stalker.follow()` for
  *our* thread id from *its* callback, and its `onLeave` stopped stalking in
  the middle of the call actually being measured. Reproduced with
  [`examples/mt.c`](examples/mt.c), whose background thread calls the traced
  function in a loop: the very first `trace_call` never returned, and was
  killed at 75 seconds. Fixed by gating both callbacks on
  `this.threadId !== tid`; the same target now returns three identical
  9-block traces. Honest limit: the fix is verified by the symptom
  disappearing, and the precise mechanism of the *hang* — as opposed to the
  obvious trace corruption — was never established.

- **`close()` hangs if the spawned process was never resumed.** Observed
  twice out of two attempts while building the recursion test above:
  `script.unload()`/`session.detach()` on a process still suspended at its
  post-spawn stop point never returns, while `resume()` then `close()`
  always worked. Not investigated further and **not fixed in v0.3.0** —
  documented because it costs real debugging time to rediscover. Both demos
  call `resume()` before exiting, so neither shows the problem; if you write
  your own harness that only ever traces a suspended target, resume it
  before closing anyway.

- **Live ARM64 testing took two attempts across v0.2.2 and v0.2.3, and the
  two failures on the way are as worth documenting as the eventual
  success.** Against a rooted POCO F7 Ultra, Android 16, `arm64-v8a`:

  1. **Frida cannot inject into a statically-linked ELF binary on this
     device.** The first, obvious move — cross-compile the test target
     statically, no NDK required, no runtime dependencies to push — failed
     identically for both `spawn()` and `attach()`:
     `frida.NotSupportedError: bootstrapper crashed with signal 11`.
     Attach crashing the same way as spawn rules out spawn-gating
     specifically — the real cause is almost certainly that Frida's
     injection depends on the target having a dynamic linker to `dlopen()`
     the agent into, which a fully static binary never touches at all.
     Not a Veridiff bug; a property of Frida's injection mechanism. Fixed
     by building with the Android NDK instead (`aarch64-linux-android26-clang`,
     no `-static`) — a normal PIE executable, dynamically linked against
     `/system/bin/linker64`, and injection just worked. `examples/licensecheck.c`
     itself needed zero changes; only the compiler did.
  2. **`Interceptor.attach` on a function inside hardened Bionic `libc.so`**
     (tried: `strcmp`) **crashed the target process** — reproducibly,
     twice, in the direct-libc-hook attempt that preceded the NDK build
     above. The same hook mechanism on a function inside a normal app's
     own bundled native library (tried: Chrome Beta's `base.odex`)
     installed and survived cleanly, which is why the eventual successful
     run traces the *test binary's own* `check_license`, not a system
     library function reached through it. Likely cause: ARM64
     control-flow hardening (PAC/BTI/CFI) on `libc.so` on a current
     Android build conflicting with inline hooking — a reasonable
     hypothesis given the evidence, held to a lower confidence bar than
     the static-binary finding above, which is confirmed. Not re-tested
     since working around it, so this remains a live landmine for anyone
     hooking system libraries specifically, not just a historical note.

  What finally worked, once the target was a proper NDK build: `spawn()`
  directly (no sleep-and-attach workaround needed for a normal
  dynamically-linked binary — that workaround was only ever needed while
  chasing the static-binary and hardened-libc dead ends above), then the
  same `trace_call`/`find_first_divergence`/`disassemble_block` sequence
  as any other target, module-base resolved once up front since Android
  requires PIE. The engine's own device-selection design needed zero
  changes to point at the phone through any of this — Python's
  `VeridiffEngine(device=...)` already took an arbitrary device, and
  Rust's engine not owning a `Device` meant the caller just used
  `DeviceType::USB` instead of local. Every real obstacle was in the
  target binary and Frida's injection layer, never in this engine.

  The full recipe, so you don't have to rediscover it:

  ```bash
  # device side: frida-server's version must line up with your host frida.
  # Bind it to an explicit port and address it directly -- a root module may
  # be running its own frida-server that would otherwise answer instead
  # (see the field note above).
  adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
  adb shell chmod 755 /data/local/tmp/frida-server
  adb forward tcp:27500 tcp:27500
  adb shell 'su -c "nohup /data/local/tmp/frida-server -l 0.0.0.0:27500 &"'

  # host side: build the SAME examples/licensecheck.c, dynamically linked
  $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang \
      -O0 -fno-inline -o licensecheck-arm64 examples/licensecheck.c
  adb push licensecheck-arm64 /data/local/tmp/licensecheck-arm64
  adb shell chmod 755 /data/local/tmp/licensecheck-arm64
  llvm-nm licensecheck-arm64 | grep check_license   # the offset, e.g. 0x798
  ```

  Then `add_remote_device("127.0.0.1:27500")` (Python) /
  `get_remote_device(...)` (Rust), `spawn()` the pushed binary, and resolve the
  module's runtime base once before computing `base + offset` — Android
  requires PIE, so the load address differs every run, exactly like any other
  ASLR target. All six targets in [`examples/`](examples/) are driven exactly
  this way.

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
  (branch-type detection, and whatever comes after it) doesn't yet. x86-64
  and ARM64 are both live-verified across the whole feature set as of v0.4.0
  (see **Proof, Not Promises**); ARM32/Thumb, MIPS, and RISC-V remain
  untried.
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
