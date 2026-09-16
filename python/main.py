#!/usr/bin/env python3
# Copyright 2026 Veridiff
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Veridiff -- Dynamic Branch Divergence Finder (Python engine).

Traces two invocations of the same native function under Frida's Stalker
and finds the exact basic block at which their control flow first splits
-- the block-diffing equivalent of "which CMP/Jcc took the license check
down a different path this time."

Everything the caller needs is on ``VeridiffEngine``: it is a plain,
importable class with no CLI/GUI framework attached. The ``__main__``
block at the bottom is a runnable usage example, not the product.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

try:
    import frida  # type: ignore
except ImportError:  # frida is only needed for live tracing, not for the
    frida = None     # pure diff algorithms below -- keep those importable.


# --------------------------------------------------------------------------
# Frida agent (JavaScript, injected into the target process).
#
# Exposes two RPCs:
#   traceCall(targetHex, args, retType, moduleName)
#     Calls the target function once with the given arguments and streams a
#     block-level execution trace back to the host while it runs.
#   disassembleRange(startHex, endHex)
#     Disassembles [start, end) and returns structured instructions.
#
# Block events are forwarded as the RAW ArrayBuffer Stalker hands to
# onReceive -- no Stalker.parse(), no JS-side array building -- because at
# millions of blocks, building JS objects and JSON-encoding them is the
# actual bottleneck, not the IPC itself. The host decodes the fixed-stride
# GumEvent records directly (see frida-gum's gumevent.h): this trades a
# pinned internal-ABI assumption (verified against Frida 17.16.4; re-check
# gumevent.h if you're targeting a release far from that) for an order of
# magnitude faster transfer than Stalker.parse() + JSON. Each record is
# `4 * Process.pointerSize` bytes: a 4-byte type tag, then the block's
# `start`/`end` pointers at offsets `pointerSize` and `2 * pointerSize`.
# GUM_BLOCK is bit 3 (value 8).
# --------------------------------------------------------------------------
_AGENT_SOURCE = r"""
'use strict';

function allocArg(spec) {
    if (spec.type === 'string') return Memory.allocUtf8String(spec.value);
    if (spec.type === 'pointer') return ptr(spec.value);
    return spec.value;
}

function nativeArgType(spec) {
    return spec.type === 'string' ? 'pointer' : spec.type;
}

rpc.exports = {
    traceCall(targetHex, args, retType, moduleName) {
        const target = ptr(targetHex);
        const mod = moduleName
            ? Process.getModuleByName(moduleName)
            : Process.findModuleByAddress(target);
        if (mod === null) {
            throw new Error('no module contains address ' + targetHex + '; pass moduleName explicitly');
        }

        send({
            type: 'meta',
            pointerSize: Process.pointerSize,
            moduleName: mod.name,
            moduleBase: mod.base.toString(),
            moduleSize: mod.size,
        });

        const fn = new NativeFunction(target, retType, args.map(nativeArgType));
        const nativeArgs = args.map(allocArg);
        const tid = Process.getCurrentThreadId();

        let blockCount = 0;
        let stalkerCleanedUp = false;
        const stopStalking = () => {
            if (stalkerCleanedUp) return; // onLeave and the finally block both call this
            stalkerCleanedUp = true;
            Stalker.flush();
            Stalker.unfollow(tid);
            Stalker.garbageCollect();
        };

        // Stalker.follow() only actually engages when called from genuine
        // native execution context -- e.g. an Interceptor trampoline that's
        // already running as instrumented code. Calling it directly from
        // this plain synchronous rpc.exports handler and then invoking
        // NativeFunction produces zero events, silently (verified
        // empirically: Interceptor.attach's onEnter/onLeave fires fine,
        // Stalker just never engages unless bracketed this way). So a
        // throwaway Interceptor hook on the target itself is used purely to
        // get Stalker engaged for the one call we're about to make.
        const listener = Interceptor.attach(target, {
            onEnter() {
                Stalker.follow(tid, {
                    events: { block: true },
                    onReceive(buffer) {
                        blockCount += buffer.byteLength / (4 * Process.pointerSize);
                        send({ type: 'chunk' }, buffer);
                    },
                });
            },
            onLeave() {
                stopStalking();
            },
        });

        try {
            const returnValue = fn(...nativeArgs);
            send({
                type: 'done',
                blockCount,
                returnValue: retType === 'void' ? null : returnValue.toString(),
            });
            return { blockCount };
        } finally {
            // onLeave won't have run if the call threw before returning
            // normally (e.g. Frida turning a native crash into a JS
            // exception) -- stopStalking() is idempotent, so this is the
            // fallback for that case and a no-op otherwise.
            listener.detach();
            stopStalking();
        }
    },

    disassembleRange(startHex, endHex) {
        const end = ptr(endHex);
        const out = [];
        let cursor = ptr(startHex);
        while (cursor.compare(end) < 0) {
            const insn = Instruction.parse(cursor);
            const bytes = cursor.readByteArray(insn.size);
            out.push({
                address: insn.address.toString(),
                mnemonic: insn.mnemonic,
                opStr: insn.opStr,
                size: insn.size,
                bytes: bytes === null
                    ? ''
                    : Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, '0')).join(''),
            });
            cursor = insn.next;
        }
        return out;
    },
};
"""


# --------------------------------------------------------------------------
# Raw GumEvent decoding.
# --------------------------------------------------------------------------
_GUM_BLOCK = 1 << 3
_TAG_STRUCT = struct.Struct("<I")


def _iter_block_events(buf: bytes, pointer_size: int) -> Iterator[Tuple[int, int]]:
    """Yield (start, end) for each GUM_BLOCK record in a raw onReceive buffer.

    See the module-level comment on ``_AGENT_SOURCE`` for the layout this
    assumes. Non-block records can't appear here in practice (the agent only
    ever enables `events.block`), but the tag is still checked defensively
    since the cost is one integer compare per record.
    """
    stride = 4 * pointer_size
    ptr_struct = struct.Struct("<Q" if pointer_size == 8 else "<I")
    start_off = pointer_size
    end_off = 2 * pointer_size
    limit = len(buf) - stride + 1
    for base in range(0, limit, stride):
        if _TAG_STRUCT.unpack_from(buf, base)[0] != _GUM_BLOCK:
            continue
        start = ptr_struct.unpack_from(buf, base + start_off)[0]
        end = ptr_struct.unpack_from(buf, base + end_off)[0]
        yield start, end


# --------------------------------------------------------------------------
# Public data model.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Arg:
    """One argument to pass into the traced call.

    kind: 'int' | 'uint' | 'int64' | 'uint64' | 'pointer' | 'string'
    'string' is allocated in the target process as a UTF-8 C string and
    passed by pointer; every other kind is passed through to Frida's
    NativeFunction as-is.
    """

    kind: str
    value: Any

    def to_payload(self) -> Dict[str, Any]:
        # Pointer-sized values go over the wire as hex strings, same as
        # every address elsewhere in this file: a JSON number silently loses
        # precision above 2**53, which a 64-bit pointer routinely exceeds.
        value = hex(self.value) if self.kind == "pointer" else self.value
        return {"type": self.kind, "value": value}


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    size: int
    raw_bytes: bytes


@dataclass
class Trace:
    """A single call's dynamic execution path, module-relative.

    ``blocks`` is the ordered sequence of basic-block start offsets (from
    ``module_base``) as actually executed -- loops repeat their block's
    offset once per iteration, this is not a deduplicated block set.
    ``block_ends`` maps every distinct start offset seen to its block's end
    offset, for later disassembly.

    Blocks outside [module_base, module_base + module_size) are dropped at
    capture time (libc, the dynamic linker, JIT stubs, ...). That filter is
    a pure function of address and the module's fixed bounds -- never of
    anything that varies between run A and run B -- so it cannot itself be a
    source of spurious divergence between two traces of the same module.
    """

    blocks: List[int]
    block_ends: Dict[int, int]
    module_name: str
    module_base: int
    module_size: int
    return_value: Optional[str]


@dataclass(frozen=True)
class DivergencePoint:
    """Where two traces' control flow first differs."""

    index: int
    last_common_block: Optional[int]
    block_a: Optional[int]  # None if trace A ended exactly at `index`
    block_b: Optional[int]  # None if trace B ended exactly at `index`


@dataclass(frozen=True)
class DivergenceRegion:
    """One split-then-possibly-rejoin episode, as found by the resync scan."""

    common_index: int
    last_common_block: Optional[int]
    branch_a: int
    branch_b: int
    resync_index_a: Optional[int]
    resync_index_b: Optional[int]
    resync_block: Optional[int]


# --------------------------------------------------------------------------
# The engine.
# --------------------------------------------------------------------------
class VeridiffEngine:
    """Traces native function calls and diffs their execution paths.

    Two independent halves live on this one class:
      * Live tracing (spawn/attach/trace_call/disassemble_block) -- needs
        Frida and a real target.
      * Pure trace diffing (find_first_divergence/find_divergence_regions,
        both @staticmethod) -- plain Python, works on any two `Trace`
        objects regardless of where they came from.
    """

    def __init__(self, device: "Optional[frida.core.Device]" = None):
        if frida is None:
            raise RuntimeError(
                "VeridiffEngine needs the 'frida' package for live tracing "
                "(pip install frida). The static find_first_divergence / "
                "find_divergence_regions methods work without it."
            )
        self._device = device or frida.get_local_device()
        self._session = None
        self._script = None
        self._pid: Optional[int] = None
        self._chunks: List[bytes] = []
        self._meta: Dict[str, Any] = {}
        self._done: Dict[str, Any] = {}

    # ---- process / session lifecycle ----

    def spawn(self, program: str, argv: Optional[Sequence[str]] = None) -> int:
        """Spawn `program` suspended and load the agent. Returns the pid.

        The process stays suspended until you call `resume()`. You can call
        `trace_call()` before or after resuming -- calling it before is
        simpler and race-free (nothing else is running yet) but only works
        if the target function doesn't depend on state that's normally set
        up by constructors/main() that haven't run yet.
        """
        self._pid = self._device.spawn([program, *(argv or [])])
        self._attach_and_load()
        return self._pid

    def attach(self, target: Union[int, str]) -> None:
        """Attach to an already-running process by pid or name."""
        self._pid = target  # type: ignore[assignment]
        self._attach_and_load()

    def resume(self) -> None:
        self._device.resume(self._pid)

    def close(self) -> None:
        if self._script is not None:
            try:
                self._script.unload()
            except frida.InvalidOperationError:
                pass
        if self._session is not None and not self._session.is_detached:
            self._session.detach()

    def __enter__(self) -> "VeridiffEngine":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def _attach_and_load(self) -> None:
        self._session = self._device.attach(self._pid)
        self._script = self._session.create_script(_AGENT_SOURCE)
        self._script.on("message", self._on_message)
        self._script.load()

    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]) -> None:
        if message.get("type") != "send":
            # A JS-level parse/runtime error outside of an RPC call. RPC
            # errors surface as exceptions from exports_sync instead, so
            # anything landing here is unexpected -- surface it, don't eat it.
            print(f"[veridiff-agent] {message}", file=sys.stderr)
            return
        payload = message["payload"]
        kind = payload.get("type")
        if kind == "meta":
            self._meta = payload
        elif kind == "chunk":
            self._chunks.append(data or b"")
        elif kind == "done":
            self._done = payload

    # ---- tracing ----

    def trace_call(
        self,
        address: int,
        args: Sequence[Arg],
        ret_type: str = "void",
        module: Optional[str] = None,
    ) -> Trace:
        """Call `address` once with `args` and return its execution trace.

        `ret_type` and each Arg.kind are Frida NativeFunction type strings
        ('void', 'int', 'uint', 'int64', 'uint64', 'pointer'), plus the
        engine's own 'string' kind for a `const char *` argument.
        """
        if self._script is None:
            raise RuntimeError("call spawn() or attach() before trace_call()")

        self._chunks = []
        self._meta = {}
        self._done = {}

        payload_args = [a.to_payload() for a in args]
        # exports_sync blocks until the agent's traceCall() returns, which is
        # strictly after its own send('done') call (same function, sequential
        # statements) -- so every chunk/meta/done message is guaranteed to
        # have already reached _on_message by the time this call returns.
        self._script.exports_sync.trace_call(hex(address), payload_args, ret_type, module)

        if not self._meta:
            raise RuntimeError("agent produced no trace metadata (target module unresolved)")

        pointer_size: int = self._meta["pointerSize"]
        module_base = int(self._meta["moduleBase"], 16)
        module_size: int = self._meta["moduleSize"]
        module_end = module_base + module_size

        blocks: List[int] = []
        block_ends: Dict[int, int] = {}
        for chunk in self._chunks:
            for start, end in _iter_block_events(chunk, pointer_size):
                if module_base <= start < module_end:
                    rel = start - module_base
                    blocks.append(rel)
                    block_ends[rel] = end - module_base

        return Trace(
            blocks=blocks,
            block_ends=block_ends,
            module_name=self._meta["moduleName"],
            module_base=module_base,
            module_size=module_size,
            return_value=self._done.get("returnValue"),
        )

    def disassemble_block(self, trace: Trace, relative_start: int) -> List[Instruction]:
        """Disassemble one block of `trace`, by its module-relative start offset."""
        end = trace.block_ends.get(relative_start)
        if end is None:
            raise KeyError(f"block {relative_start:#x} is not present in this trace")
        start_abs = trace.module_base + relative_start
        end_abs = trace.module_base + end
        raw = self._script.exports_sync.disassemble_range(hex(start_abs), hex(end_abs))
        return [
            Instruction(
                address=int(r["address"], 16),
                mnemonic=r["mnemonic"],
                op_str=r["opStr"],
                size=r["size"],
                raw_bytes=bytes.fromhex(r["bytes"]),
            )
            for r in raw
        ]

    # ---- pure algorithmic core: no Frida, no I/O, unit-testable standalone ----

    @staticmethod
    def find_first_divergence(trace_a: Trace, trace_b: Trace) -> Optional[DivergencePoint]:
        """Find the first index at which the two traces' block sequences differ.

        Note on a real confound, found while testing this against a live
        target rather than only synthetic traces: even two calls with
        *identical* arguments can report a first "divergence" at a PLT stub
        (e.g. strcmp@plt) -- the first call in the process's lifetime takes
        the lazy-binding resolver path, later calls skip straight to the
        now-resolved GOT entry, so the two traces briefly take different
        blocks for reasons that have nothing to do with your arguments.
        `find_divergence_regions` will show this as one region that
        immediately resyncs; a one-off resync right after a PLT-looking
        address is usually linker noise, not your target's own logic.

        Deliberately a longest-common-prefix scan, O(min(len(a), len(b))),
        not a Myers/LCS-style diff. LCS-family algorithms solve "what's the
        minimal edit script between these two sequences", which is the wrong
        question here: after a real branch divergence, both paths commonly
        rejoin a shared library call or a common epilogue, and a minimal-
        edit-script algorithm would happily treat that coincidental address
        match as "unchanged" and report a confusing, fragmented alignment
        instead of the one thing you actually want -- the first point the
        paths split. A prefix scan answers exactly that question, and is
        both simpler and asymptotically cheaper (LCS-family diffing is
        O(N*D) with Myers, or O(N log N) at best with hash/patience tricks;
        this is O(N) with no hashing at all).
        """
        a, b = trace_a.blocks, trace_b.blocks
        n = min(len(a), len(b))
        i = 0
        while i < n and a[i] == b[i]:
            i += 1
        if i == len(a) and i == len(b):
            return None
        return DivergencePoint(
            index=i,
            last_common_block=a[i - 1] if i > 0 else None,
            block_a=a[i] if i < len(a) else None,
            block_b=b[i] if i < len(b) else None,
        )

    @staticmethod
    def find_divergence_regions(
        trace_a: Trace,
        trace_b: Trace,
        resync_window: int = 4096,
        max_regions: int = 32,
    ) -> List[DivergenceRegion]:
        """Find multiple split/rejoin episodes -- useful when a check runs
        several independent conditionals in sequence rather than one.

        Bounded greedy re-sync: on a mismatch, look up to `resync_window`
        blocks ahead in each trace for a value they share, jump both cursors
        there, and continue. This is a heuristic, not a minimal alignment
        (see `find_first_divergence` for why minimal alignment is the wrong
        goal here in the first place) -- it is O(N + regions * resync_window)
        and intentionally gives up on a region it can't resync within the
        window rather than searching unboundedly.
        """
        a, b = trace_a.blocks, trace_b.blocks
        i = j = 0
        regions: List[DivergenceRegion] = []
        while len(regions) < max_regions:
            while i < len(a) and j < len(b) and a[i] == b[j]:
                i += 1
                j += 1
            if i >= len(a) or j >= len(b):
                break

            window_b: Dict[int, int] = {}
            for k in range(j, min(j + resync_window, len(b))):
                window_b.setdefault(b[k], k)

            resync_a: Optional[int] = None
            resync_b: Optional[int] = None
            resync_val: Optional[int] = None
            for p in range(i, min(i + resync_window, len(a))):
                k = window_b.get(a[p])
                if k is not None:
                    resync_a, resync_b, resync_val = p, k, a[p]
                    break

            regions.append(
                DivergenceRegion(
                    common_index=i - 1,
                    last_common_block=a[i - 1] if i > 0 else None,
                    branch_a=a[i],
                    branch_b=b[j],
                    resync_index_a=resync_a,
                    resync_index_b=resync_b,
                    resync_block=resync_val,
                )
            )
            if resync_a is None:
                break
            i, j = resync_a, resync_b
        return regions


# --------------------------------------------------------------------------
# Minimal usage example -- not the product, just wiring.
# --------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(
            f"usage: {sys.argv[0]} <executable> <hex-address-of-target-fn> <arg-a> <arg-b>\n\n"
            "Spawns <executable> suspended, calls the function at the given "
            "address twice -- once with each string argument -- and reports "
            "the first basic block where the two runs' control flow diverged.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    program, hex_addr, arg_a, arg_b = sys.argv[1:]
    target_address = int(hex_addr, 16)

    with VeridiffEngine() as engine:
        engine.spawn(program)

        trace_a = engine.trace_call(target_address, [Arg("string", arg_a)], ret_type="int")
        trace_b = engine.trace_call(target_address, [Arg("string", arg_b)], ret_type="int")
        engine.resume()

        print(f"trace A ({arg_a!r}): {len(trace_a.blocks)} blocks, returned {trace_a.return_value}")
        print(f"trace B ({arg_b!r}): {len(trace_b.blocks)} blocks, returned {trace_b.return_value}")

        divergence = VeridiffEngine.find_first_divergence(trace_a, trace_b)
        if divergence is None:
            print("no divergence: both runs executed identical control flow")
            raise SystemExit(0)

        fmt = lambda v: hex(v) if v is not None else "(trace ended here)"
        print(f"\nfirst divergence at trace index {divergence.index}")
        print(f"  last common block : {fmt(divergence.last_common_block)}")
        print(f"  run A took block  : {fmt(divergence.block_a)}")
        print(f"  run B took block  : {fmt(divergence.block_b)}")

        if divergence.last_common_block is not None:
            print("\n  disassembly of the deciding block:")
            for insn in engine.disassemble_block(trace_a, divergence.last_common_block):
                print(f"    {insn.address:#x}  {insn.mnemonic} {insn.op_str}")
