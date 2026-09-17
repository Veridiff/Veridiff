// Copyright 2026 Veridiff
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Veridiff -- Dynamic Branch Divergence Finder (Rust engine).
//!
//! Traces two invocations of the same native function under Frida's
//! Stalker and finds the exact basic block at which their control flow
//! first splits.
//!
//! `VeridiffEngine` deliberately does not own a Frida `Device`/`Session`/
//! `Script`: the `frida` crate's own types (`Device<'a>`, `Session<'a>`,
//! `Script<'a>`) are already the right tool for process/session lifecycle,
//! and bundling them into this struct would either force it to carry their
//! lifetime parameters everywhere or fight the borrow checker for no real
//! benefit. Instead the engine holds only its own message channel and takes
//! `&mut Script` as a parameter on the calls that need one -- the caller
//! (an RE tool, a bot, anything) keeps owning its Frida session exactly as
//! it already does, and just hands this engine a script to drive.

use frida::{Message, Script, ScriptHandler};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

// --------------------------------------------------------------------------
// Frida agent (JavaScript, injected into the target process).
//
// Identical to the agent embedded in the Python engine -- see that file's
// comment for the full rationale. Summary: block events are forwarded as
// the RAW ArrayBuffer Stalker hands to onReceive (no Stalker.parse(), no
// JS-side array building), because at millions of blocks, building JS
// objects and JSON-encoding them is the actual bottleneck, not the IPC.
// The host decodes the fixed-stride GumEvent records itself (see
// frida-gum's gumevent.h; verified against Frida 17.16.4). Each record is
// `4 * Process.pointerSize` bytes: a 4-byte type tag, then the block's
// `start`/`end` pointers at offsets `pointerSize` and `2 * pointerSize`.
// GUM_BLOCK is bit 3 (value 8).
// --------------------------------------------------------------------------
pub const AGENT_SOURCE: &str = r#"
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
    traceCall(targetHex, args, retType, moduleName, warmUp) {
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

        // Optional pre-execution pass: calls the target once, untraced,
        // before the real (traced) call below. Exists because of a real,
        // reproducible confound: a target's first-ever call to an
        // externally-linked function (strcmp@plt, anything else routed
        // through the PLT/GOT) takes the dynamic linker's lazy-binding
        // resolver path, while every later call to that same external
        // function skips straight to the now-resolved GOT entry -- a
        // one-time difference in block-level control flow that has nothing
        // to do with your arguments. Warming up with a fresh, untraced call
        // using these SAME arguments resolves whatever GOT entries this
        // exact code path touches before the traced call below runs, so the
        // trace actually recorded isn't the one paying the resolver tax.
        //
        // Uses its OWN allocArg() pass -- args.map(allocArg) again, not the
        // nativeArgs built below -- deliberately, not redundantly. Found by
        // an independent review pass: a 'string' arg is a pointer to one
        // Memory.allocUtf8String buffer; reusing that same allocation for
        // both calls means a target that decodes/transforms its argument
        // in place (routine for the obfuscated checks this tool targets)
        // would have the untraced warm-up call mutate the buffer the traced
        // call then reads -- silently tracing execution over already-
        // mutated input instead of the caller's actual argument. A 'string'
        // arg is the only kind this matters for: 'pointer' args wrap
        // caller-owned memory this agent doesn't allocate and has no
        // business duplicating, and every other kind is an immutable value,
        // not shared mutable storage.
        if (warmUp) {
            fn(...args.map(allocArg));
        }
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
"#;

// --------------------------------------------------------------------------
// Raw GumEvent decoding.
// --------------------------------------------------------------------------
const GUM_BLOCK: u32 = 1 << 3;

/// Yield `(start, end)` for each GUM_BLOCK record in a raw `onReceive` buffer.
///
/// See the `AGENT_SOURCE` doc comment for the layout this assumes.
/// Non-block records can't appear here in practice (the agent only ever
/// enables `events.block`), but the tag is still checked defensively since
/// the cost is one integer compare per record.
fn iter_block_events(buf: &[u8], pointer_size: usize) -> impl Iterator<Item = (u64, u64)> + '_ {
    let stride = 4 * pointer_size;
    let start_off = pointer_size;
    let end_off = 2 * pointer_size;
    let limit = buf.len().saturating_sub(stride.saturating_sub(1));
    (0..limit).step_by(stride).filter_map(move |base| {
        let tag = u32::from_le_bytes(buf[base..base + 4].try_into().unwrap());
        if tag != GUM_BLOCK {
            return None;
        }
        let read_ptr = |off: usize| -> u64 {
            if pointer_size == 8 {
                u64::from_le_bytes(buf[base + off..base + off + 8].try_into().unwrap())
            } else {
                u32::from_le_bytes(buf[base + off..base + off + 4].try_into().unwrap()) as u64
            }
        };
        Some((read_ptr(start_off), read_ptr(end_off)))
    })
}

// --------------------------------------------------------------------------
// Public data model.
// --------------------------------------------------------------------------

/// One argument to pass into the traced call. Pointer-sized values are
/// marshalled as hex strings (see `to_json`) rather than JSON numbers,
/// because a JSON number silently loses precision above 2**53, which a
/// 64-bit pointer routinely exceeds; plain `Int64`/`Uint64` values are sent
/// as JSON numbers and so are expected to fit a JS safe integer -- fine for
/// the realistic case (flags, small counts) but worth knowing if you're
/// passing raw 64-bit hashes as *values* rather than *pointers*.
#[derive(Debug, Clone)]
pub enum Arg {
    Int(i32),
    Uint(u32),
    Int64(i64),
    Uint64(u64),
    Pointer(u64),
    Str(String),
}

impl Arg {
    fn to_json(&self) -> Value {
        match self {
            Arg::Int(v) => json!({"type": "int", "value": v}),
            Arg::Uint(v) => json!({"type": "uint", "value": v}),
            Arg::Int64(v) => json!({"type": "int64", "value": v}),
            Arg::Uint64(v) => json!({"type": "uint64", "value": v}),
            Arg::Pointer(v) => json!({"type": "pointer", "value": format!("{v:#x}")}),
            Arg::Str(v) => json!({"type": "string", "value": v}),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub op_str: String,
    pub size: usize,
    pub raw_bytes: Vec<u8>,
}

/// ARM64 mnemonics that are conditional branches despite having no
/// dot-suffix of their own -- see `Instruction::is_conditional_branch`.
const ARM64_CONDITIONAL_MNEMONICS: [&str; 4] = ["cbz", "cbnz", "tbz", "tbnz"];

impl Instruction {
    /// Whether this instruction is a conditional branch, across x86 and
    /// ARM64.
    ///
    /// Disassembly itself needs no architecture-specific code --
    /// `Instruction::parse` (Capstone, via frida-gum) already decodes every
    /// architecture Frida attaches to. This classification does, because
    /// Capstone's own `Instruction.groups` doesn't distinguish conditional
    /// from unconditional branches: verified live against a real x86
    /// target, a `jne` and the `jmp` two instructions later in the same
    /// basic block both report `groups: ["branch_relative", "jump"]`, with
    /// nothing to tell them apart. Mnemonic text is the only signal that
    /// does, on any architecture, so that's what this checks instead of
    /// trusting `.groups`.
    ///
    /// x86: any `jCC` mnemonic (`jz`, `jne`, `jle`, ...) except the
    /// unconditional `jmp`.
    ///
    /// ARM64: `b.cond` forms (`b.eq`, `b.ne`, `b.lt`, ...; Capstone renders
    /// the condition as a dot-suffix) plus the compare/test-and-branch
    /// forms (`cbz`, `cbnz`, `tbz`, `tbnz`), inherently conditional despite
    /// having no dot-suffix of their own. Plain `b`/`bl`/`br`/`blr` are
    /// unconditional and correctly fall through to `false`.
    ///
    /// Unrecognized mnemonics (ARM32/Thumb, MIPS, anything else Capstone
    /// supports that this hasn't been taught) return `false` rather than
    /// guessing -- an unmarked instruction is a safe default; a wrongly
    /// marked one isn't.
    pub fn is_conditional_branch(&self) -> bool {
        let m = self.mnemonic.to_ascii_lowercase();
        if m.starts_with('j') && m != "jmp" {
            return true;
        }
        m.starts_with("b.") || ARM64_CONDITIONAL_MNEMONICS.contains(&m.as_str())
    }
}

/// A single call's dynamic execution path, module-relative.
///
/// `blocks` is the ordered sequence of basic-block start offsets (from
/// `module_base`) as actually executed -- loops repeat their block's offset
/// once per iteration, this is not a deduplicated block set. `block_ends`
/// maps every distinct start offset seen to its block's end offset, for
/// later disassembly.
///
/// Blocks outside `[module_base, module_base + module_size)` are dropped at
/// capture time (libc, the dynamic linker, JIT stubs, ...). That filter is
/// a pure function of address and the module's fixed bounds -- never of
/// anything that varies between run A and run B -- so it cannot itself be a
/// source of spurious divergence between two traces of the same module.
#[derive(Debug, Clone)]
pub struct Trace {
    pub blocks: Vec<u64>,
    pub block_ends: HashMap<u64, u64>,
    pub module_name: String,
    pub module_base: u64,
    pub module_size: u64,
    pub return_value: Option<String>,
}

/// Optional, non-default knobs for `trace_call`. `TraceCallOptions::default()`
/// is today's existing behavior. A plain trailing `bool` parameter was
/// deliberately not used here -- `trace_call(.., true)` doesn't self-document
/// what `true` means at the call site, and every future optional knob would
/// otherwise mean another breaking positional-parameter addition. A struct
/// absorbs both problems, and costs nothing at the one call site that sets it.
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceCallOptions {
    /// Call the target once, untraced, with the same arguments, immediately
    /// before the traced call. See `trace_call`'s doc comment for why (PLT/
    /// GOT lazy binding is a one-time, argument-independent confound this
    /// resolves ahead of the call actually being measured). Off by default:
    /// the target executes an extra time before being traced, which isn't
    /// safe for a target with side effects or other non-idempotent state.
    pub warm_up: bool,
}

/// Where two traces' control flow first differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DivergencePoint {
    pub index: usize,
    pub last_common_block: Option<u64>,
    /// `None` if trace A ended exactly at `index`.
    pub block_a: Option<u64>,
    /// `None` if trace B ended exactly at `index`.
    pub block_b: Option<u64>,
}

/// One split-then-possibly-rejoin episode, as found by the resync scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DivergenceRegion {
    pub common_index: isize,
    pub last_common_block: Option<u64>,
    pub branch_a: u64,
    pub branch_b: u64,
    pub resync_index_a: Option<usize>,
    pub resync_index_b: Option<usize>,
    pub resync_block: Option<u64>,
}

/// Errors from the live-tracing half of the engine. The pure diff functions
/// (`find_first_divergence`, `find_divergence_regions`) never return this.
///
/// `#[non_exhaustive]` since 0.2.1, added along with the `MalformedResponse`
/// variant it should have had from the start: a new variant is otherwise a
/// breaking change for any caller that matches this exhaustively, which
/// isn't a distinction a 0.x patch release should be forced to respect.
#[derive(Debug)]
#[non_exhaustive]
pub enum VeridiffError {
    /// The agent's `traceCall`/`disassembleRange` RPC threw or transport-failed.
    Rpc(frida::Error),
    /// The message channel closed, or timed out, before a `done` event arrived.
    IncompleteTrace,
    /// `disassemble_block` was asked for a block this trace never visited.
    UnknownBlock(u64),
    /// The agent's `disassembleRange` response was missing or misshaped a
    /// field. Should not happen in practice -- both ends of this protocol
    /// are this crate's own code -- but this is a `pub fn` on a library:
    /// an embedder's process should get a `Result::Err` back for a decode
    /// problem, not have this crate panic and take the caller down with it.
    MalformedResponse(String),
}

impl std::fmt::Display for VeridiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VeridiffError::Rpc(e) => write!(f, "agent RPC failed: {e}"),
            VeridiffError::IncompleteTrace => {
                write!(f, "trace collection did not complete (timed out or channel closed)")
            }
            VeridiffError::UnknownBlock(addr) => {
                write!(f, "block {addr:#x} is not present in this trace")
            }
            VeridiffError::MalformedResponse(detail) => {
                write!(f, "malformed response from agent: {detail}")
            }
        }
    }
}

impl std::error::Error for VeridiffError {}

// --------------------------------------------------------------------------
// Agent message plumbing.
// --------------------------------------------------------------------------

#[derive(Debug)]
enum AgentEvent {
    Meta {
        pointer_size: usize,
        module_name: String,
        module_base: u64,
        module_size: u64,
    },
    Chunk(Vec<u8>),
    Done {
        return_value: Option<String>,
    },
    Log(String),
}

struct RelayHandler {
    tx: Sender<AgentEvent>,
}

impl ScriptHandler for RelayHandler {
    fn on_message(&mut self, message: Message, data: Option<Vec<u8>>) {
        match message {
            Message::Send(m) => {
                let Some(kind) = m.payload.get("type").and_then(Value::as_str) else {
                    return;
                };
                let event = match kind {
                    "meta" => {
                        // This runs inside the C callback that dispatches
                        // Frida's "message" signal (see call_on_message,
                        // invoked through an `extern "C" fn` boundary) --
                        // panicking here on malformed data would unwind
                        // into that boundary and abort the whole host
                        // process, not just this call, which is far worse
                        // than the bug that triggered it. But silently
                        // defaulting a missing moduleBase to 0 would be
                        // worse in a different way: every subsequent block
                        // in this trace would get "normalized" against the
                        // wrong base and look like plausible-but-wrong
                        // data instead of visibly failing. So: validate all
                        // fields together, and on any failure, log instead
                        // of fabricating a Meta event. Downstream, absorb()
                        // never sees got_meta=true, chunks are dropped, and
                        // the trace comes back empty -- an obviously wrong
                        // result instead of a subtly wrong one.
                        let payload = &m.payload;
                        let parsed = (|| {
                            Some(AgentEvent::Meta {
                                pointer_size: payload["pointerSize"].as_u64()? as usize,
                                module_name: payload["moduleName"].as_str()?.to_string(),
                                module_base: u64::from_str_radix(
                                    payload["moduleBase"].as_str()?.trim_start_matches("0x"),
                                    16,
                                )
                                .ok()?,
                                module_size: payload["moduleSize"].as_u64()?,
                            })
                        })();
                        match parsed {
                            Some(event) => event,
                            None => AgentEvent::Log(format!(
                                "malformed 'meta' message from agent, ignoring: {payload}"
                            )),
                        }
                    }
                    "chunk" => AgentEvent::Chunk(data.unwrap_or_default()),
                    "done" => AgentEvent::Done {
                        return_value: m
                            .payload
                            .get("returnValue")
                            .and_then(Value::as_str)
                            .map(String::from),
                    },
                    _ => return,
                };
                let _ = self.tx.send(event);
            }
            Message::Log(l) => {
                let _ = self.tx.send(AgentEvent::Log(l.payload));
            }
            Message::Error(e) => {
                let _ = self.tx.send(AgentEvent::Log(format!(
                    "JS error: {} ({}:{})",
                    e.description, e.file_name, e.line_number
                )));
            }
            Message::Other(_) => {}
        }
    }
}

#[derive(Default)]
struct TraceBuilder {
    pointer_size: usize,
    module_name: String,
    module_base: u64,
    module_size: u64,
    blocks: Vec<u64>,
    block_ends: HashMap<u64, u64>,
    got_meta: bool,
}

impl TraceBuilder {
    fn absorb(&mut self, event: AgentEvent) {
        match event {
            AgentEvent::Meta { pointer_size, module_name, module_base, module_size } => {
                self.pointer_size = pointer_size;
                self.module_name = module_name;
                self.module_base = module_base;
                self.module_size = module_size;
                self.got_meta = true;
            }
            AgentEvent::Chunk(buf) => {
                if !self.got_meta {
                    return; // meta always precedes chunks; ignore stray data otherwise
                }
                let module_end = self.module_base + self.module_size;
                // Upper bound on how many block events this chunk can hold;
                // reserving it up front turns what would otherwise be
                // O(log n) incremental reallocations-and-copies across a
                // multi-million-block trace into (at most) one growth per
                // chunk. Some of these slots go unused when blocks outside
                // the target module get filtered below, which just means
                // `reserve` over-estimates slightly -- never a correctness
                // issue, only a (small, bounded) over-allocation.
                let stride = 4 * self.pointer_size;
                if let Some(max_new) = buf.len().checked_div(stride) {
                    self.blocks.reserve(max_new);
                    self.block_ends.reserve(max_new);
                }
                for (start, end) in iter_block_events(&buf, self.pointer_size) {
                    if start >= self.module_base && start < module_end {
                        let rel = start - self.module_base;
                        self.blocks.push(rel);
                        self.block_ends.insert(rel, end - self.module_base);
                    }
                }
            }
            AgentEvent::Done { .. } => {
                debug_assert!(false, "Done is consumed by trace_call's loop, not absorbed");
            }
            AgentEvent::Log(l) => eprintln!("[veridiff-agent] {l}"),
        }
    }

    fn into_trace(self, return_value: Option<String>) -> Trace {
        Trace {
            blocks: self.blocks,
            block_ends: self.block_ends,
            module_name: self.module_name,
            module_base: self.module_base,
            module_size: self.module_size,
            return_value,
        }
    }
}

const RECV_TIMEOUT: Duration = Duration::from_secs(30);

// --------------------------------------------------------------------------
// The engine.
// --------------------------------------------------------------------------

/// Traces native function calls and diffs their execution paths.
///
/// Two independent halves live on this one type:
///   * Live tracing (`new`, `trace_call`, `disassemble_block`) -- needs a
///     `&mut Script` from an already-attached Frida session.
///   * Pure trace diffing (`find_first_divergence`, `find_divergence_regions`,
///     both associated functions) -- plain Rust, works on any two `Trace`
///     values regardless of where they came from, no Frida required even to
///     compile a caller that only uses these.
pub struct VeridiffEngine {
    rx: Receiver<AgentEvent>,
}

impl VeridiffEngine {
    /// Installs this engine's message handler on `script`. Call once per
    /// script (a second call would replace the handler `frida-rust` already
    /// has installed, losing the first channel).
    pub fn new(script: &mut Script) -> Result<Self, VeridiffError> {
        let (tx, rx) = mpsc::channel();
        script
            .handle_message(RelayHandler { tx })
            .map_err(VeridiffError::Rpc)?;
        Ok(Self { rx })
    }

    /// Calls the function at `address` once with `args` and returns its
    /// execution trace. `ret_type` and each `Arg`'s kind are Frida
    /// `NativeFunction` type strings (`"void"`, `"int"`, `"uint"`,
    /// `"int64"`, `"uint64"`, `"pointer"`), plus this engine's own `Str`
    /// kind for a `const char *` argument. `module` restricts/normalizes
    /// against a specific module by name; pass `None` to auto-resolve the
    /// module containing `address`. See `TraceCallOptions` for `options.warm_up`.
    pub fn trace_call(
        &self,
        script: &mut Script,
        address: u64,
        args: &[Arg],
        ret_type: &str,
        module: Option<&str>,
        options: TraceCallOptions,
    ) -> Result<Trace, VeridiffError> {
        let args_json: Vec<Value> = args.iter().map(Arg::to_json).collect();
        let call_args = json!([
            format!("{address:#x}"),
            args_json,
            ret_type,
            module,
            options.warm_up,
        ]);

        script
            .exports
            .call("traceCall", Some(call_args))
            .map_err(VeridiffError::Rpc)?;
        // `.call()` blocks until the agent's traceCall() JS function returns,
        // which happens strictly after its own `send({type:'done'}, ...)`
        // (same function, sequential statements, single-threaded JS). Every
        // Meta/Chunk/Done event for this call is therefore already queued,
        // or arrives within microseconds -- but we still drive the read via
        // `recv_timeout` looping until we see `Done`, rather than assuming
        // the channel is already fully drained, so correctness here doesn't
        // depend on being right about frida-core's internal thread model.

        let mut builder = TraceBuilder::default();
        loop {
            match self.rx.recv_timeout(RECV_TIMEOUT) {
                Ok(AgentEvent::Done { return_value }) => return Ok(builder.into_trace(return_value)),
                Ok(event) => builder.absorb(event),
                Err(_) => return Err(VeridiffError::IncompleteTrace),
            }
        }
    }

    /// Disassembles one block of `trace`, given its module-relative start offset.
    pub fn disassemble_block(
        &self,
        script: &mut Script,
        trace: &Trace,
        relative_start: u64,
    ) -> Result<Vec<Instruction>, VeridiffError> {
        let end = *trace
            .block_ends
            .get(&relative_start)
            .ok_or(VeridiffError::UnknownBlock(relative_start))?;
        let start_abs = trace.module_base + relative_start;
        let end_abs = trace.module_base + end;

        let result = script
            .exports
            .call(
                "disassembleRange",
                Some(json!([format!("{start_abs:#x}"), format!("{end_abs:#x}")])),
            )
            .map_err(VeridiffError::Rpc)?;

        // MalformedResponse, not IncompleteTrace -- found by review.
        // IncompleteTrace's own doc comment defines it as specifically "the
        // message channel closed, or timed out, before a done event
        // arrived" (trace_call's failure mode). A disassembleRange response
        // that isn't a JSON array is a different, unrelated problem -- the
        // same "agent response doesn't have the shape we expected" case
        // MalformedResponse exists for, one call below in parse_instruction.
        // Reusing IncompleteTrace here would give a caller that pattern-
        // matches on VeridiffError to decide "is this worth retrying" the
        // wrong signal: a timeout may be transient, a malformed response
        // to a well-formed request never is.
        let items = result.as_ref().and_then(Value::as_array).ok_or_else(|| {
            VeridiffError::MalformedResponse(format!(
                "disassembleRange did not return a JSON array: {result:?}"
            ))
        })?;

        items.iter().map(parse_instruction).collect()
    }

    // ---- pure algorithmic core: no Frida, no I/O, unit-testable standalone ----

    /// Finds the first index at which the two traces' block sequences differ.
    ///
    /// Note on a real confound, found while testing this against a live
    /// target rather than only synthetic traces: even two calls with
    /// *identical* arguments can report a first "divergence" at a PLT stub
    /// (e.g. strcmp@plt) -- the first call in the process's lifetime takes
    /// the lazy-binding resolver path, later calls skip straight to the
    /// now-resolved GOT entry, so the two traces briefly take different
    /// blocks for reasons that have nothing to do with your arguments.
    /// `find_divergence_regions` will show this as one region that
    /// immediately resyncs; a one-off resync right after a PLT-looking
    /// address is usually linker noise, not your target's own logic.
    ///
    /// Deliberately a longest-common-prefix scan, O(min(len(a), len(b))),
    /// not a Myers/LCS-style diff. LCS-family algorithms solve "what's the
    /// minimal edit script between these two sequences", which is the wrong
    /// question here: after a real branch divergence, both paths commonly
    /// rejoin a shared library call or a common epilogue, and a minimal-
    /// edit-script algorithm would happily treat that coincidental address
    /// match as "unchanged" and report a confusing, fragmented alignment
    /// instead of the one thing you actually want -- the first point the
    /// paths split. A prefix scan answers exactly that question, and is both
    /// simpler and asymptotically cheaper (LCS-family diffing is O(N*D) with
    /// Myers, or O(N log N) at best with hash/patience tricks; this is O(N)
    /// with no hashing at all).
    pub fn find_first_divergence(trace_a: &Trace, trace_b: &Trace) -> Option<DivergencePoint> {
        let (a, b) = (&trace_a.blocks, &trace_b.blocks);
        let n = a.len().min(b.len());
        let mut i = 0;
        while i < n && a[i] == b[i] {
            i += 1;
        }
        if i == a.len() && i == b.len() {
            return None;
        }
        Some(DivergencePoint {
            index: i,
            last_common_block: if i > 0 { Some(a[i - 1]) } else { None },
            block_a: a.get(i).copied(),
            block_b: b.get(i).copied(),
        })
    }

    /// Finds multiple split/rejoin episodes -- useful when a check runs
    /// several independent conditionals in sequence rather than one.
    ///
    /// Bounded greedy re-sync: on a mismatch, look up to `resync_window`
    /// blocks ahead in each trace for a value they share, jump both cursors
    /// there, and continue. This is a heuristic, not a minimal alignment
    /// (see `find_first_divergence` for why minimal alignment is the wrong
    /// goal here in the first place), and it intentionally gives up on a
    /// region it can't resync within the window rather than searching
    /// unboundedly. Typical-case cost is O(N + regions * resync_window):
    /// most candidates simply aren't present in the other trace's window at
    /// all, an O(1) hashmap miss. Worst case is O(N + regions *
    /// resync_window^2): a candidate whose value recurs throughout the
    /// window (a dispatcher hit on every loop iteration, say) triggers an
    /// O(resync_window) fallback re-scan on every one of up to
    /// resync_window outer candidates before the outer search gives up on
    /// that region. Flagged by an independent review pass, not hit in
    /// practice against any real or synthetic case run through this engine
    /// so far -- accepted rather than fixed with an explicit comparison
    /// budget, since `resync_window` already bounds the pathological case
    /// to a fixed, known worst cost, and a budget mechanism would be new
    /// machinery on a hot path to shave a constant this engine hasn't
    /// needed shaved.
    ///
    /// A single shared address is not enough to accept as a resync point:
    /// OLLVM-flattened code (and, less exotically, any code with a commonly
    /// called helper) routes many logically-different paths through the
    /// *same* dispatcher or helper block, so that address will trivially
    /// show up in both windows almost immediately after nearly any
    /// divergence -- without the two paths actually having merged back into
    /// the same control flow. See `resync_confirmed` for how a candidate
    /// earns acceptance instead of just being the first thing found.
    pub fn find_divergence_regions(
        trace_a: &Trace,
        trace_b: &Trace,
        resync_window: usize,
        max_regions: usize,
    ) -> Vec<DivergenceRegion> {
        let (a, b) = (&trace_a.blocks, &trace_b.blocks);
        let (mut i, mut j) = (0usize, 0usize);
        let mut regions = Vec::new();
        // Reused across every region found in this call rather than
        // allocated fresh per region -- clear() drops entries but keeps the
        // table's backing storage, so a trace with many regions doesn't pay
        // a fresh hashmap allocation for each one.
        let mut window_b: HashMap<u64, usize> = HashMap::new();

        while regions.len() < max_regions {
            while i < a.len() && j < b.len() && a[i] == b[j] {
                i += 1;
                j += 1;
            }
            if i >= a.len() || j >= b.len() {
                break;
            }

            window_b.clear();
            let b_hi = (j + resync_window).min(b.len());
            for (k, &val) in b.iter().enumerate().take(b_hi).skip(j) {
                window_b.entry(val).or_insert(k);
            }

            let mut resync: Option<(usize, usize, u64)> = None;
            let a_hi = (i + resync_window).min(a.len());
            'search: for (p, &val) in a.iter().enumerate().take(a_hi).skip(i) {
                let Some(&first_bj) = window_b.get(&val) else {
                    continue;
                };
                if Self::resync_confirmed(a, b, p, first_bj) {
                    resync = Some((p, first_bj, val));
                    break 'search;
                }
                // `val`'s first occurrence didn't hold up -- exactly the
                // signature of shared/looped infrastructure rather than a
                // structural merge (see doc comment above). Before moving on
                // to the next candidate address, check whether `val` recurs
                // *again* later in b's window; a later occurrence can still
                // be the real merge point even though the first wasn't.
                for k in (first_bj + 1)..b_hi {
                    if b[k] == val && Self::resync_confirmed(a, b, p, k) {
                        resync = Some((p, k, val));
                        break 'search;
                    }
                }
            }

            regions.push(DivergenceRegion {
                common_index: i as isize - 1,
                last_common_block: if i > 0 { Some(a[i - 1]) } else { None },
                branch_a: a[i],
                branch_b: b[j],
                resync_index_a: resync.map(|(p, ..)| p),
                resync_index_b: resync.map(|(_, k, _)| k),
                resync_block: resync.map(|(_, _, v)| v),
            });

            match resync {
                Some((p, k, _)) => (i, j) = (p, k),
                None => break,
            }
        }
        regions
    }

    /// Minimum consecutive blocks that must agree, starting right after a
    /// candidate resync point, before that point is accepted as a real
    /// control-flow merge rather than a coincidental single-block match. A
    /// dispatcher or shared-helper hit is followed by state-dependent
    /// blocks that differ between the two traces almost every time;
    /// requiring a short run of continued agreement is what tells a real
    /// merge apart from a fly-by through shared code, without needing a
    /// separate "is this address unique" pass. Not exposed as a public knob
    /// -- 3 held up against every real and synthetic case this engine has
    /// been run against (including the live PLT-lazy-binding confound and a
    /// synthetic flattening-dispatcher case in the test suite below); treat
    /// it as an implementation detail unless a real case demands otherwise.
    const MIN_CONFIRM: usize = 3;

    /// Whether the candidate `(p, bj)` is confirmed by what comes *after*
    /// it: up to `MIN_CONFIRM` blocks strictly beyond the candidate in both
    /// traces, required to agree.
    ///
    /// Found by an independent review pass (2026-09-17), not by any test:
    /// the original version of this function compared `a[p..p+len]` against
    /// `b[bj..bj+len]` -- starting AT the candidate, not after it. Since
    /// `bj` is only ever looked up because `b[bj] == a[p]` already, that
    /// leading element is a trivial self-match by construction. Whenever
    /// one trace happened to end exactly at the candidate (`a.len()-p == 1`
    /// or `b.len()-bj == 1`), `len` collapsed to 1 and the "confirmation"
    /// compared literally nothing but that tautology -- silently defeating
    /// the entire point of MIN_CONFIRM in precisely the single-block-fly-by
    /// case it exists to reject. Concretely:
    /// `a=[0x10,0x20,0x30,0xD0]` vs `b=[0x10,0x20,0x31,0xD0,0xBB,0xBC,0xBD]`
    /// -- trace A ends right at the shared dispatcher `0xD0`, trace B has
    /// three more (never-examined, genuinely different) blocks after it --
    /// used to confirm `0xD0` as a real merge on zero real evidence.
    ///
    /// The two traces ending at exactly the same point is a different,
    /// legitimate case, not the bug above: if BOTH are exhausted right at
    /// the candidate, there is provably nothing left in either trace that
    /// could disagree -- that's exhaustive evidence, not absent evidence,
    /// and is accepted. It's specifically the *asymmetric* case -- one
    /// trace exhausted, the other still has unexamined blocks -- that must
    /// be rejected, because the continuing trace's future was simply never
    /// looked at.
    fn resync_confirmed(a: &[u64], b: &[u64], p: usize, bj: usize) -> bool {
        let a_remaining = a.len() - (p + 1);
        let b_remaining = b.len() - (bj + 1);
        if a_remaining == 0 && b_remaining == 0 {
            return true; // both traces end here together -- nothing left to disagree on
        }
        let len = Self::MIN_CONFIRM.min(a_remaining).min(b_remaining);
        len > 0 && a[p + 1..p + 1 + len] == b[bj + 1..bj + 1 + len]
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Parses one `disassembleRange` response item into an `Instruction`.
///
/// Every field here comes from this crate's own agent, over JSON -- not
/// external input -- so a missing/misshaped field means a real bug
/// somewhere in this protocol, not a hostile or malformed input to guard
/// against defensively. But `disassemble_block` is a `pub fn` on a library
/// other processes embed, and it already returns a `Result`: an `Err` costs
/// this crate nothing and lets the embedder decide what to do, where a
/// `.expect()` panic would decide for them by taking their process down.
/// Runs on the caller's own thread (after `Exports::call`'s blocking wait
/// already returned), not inside a Frida callback, so unlike
/// `RelayHandler::on_message` there's no FFI-unwind hazard either way --
/// this is purely an API-design choice, not a safety requirement.
fn parse_instruction(item: &Value) -> Result<Instruction, VeridiffError> {
    let bad = |field: &str| VeridiffError::MalformedResponse(format!("{field} missing or wrong type in {item}"));

    let address_hex = item["address"].as_str().ok_or_else(|| bad("address"))?;
    let address = u64::from_str_radix(address_hex.trim_start_matches("0x"), 16)
        .map_err(|_| VeridiffError::MalformedResponse(format!("address {address_hex:?} is not valid hex")))?;
    let mnemonic = item["mnemonic"].as_str().ok_or_else(|| bad("mnemonic"))?.to_string();
    let op_str = item["opStr"].as_str().ok_or_else(|| bad("opStr"))?.to_string();
    let size = item["size"].as_u64().ok_or_else(|| bad("size"))? as usize;
    let bytes_hex = item["bytes"].as_str().ok_or_else(|| bad("bytes"))?;

    // hex_decode() silently drops a malformed pair (odd length, non-hex
    // chars) rather than erroring -- fine for a private helper, but it
    // means a malformed `bytes` field would otherwise pass through as a
    // shorter-than-expected raw_bytes instead of the loud failure every
    // other field here gets. Checking the decoded length against `size`
    // (which the agent always sets to the true byte count) catches that
    // silently, the same "fail loud on our own protocol" standard as the
    // rest of this function -- found in the same review pass as the
    // MalformedResponse variant itself, for consistency, not because it
    // was ever observed to actually happen.
    let raw_bytes = hex_decode(bytes_hex);
    if raw_bytes.len() != size {
        return Err(VeridiffError::MalformedResponse(format!(
            "bytes field {bytes_hex:?} decoded to {} bytes, expected {size}",
            raw_bytes.len()
        )));
    }

    Ok(Instruction { address, mnemonic, op_str, size, raw_bytes })
}

// --------------------------------------------------------------------------
// Tests: pure logic only, no live Frida session required.
// --------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use frida::MessageSend;

    fn mk_trace(blocks: Vec<u64>) -> Trace {
        let mut block_ends = HashMap::new();
        for &b in &blocks {
            block_ends.insert(b, b + 4);
        }
        Trace {
            blocks,
            block_ends,
            module_name: "t".into(),
            module_base: 0,
            module_size: 0x10000,
            return_value: None,
        }
    }

    #[test]
    fn identical_traces_have_no_divergence() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0x40]);
        let b = mk_trace(vec![0x10, 0x20, 0x30, 0x40]);
        assert!(VeridiffEngine::find_first_divergence(&a, &b).is_none());
    }

    #[test]
    fn mid_trace_divergence() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0x40, 0x50]);
        let b = mk_trace(vec![0x10, 0x20, 0x99, 0x40, 0x50]);
        let d = VeridiffEngine::find_first_divergence(&a, &b).unwrap();
        assert_eq!(d.index, 2);
        assert_eq!(d.last_common_block, Some(0x20));
        assert_eq!(d.block_a, Some(0x30));
        assert_eq!(d.block_b, Some(0x99));
    }

    #[test]
    fn prefix_divergence_when_one_trace_ends_early() {
        let a = mk_trace(vec![0x10, 0x20, 0x30]);
        let b = mk_trace(vec![0x10, 0x20, 0x30, 0x40, 0x50]);
        let d = VeridiffEngine::find_first_divergence(&a, &b).unwrap();
        assert_eq!(d.index, 3);
        assert_eq!(d.block_a, None);
        assert_eq!(d.block_b, Some(0x40));
    }

    #[test]
    fn immediate_divergence_has_no_last_common_block() {
        let a = mk_trace(vec![0x11, 0x20]);
        let b = mk_trace(vec![0x22, 0x20]);
        let d = VeridiffEngine::find_first_divergence(&a, &b).unwrap();
        assert_eq!(d.index, 0);
        assert_eq!(d.last_common_block, None);
    }

    /// The whole reason this isn't a Myers/LCS diff: 0x30 reappearing in
    /// trace B right after the real split must NOT be read as "the traces
    /// realign at 0x30" -- the first divergence is what matters, full stop.
    #[test]
    fn prefix_scan_is_not_fooled_by_a_coincidental_downstream_match() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0xAA, 0xBB]);
        let b = mk_trace(vec![0x10, 0x20, 0x99, 0x30, 0xBB]);
        let d = VeridiffEngine::find_first_divergence(&a, &b).unwrap();
        assert_eq!(d.index, 2);
        assert_eq!(d.block_a, Some(0x30));
        assert_eq!(d.block_b, Some(0x99));
    }

    #[test]
    fn multi_region_resync() {
        // Four fully-shared blocks (0x40/0x50/0x55/0x58) separate the two
        // divergences -- enough runway for MIN_CONFIRM=3 to solidly confirm
        // the first resync before the second divergence hits.
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x55, 0x58, 0x60, 0x70]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0x40, 0x50, 0x55, 0x58, 0x61, 0x70]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 16, 32);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].branch_a, 0x30);
        assert_eq!(regions[0].branch_b, 0x31);
        assert_eq!(regions[0].resync_block, Some(0x40));
        assert_eq!(regions[1].branch_a, 0x60);
        assert_eq!(regions[1].resync_block, Some(0x70));
    }

    #[test]
    fn no_resync_within_window_stops_after_one_region() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0x99999]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0x88888]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 2, 32);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].resync_block, None);
    }

    /// The core claim of the v0.2.0 resync tuning: a single-block hit on a
    /// shared dispatcher/helper (0xD0 here) must NOT be accepted as a real
    /// merge when the two traces immediately diverge again afterward --
    /// exactly the shape of two paths transiting the same OLLVM-flattening
    /// dispatcher block before dispatching to genuinely different targets.
    /// The pre-v0.2.0 algorithm (first shared address wins, no
    /// confirmation) would have wrongly reported 0xD0 as the resync point.
    #[test]
    fn dispatcher_style_coincidental_match_is_rejected() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0xD0, 0xAA, 0xAB, 0xAC]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0xD0, 0xBB, 0xBC, 0xBD]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 16, 32);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].branch_a, 0x30);
        assert_eq!(regions[0].branch_b, 0x31);
        assert_eq!(
            regions[0].resync_block, None,
            "a single-block dispatcher fly-by must not be accepted as a real merge"
        );
    }

    /// Same shared block 0xD0 as above, but this time both traces genuinely
    /// continue identically afterward. Paired with the rejection test above,
    /// this confirms the algorithm discriminates on whether a shared address
    /// holds up under continued comparison, not on whether it's shared at
    /// all -- it doesn't become universally suspicious of dispatcher-shaped
    /// addresses, only of ones that turn out to be coincidental.
    #[test]
    fn dispatcher_style_match_is_accepted_when_it_actually_holds_up() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0xD0, 0xAA, 0xAB, 0xAC]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0xD0, 0xAA, 0xAB, 0xAC]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 16, 32);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].resync_block, Some(0xD0));
        assert_eq!(regions[0].resync_index_a, Some(3));
        assert_eq!(regions[0].resync_index_b, Some(3));
    }

    /// A candidate whose *first* occurrence in b's window fails to confirm
    /// must not eliminate that address outright -- a later occurrence of the
    /// same value can still be the genuine merge point (e.g. a dispatcher
    /// visited twice before the two paths actually reconverge).
    #[test]
    fn later_occurrence_of_a_repeated_value_can_still_confirm() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0xD0, 0xAA, 0xD0, 0xEE, 0xEF, 0xF0]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0xD0, 0xBB, 0xD0, 0xEE, 0xEF, 0xF0]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 16, 32);
        assert_eq!(regions.len(), 1);
        // The first 0xD0 (index 3) fails to confirm (0xAA != 0xBB follows
        // it); the second 0xD0 (index 5) does, and must be what's reported.
        assert_eq!(regions[0].resync_block, Some(0xD0));
        assert_eq!(regions[0].resync_index_a, Some(5));
        assert_eq!(regions[0].resync_index_b, Some(5));
    }

    /// Regression test for the resync_confirmed bug found in the
    /// 2026-09-17 review pass (see its doc comment for the full
    /// explanation). Trace A ends exactly at the shared dispatcher 0xD0;
    /// trace B has three further, genuinely different blocks after it that
    /// were never examined. Must NOT confirm -- before the fix, this
    /// exact shape confirmed on zero real evidence, silently defeating the
    /// whole point of MIN_CONFIRM.
    #[test]
    fn resync_is_rejected_when_only_one_trace_is_exhausted_at_the_candidate() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0xD0]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0xD0, 0xBB, 0xBC, 0xBD]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 16, 32);
        assert_eq!(regions.len(), 1);
        assert_eq!(
            regions[0].resync_block, None,
            "trace A ending at the candidate must not vacuously confirm it while trace B's \
             remaining blocks go unexamined"
        );
    }

    /// Companion to the test above: BOTH traces ending together, right at
    /// the candidate, is the legitimate case resync_confirmed's early
    /// return covers -- there is nothing left in either trace that could
    /// disagree, which is exhaustive evidence, not absent evidence.
    /// multi_region_resync's second region exercises this shape
    /// incidentally; this test names and isolates it explicitly.
    #[test]
    fn resync_is_accepted_when_both_traces_are_exhausted_together_at_the_candidate() {
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0xD0]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0xD0]);
        let regions = VeridiffEngine::find_divergence_regions(&a, &b, 16, 32);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].resync_block, Some(0xD0));
        assert_eq!(regions[0].resync_index_a, Some(3));
        assert_eq!(regions[0].resync_index_b, Some(3));
    }

    #[test]
    fn block_event_parsing_64bit_skips_non_block_records() {
        let mut buf = Vec::new();
        // A GUM_CALL record (tag=1): type + pad + location + target + depth + pad = 32 bytes.
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&0x1111u64.to_le_bytes());
        buf.extend_from_slice(&0x2222u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        // A GUM_BLOCK record: type + pad + start + end, padded to the 32-byte stride.
        buf.extend_from_slice(&GUM_BLOCK.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&0x401000u64.to_le_bytes());
        buf.extend_from_slice(&0x401010u64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);

        let events: Vec<(u64, u64)> = iter_block_events(&buf, 8).collect();
        assert_eq!(events, vec![(0x401000, 0x401010)]);
    }

    #[test]
    fn block_event_parsing_32bit() {
        let mut buf = Vec::new();
        for _ in 0..3 {
            buf.extend_from_slice(&GUM_BLOCK.to_le_bytes());
            buf.extend_from_slice(&0x8048000u32.to_le_bytes());
            buf.extend_from_slice(&0x8048010u32.to_le_bytes());
            buf.extend_from_slice(&[0u8; 4]); // pad to the 16-byte stride
        }
        let events: Vec<(u64, u64)> = iter_block_events(&buf, 4).collect();
        assert_eq!(events, vec![(0x8048000, 0x8048010); 3]);
    }

    #[test]
    fn truncated_tail_is_ignored_not_panicked_on() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GUM_BLOCK.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&0x401000u64.to_le_bytes());
        buf.extend_from_slice(&0x401010u64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&[1, 2, 3]); // shorter than one stride

        let events: Vec<(u64, u64)> = iter_block_events(&buf, 8).collect();
        assert_eq!(events, vec![(0x401000, 0x401010)]);
    }

    #[test]
    fn hex_decode_round_trips() {
        assert_eq!(hex_decode("48c7c000000000"), vec![0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(hex_decode(""), Vec::<u8>::new());
    }

    // ------------------------------------------------------------------
    // Feature 3: cross-architecture conditional-branch classification.
    //
    // Instruction::parse (Capstone, via frida-gum) already decodes every
    // architecture Frida attaches to -- there is no x86-specific code in
    // the agent to "extend" for ARM64. What's genuinely missing is
    // classification: live-verified (see README field notes) that
    // Capstone's own Instruction.groups does NOT distinguish conditional
    // from unconditional branches -- a real `jne` and the `jmp` two
    // instructions later in the same block both report
    // groups=["branch_relative", "jump"]. Mnemonic text is the only signal
    // that does, which is what these mock payloads exercise: no live ARM64
    // hardware is available to this test suite, so ARM64 coverage here is
    // the classifier alone, fed synthetic (but architecturally accurate)
    // mnemonics -- not an end-to-end live ARM64 trace.
    // ------------------------------------------------------------------

    fn mk_insn(mnemonic: &str) -> Instruction {
        Instruction {
            address: 0,
            mnemonic: mnemonic.to_string(),
            op_str: String::new(),
            size: 4,
            raw_bytes: Vec::new(),
        }
    }

    #[test]
    fn x86_conditional_jumps_are_recognized() {
        for m in ["je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe", "jcxz"] {
            assert!(mk_insn(m).is_conditional_branch(), "{m}");
        }
    }

    #[test]
    fn x86_unconditional_jump_is_not_a_conditional_branch() {
        assert!(!mk_insn("jmp").is_conditional_branch());
    }

    #[test]
    fn x86_non_branch_mnemonics_are_not_conditional_branches() {
        for m in ["mov", "cmp", "call", "ret", "push", "pop", "lea", "test"] {
            assert!(!mk_insn(m).is_conditional_branch(), "{m}");
        }
    }

    #[test]
    fn arm64_compare_and_test_branches_are_recognized() {
        for m in ["cbz", "cbnz", "tbz", "tbnz"] {
            assert!(mk_insn(m).is_conditional_branch(), "{m}");
        }
    }

    #[test]
    fn arm64_b_cond_forms_are_recognized() {
        for m in ["b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge", "b.hi", "b.ls", "b.mi", "b.pl"] {
            assert!(mk_insn(m).is_conditional_branch(), "{m}");
        }
    }

    #[test]
    fn arm64_unconditional_branches_are_not_conditional() {
        for m in ["b", "bl", "br", "blr", "ret"] {
            assert!(!mk_insn(m).is_conditional_branch(), "{m}");
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        // Not observed to matter in practice -- every live capture in this
        // repo has Capstone/Frida returning lowercase mnemonics -- but the
        // check is nearly free, so it's defensive rather than assumed.
        assert!(mk_insn("JNE").is_conditional_branch());
        assert!(mk_insn("B.EQ").is_conditional_branch());
        assert!(!mk_insn("JMP").is_conditional_branch());
    }

    #[test]
    fn mock_arm64_disassembly_payload_flags_the_decisive_instruction() {
        // Shaped exactly like what disassemble_block() builds from a real
        // disassembleRange RPC response -- a mock ARM64 trace payload,
        // standing in for hardware this suite doesn't have access to.
        // Models a null-check-shaped block: `cbz x0, +0x18` deciding the
        // branch.
        let instructions = [
            Instruction { address: 0x4009f0, mnemonic: "mov".into(), op_str: "x1, x0".into(), size: 4, raw_bytes: vec![0xe1, 0x03, 0x00, 0xaa] },
            Instruction { address: 0x4009f4, mnemonic: "cbz".into(), op_str: "x0, #0x4009fc".into(), size: 4, raw_bytes: vec![0x00, 0x00, 0xb0, 0xb4] },
        ];
        let decisive: Vec<&Instruction> = instructions.iter().filter(|i| i.is_conditional_branch()).collect();
        assert_eq!(decisive.len(), 1);
        assert_eq!(decisive[0].mnemonic, "cbz");
        assert_eq!(decisive[0].address, 0x4009f4);
    }

    // ------------------------------------------------------------------
    // Review pass (2026-09-17): failure-path coverage for the two fixes
    // below, both found by re-reading the code rather than by any test or
    // live run turning up wrong behavior. Neither was manifesting in
    // practice -- both sides of this protocol are this crate's own code,
    // so a genuinely malformed message has never actually occurred -- but
    // an untested failure path is exactly the kind of thing that silently
    // breaks later. See the doc comments on RelayHandler::on_message's
    // "meta" arm and on `parse_instruction` for the reasoning.
    // ------------------------------------------------------------------

    #[test]
    fn malformed_meta_message_produces_a_log_not_a_fabricated_meta() {
        let (tx, rx) = mpsc::channel();
        let mut handler = RelayHandler { tx };
        // Missing moduleBase/moduleName/moduleSize entirely.
        let payload = serde_json::json!({"type": "meta", "pointerSize": 8});
        handler.on_message(Message::Send(MessageSend { payload }), None);

        match rx.try_recv() {
            Ok(AgentEvent::Log(_)) => {} // correct: surfaced, not silently defaulted
            Ok(AgentEvent::Meta { .. }) => panic!("malformed meta must not produce a fabricated Meta event"),
            other => panic!("expected exactly one Log event, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_meta_message_still_parses_normally() {
        // Companion to the test above: the fix must reject bad data
        // without breaking the good-data path it already had to handle.
        let (tx, rx) = mpsc::channel();
        let mut handler = RelayHandler { tx };
        let payload = serde_json::json!({
            "type": "meta",
            "pointerSize": 8,
            "moduleName": "licensecheck",
            "moduleBase": "0x400000",
            "moduleSize": 16424,
        });
        handler.on_message(Message::Send(MessageSend { payload }), None);

        match rx.try_recv() {
            Ok(AgentEvent::Meta { pointer_size, module_name, module_base, module_size }) => {
                assert_eq!(pointer_size, 8);
                assert_eq!(module_name, "licensecheck");
                assert_eq!(module_base, 0x400000);
                assert_eq!(module_size, 16424);
            }
            other => panic!("expected a well-formed Meta event, got {other:?}"),
        }
    }

    #[test]
    fn malformed_disassembly_item_is_an_error_not_a_panic_or_fabricated_default() {
        let missing_size = serde_json::json!({
            "address": "0x401146",
            "mnemonic": "push",
            "opStr": "rbp",
            "bytes": "55",
        });
        match parse_instruction(&missing_size) {
            Err(VeridiffError::MalformedResponse(_)) => {}
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_disassembly_item_still_parses_normally() {
        let item = serde_json::json!({
            "address": "0x401146",
            "mnemonic": "push",
            "opStr": "rbp",
            "size": 1,
            "bytes": "55",
        });
        let insn = parse_instruction(&item).expect("well-formed item must parse");
        assert_eq!(insn.address, 0x401146);
        assert_eq!(insn.mnemonic, "push");
        assert_eq!(insn.op_str, "rbp");
        assert_eq!(insn.size, 1);
        assert_eq!(insn.raw_bytes, vec![0x55]);
    }

    #[test]
    fn bytes_field_shorter_than_size_is_an_error_not_a_silent_truncation() {
        // hex_decode() would otherwise silently drop the malformed trailing
        // "5" (odd-length) rather than erroring; parse_instruction must
        // catch that via the size cross-check instead of returning a
        // 1-byte raw_bytes for a declared size of 2.
        let item = serde_json::json!({
            "address": "0x401146", "mnemonic": "push", "opStr": "rbp", "size": 2, "bytes": "555",
        });
        match parse_instruction(&item) {
            Err(VeridiffError::MalformedResponse(_)) => {}
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    /// Companion to the test above, isolating what it didn't actually
    /// cover: found by review. "555" (odd length) is malformed hex, so it
    /// would still error even if the explicit `raw_bytes.len() != size`
    /// check were deleted and hex-decoding were relied on alone -- that
    /// test alone wouldn't catch a regression back to the original bug.
    /// This uses well-formed hex ("55", one valid byte) that simply
    /// disagrees with a separately-declared `size` of 2 -- the actual
    /// shape of the bug the check exists to catch, and the only shape
    /// that distinguishes "the explicit check is doing real work" from
    /// "hex-decoding happens to error for an unrelated reason."
    #[test]
    fn well_formed_bytes_field_disagreeing_with_size_is_also_an_error() {
        let item = serde_json::json!({
            "address": "0x401146", "mnemonic": "push", "opStr": "rbp", "size": 2, "bytes": "55",
        });
        match parse_instruction(&item) {
            Err(VeridiffError::MalformedResponse(_)) => {}
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }
}
