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
#[derive(Debug)]
pub enum VeridiffError {
    /// The agent's `traceCall`/`disassembleRange` RPC threw or transport-failed.
    Rpc(frida::Error),
    /// The message channel closed, or timed out, before a `done` event arrived.
    IncompleteTrace,
    /// `disassemble_block` was asked for a block this trace never visited.
    UnknownBlock(u64),
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
        }
    }
}

impl std::error::Error for VeridiffError {}

// --------------------------------------------------------------------------
// Agent message plumbing.
// --------------------------------------------------------------------------

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
                        let payload = &m.payload;
                        let module_base_hex = payload["moduleBase"].as_str().unwrap_or("0x0");
                        AgentEvent::Meta {
                            pointer_size: payload["pointerSize"].as_u64().unwrap_or(8) as usize,
                            module_name: payload["moduleName"].as_str().unwrap_or("").to_string(),
                            module_base: u64::from_str_radix(
                                module_base_hex.trim_start_matches("0x"),
                                16,
                            )
                            .unwrap_or(0),
                            module_size: payload["moduleSize"].as_u64().unwrap_or(0),
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
    /// module containing `address`.
    pub fn trace_call(
        &self,
        script: &mut Script,
        address: u64,
        args: &[Arg],
        ret_type: &str,
        module: Option<&str>,
    ) -> Result<Trace, VeridiffError> {
        let args_json: Vec<Value> = args.iter().map(Arg::to_json).collect();
        let call_args = json!([format!("{address:#x}"), args_json, ret_type, module]);

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

        let items = result
            .as_ref()
            .and_then(Value::as_array)
            .ok_or(VeridiffError::IncompleteTrace)?;

        Ok(items
            .iter()
            .map(|item| Instruction {
                address: u64::from_str_radix(
                    item["address"]
                        .as_str()
                        .expect("agent always returns a hex address string")
                        .trim_start_matches("0x"),
                    16,
                )
                .expect("agent always returns a well-formed hex address"),
                mnemonic: item["mnemonic"].as_str().unwrap_or("").to_string(),
                op_str: item["opStr"].as_str().unwrap_or("").to_string(),
                size: item["size"].as_u64().unwrap_or(0) as usize,
                raw_bytes: hex_decode(item["bytes"].as_str().unwrap_or("")),
            })
            .collect())
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
    /// goal here in the first place) -- it is O(N + regions * resync_window)
    /// and intentionally gives up on a region it can't resync within the
    /// window rather than searching unboundedly.
    pub fn find_divergence_regions(
        trace_a: &Trace,
        trace_b: &Trace,
        resync_window: usize,
        max_regions: usize,
    ) -> Vec<DivergenceRegion> {
        let (a, b) = (&trace_a.blocks, &trace_b.blocks);
        let (mut i, mut j) = (0usize, 0usize);
        let mut regions = Vec::new();

        while regions.len() < max_regions {
            while i < a.len() && j < b.len() && a[i] == b[j] {
                i += 1;
                j += 1;
            }
            if i >= a.len() || j >= b.len() {
                break;
            }

            let mut window_b: HashMap<u64, usize> = HashMap::new();
            for (k, &val) in b.iter().enumerate().skip(j).take(resync_window) {
                window_b.entry(val).or_insert(k);
            }

            let mut resync: Option<(usize, usize, u64)> = None;
            for (p, &val) in a.iter().enumerate().skip(i).take(resync_window) {
                if let Some(&k) = window_b.get(&val) {
                    resync = Some((p, k, val));
                    break;
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
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// --------------------------------------------------------------------------
// Tests: pure logic only, no live Frida session required.
// --------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

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
        let a = mk_trace(vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]);
        let b = mk_trace(vec![0x10, 0x20, 0x31, 0x40, 0x50, 0x61, 0x70]);
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
}
