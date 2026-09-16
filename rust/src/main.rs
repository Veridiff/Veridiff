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

//! Minimal usage example for the `veridiff` library -- not the product,
//! just wiring. See `src/lib.rs` for the actual engine.

use frida::{DeviceManager, Frida, ScriptOption, SpawnOptions};
use veridiff::{Arg, TraceCallOptions, VeridiffEngine};

fn main() {
    let cli_args: Vec<String> = std::env::args().collect();
    if cli_args.len() != 5 {
        eprintln!(
            "usage: {} <executable> <hex-address-of-target-fn> <arg-a> <arg-b>\n\n\
             Spawns <executable> suspended, calls the function at the given address\n\
             twice -- once with each string argument -- and reports the first basic\n\
             block where the two runs' control flow diverged.",
            cli_args.first().map(String::as_str).unwrap_or("veridiff")
        );
        std::process::exit(1);
    }
    let program = &cli_args[1];
    let target_address = u64::from_str_radix(cli_args[2].trim_start_matches("0x"), 16)
        .expect("address must be a hex number, e.g. 0x401230");
    let arg_a = cli_args[3].clone();
    let arg_b = cli_args[4].clone();

    // frida-rust's Device/Session/Script types borrow from each other (a
    // Session borrows its Device, a Script borrows its Session), so they're
    // kept as local bindings here in dependency order and dropped in
    // reverse automatically -- see the doc comment on VeridiffEngine in
    // lib.rs for why the engine itself stays out of that lifetime chain.
    let frida = unsafe { Frida::obtain() };
    let device_manager = DeviceManager::obtain(&frida);
    let mut device = device_manager.get_local_device().expect("no local Frida device");

    let pid = device
        .spawn(program.as_str(), &SpawnOptions::new())
        .unwrap_or_else(|e| panic!("failed to spawn {program}: {e}"));
    let session = device.attach(pid).expect("failed to attach to spawned process");

    let mut script_option = ScriptOption::default();
    let mut script = session
        .create_script(veridiff::AGENT_SOURCE, &mut script_option)
        .expect("failed to create agent script");
    script.load().expect("failed to load agent script");

    let engine = VeridiffEngine::new(&mut script).expect("failed to install message handler");

    // Both calls happen with the process still suspended at its post-spawn,
    // post-relocation stop point (resume() is only called afterwards) so
    // there's no race with the target's own main() -- see trace_call's doc
    // comment in lib.rs. This requires the target function not to depend on
    // state that's normally set up by constructors/main() that haven't run
    // yet; if yours does, call engine.resume-equivalent (device.resume) and
    // arrange your own synchronization before tracing.
    //
    // warm_up: true so this demo doesn't itself fall into the PLT/GOT
    // lazy-binding confound documented on TraceCallOptions -- without it,
    // run A's first call into any externally-linked function (strcmp,
    // here) would show a spurious divergence against run B that has
    // nothing to do with arg_a vs arg_b.
    let options = TraceCallOptions { warm_up: true };
    let trace_a = engine
        .trace_call(&mut script, target_address, &[Arg::Str(arg_a.clone())], "int", None, options)
        .expect("trace A failed");
    let trace_b = engine
        .trace_call(&mut script, target_address, &[Arg::Str(arg_b.clone())], "int", None, options)
        .expect("trace B failed");

    println!(
        "trace A ({arg_a:?}): {} blocks, returned {:?}",
        trace_a.blocks.len(),
        trace_a.return_value
    );
    println!(
        "trace B ({arg_b:?}): {} blocks, returned {:?}",
        trace_b.blocks.len(),
        trace_b.return_value
    );

    let fmt = |v: Option<u64>| v.map(|x| format!("{x:#x}")).unwrap_or_else(|| "(trace ended here)".to_string());

    match VeridiffEngine::find_first_divergence(&trace_a, &trace_b) {
        None => println!("no divergence: both runs executed identical control flow"),
        Some(d) => {
            println!("\nfirst divergence at trace index {}", d.index);
            println!("  last common block : {}", fmt(d.last_common_block));
            println!("  run A took block  : {}", fmt(d.block_a));
            println!("  run B took block  : {}", fmt(d.block_b));

            if let Some(last_common) = d.last_common_block {
                // Disassembling only reads static code bytes at an address,
                // so it needs the target mapped, not running -- this has to
                // happen before device.resume() below, not after. Any RPC
                // into the agent after resume() races the target actually
                // exiting, and frida-rust's Exports::call has no timeout or
                // dead-session detection on that blocking wait: losing that
                // race hangs this process forever instead of erroring (see
                // README field notes -- frida-python detects it and raises
                // cleanly instead, so this is Rust-specific).
                println!("\n  disassembly of the deciding block:");
                match engine.disassemble_block(&mut script, &trace_a, last_common) {
                    Ok(instructions) => {
                        for insn in instructions {
                            let marker = if insn.is_conditional_branch() { "  <-- decides here" } else { "" };
                            println!("    {:#x}  {} {}{marker}", insn.address, insn.mnemonic, insn.op_str);
                        }
                    }
                    Err(e) => eprintln!("  (failed to disassemble: {e})"),
                }
            }
        }
    }

    // Purely a courtesy: lets the spawned process actually run and exit
    // instead of being left stopped. Nothing above depends on this.
    let _ = device.resume(pid);
}
