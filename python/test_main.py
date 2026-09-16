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

"""Unit tests for the pure algorithmic core: no Frida, no live target.

Mirrors the #[cfg(test)] suite in rust/src/lib.rs test-for-test, so both
engines carry the same behavioral guarantees. Run with: pytest python/
"""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import main as veridiff


def mk_trace(blocks):
    ends = {b: b + 4 for b in set(blocks)}
    return veridiff.Trace(
        blocks=blocks,
        block_ends=ends,
        module_name="t",
        module_base=0,
        module_size=0x10000,
        return_value=None,
    )


def test_identical_traces_have_no_divergence():
    a = mk_trace([0x10, 0x20, 0x30, 0x40])
    b = mk_trace([0x10, 0x20, 0x30, 0x40])
    assert veridiff.VeridiffEngine.find_first_divergence(a, b) is None


def test_mid_trace_divergence():
    a = mk_trace([0x10, 0x20, 0x30, 0x40, 0x50])
    b = mk_trace([0x10, 0x20, 0x99, 0x40, 0x50])
    d = veridiff.VeridiffEngine.find_first_divergence(a, b)
    assert d.index == 2
    assert d.last_common_block == 0x20
    assert d.block_a == 0x30
    assert d.block_b == 0x99


def test_prefix_divergence_when_one_trace_ends_early():
    a = mk_trace([0x10, 0x20, 0x30])
    b = mk_trace([0x10, 0x20, 0x30, 0x40, 0x50])
    d = veridiff.VeridiffEngine.find_first_divergence(a, b)
    assert d.index == 3
    assert d.block_a is None
    assert d.block_b == 0x40


def test_immediate_divergence_has_no_last_common_block():
    a = mk_trace([0x11, 0x20])
    b = mk_trace([0x22, 0x20])
    d = veridiff.VeridiffEngine.find_first_divergence(a, b)
    assert d.index == 0
    assert d.last_common_block is None


def test_prefix_scan_is_not_fooled_by_a_coincidental_downstream_match():
    # The whole reason this isn't a Myers/LCS diff: 0x30 reappearing in
    # trace B right after the real split must NOT be read as "the traces
    # realign at 0x30" -- the first divergence is what matters, full stop.
    a = mk_trace([0x10, 0x20, 0x30, 0xAA, 0xBB])
    b = mk_trace([0x10, 0x20, 0x99, 0x30, 0xBB])
    d = veridiff.VeridiffEngine.find_first_divergence(a, b)
    assert d.index == 2
    assert d.block_a == 0x30
    assert d.block_b == 0x99


def test_multi_region_resync():
    # Four fully-shared blocks (0x40/0x50/0x55/0x58) separate the two
    # divergences -- enough runway for _MIN_CONFIRM=3 to solidly confirm
    # the first resync before the second divergence hits.
    a = mk_trace([0x10, 0x20, 0x30, 0x40, 0x50, 0x55, 0x58, 0x60, 0x70])
    b = mk_trace([0x10, 0x20, 0x31, 0x40, 0x50, 0x55, 0x58, 0x61, 0x70])
    regions = veridiff.VeridiffEngine.find_divergence_regions(a, b, resync_window=16)
    assert len(regions) == 2
    assert regions[0].branch_a == 0x30
    assert regions[0].branch_b == 0x31
    assert regions[0].resync_block == 0x40
    assert regions[1].branch_a == 0x60
    assert regions[1].resync_block == 0x70


def test_no_resync_within_window_stops_after_one_region():
    a = mk_trace([0x10, 0x20, 0x30, 0x99999])
    b = mk_trace([0x10, 0x20, 0x31, 0x88888])
    regions = veridiff.VeridiffEngine.find_divergence_regions(a, b, resync_window=2)
    assert len(regions) == 1
    assert regions[0].resync_block is None


def test_dispatcher_style_coincidental_match_is_rejected():
    # The core claim of the v0.2.0 resync tuning: a single-block hit on a
    # shared dispatcher/helper (0xD0) must NOT be accepted as a real merge
    # when the two traces immediately diverge again afterward -- exactly
    # the shape of two paths transiting the same OLLVM-flattening dispatcher
    # block before dispatching to genuinely different targets. The
    # pre-v0.2.0 algorithm (first shared address wins, no confirmation)
    # would have wrongly reported 0xD0 as the resync point.
    a = mk_trace([0x10, 0x20, 0x30, 0xD0, 0xAA, 0xAB, 0xAC])
    b = mk_trace([0x10, 0x20, 0x31, 0xD0, 0xBB, 0xBC, 0xBD])
    regions = veridiff.VeridiffEngine.find_divergence_regions(a, b, resync_window=16)
    assert len(regions) == 1
    assert regions[0].branch_a == 0x30
    assert regions[0].branch_b == 0x31
    assert regions[0].resync_block is None


def test_dispatcher_style_match_is_accepted_when_it_actually_holds_up():
    # Same shared block 0xD0 as above, but this time both traces genuinely
    # continue identically afterward. Paired with the rejection test above,
    # this confirms the algorithm discriminates on whether a shared address
    # holds up under continued comparison, not on whether it's shared at
    # all -- it doesn't become universally suspicious of dispatcher-shaped
    # addresses, only of ones that turn out to be coincidental.
    a = mk_trace([0x10, 0x20, 0x30, 0xD0, 0xAA, 0xAB, 0xAC])
    b = mk_trace([0x10, 0x20, 0x31, 0xD0, 0xAA, 0xAB, 0xAC])
    regions = veridiff.VeridiffEngine.find_divergence_regions(a, b, resync_window=16)
    assert len(regions) == 1
    assert regions[0].resync_block == 0xD0
    assert regions[0].resync_index_a == 3
    assert regions[0].resync_index_b == 3


def test_later_occurrence_of_a_repeated_value_can_still_confirm():
    # A candidate whose *first* occurrence in b's window fails to confirm
    # must not eliminate that address outright -- a later occurrence of the
    # same value can still be the genuine merge point (e.g. a dispatcher
    # visited twice before the two paths actually reconverge). The first
    # 0xD0 (index 3) fails to confirm (0xAA != 0xBB follows it); the second
    # 0xD0 (index 5) does, and must be what's reported.
    a = mk_trace([0x10, 0x20, 0x30, 0xD0, 0xAA, 0xD0, 0xEE, 0xEF, 0xF0])
    b = mk_trace([0x10, 0x20, 0x31, 0xD0, 0xBB, 0xD0, 0xEE, 0xEF, 0xF0])
    regions = veridiff.VeridiffEngine.find_divergence_regions(a, b, resync_window=16)
    assert len(regions) == 1
    assert regions[0].resync_block == 0xD0
    assert regions[0].resync_index_a == 5
    assert regions[0].resync_index_b == 5


def test_block_event_parsing_64bit_skips_non_block_records():
    call_event = struct.pack("<IxxxxQQi", 1, 0x1111, 0x2222, 3) + b"\x00" * 4
    block_event = struct.pack("<IxxxxQQ", veridiff._GUM_BLOCK, 0x401000, 0x401010) + b"\x00" * 8
    events = list(veridiff._iter_block_events(call_event + block_event, pointer_size=8))
    assert events == [(0x401000, 0x401010)]


def test_block_event_parsing_32bit():
    block_event = struct.pack("<III", veridiff._GUM_BLOCK, 0x8048000, 0x8048010) + b"\x00" * 4
    events = list(veridiff._iter_block_events(block_event * 3, pointer_size=4))
    assert events == [(0x8048000, 0x8048010)] * 3


def test_truncated_tail_is_ignored_not_raised_on():
    block_event = struct.pack("<IxxxxQQ", veridiff._GUM_BLOCK, 0x401000, 0x401010) + b"\x00" * 8
    events = list(veridiff._iter_block_events(block_event + b"\x01\x02\x03", pointer_size=8))
    assert events == [(0x401000, 0x401010)]


# --------------------------------------------------------------------------
# Feature 3: cross-architecture conditional-branch classification.
#
# Instruction.parse (Capstone, via frida-gum) already decodes every
# architecture Frida attaches to -- there is no x86-specific code in the
# agent to "extend" for ARM64. What's genuinely missing is classification:
# live-verified (see README field notes) that Capstone's own
# Instruction.groups does NOT distinguish conditional from unconditional
# branches -- a real `jne` and the `jmp` two instructions later in the same
# block both report groups=['branch_relative', 'jump']. Mnemonic text is
# the only signal that does, which is what these mock payloads exercise:
# no live ARM64 hardware is available to this test suite, so ARM64 coverage
# here is the classifier alone, fed synthetic (but architecturally accurate)
# mnemonics -- not an end-to-end live ARM64 trace.
# --------------------------------------------------------------------------


def test_x86_conditional_jumps_are_recognized():
    for mnemonic in ["je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe", "jcxz"]:
        assert veridiff._is_conditional_branch(mnemonic), mnemonic


def test_x86_unconditional_jump_is_not_a_conditional_branch():
    assert not veridiff._is_conditional_branch("jmp")


def test_x86_non_branch_mnemonics_are_not_conditional_branches():
    for mnemonic in ["mov", "cmp", "call", "ret", "push", "pop", "lea", "test"]:
        assert not veridiff._is_conditional_branch(mnemonic), mnemonic


def test_arm64_compare_and_test_branches_are_recognized():
    for mnemonic in ["cbz", "cbnz", "tbz", "tbnz"]:
        assert veridiff._is_conditional_branch(mnemonic), mnemonic


def test_arm64_b_cond_forms_are_recognized():
    for mnemonic in ["b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge", "b.hi", "b.ls", "b.mi", "b.pl"]:
        assert veridiff._is_conditional_branch(mnemonic), mnemonic


def test_arm64_unconditional_branches_are_not_conditional():
    for mnemonic in ["b", "bl", "br", "blr", "ret"]:
        assert not veridiff._is_conditional_branch(mnemonic), mnemonic


def test_classification_is_case_insensitive():
    # Not observed to matter in practice -- every live capture in this repo
    # has Capstone/Frida returning lowercase mnemonics -- but the check is
    # nearly free, so it's defensive rather than assumed.
    assert veridiff._is_conditional_branch("JNE")
    assert veridiff._is_conditional_branch("B.EQ")
    assert not veridiff._is_conditional_branch("JMP")


def test_mock_arm64_disassembly_payload_flags_the_decisive_instruction():
    # Shaped exactly like what disassemble_block() builds from a real
    # disassembleRange RPC response -- a mock ARM64 trace payload, standing
    # in for hardware this suite doesn't have access to. Models a
    # null-check-shaped block: `cbz x0, +0x18` deciding the branch.
    raw_arm64_block = [
        {"address": "0x4009f0", "mnemonic": "mov", "opStr": "x1, x0", "size": 4, "bytes": "e10300aa"},
        {"address": "0x4009f4", "mnemonic": "cbz", "opStr": "x0, #0x4009fc", "size": 4, "bytes": "0000b0b4"},
    ]
    instructions = [veridiff._parse_instruction(r) for r in raw_arm64_block]
    decisive = [insn for insn in instructions if insn.is_conditional_branch]
    assert len(decisive) == 1
    assert decisive[0].mnemonic == "cbz"
    assert decisive[0].address == 0x4009F4


# --------------------------------------------------------------------------
# Review pass (2026-09-17): failure-path coverage for _parse_instruction.
#
# Found by re-reading the code, not by any test or live run turning up
# wrong behavior -- both ends of this protocol are this repo's own agent,
# so a genuinely malformed disassembleRange item has never actually
# occurred. Direct dict indexing (not `.get()`) was already the right
# choice here -- it raises KeyError immediately rather than fabricating a
# plausible-looking default -- but it was untested and inline. This locks
# the behavior in and matches the Rust engine's explicit
# MalformedResponse error for the same case (see its doc comment on
# parse_instruction for the fuller reasoning, including why Rust returns
# a Result here instead of panicking: disassemble_block is a public
# library entry point, and a panic there would take an embedder's whole
# process down for what should be a recoverable error).
# --------------------------------------------------------------------------


def test_malformed_disassembly_item_raises_immediately():
    missing_size = {"address": "0x401146", "mnemonic": "push", "opStr": "rbp", "bytes": "55"}
    with pytest.raises(KeyError):
        veridiff._parse_instruction(missing_size)


def test_well_formed_disassembly_item_still_parses_normally():
    item = {"address": "0x401146", "mnemonic": "push", "opStr": "rbp", "size": 1, "bytes": "55"}
    insn = veridiff._parse_instruction(item)
    assert insn.address == 0x401146
    assert insn.mnemonic == "push"
    assert insn.op_str == "rbp"
    assert insn.size == 1
    assert insn.raw_bytes == b"\x55"
