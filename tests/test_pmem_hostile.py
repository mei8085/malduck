"""
Tests for hostile process-memory region table handling.

The region descriptors embedded in a memory dump are attacker-controlled.
These tests assert that malduck never treats their fields as a trusted
mapping: overlapping, unsorted, overflowing, truncated and exceptional
(guard-bit) descriptors are canonicalized into a table where every virtual
address maps to exactly one in-bounds physical offset.
"""
import struct

import pytest

from malduck import (
    PAGE_GUARD,
    PAGE_READWRITE,
    cuckoomem,
    normalize_regions,
    page_protect_to_access,
    procmem,
)
from malduck.procmem import Region


def _assert_consistent(mem):
    """Invariants every normalized region table must uphold."""
    prev = None
    for region in mem.regions:
        # Non-empty and representable without wrapping.
        assert region.size > 0
        assert 0 <= region.addr and 0 <= region.offset
        assert region.end == region.addr + region.size
        assert region.end_offset == region.offset + region.size
        # Fully backed by the underlying buffer: no invented bytes.
        assert 0 <= region.offset < mem.length
        assert region.end_offset <= mem.length
        # Sorted, non-overlapping virtual layout.
        if prev is not None:
            assert region.addr >= prev.end
        # Virtual-to-physical translation is stable and agrees with the
        # region's own mapping at both boundaries.
        assert mem.v2p(region.addr) == region.offset
        assert mem.v2p(region.last) == region.last_offset
        # The bytes actually exposed at the virtual address are exactly the
        # buffer bytes the region points at (no attacker-controlled aliasing).
        assert mem.readv(region.addr, region.size) == mem.readp(
            region.offset, region.size
        )
        prev = region


def test_normalize_unsorted_regions_get_sorted():
    payload = b"abcdefghijkl"
    regions = [
        Region(0x20000, 4, 0, 0, 0, 8),
        Region(0x10000, 4, 0, 0, 0, 0),
        Region(0x30000, 4, 0, 0, 0, 4),
    ]
    mem = procmem(payload, regions=regions)
    assert [r.addr for r in mem.regions] == [0x10000, 0x20000, 0x30000]
    _assert_consistent(mem)
    # Contents still correspond to the original physical offsets.
    assert mem.readv(0x10000, 4) == b"abcd"
    assert mem.readv(0x20000, 4) == b"ijkl"
    assert mem.readv(0x30000, 4) == b"efgh"


def test_normalize_overlapping_regions_first_wins():
    payload = b"".join([b"a" * 8, b"b" * 8, b"c" * 8])
    # Three physically contiguous runs, but the second descriptor overlaps
    # the first in virtual space: raw table is neither disjoint nor covering
    # the whole intended range without a hole.
    regions = [
        Region(0x10000, 8, 0, 0, 0, 0),    # backed by 'a'
        Region(0x10004, 8, 0, 0, 0, 8),    # overlaps 4 bytes, backed by 'b'
        Region(0x1000c, 8, 0, 0, 0, 16),   # adjacent to the clipped tail, 'c'
    ]
    mem = procmem(payload, regions=regions)
    _assert_consistent(mem)
    # The overlapping part keeps the first region's mapping; the second
    # region is clipped to its unclaimed tail and its offset shifts with it.
    assert mem.regions == [
        Region(0x10000, 8, 0, 0, 0, 0),
        Region(0x10008, 4, 0, 0, 0, 12),
        Region(0x1000c, 8, 0, 0, 0, 16),
    ]
    # Each virtual address resolves to a single, stable physical offset.
    assert mem.v2p(0x10005) == 5
    assert mem.v2p(0x10008) == 12
    # Contiguous read spans the resolved layout without duplicated mappings.
    assert mem.readv(0x10000, 0x14) == b"a" * 8 + b"b" * 4 + b"c" * 8
    # Bytes the second descriptor used to claim (0x10004-0x10008) stay owned
    # by the first region.
    assert mem.readv(0x10004, 4) == b"aaaa"


def test_normalize_fully_shadowed_region_is_dropped():
    payload = b"x" * 16
    regions = [
        Region(0x10000, 8, 1, 1, 1, 0),
        Region(0x10002, 4, 2, 2, 2, 8),  # entirely inside the first region
    ]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x10000, 8, 1, 1, 1, 0)]
    _assert_consistent(mem)


def test_normalize_same_address_keeps_first_descriptor():
    payload = b"0123456789abcdef"
    regions = [
        Region(0x10000, 4, 0, 0, 0, 0),
        Region(0x10000, 4, 0, 0, 0, 8),
    ]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x10000, 4, 0, 0, 0, 0)]
    assert mem.readv(0x10000, 4) == b"0123"
    _assert_consistent(mem)


def test_normalize_virtual_address_overflow_dropped():
    payload = b"a" * 16
    max_addr = (1 << 64) - 1
    regions = [
        Region(0x10000, 4, 0, 0, 0, 0),
        # addr + size wraps the 64-bit address space.
        Region(max_addr - 1, 8, 0, 0, 0, 4),
    ]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x10000, 4, 0, 0, 0, 0)]
    _assert_consistent(mem)


def test_normalize_physical_overflow_dropped():
    payload = b"a" * 16
    huge = 1 << 62
    regions = [
        Region(0x10000, 4, 0, 0, 0, 0),
        # offset + size wraps / runs far beyond the buffer.
        Region(0x20000, 8, 0, 0, 0, huge),
    ]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x10000, 4, 0, 0, 0, 0)]
    _assert_consistent(mem)


def test_normalize_truncated_region_clipped_to_buffer():
    payload = b"abcdef"
    # Claims 8 bytes but only 6 exist from offset 0.
    regions = [Region(0x10000, 8, 0, 0, 0, 0)]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x10000, 6, 0, 0, 0, 0)]
    _assert_consistent(mem)
    assert mem.readv(0x10000, 6) == b"abcdef"
    # The clipped tail must not be considered mapped.
    assert mem.v2p(0x10006) is None


def test_normalize_region_outside_buffer_dropped():
    payload = b"abcdef"
    regions = [
        Region(0x10000, 2, 0, 0, 0, 0),
        Region(0x20000, 4, 0, 0, 0, 6),   # offset == length: nothing backed
        Region(0x30000, 4, 0, 0, 0, 100),
    ]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x10000, 2, 0, 0, 0, 0)]
    _assert_consistent(mem)


def test_normalize_zero_and_negative_sized_dropped():
    payload = b"abcdef"
    regions = [
        Region(0x10000, 0, 0, 0, 0, 0),
        Region(0x20000, 4, 0, 0, 0, 2),
    ]
    mem = procmem(payload, regions=regions)
    assert mem.regions == [Region(0x20000, 4, 0, 0, 0, 2)]
    _assert_consistent(mem)


def test_normalize_guard_protection_bits_preserved_but_not_trusted():
    payload = b"abcdefgh"
    guard_protect = PAGE_READWRITE | PAGE_GUARD
    regions = [Region(0x10000, 8, 0, 0, guard_protect, 0)]
    mem = procmem(payload, regions=regions)
    # The raw, attacker-provided protect value is preserved verbatim.
    assert mem.regions[0].protect == guard_protect
    # Guard/modifier bits don't remove or alter the mapping...
    assert mem.readv(0x10000, 8) == b"abcdefgh"
    _assert_consistent(mem)
    # ...and to_json resolves only the base access rights, never raising.
    assert mem.regions[0].to_json()["protect"] == "rw"
    assert page_protect_to_access(guard_protect) == "rw"
    assert page_protect_to_access(0xDEADBEEF) is None


def test_normalize_empty_and_none_tables():
    assert normalize_regions(None) == []
    assert normalize_regions([]) == []
    mem = procmem(b"abcd", regions=[])
    assert mem.regions == []
    # Empty table must behave as "nothing mapped", not crash.
    assert mem.v2p(0x10000) is None
    assert mem.p2v(0) is None
    assert mem.readv(0x10000, 4) == b""
    assert list(mem.iter_regions()) == []
    assert list(mem.findv(b"ab")) == []


def test_normalize_is_idempotent_and_does_not_mutate_input():
    payload = b"a" * 32
    regions = [
        Region(0x20000, 4, 0, 0, 0, 8),
        Region(0x10000, 4, 0, 0, 0, 0),
    ]
    once = normalize_regions(regions, len(payload))
    twice = normalize_regions(once, len(payload))
    assert once == twice
    # Original caller list keeps its (hostile) order.
    assert [r.addr for r in regions] == [0x20000, 0x10000]


def test_iter_regions_unmapped_lookups_stay_safe_after_normalization():
    payload = b"a" * 16
    regions = [
        Region(0x10000, 8, 0, 0, 0, 0),
        Region(0x10004, 8, 0, 0, 0, 8),  # overlaps, gets clipped
    ]
    mem = procmem(payload, regions=regions)
    # Lookup inside the clipped-away tail must report unmapped.
    assert mem.v2p(0x10010) is None
    assert mem.addr_region(0x10010) is None
    # A length crossing into the gap cannot be satisfied contiguously.
    assert mem.v2p(0x1000c, length=8) is None


def _cuckoo_dump(entries):
    out = b""
    for addr, size, state, typ, protect, data in entries:
        out += struct.pack("QIIII", addr, size, state, typ, protect) + data
    return out


def test_cuckoomem_parses_hostile_table():
    payload = _cuckoo_dump([
        # Unsorted, overlapping pair (second clips to tail at 0x10008).
        (0x10008, 8, 0, 0, PAGE_READWRITE, b"b" * 8),
        (0x10000, 8, 0, 0, PAGE_READWRITE, b"a" * 8),
        # Guard-protected region is kept and fully mapped.
        (0x20000, 4, 0, 0, PAGE_READWRITE | PAGE_GUARD, b"g" * 4),
        # Truncated descriptor: claims 8 bytes, only 4 present in file.
        (0x30000, 8, 0, 0, PAGE_READWRITE, b"t" * 4),
    ])
    mem = cuckoomem(payload)
    assert [r.addr for r in mem.regions] == [0x10000, 0x10008, 0x20000, 0x30000]
    # Overlap resolved first-wins: 0x10000 region covers 0x10000-0x10008,
    # the originally-later region keeps only its tail with shifted offset.
    first, second = mem.regions[0], mem.regions[1]
    assert first.size == 8
    assert second == Region(0x10008, 8, 0, 0, PAGE_READWRITE, second.offset)
    # Truncated region clipped to the bytes actually present.
    last = mem.regions[-1]
    assert last.addr == 0x30000 and last.size == 4
    assert mem.readv(0x30000, 4) == b"tttt"
    assert mem.v2p(0x30004) is None
    _assert_consistent(mem)


def test_cuckoomem_truncated_header_stops_parse():
    # A complete region followed by a cut-off 24-byte header.
    good = struct.pack("QIIII", 0x10000, 4, 0, 0, PAGE_READWRITE) + b"abcd"
    payload = good + b"\x10\x00"  # only 2 bytes of the next header
    mem = cuckoomem(payload)
    assert mem.regions == [Region(0x10000, 4, 0, 0, PAGE_READWRITE, 24)]
    assert mem.readv(0x10000, 4) == b"abcd"


def test_cuckoomem_overflowing_size_does_not_loop_or_crash():
    # Descriptor claims an enormous size that would advance the cursor past
    # the file. It must be clipped/dropped and parsing must stop, not loop.
    payload = (
        struct.pack("QIIII", 0x10000, 4, 0, 0, PAGE_READWRITE)
        + b"abcd"
        + struct.pack("QIIII", 0x20000, 0xFFFFFFFF, 0, 0, PAGE_READWRITE)
    )
    mem = cuckoomem(payload)
    assert [r.addr for r in mem.regions] == [0x10000]
    assert mem.readv(0x10000, 4) == b"abcd"
    _assert_consistent(mem)


def test_cuckoomem_empty_dump():
    mem = cuckoomem(b"")
    assert mem.regions == []
    assert mem.imgbase == 0
    assert mem.readv(0, 4) == b""


def test_yara_mapping_uses_canonical_regions():
    # YARA scans the raw buffer and maps physical offsets back to VAs via
    # p2v. Overlapping descriptors must not yield duplicate/alias addresses.
    # Physical layout (24 bytes):
    #   off 0..7   = 'a' * 8
    #   off 8..15  = 'b' * 8  (contains "need" at off 8, "le" at off 12)
    #   off 16..23 = 'c' * 8
    payload = b"".join([b"a" * 8, b"needle" + b"b" * 2, b"c" * 8])
    regions = [
        Region(0x10000, 8, 0, 0, 0, 0),
        # Overlaps the first; physically contiguous so p2v stays in one run.
        # Clipped to the tail (VA 0x10008-0x1000c, offset 12-15) holding "le".
        Region(0x10004, 8, 0, 0, 0, 8),
        Region(0x1000c, 8, 0, 0, 0, 16),
    ]
    mem = procmem(payload, regions=regions)
    # "need" lives wholly in the second region's physical run but is reached
    # via the clipped tail only for "le"; each string is reported exactly once
    # and never duplicated through the shadowed overlapping descriptor.
    assert list(mem.findv(b"le")) == [0x10008]
    # The shadowed alias (unclipped descriptor claimed VA 0x10004 for offset
    # 8) is gone: 0x10004 still resolves through the first region.
    assert mem.v2p(0x10004) == 4
    assert mem.readv(0x10004, 4) == b"aaaa"
    assert mem.readv(0x10008, 2) == b"le"
