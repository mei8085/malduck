"""
Tests for strict Windows key-blob import and provenance binding.

Key material found in a process memory dump is attacker-controlled. These tests
cover the trust boundary requested for the feature:

* a key structure is only accepted when its region address, its declared
  length and its structure version all validate,
* accepted keys are bound to the origin region and to their algorithm family,
* overlapping regions, truncated structures, overflowing lengths and several
  competing keys produce *distinguishable* failures instead of ``None``,
* later decryption through the imported object uses the same cipher family,
* the analyser fails closed for hostile dumps.
"""

import binascii
import struct

import pytest

from malduck import aes, procmem
from malduck.crypto import keyblob
from malduck.crypto.keyblob import (
    MAX_KEY_BLOB_SIZE,
    KeyFamily,
    KeyImportResult,
    KeyImportStatus,
    KeyMaterial,
    parse_key_blob,
    plan_key_blob,
    scan_key_blobs,
)
from malduck.procmem import Region

AES_KEY = b"A" * 16
AES_KEY_256 = b"K" * 32


def aes_blob(key=AES_KEY, alg=0x0000660E):
    return struct.pack("<BBHI", 8, 2, 0, alg) + struct.pack("<I", len(key)) + key


RSA_PRIVATE_BLOB = binascii.a2b_base64(b"""
BwIAAACkAABSU0EyAAQAAAEAAQCxTx++ykWtb2UaYFYQLt1yM893SV/wLehU2DwzeAMpxq5MsOF5
XVAd1qSElMN8Uqxdn7FXuT4XFJjH2o6MsnkheoWKPmIC357IUk/N/49dyjtk14In+HdxWKKoguXd
lOfGoriyieo8cr4kYCoYGPpHNv50NlZi3jkzQvW+hVK6v/ufshtYBRd/+NjecYVQlt7ivap8d/9g
szM+eSC91zZm8OPUCmfQX8AJOq9r7LUB/tS5DLswtJZdDDmpjhbGf/ZDg+YhHFPYvRlnGP4PlXBW
Qds44ZlSJJ780+tDuxP3Zn1Nfch4IZjkATGx7Zd9tzr8iLDe0zAGzJDaV92qHR7Hn5V5VGH1dZk2
DMiR1893vJfuE9RwDja6hUycXNjj9Y1fCYGK3rsVGO7+Dg9xab3HFqueydlMgir8MD4jShsaXk2P
jUYp2KdJuyN6BZP1oorUntgJIJGeoK59w5Vxni64rJp6KKhsKiOWM37cWAVYmd3dc0PeF3R9s/1Y
nTMtXoo1r77CjBv5q+zvMSzeFUl+ji9beSZbzl9rAvJOBw4v1Bj8EzPq5aYvEs7h9M66BbZjuyeH
zp2sRBuxE6K13j1AIVHCK7gbVwlieHWKuE5d45ealzSsChwoxGlJcHlHBI62zQqo7SHbb2An72IS
XtyKY18/3bYV4nv6ydeC9zgpVlNfGwgwP05Rkp7ldJsCz7uT6RAANV86JIp+65SCKs4gcgWWPIbn
KJ4s7fs/3oy7tUSTdviZShGj2cJGiEIyIiA=
""")


def mem_with(blob, base=0x41410000, padding=0x100):
    data = b"\x00" * padding + blob + b"\x00" * padding
    regions = [Region(base, len(data), 0, 0, 0, 0)]
    return procmem(data, base=base, regions=regions), base + padding


# ---------------------------------------------------------------------------
# Buffer-level parsing
# ---------------------------------------------------------------------------


def test_parse_aes_blob():
    result = parse_key_blob(aes_blob())
    assert result.ok
    assert result.status is KeyImportStatus.OK
    assert result.material is not None
    assert result.material.family is KeyFamily.AES
    assert result.material.algorithm == "AES-128"
    assert result.export_key() == AES_KEY
    assert result.material.bits == 128
    assert not result.material.private


def test_parse_aes_256_blob():
    result = parse_key_blob(aes_blob(AES_KEY_256, 0x00006610))
    assert result.ok
    assert result.material.algorithm == "AES-256"
    assert result.export_key() == AES_KEY_256


def test_parse_rsa_private_blob():
    result = parse_key_blob(RSA_PRIVATE_BLOB)
    assert result.ok
    assert result.material.family is KeyFamily.RSA
    assert result.material.private
    assert result.material.bits == 1024
    assert result.export_key().startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_parse_returns_distinguishable_failures():
    blob = aes_blob()

    assert parse_key_blob(b"").status is KeyImportStatus.NO_HEADER
    assert parse_key_blob(blob[:4]).status is KeyImportStatus.NO_HEADER

    # Wrong structure version.
    bad_version = blob[:1] + b"\x01" + blob[2:]
    assert parse_key_blob(bad_version).status is KeyImportStatus.BAD_VERSION
    # Requesting an explicit version that does not match is a hard failure too.
    assert (
        parse_key_blob(blob, expected_version=1).status is KeyImportStatus.BAD_VERSION
    )

    # Non-zero reserved field.
    bad_reserved = blob[:2] + b"\x01\x00" + blob[4:]
    assert parse_key_blob(bad_reserved).status is KeyImportStatus.BAD_RESERVED

    # Unsupported blob type.
    bad_type = b"\x09" + blob[1:]
    assert parse_key_blob(bad_type).status is KeyImportStatus.UNSUPPORTED

    # Algorithm / blob type mismatch.
    bad_alg = blob[:4] + struct.pack("<I", 0x0000A400) + blob[8:]
    assert parse_key_blob(bad_alg).status is KeyImportStatus.UNSUPPORTED

    # Truncated structure.
    assert parse_key_blob(blob[:-1]).status is KeyImportStatus.TRUNCATED

    # Declared length larger than the buffer: overflowing/truncated, not read.
    overflow = blob[:8] + struct.pack("<I", MAX_KEY_BLOB_SIZE) + AES_KEY
    assert parse_key_blob(overflow).status in (
        KeyImportStatus.LENGTH_OVERFLOW,
        KeyImportStatus.TRUNCATED,
    )
    huge = blob[:8] + struct.pack("<I", 0xFFFFFFFF) + AES_KEY
    assert parse_key_blob(huge).status is KeyImportStatus.LENGTH_OVERFLOW

    # Declared length smaller than the supplied buffer.
    assert parse_key_blob(blob + b"extra").status is KeyImportStatus.LENGTH_MISMATCH
    assert parse_key_blob(blob + b"extra", allow_trailing=True).ok

    # Key size does not match the fixed algorithm identifier.
    wrong_size = blob[:4] + struct.pack("<I", 0x0000660E) + struct.pack("<I", 32)
    wrong_size += b"S" * 32
    assert parse_key_blob(wrong_size).status is KeyImportStatus.INVALID_KEY


def test_parse_does_not_raise_on_hostile_input():
    # Every single-byte mutation must produce a result, never an exception.
    blob = aes_blob()
    for idx in range(len(blob)):
        for value in (0x00, 0xFF, 0x02, 0x08):
            mutated = bytearray(blob)
            mutated[idx] = value
            parse_key_blob(bytes(mutated))
    # Random-ish header garbage.
    for header in (
        b"\x07\x02\x00\x00\x00\x00\x00\x00",
        b"\x06\x02\x00\x00\x00\xa4\x00\x00",
    ):
        parse_key_blob(header + b"\xff" * 64)


def test_parse_generic_aes_algorithm_size_validation():
    # CALG_AES carries the size in the blob, but only supported sizes pass.
    assert parse_key_blob(aes_blob(AES_KEY, 0x00006611)).ok
    assert parse_key_blob(aes_blob(AES_KEY_256, 0x00006611)).ok
    assert (
        parse_key_blob(aes_blob(b"S" * 20, 0x00006611)).status
        is KeyImportStatus.INVALID_KEY
    )


def test_family_constraint():
    blob = aes_blob()
    assert (
        parse_key_blob(blob, expected_family=KeyFamily.RSA).status
        is KeyImportStatus.FAMILY_MISMATCH
    )
    assert parse_key_blob(blob, expected_family=KeyFamily.AES).ok


def test_result_truthiness_and_json():
    ok = parse_key_blob(aes_blob())
    assert ok
    assert not ok.failed
    assert not ok.ambiguous

    bad = parse_key_blob(b"")
    assert not bad
    assert bad.failed
    assert bad.material is None
    assert bad.export_key() is None

    payload = ok.to_json()
    assert payload["status"] == "ok"
    assert payload["material"]["family"] == "aes"
    assert "key" not in payload["material"]


def test_plan_rejects_overlong_rsa_before_reading():
    # A hostile header claiming a gigantic modulus must be rejected from the
    # prefix alone, without requiring the declared number of bytes.
    header = struct.pack("<BBHI", 6, 2, 0, 0x0000A400)
    rsa_pub = struct.pack("<4sII", b"RSA1", 0xFFFFFFFF & ~7, 65537)
    result = parse_key_blob(header + rsa_pub)
    assert result.status in (
        KeyImportStatus.LENGTH_OVERFLOW,
        KeyImportStatus.TRUNCATED,
    )

    with pytest.raises(keyblob.KeyImportError):
        plan_key_blob(header + rsa_pub, len(header + rsa_pub) + (1 << 22))


# ---------------------------------------------------------------------------
# Region-bound import
# ---------------------------------------------------------------------------


def test_import_key_binds_region_and_family():
    mem, addr = mem_with(aes_blob())
    result = mem.import_key(addr)
    assert result.ok
    material = result.material
    assert material is not None
    assert material.region is mem.regions[0]
    assert material.addr == addr
    assert material.offset == 0x100
    assert material.size == len(aes_blob())
    assert material.end == addr + len(aes_blob())
    assert material.family is KeyFamily.AES
    # Provenance survives in the result as well.
    assert result.region is mem.regions[0]
    assert result.addr == addr
    assert result.offset == 0x100


def test_import_key_by_offset():
    mem, addr = mem_with(aes_blob())
    result = mem.import_key(offset=0x100)
    assert result.ok
    assert result.addr == addr
    assert result.material.region is mem.regions[0]


def test_import_key_requires_exactly_one_locator():
    mem, addr = mem_with(aes_blob())
    assert mem.import_key().status is KeyImportStatus.REGION_MISMATCH
    assert mem.import_key(addr, offset=0x100).status is KeyImportStatus.REGION_MISMATCH


def test_import_key_unmapped_address():
    mem, addr = mem_with(aes_blob())
    result = mem.import_key(addr + 0x10000)
    assert result.status is KeyImportStatus.REGION_MISMATCH
    assert not result


def test_import_key_overlapping_regions_fail_closed():
    blob = aes_blob()
    data = b"\x00" * 0x100 + blob
    # Two descriptors claim the same virtual range: the bytes are ambiguous.
    regions = [
        Region(0x1000, len(data), 0, 0, 0, 0),
        Region(0x1000, len(data), 0, 0, 0, 0),
    ]
    mem = procmem(data, regions=regions)
    assert mem.import_key(0x1100).status is KeyImportStatus.REGION_OVERLAP


def test_import_key_structure_crossing_region_end_is_truncated():
    blob = aes_blob()
    data = b"\x00" * 0x100 + blob
    # Region ends in the middle of the key structure.
    regions = [Region(0x1000, 0x100 + len(blob) - 1, 0, 0, 0, 0)]
    mem = procmem(data, regions=regions)
    result = mem.import_key(0x1100)
    assert result.status is KeyImportStatus.TRUNCATED
    assert result.size == len(blob)


def test_import_key_structure_crossing_region_into_other_region():
    blob = aes_blob()
    data = b"\x00" * 0x100 + blob
    # The region ends mid-structure; a second region happens to map the tail.
    # The structure is incomplete in its origin region, so it is reported as
    # truncated rather than being stitched together from two regions.
    regions = [
        Region(0x1000, 0x100 + len(blob) - 4, 0, 0, 0, 0),
        Region(0x1110, 0x100, 0, 0, 0, 0x100),
    ]
    mem = procmem(data, regions=regions)
    assert mem.import_key(0x1100).status is KeyImportStatus.TRUNCATED


def test_import_key_fully_mapped_but_overlapping_region_is_ambiguous():
    blob = aes_blob()
    data = b"\x00" * 0x100 + blob
    # The origin region fully covers the structure, but a second descriptor
    # also maps part of it: the bytes are ambiguous and must not be trusted.
    regions = [
        Region(0x1000, 0x100 + len(blob), 0, 0, 0, 0),
        Region(0x1110, 0x100, 0, 0, 0, 0x100),
    ]
    mem = procmem(data, regions=regions)
    assert mem.import_key(0x1100).status is KeyImportStatus.REGION_OVERLAP


def test_import_key_short_region_header():
    # Region too small to even hold a BLOBHEADER must not be treated as a key.
    mem = procmem(b"\x08\x02\x00\x00", regions=[Region(0x1000, 4, 0, 0, 0, 0)])
    result = mem.import_key(0x1000)
    assert result.status is KeyImportStatus.REGION_MISMATCH


def test_import_key_version_constraint():
    blob = aes_blob()
    mem, addr = mem_with(blob)
    bad_version = blob[:1] + b"\x01" + blob[2:]
    mem_bad, addr_bad = mem_with(bad_version)
    assert mem_bad.import_key(addr_bad).status is KeyImportStatus.BAD_VERSION
    assert mem.import_key(addr, expected_version=2).ok


def test_import_key_family_constraint():
    mem, addr = mem_with(aes_blob())
    assert (
        mem.import_key(addr, expected_family=KeyFamily.RSA).status
        is KeyImportStatus.FAMILY_MISMATCH
    )


def test_import_key_rsa_private():
    mem, addr = mem_with(RSA_PRIVATE_BLOB)
    result = mem.import_key(addr)
    assert result.ok
    assert result.material.family is KeyFamily.RSA
    assert result.material.private
    assert result.material.region is mem.regions[0]
    assert result.material.addr == addr


def test_import_key_does_not_read_beyond_region():
    # Region claims a huge size but the backing buffer is short: the import
    # must report truncation instead of reading fabricated bytes.
    blob = aes_blob()[:14]
    mem = procmem(blob, regions=[Region(0x1000, 0x1000, 0, 0, 0, 0)])
    result = mem.import_key(0x1000)
    assert result.status in (
        KeyImportStatus.TRUNCATED,
        KeyImportStatus.REGION_MISMATCH,
    )


# ---------------------------------------------------------------------------
# Decryption through the imported object keeps the family
# ---------------------------------------------------------------------------


def test_material_decrypts_with_its_own_family():
    mem, addr = mem_with(aes_blob())
    material = mem.import_key(addr).material
    assert material is not None

    iv = b"B" * 16
    plaintext = b"C" * 16
    ciphertext = aes.cbc.encrypt(AES_KEY, iv, plaintext)
    assert material.decrypt(ciphertext, iv=iv) == plaintext
    assert material.decrypt(ciphertext, mode="cbc", iv=iv) == plaintext


def test_material_rsa_roundtrip():
    mem, addr = mem_with(RSA_PRIVATE_BLOB)
    material = mem.import_key(addr).material
    assert material is not None

    message = b"configuration blob"
    ciphertext = material.encrypt(message)
    assert material.decrypt(ciphertext) == message


def test_rsa_public_material_refuses_decryption():
    # Public key: must not silently attempt RSA private operations.
    n = 0xC87F0A3E4B5D69788293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F1
    e = 65537
    material = KeyMaterial(
        KeyFamily.RSA, "RSA-PUBLIC", b"pem", 0x0000A400, 6, bitsize=256, private=False
    )
    with pytest.raises(ValueError):
        material.decrypt(b"\x00" * 32)


def test_material_rejects_unknown_mode():
    mem, addr = mem_with(aes_blob())
    material = mem.import_key(addr).material
    assert material is not None
    with pytest.raises(ValueError):
        material.decrypt(b"\x00" * 16, mode="gcm", iv=b"B" * 16)
    with pytest.raises(ValueError):
        material.decrypt(b"\x00" * 16, mode="cbc")


# ---------------------------------------------------------------------------
# Whole-dump scanning and ambiguity
# ---------------------------------------------------------------------------


def test_scan_single_key():
    mem, addr = mem_with(aes_blob())
    result = mem.scan_keys()
    assert result.ok
    assert result.material.addr == addr
    assert result.material.region is mem.regions[0]


def test_scan_ambiguous_keys_fail_closed():
    other = aes_blob(b"Q" * 16)
    blob = aes_blob()
    data = blob + b"\x00" * 8 + other
    mem = procmem(data, regions=[Region(0x4000, len(data), 0, 0, 0, 0)])
    result = mem.scan_keys()
    assert result.status is KeyImportStatus.AMBIGUOUS
    assert not result
    assert result.material is None
    assert len(result.candidates) == 2
    assert {c.key for c in result.candidates} == {AES_KEY, b"Q" * 16}
    # Candidates keep their provenance.
    assert all(c.region is mem.regions[0] for c in result.candidates)


def test_scan_duplicate_key_is_not_ambiguous():
    blob = aes_blob()
    data = blob + b"\x00" * 8 + blob
    mem = procmem(data, regions=[Region(0x4000, len(data), 0, 0, 0, 0)])
    result = mem.scan_keys()
    assert result.ok


def test_scan_across_regions_ambiguous():
    blob_a = aes_blob()
    blob_b = aes_blob(b"R" * 16)
    data = blob_a + b"\x00" * 8 + blob_b
    regions = [
        Region(0x1000, len(blob_a), 0, 0, 0, 0),
        Region(0x2000, len(blob_b), 0, 0, 0, len(blob_a) + 8),
    ]
    mem = procmem(data, regions=regions)
    result = mem.scan_keys()
    assert result.status is KeyImportStatus.AMBIGUOUS
    assert len(result.candidates) == 2


def test_scan_overlapping_regions_reports_overlap():
    blob = aes_blob()
    data = b"\x00" * 0x10 + blob
    regions = [
        Region(0x1000, len(data), 0, 0, 0, 0),
        Region(0x1000, len(data), 0, 0, 0, 0),
    ]
    mem = procmem(data, regions=regions)
    result = mem.scan_keys()
    assert result.status is KeyImportStatus.REGION_OVERLAP
    assert not result


def test_scan_overlap_elsewhere_fails_closed():
    # A valid key sits in one region, but an unrelated overlapping pair of
    # descriptors exists elsewhere: the dump is partially ambiguous, so the
    # scan must not report a trusted key.
    blob = aes_blob()
    data = blob + b"\x00" * 8
    regions = [
        Region(0x1000, len(blob), 0, 0, 0, 0),
        Region(0x2000, len(data), 0, 0, 0, len(blob) + 8),
        Region(0x2000, len(data), 0, 0, 0, len(blob) + 8),
    ]
    mem = procmem(data, regions=regions)
    result = mem.scan_keys()
    assert result.status is KeyImportStatus.REGION_OVERLAP
    assert not result


def test_scan_no_candidates():
    mem = procmem(b"\x00" * 0x1000, regions=[Region(0x1000, 0x1000, 0, 0, 0, 0)])
    result = mem.scan_keys()
    assert result.status is KeyImportStatus.NO_HEADER


def test_scan_bounded_on_hostile_region():
    # Thousands of fake algorithm signatures must not make the scan unbounded
    # or raise; it terminates and reports a distinguishable failure.
    signature = struct.pack("<I", 0x0000660E)
    payload = (b"\x00\x00\x00\x00" + signature + b"\xff" * 4) * 2000
    mem = procmem(payload, regions=[Region(0x1000, len(payload), 0, 0, 0, 0)])
    result = mem.scan_keys()
    assert not result
    assert result.status is not KeyImportStatus.OK


def test_scan_checking_truthiness_fails_closed():
    data = aes_blob() + b"\x00" * 8 + aes_blob(b"Z" * 16)
    mem = procmem(data, regions=[Region(0x4000, len(data), 0, 0, 0, 0)])
    result = mem.scan_keys()
    # A caller that writes ``if result:`` must not proceed on ambiguity.
    assert bool(result) is False
    assert bool(mem.scan_keys()) is False


def test_scan_key_blobs_buffer_level():
    result = scan_key_blobs(aes_blob() + b"\x00" * 8)
    assert result.ok
    assert result.material.offset == 0
    assert result.material.addr is None


def test_legacy_aes_import_key_still_works():
    assert aes.import_key(aes_blob()) == ("AES-128", AES_KEY)
