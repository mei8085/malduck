import hashlib
import os
import struct

from malduck import procmem, procmempe, xor
from malduck.extractor import ExtractManager, ExtractorModules


def test_scan_base64():
    modules = ExtractorModules("tests/files/modules")
    assert "Unbase64" in [extractor.__name__ for extractor in modules.extractors]

    for fname in os.listdir("tests/files"):
        fpath = os.path.join("tests/files", fname)
        if os.path.isfile(fpath):
            extractor = ExtractManager(modules)
            extractor.push_file(fpath)
            if extractor.config:
                assert len(extractor.config) == 1
                matched_base = extractor.config[0].get("base64", False)
            else:
                matched_base = False
            should_be_base = fname.endswith(".b64")
            # To be or not to be
            assert matched_base == should_be_base


def test_scan_ollydbg():
    modules = ExtractorModules("tests/files/modules")
    olly = procmempe.from_file("tests/files/ollydbg.exe", image=True)
    cfg = olly.extract(modules)[0]

    assert cfg["family"] == "ollydbg"
    assert sorted(cfg["olly"]) == [
        " - OllyDbg is a JIT debugger\n",
        " - OllyDbg is in Explorer's menu\n",
        " - OllyDbg is not in Explorer's menu"
    ]
    assert "olly_is_not" in cfg["matches"]


def test_apliebe():
    modules = ExtractorModules("tests/files/modules")
    p = procmem.from_file("tests/files/mal1.b64")
    assert p.extract(modules) == [{
        "base64": True,
        "family": "apliebe",
        "str_to_int_offs": [0x1000a410]
    }]


def test_weaky():
    modules = ExtractorModules("tests/files/modules")
    weaky = procmem(b"weakyx")
    strongy = procmem(b"strongy")
    strongyweaky = procmem(b"strongyweakyx")
    assert not weaky.extract(modules)
    assert strongy.extract(modules) == [{
        "family": "weaky"
    }]
    assert strongyweaky.extract(modules) == [{
        "family": "weaky",
        "weak": True,
        "weaky": True
    }]


def test_multirules():
    modules = ExtractorModules("tests/files/modules")
    multistring = procmem(b"FiRsT string fIrSt string"
                          b"SeCoNd string sEcOnD string"
                          b"ThIrD string tHiRd string")
    assert multistring.extract(modules) == [{
        'family': 'multistring',
        'first': ['FiRsT string', 'fIrSt string', 'SeCoNd string', 'sEcOnD string'],
        'third': ['ThIrD string']
    }]

    multistring_v2 = procmem(b"ThIrD stringa0a1b2b3c4c5d6d7e8e9FoUrTh string")
    assert multistring_v2.extract(modules) == [{
        'family': 'multistring_v2',
        'matched': ['v2'],
        'third': ['ThIrD string']
    }]


def make_nested_dropper(payload):
    encoded = xor(0x42, payload)
    return b"NESTEDLAYER:" + struct.pack("<I", len(encoded)) + encoded


def test_nested_recursive_extraction():
    # Multi-stage dropper: nested layer wrapping a payload of an unrelated family
    modules = ExtractorModules("tests/files/modules")
    alien = b"ALIENSTRUCT:" + b"\xde\xad\xbe\xef"
    manager = ExtractManager(modules)
    manager.push_procmem(procmem(make_nested_dropper(alien)))
    # Configurations of unrelated families are isolated, not merged
    assert sorted(manager.config, key=lambda c: c["family"]) == [
        {"family": "alien", "alien_marker": [0]},
        {"family": "nested", "layers": [0]},
    ]
    # Provenance of the nested payload is recorded
    assert len(manager.payloads) == 1
    record = manager.payloads[0]
    assert record["status"] == "ok"
    assert record["depth"] == 1
    assert record["source_family"] == "nested"
    assert record["family"] == "alien"
    assert record["encoding"] == "xor:0x42"
    assert record["offset"] == 16
    assert record["length"] == len(alien)
    assert record["sha256"] == hashlib.sha256(alien).hexdigest()


def test_nested_multilayer():
    # Two nesting layers around an unrelated family payload
    modules = ExtractorModules("tests/files/modules")
    alien = b"ALIENSTRUCT:" + b"\xaa" * 4
    dropper = make_nested_dropper(make_nested_dropper(alien))
    manager = ExtractManager(modules)
    manager.push_procmem(procmem(dropper))
    assert sorted(manager.config, key=lambda c: c["family"]) == [
        {"family": "alien", "alien_marker": [0]},
        {"family": "nested", "layers": [0]},
    ]
    assert [rec["depth"] for rec in manager.payloads] == [1, 2]
    assert [rec["status"] for rec in manager.payloads] == ["ok", "ok"]
    assert manager.payloads[0]["source_family"] == "nested"
    assert manager.payloads[1]["source_family"] == "nested"
    assert manager.payloads[1]["family"] == "alien"


def test_mixed_families_same_buffer():
    # Structures of two unrelated families mixed into the same buffer:
    # none of them may be misattributed to the other family
    modules = ExtractorModules("tests/files/modules")
    buf = b"NESTEDLAYER:" + struct.pack("<I", 0) + b"ALIENSTRUCT:" + b"\x01\x02"
    manager = ExtractManager(modules)
    manager.push_procmem(procmem(buf))
    assert sorted(manager.config, key=lambda c: c["family"]) == [
        {"family": "alien", "alien_marker": [16]},
        {"family": "nested", "layers": [0]},
    ]


def test_nested_circular_payload():
    # Payload decodes to a buffer that decodes back to the original one:
    # circular nesting must stop the branch
    modules = ExtractorModules("tests/files/modules")
    marker = b"CIRCULARPAYLOAD:"
    buf = marker + xor(0x42, marker)
    manager = ExtractManager(modules)
    manager.push_procmem(procmem(buf))
    assert manager.config == [{"family": "looper", "looped": True}]
    assert [rec["status"] for rec in manager.payloads] == ["ok", "circular"]


def test_nested_depth_limit():
    # Each layer produces a new payload: nesting depth must be bounded
    modules = ExtractorModules("tests/files/modules")
    manager = ExtractManager(modules, max_payload_depth=4)
    manager.push_procmem(procmem(b"DEPTHPAYLOAD:"))
    assert manager.config == [{"family": "bomber", "bombed": True}]
    assert [rec["status"] for rec in manager.payloads] == ["ok"] * 4 + ["max-depth"]
    assert [rec["depth"] for rec in manager.payloads] == [1, 2, 3, 4, 5]


def test_nested_payload_budget():
    # Malicious sample spawning unbounded payloads: count budget stops the branch
    modules = ExtractorModules("tests/files/modules")
    manager = ExtractManager(modules, max_payload_depth=16, max_payloads=3)
    manager.push_procmem(procmem(b"DEPTHPAYLOAD:"))
    assert [rec["status"] for rec in manager.payloads] == ["ok"] * 3 + [
        "budget-exceeded"
    ]
    assert manager.config == [{"family": "bomber", "bombed": True}]

    # Total payload size is bounded as well
    manager = ExtractManager(modules, max_payload_depth=16, max_payload_bytes=20)
    manager.push_procmem(procmem(b"DEPTHPAYLOAD:"))
    assert [rec["status"] for rec in manager.payloads] == ["ok", "budget-exceeded"]
    assert manager.config == [{"family": "bomber", "bombed": True}]


def test_nested_truncated_payload():
    # Declared payload length is huge but the payload is truncated:
    # the branch stops without consuming unbounded resources
    modules = ExtractorModules("tests/files/modules")
    buf = b"NESTEDLAYER:" + struct.pack("<I", 0xFFFFFFFF) + b"short"
    manager = ExtractManager(modules)
    manager.push_procmem(procmem(buf))
    assert manager.config == [{"family": "nested", "truncated": True}]
    assert manager.payloads == []


def test_nested_decode_failure():
    # Decoding failure stops the branch but the config collected
    # so far is preserved
    modules = ExtractorModules("tests/files/modules")
    buf = b"FAULTYPAYLOAD:" + b"B64PAYLOAD:" + b"!!!not-base64!!!"
    manager = ExtractManager(modules)
    manager.push_procmem(procmem(buf))
    assert manager.config == [{"family": "faulty", "attempted": True}]
