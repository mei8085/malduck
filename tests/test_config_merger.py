"""
Tests for cross-dump configuration merging with provenance, confidence and
conflict/decoy handling.
"""
import json

import pytest

from malduck import procmem
from malduck.extractor import (
    ConfigSource,
    ExtractManager,
    ExtractorModules,
    FieldStatus,
    MergedConfig,
    merge_configs,
)
from malduck.extractor.config_merger import CONFIG_META_KEY, _type_category


SRC1 = ConfigSource("dump1.raw")
SRC2 = ConfigSource("dump2.raw")
SRC3 = ConfigSource("dump3.raw")


# ---------------------------------------------------------------------------
# Basic merging: equivalent values are unified, new keys are added
# ---------------------------------------------------------------------------


def test_equivalent_scalars_merge_into_single_value():
    merged = merge_configs("evil", [
        ({"family": "evil", "key": "A"}, SRC1),
        ({"family": "evil", "key": "A"}, SRC2),
    ])
    field = merged["key"]
    assert field.status == FieldStatus.TRUSTED
    assert len(field.values) == 1
    assert field.values[0].value == "A"
    assert {s.name for s in field.values[0].sources} == {"dump1.raw", "dump2.raw"}
    assert field.confidence == 1.0
    assert merged.trusted_dict()["key"] == "A"


def test_new_keys_from_other_dumps_are_collected():
    merged = merge_configs("evil", [
        ({"family": "evil", "a": 1}, SRC1),
        ({"family": "evil", "b": 2}, SRC2),
    ])
    trusted = merged.trusted_dict()
    assert trusted == {"family": "evil", "a": 1, "b": 2}


def test_lists_are_unioned_with_dedup_and_order():
    merged = merge_configs("evil", [
        ({"family": "evil", "urls": ["http://a/", "http://b/"]}, SRC1),
        ({"family": "evil", "urls": ["http://b/", "http://c/"]}, SRC2),
    ])
    field = merged["urls"]
    assert field.status == FieldStatus.TRUSTED
    assert field.values[0].value == ["http://a/", "http://b/", "http://c/"]
    assert {s.name for s in field.values[0].sources} == {"dump1.raw", "dump2.raw"}


def test_nested_dicts_are_merged_recursively():
    merged = merge_configs("evil", [
        ({"family": "evil", "meta": {"x": 1, "y": 2}}, SRC1),
        ({"family": "evil", "meta": {"y": 2, "z": 3}}, SRC2),
    ])
    field = merged["meta"]
    assert field.status == FieldStatus.TRUSTED
    assert merged.trusted_dict()["meta"] == {"x": 1, "y": 2, "z": 3}


# ---------------------------------------------------------------------------
# Conflicts: contradictory values keep all sources and block the trusted view
# ---------------------------------------------------------------------------


def test_contradictory_scalars_become_conflict():
    merged = merge_configs("evil", [
        ({"family": "evil", "key": 1}, SRC1),
        ({"family": "evil", "key": 2}, SRC2),
    ])
    field = merged["key"]
    assert field.status == FieldStatus.CONFLICT
    assert field.needs_review
    assert {v.value for v in field.values} == {1, 2}
    # Both variants keep their provenance
    sources_by_value = {v.value: {s.name for s in v.sources} for v in field.values}
    assert sources_by_value == {1: {"dump1.raw"}, 2: {"dump2.raw"}}
    # Confidence reflects the split (1 of 2 non-decoy observations each)
    assert all(v.confidence == 0.5 for v in field.values)
    # The conflicted field is not silently exposed to downstream steps
    assert "key" not in merged.trusted_dict()
    assert [f.key for f in merged.pending_review_fields()] == ["key"]
    assert not merged.is_field_trusted("key")


def test_conflict_majority_value_is_visible_but_still_blocked():
    merged = merge_configs("evil", [
        ({"family": "evil", "key": "A"}, SRC1),
        ({"family": "evil", "key": "A"}, SRC2),
        ({"family": "evil", "key": "B"}, SRC3),
    ])
    field = merged["key"]
    assert field.status == FieldStatus.CONFLICT
    best = max(field.values, key=lambda v: v.confidence)
    assert best.value == "A"
    assert best.confidence == pytest.approx(2 / 3)
    assert "key" not in merged.trusted_dict()


def test_nested_conflict_bubbles_up_and_partial_trusted_view():
    merged = merge_configs("evil", [
        ({"family": "evil", "meta": {"x": 1, "y": 1}}, SRC1),
        ({"family": "evil", "meta": {"x": 2, "y": 1}}, SRC2),
    ])
    assert merged["meta"].status == FieldStatus.CONFLICT
    # Conflict on x means the whole nested object needs review
    assert "meta" not in merged.trusted_dict()
    sub = merged["meta"].values[0].value
    assert isinstance(sub, MergedConfig)
    assert sub["x"].status == FieldStatus.CONFLICT
    assert sub["y"].status == FieldStatus.TRUSTED
    assert sub.trusted_dict() == {"y": 1}


# ---------------------------------------------------------------------------
# Type inconsistencies are never merged away
# ---------------------------------------------------------------------------


def test_type_mismatch_is_retained_not_overwritten():
    merged = merge_configs("evil", [
        ({"family": "evil", "key": 42}, SRC1),
        ({"family": "evil", "key": "42"}, SRC2),
    ])
    field = merged["key"]
    assert field.status == FieldStatus.TYPE_MISMATCH
    assert {v.value for v in field.values} == {42, "42"}
    assert "key" not in merged.trusted_dict()


def test_bool_and_int_are_distinct_categories():
    assert _type_category(True) == "bool"
    assert _type_category(1) == "int"
    merged = merge_configs("evil", [
        ({"family": "evil", "flag": True}, SRC1),
        ({"family": "evil", "flag": 1}, SRC2),
    ])
    assert merged["flag"].status == FieldStatus.TYPE_MISMATCH


def test_list_versus_scalar_is_type_mismatch():
    merged = merge_configs("evil", [
        ({"family": "evil", "urls": ["a"]}, SRC1),
        ({"family": "evil", "urls": "a"}, SRC2),
    ])
    assert merged["urls"].status == FieldStatus.TYPE_MISMATCH
    assert "urls" not in merged.trusted_dict()


# ---------------------------------------------------------------------------
# Decoys: retained, provenanced, never silently trusted
# ---------------------------------------------------------------------------


def test_decoy_only_field_is_marked_decoy():
    decoy = ConfigSource("decoy_dump.raw", decoy=True)
    merged = merge_configs("evil", [
        ({"family": "evil", "c2": "http://fake/"}, decoy),
    ])
    field = merged["c2"]
    assert field.status == FieldStatus.DECOY
    assert "c2" not in merged.trusted_dict()
    assert field.values[0].decoy_sources[0].name == "decoy_dump.raw"


def test_decoy_does_not_overwrite_trusted_value():
    decoy = ConfigSource("decoy_dump.raw", decoy=True)
    merged = merge_configs("evil", [
        ({"family": "evil", "c2": "http://real/"}, SRC1),
        ({"family": "evil", "c2": "http://fake/"}, decoy),
    ])
    field = merged["c2"]
    # Decoy variant is preserved with its source...
    assert {v.value for v in field.values} == {"http://real/", "http://fake/"}
    # ...but the field stays trusted and resolves to the non-decoy value
    assert field.status == FieldStatus.TRUSTED
    assert merged.trusted_dict()["c2"] == "http://real/"
    fake = next(v for v in field.values if v.value == "http://fake/")
    assert fake.support == 0
    assert fake.confidence == 0.0


def test_decoy_agreement_boosts_nothing_but_keeps_provenance():
    decoy = ConfigSource("decoy_dump.raw", decoy=True)
    merged = merge_configs("evil", [
        ({"family": "evil", "c2": "A"}, SRC1),
        ({"family": "evil", "c2": "A"}, decoy),
    ])
    field = merged["c2"]
    value = field.values[0]
    assert {s.name for s in value.sources} == {"dump1.raw", "decoy_dump.raw"}
    assert value.support == 1
    assert field.status == FieldStatus.TRUSTED


# ---------------------------------------------------------------------------
# Missing provenance
# ---------------------------------------------------------------------------


def test_sourceless_observation_is_retained_and_flagged():
    merged = MergedConfig("evil")
    merged.merge({"family": "evil", "key": "A"}, source=None)
    field = merged["key"]
    assert field.has_unknown_source
    # Single uncontradicted sourceless value stays usable but the gap is visible
    assert field.status == FieldStatus.TRUSTED
    assert merged.trusted_dict()["key"] == "A"
    assert field.to_dict()["has_unknown_source"] is True


def test_sourceless_conflict_cannot_be_attributed_and_blocks_field():
    merged = MergedConfig("evil")
    merged.merge({"family": "evil", "key": "A"}, source=SRC1)
    merged.merge({"family": "evil", "key": "B"}, source=None)
    field = merged["key"]
    assert field.status == FieldStatus.UNKNOWN_SOURCE
    assert field.needs_review
    assert "key" not in merged.trusted_dict()
    assert {v.value for v in field.values} == {"A", "B"}


# ---------------------------------------------------------------------------
# Serialization and API surface
# ---------------------------------------------------------------------------


def test_full_provenance_view_is_json_serializable():
    merged = merge_configs("evil", [
        ({"family": "evil", "key": 1, "urls": ["a"]}, SRC1),
        ({"family": "evil", "key": 2, "urls": ["b"]}, SRC2),
        ({"family": "evil", "only_here": True}, SRC3),
    ])
    dumped = json.dumps(merged.to_dict())
    view = json.loads(dumped)
    assert view["family"] == "evil"
    assert view["pending_review"] == ["key"]
    assert set(view["trusted_keys"]) == {"family", "urls", "only_here"}
    assert view["fields"]["key"]["status"] == "conflict"
    assert {s["name"] for s in view["sources"]} == {
        "dump1.raw",
        "dump2.raw",
        "dump3.raw",
    }


def test_bytes_values_are_json_safe():
    merged = MergedConfig("evil")
    merged.merge({"family": "evil", "blob": b"\x00\x01"}, source=SRC1)
    # to_dict must not raise
    json.dumps(merged.to_dict())


# ---------------------------------------------------------------------------
# ExtractManager integration: cross-dump merging end to end
# ---------------------------------------------------------------------------


class DummyModules:
    """Minimal stand-in for ExtractorModules used by push_config tests."""

    def __init__(self):
        self.override_paths = {}

    def compare_family_overrides(self, first, second):
        return 0


def _manager():
    return ExtractManager(DummyModules())


def test_manager_merges_configs_from_multiple_sources():
    manager = _manager()
    assert manager.push_config(
        {"family": "evil", "key": "A", "urls": ["u1"]},
        source=ConfigSource("dump1"),
    )
    assert manager.push_config(
        {"family": "evil", "key": "A", "urls": ["u2"]},
        source=ConfigSource("dump2"),
    )
    assert len(manager.merged_configs) == 1
    merged = manager.merged_configs["evil"]
    assert merged["key"].status == FieldStatus.TRUSTED
    assert merged.trusted_dict()["urls"] == ["u1", "u2"]
    # Backward-compatible flat view
    assert manager.config == [
        {"family": "evil", "key": "A", "urls": ["u1", "u2"]}
    ]
    assert [m.family for m in manager.merged] == ["evil"]


def test_manager_conflict_is_visible_in_merged_view_not_flat_view():
    manager = _manager()
    manager.push_config(
        {"family": "evil", "key": 1}, source=ConfigSource("dump1")
    )
    manager.push_config(
        {"family": "evil", "key": 2}, source=ConfigSource("dump2")
    )
    assert manager.config == [{"family": "evil"}]
    merged = manager.merged_configs["evil"]
    assert merged["key"].status == FieldStatus.CONFLICT
    assert [f.key for f in merged.pending_review_fields()] == ["key"]


def test_manager_decoy_flag_via_argument_and_meta():
    manager = _manager()
    manager.push_config(
        {"family": "evil", "c2": "real"}, source=ConfigSource("dump1")
    )
    # Decoy marked explicitly through push_config
    manager.push_config(
        {"family": "evil", "c2": "fake"},
        source=ConfigSource("dump2"),
        decoy=True,
    )
    # Decoy marked through the reserved __meta__ key
    manager.push_config(
        {"family": "evil", "other": "x", CONFIG_META_KEY: {"decoy": True}},
        source=ConfigSource("dump3"),
    )
    merged = manager.merged_configs["evil"]
    assert merged.trusted_dict()["c2"] == "real"
    assert merged["other"].status == FieldStatus.DECOY
    assert "other" not in merged.trusted_dict()


def test_manager_sourceless_config_does_not_crash_and_flags_gap():
    manager = _manager()
    assert manager.push_config({"family": "evil", "key": "A"})
    merged = manager.merged_configs["evil"]
    assert merged["key"].has_unknown_source
    assert manager.config == [{"family": "evil", "key": "A"}]


def test_manager_explicit_decoy_overrides_non_decoy_current_source():
    manager = _manager()
    manager._source_stack.append(ConfigSource("dump1"))
    manager.push_config({"family": "evil", "key": "A"}, decoy=True)
    field = manager.merged_configs["evil"]["key"]
    assert field.status == FieldStatus.DECOY
    assert field.values[0].sources[0].decoy is True


def test_manager_push_config_without_family_is_ignored():
    manager = _manager()
    assert manager.push_config({"key": "A"}, source=SRC1) is False
    assert manager.merged_configs == {}
    assert manager.config == []


def test_meta_key_survives_multiple_partial_configs_without_override_error():
    """Two partial configs from one dump both carrying __meta__ must merge,
    not raise the apply_config_part override RuntimeError."""
    from malduck.extractor.extract_manager import ExtractionContext

    manager = _manager()
    ctx = ExtractionContext(parent=manager)

    class FakeExtractor:
        pass

    ctx.push_config(
        {"family": "evil", "a": 1, CONFIG_META_KEY: {"decoy": True}},
        FakeExtractor(),
    )
    # Second partial with a different meta dict and a different field must work
    ctx.push_config(
        {"family": "evil", "b": 2, CONFIG_META_KEY: {"decoy": True, "note": "x"}},
        FakeExtractor(),
    )
    assert ctx.collected_config[CONFIG_META_KEY] == {"decoy": True, "note": "x"}
    assert ctx.collected_config["a"] == 1
    assert ctx.collected_config["b"] == 2

    manager.push_config(ctx.collected_config, source=ConfigSource("d"))
    merged = manager.merged_configs["evil"]
    assert merged["a"].status == FieldStatus.DECOY
    assert merged["b"].status == FieldStatus.DECOY


def test_manager_type_mismatch_is_kept_for_review():
    manager = _manager()
    manager.push_config(
        {"family": "evil", "key": 1}, source=ConfigSource("dump1")
    )
    manager.push_config(
        {"family": "evil", "key": 1}, source=ConfigSource("dump2")
    )
    assert manager.config == [{"family": "evil", "key": 1}]
    manager.push_config(
        {"family": "evil", "key": 1.2}, source=ConfigSource("dump3")
    )
    merged = manager.merged_configs["evil"]
    assert merged["key"].status == FieldStatus.TYPE_MISMATCH
    assert "key" not in manager.config[0]
    # Nothing was overwritten: both representations remain with provenance
    field = merged["key"]
    assert {v.value for v in field.values} == {1, 1.2}
    assert {s.name for v in field.values for s in v.sources} == {
        "dump1",
        "dump2",
        "dump3",
    }


def test_manager_override_family_still_replaces_stored_family():
    class OverrideModules:
        override_paths = {
            "citadel": [["citadel", "zeus"]],
            "zeus": [["citadel", "zeus"]],
        }

        def compare_family_overrides(self, first, second):
            path = ["citadel", "zeus"]
            if path.index(first) < path.index(second):
                return -1
            return 1

    manager = ExtractManager(OverrideModules())
    manager.push_config(
        {"family": "zeus", "key": "z"}, source=ConfigSource("dump1")
    )
    manager.push_config(
        {"family": "citadel", "key": "c"}, source=ConfigSource("dump2")
    )
    assert list(manager.merged_configs) == ["citadel"]
    assert manager.config[0]["family"] == "citadel"


# ---------------------------------------------------------------------------
# End-to-end: real extractor engine fed with multiple dumps
# ---------------------------------------------------------------------------


def test_end_to_end_provenance_across_multiple_procmems():
    modules = ExtractorModules("tests/files/modules")
    manager = ExtractManager(modules)

    dump1 = procmem(b"FiRsT string fIrSt string"
                    b"SeCoNd string sEcOnD string"
                    b"ThIrD string")
    dump2 = procmem(b"FiRsT string"
                    b"SeCoNd string sEcOnD string"
                    b"ThIrD string")

    manager.push_procmem(dump1, source="dump-a.bin")
    manager.push_procmem(dump2, source="dump-b.bin")

    assert len(manager.merged_configs) == 1
    merged = manager.merged_configs["multistring"]
    # Both dumps are recorded as provenance
    assert {source.name for source in merged.sources} == {
        "dump-a.bin",
        "dump-b.bin",
    }
    # Equivalent list elements unioned, nothing conflicts
    assert merged["first"].status == FieldStatus.TRUSTED
    first = merged["first"].values[0]
    assert "FiRsT string" in first.value and "SeCoNd string" in first.value
    assert {source.name for source in first.sources} == {
        "dump-a.bin",
        "dump-b.bin",
    }
    # Flat backward-compatible view still works
    assert manager.config[0]["family"] == "multistring"
    assert "ThIrD string" in manager.config[0]["third"]


def test_end_to_end_sourceless_dump_keeps_fields_without_crash():
    modules = ExtractorModules("tests/files/modules")
    manager = ExtractManager(modules)
    dump = procmem(b"strongyweakyx")
    manager.push_procmem(dump)
    # No source given: fields remain usable but provenance gap is recorded
    merged = manager.merged_configs["weaky"]
    assert merged["weak"].has_unknown_source
    assert manager.config[0] == {
        "family": "weaky",
        "weak": True,
        "weaky": True,
    }


def test_end_to_end_decoy_dump_never_promotes_its_values_to_trusted():
    modules = ExtractorModules("tests/files/modules")
    trusted_manager = ExtractManager(modules)
    trusted_manager.push_procmem(
        procmem(b"strongyweakyx"), source=ConfigSource("real-dump")
    )

    decoy_manager = ExtractManager(modules)
    decoy_manager.push_procmem(
        procmem(b"strongyweakyx"),
        source=ConfigSource("decoy-dump", decoy=True),
    )

    real = trusted_manager.merged_configs["weaky"]
    decoy = decoy_manager.merged_configs["weaky"]
    assert real["weak"].status == FieldStatus.TRUSTED
    assert decoy["weak"].status == FieldStatus.DECOY
    assert decoy["weak"].needs_review
    assert "weak" not in decoy.trusted_dict()
