"""
Cross-dump configuration merging.

Configs ripped from multiple memory dumps of the same malware family need to be
combined without losing provenance. This module keeps, for every field, every
distinct observed value together with the dumps (sources) that reported it.

Equivalent values are merged into a single field entry. Contradictory values,
type inconsistencies and values coming from configurations flagged as decoys
are never used to silently overwrite an already collected value: they are
preserved on the resulting object with a :class:`FieldStatus` and a per-value
confidence. Observations without a proven source are retained with a visible
provenance gap, and any such anonymous observation that contradicts a sourced
one blocks the field pending review, so that later decryption and analysis
steps can tell trusted fields apart from fields that require review.

Typical usage::

    from malduck.extractor.config_merger import ConfigSource, merge_configs

    merged = merge_configs(family="evil")
    merged.merge({"urls": ["http://a/"], "key": 1},
                 source=ConfigSource("dump1.raw"))
    merged.merge({"urls": ["http://b/"], "key": 2},
                 source=ConfigSource("dump2.raw"))

    merged.trusted_dict            # only fields safe to feed downstream steps
    merged.pending_review_fields() # fields an analyst must look at
    merged.to_dict()               # full provenance, JSON-serializable
"""

import logging
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

log = logging.getLogger(__name__)

#: Key reserved for per-config flags consumed by the merger (e.g. decoys).
#: It never reaches the collected configuration itself.
CONFIG_META_KEY = "__meta__"

__all__ = [
    "CONFIG_META_KEY",
    "FieldStatus",
    "ConfigSource",
    "FieldValue",
    "MergedField",
    "MergedConfig",
    "merge_configs",
]


class FieldStatus:
    """
    Review status of a merged field.

    * ``TRUSTED`` - all observations agree (or only add new elements), the field
      can be consumed by subsequent decryption/analysis steps directly.
    * ``CONFLICT`` - contradictory values of the same type were reported by
      different sources. Every variant is retained with its sources.
    * ``TYPE_MISMATCH`` - values with incompatible types were reported for the
      same key. Nothing is overwritten, every type group is retained.
    * ``DECOY`` - every observation of the field comes from a configuration
      flagged as a decoy.
    * ``UNKNOWN_SOURCE`` - the field has contradictory observations and at
      least one of them was reported without a proven source, so the conflict
      cannot be attributed to a dump and requires review.
    """

    TRUSTED = "trusted"
    CONFLICT = "conflict"
    TYPE_MISMATCH = "type_mismatch"
    DECOY = "decoy"
    UNKNOWN_SOURCE = "unknown_source"

    #: Statuses which prevent the field from being treated as trusted
    REVIEW_STATUSES = (CONFLICT, TYPE_MISMATCH, DECOY, UNKNOWN_SOURCE)


class ConfigSource(NamedTuple):
    """
    Provenance of a single ripped configuration.

    :param name: Source identifier, usually the memory dump path or an explicit
        label given to :meth:`ExtractManager.push_file` /
        :meth:`ExtractManager.push_procmem`.
    :param decoy: ``True`` when the source configuration is suspected to be a
        decoy (e.g. a fake config planted by the sample). Decoy observations are
        kept but never promoted to trusted values on their own.
    """

    name: str
    decoy: bool = False

    def __str__(self) -> str:
        return self.name


#: Statuses that always mean "needs review"
_REVIEW = FieldStatus.REVIEW_STATUSES


def _type_category(value: Any) -> str:
    """
    Coarse type category used to detect type inconsistencies.

    ``bool`` is intentionally not merged with ``int`` (even though ``True``
    equals ``1`` in Python) and every distinct non-scalar type gets its own
    category.
    """
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, (list, tuple)):
        return "list"
    if isinstance(value, dict):
        return "dict"
    if value is None:
        return "none"
    return type(value).__name__


def _jsonable(value: Any) -> Any:
    """Best-effort conversion of an observed value to a JSON-friendly form."""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


class FieldValue:
    """
    A single distinct observed value of a field.

    :param value: The observed value
    :param sources: Sources that reported exactly this value
    :param decoy_sources: Subset of ``sources`` that were flagged as decoys
    """

    def __init__(
        self,
        value: Any,
        sources: Optional[List[ConfigSource]] = None,
        decoy_sources: Optional[List[ConfigSource]] = None,
    ) -> None:
        self.value = value
        self.sources: List[ConfigSource] = list(sources or [])
        self.decoy_sources: List[ConfigSource] = list(decoy_sources or [])

    @property
    def support(self) -> int:
        """Number of non-decoy sources backing this value."""
        return sum(1 for source in self.sources if not source.decoy)

    @property
    def confidence(self) -> float:
        """
        Share of non-decoy observations of the key that carry this value.

        Ranges from 0.0 (only decoy sources) to 1.0 (every non-decoy source
        that observed the key reported this value). Computed by the owning
        :class:`MergedField` which knows the total non-decoy observation count.
        """
        return getattr(self, "_confidence", 0.0)

    def _set_confidence(self, total_support: int) -> None:
        self._confidence = (
            self.support / total_support if total_support else 0.0
        )

    def add_source(self, source: ConfigSource) -> None:
        if source not in self.sources:
            self.sources.append(source)
        if source.decoy and source not in self.decoy_sources:
            self.decoy_sources.append(source)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": _jsonable(self.value),
            "confidence": round(self.confidence, 4),
            "sources": [source.name for source in self.sources],
            "decoy_sources": [source.name for source in self.decoy_sources],
        }

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FieldValue) and self.value == other.value

    def __repr__(self) -> str:
        return f"FieldValue({self.value!r}, support={self.support})"


class MergedField:
    """
    All observations collected for a single configuration key.

    Holds one :class:`FieldValue` per distinct observed value (for lists, one
    entry holding the de-duplicated union; for nested dicts, a
    :class:`MergedConfig`), the field :attr:`status` and a :attr:`confidence`
    score for its most supported value.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        self.values: List[FieldValue] = []
        self.status: str = FieldStatus.TRUSTED
        self.confidence: float = 0.0
        # Total number of non-decoy source observations of this key
        self._total_support = 0
        # Distinct type categories seen across observations
        self._categories: set = set()
        # Set when at least one observation came without a proven source
        self.has_unknown_source = False
        # Set when every observation came from a decoy-flagged source
        self._only_decoys = True

    # -- observation handling -------------------------------------------------

    def add_observation(self, value: Any, source: Optional[ConfigSource]) -> None:
        """
        Merge one observation of this field.

        Existing values are never overwritten. Equal values gain an additional
        source, different values become additional :class:`FieldValue` entries.
        """
        category = _type_category(value)
        self._categories.add(category)

        if source is None:
            self.has_unknown_source = True
            self._only_decoys = False
            # Anonymous, non-verifiable provenance. Keep a stable placeholder
            # so the value is still retained and visible in the review output.
            source = ConfigSource("unknown", decoy=False)
        elif not source.decoy:
            self._only_decoys = False

        if category == "list":
            self._merge_list(value, source)
        elif category == "dict":
            self._merge_dict(value, source)
        else:
            self._merge_scalar(value, source)

        self._recompute_status()

    def _find_value(self, value: Any) -> Optional[FieldValue]:
        for field_value in self.values:
            if field_value.value == value:
                return field_value
        return None

    def _merge_scalar(self, value: Any, source: ConfigSource) -> None:
        field_value = self._find_value(value)
        if field_value is None:
            field_value = FieldValue(value)
            self.values.append(field_value)
        field_value.add_source(source)

    def _merge_list(self, value: Iterable[Any], source: ConfigSource) -> None:
        # Lists represent collections of equivalent elements (e.g. C2 URLs):
        # elements are unioned while preserving first-seen order.
        existing = self.values[0] if self.values else None
        if existing is not None and isinstance(existing.value, list):
            field_value = existing
        else:
            field_value = FieldValue([])
            self.values = [
                candidate
                for candidate in self.values
                if not isinstance(candidate.value, list)
            ]
            self.values.insert(0, field_value)
        for element in value:
            if element not in field_value.value:
                field_value.value.append(element)
        field_value.add_source(source)

    def _merge_dict(self, value: Dict[str, Any], source: ConfigSource) -> None:
        # Nested dictionaries are merged with the same provenance semantics.
        existing = self.values[0] if self.values else None
        if existing is not None and isinstance(existing.value, MergedConfig):
            field_value = existing
            subconfig = field_value.value
        else:
            subconfig = MergedConfig(family=None)
            field_value = FieldValue(subconfig)
            self.values = [
                candidate
                for candidate in self.values
                if not isinstance(candidate.value, MergedConfig)
            ]
            self.values.insert(0, field_value)
        for subkey, subvalue in value.items():
            subconfig.fields.setdefault(
                subkey, MergedField(subkey)
            ).add_observation(subvalue, source)
        field_value.add_source(source)

    # -- status / confidence --------------------------------------------------

    def _recompute_status(self) -> None:
        self._total_support = sum(
            sum(1 for source in field_value.sources if not source.decoy)
            for field_value in self.values
        )
        for field_value in self.values:
            field_value._set_confidence(self._total_support)

        if self.values:
            self.confidence = max(
                field_value.confidence for field_value in self.values
            )
        else:
            self.confidence = 0.0

        if len(self._categories) > 1:
            # Numeric categories (int/float/bool) may still carry the same
            # abstract value (e.g. int 1 and float 1.0): treat equal
            # cross-category observations as a type inconsistency anyway,
            # because the downstream type contract of the field is ambiguous.
            self.status = FieldStatus.TYPE_MISMATCH
        elif self._only_decoys:
            self.status = FieldStatus.DECOY
        elif len(self._real_values()) > 1:
            # Multiple distinct, non-decoy-only observations of a scalar/dict
            # field that are not just list element additions: contradiction.
            # An anonymous observation contradicting a sourced one cannot be
            # attributed to any dump, so it is surfaced as unknown_source.
            if self.has_unknown_source:
                self.status = FieldStatus.UNKNOWN_SOURCE
            else:
                self.status = FieldStatus.CONFLICT
        elif self._nested_conflict():
            self.status = FieldStatus.CONFLICT
        else:
            self.status = FieldStatus.TRUSTED

    def _real_values(self) -> List[FieldValue]:
        """Values backed by at least one non-decoy source."""
        return [field_value for field_value in self.values if field_value.support]

    def _nested_conflict(self) -> bool:
        for field_value in self.values:
            if isinstance(field_value.value, MergedConfig):
                if field_value.value.pending_review_fields():
                    return True
        return False

    @property
    def needs_review(self) -> bool:
        """Whether downstream steps should treat this field as untrusted."""
        return self.status in _REVIEW

    def trusted_value(self) -> Tuple[bool, Any]:
        """
        Return ``(usable, value)``.

        ``usable`` is ``False`` for conflicted, type-inconsistent, decoy-only or
        unattributable fields. For list fields the unioned list is returned; for
        nested dicts the trusted sub-dict (with review-required sub-fields
        removed) is returned.
        """
        if self.needs_review or not self._real_values():
            return False, None
        field_value = self._real_values()[0]
        if isinstance(field_value.value, MergedConfig):
            return True, field_value.value.trusted_dict()
        return True, field_value.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "confidence": round(self.confidence, 4),
            "needs_review": self.needs_review,
            "has_unknown_source": self.has_unknown_source,
            "values": [field_value.to_dict() for field_value in self.values],
        }

    def __repr__(self) -> str:
        return (
            f"MergedField({self.key!r}, status={self.status}, "
            f"values={len(self.values)})"
        )


class MergedConfig:
    """
    Provenance-preserving merge of every configuration ripped for one family.

    Iterating yields ``(key, MergedField)`` pairs. Use :meth:`trusted_dict` for
    a plain configuration containing only fields safe to consume,
    :meth:`pending_review_fields` for fields requiring analyst review and
    :meth:`to_dict` for the complete, JSON-serializable provenance view.
    """

    def __init__(self, family: Optional[str]) -> None:
        self.family = family
        self.fields: "OrderedDict[str, MergedField]" = OrderedDict()
        self.sources: List[ConfigSource] = []

    def __iter__(self):
        return iter(self.fields.items())

    def __contains__(self, key: str) -> bool:
        return key in self.fields

    def __getitem__(self, key: str) -> MergedField:
        return self.fields[key]

    def get(self, key: str) -> Optional[MergedField]:
        return self.fields.get(key)

    def merge(
        self,
        config: Dict[str, Any],
        source: Optional[ConfigSource] = None,
        decoy: Optional[bool] = None,
    ) -> None:
        """
        Merge one ripped configuration.

        :param config: Raw configuration dict. A ``__meta__`` dict may carry
            per-config flags, currently ``{"decoy": True}``.
        :param source: Proven source of the configuration. When ``None``,
            observations are still retained, but a provenance gap is recorded
            and any contradiction involving an anonymous observation blocks the
            field instead of being silently resolved.
        :param decoy: Explicit decoy override. Takes precedence over a
            ``__meta__`` flag when provided.
        """
        config = dict(config)
        meta = config.pop(CONFIG_META_KEY, None) or {}
        if decoy is None:
            decoy = bool(meta.get("decoy", False))

        if source is not None:
            if decoy and not source.decoy:
                source = ConfigSource(source.name, decoy=True)
            if source not in self.sources:
                self.sources.append(source)
        else:
            log.warning(
                "Merging configuration for family %r without a source: "
                "provenance gap will be recorded on the affected fields",
                self.family,
            )

        family = config.get("family")
        if family is not None:
            self.family = family

        for key, value in config.items():
            field = self.fields.get(key)
            if field is None:
                field = MergedField(key)
                self.fields[key] = field
            field.add_observation(value, source)

    @property
    def trusted_keys(self) -> List[str]:
        """Keys of fields that can be consumed without manual review."""
        return [
            key
            for key, field in self.fields.items()
            if not field.needs_review
        ]

    def pending_review_fields(self) -> List[MergedField]:
        """Fields that carry conflicts, type issues, decoys or missing sources."""
        return [field for field in self.fields.values() if field.needs_review]

    def is_field_trusted(self, key: str) -> bool:
        """Whether ``key`` exists and can be consumed without review."""
        field = self.fields.get(key)
        return field is not None and not field.needs_review

    def trusted_dict(self) -> Dict[str, Any]:
        """
        Plain configuration view containing only trusted fields.

        Fields requiring review are omitted so that decryption and analysis
        code consuming this dict can never pick up an unverified value. The
        ``family`` key is always present when a family has been matched.
        """
        result: Dict[str, Any] = {}
        if self.family is not None:
            result["family"] = self.family
        for key, field in self.fields.items():
            if key == "family":
                continue
            usable, value = field.trusted_value()
            if usable:
                result[key] = value
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Full JSON-serializable representation including all provenance."""
        result: Dict[str, Any] = {
            "family": self.family,
            "sources": [
                {"name": source.name, "decoy": source.decoy}
                for source in self.sources
            ],
            "trusted_keys": self.trusted_keys,
            "pending_review": [field.key for field in self.pending_review_fields()],
            "fields": {
                key: field.to_dict() for key, field in self.fields.items()
            },
        }
        return result

    def __repr__(self) -> str:
        return (
            f"MergedConfig(family={self.family!r}, "
            f"fields={len(self.fields)}, sources={len(self.sources)})"
        )


def merge_configs(
    family: Optional[str],
    configs: Optional[Iterable[Tuple[Dict[str, Any], Optional[ConfigSource]]]] = None,
) -> MergedConfig:
    """
    Build a :class:`MergedConfig` from an iterable of ``(config, source)`` pairs.

    Sources may be ``None``; those observations are retained with a recorded
    provenance gap instead of being dropped or overwriting anything. A
    contradiction involving an anonymous observation yields an
    :attr:`FieldStatus.UNKNOWN_SOURCE` field.
    """
    merged = MergedConfig(family)
    for config, source in configs or []:
        merged.merge(config, source=source)
    return merged
