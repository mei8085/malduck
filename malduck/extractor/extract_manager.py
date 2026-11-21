import json
import logging
import warnings
from typing import Any, Dict, Iterator, List, Optional, Type

from ..procmem import ProcessMemory, ProcessMemoryELF, ProcessMemoryPE
from ..procmem.binmem import ProcessMemoryBinary
from ..yara import Yara, YaraRuleOffsets, YaraRulesetMatch
from .config_merger import CONFIG_META_KEY, ConfigSource, MergedConfig
from .config_utils import (
    Config,
    apply_config_part,
    encode_for_json,
    sanitize_config,
)
from .extractor import Extractor
from .modules import ExtractorModules

log = logging.getLogger(__name__)

__all__ = ["ExtractManager"]


class ExtractManager:
    """
    Multi-dump extraction context. Handles merging configs from different dumps, additional dropped families etc.

    Configurations ripped from different memory dumps are merged with full
    provenance: equivalent fields are combined, contradictory values keep their
    sources and are flagged for review, and decoy / sourceless /
    type-inconsistent observations never silently overwrite an existing value.
    See :mod:`malduck.extractor.config_merger` for the merge semantics.

    :param modules: Object with loaded extractor modules
    :type modules: :class:`ExtractorModules`
    """

    def __init__(self, modules: ExtractorModules) -> None:
        self.modules = modules
        self.binary_classes: List[Type[ProcessMemoryBinary]] = [
            ProcessMemoryPE,
            ProcessMemoryELF,
        ]
        #: Provenance-preserving merged configuration for each extracted family
        self.merged_configs: Dict[str, MergedConfig] = {}
        #: Stack of sources currently being extracted (push_procmem/push_file)
        self._source_stack: List[ConfigSource] = []

    @property
    def rules(self) -> Yara:
        """
        Bound Yara rules
        :rtype: :class:`malduck.yara.Yara`
        """
        return self.modules.rules

    @property
    def extractors(self) -> List[Type[Extractor]]:
        """
        Bound extractor modules
        :rtype: List[Type[:class:`malduck.extractor.Extractor`]]
        """
        return self.modules.extractors

    @property
    def current_source(self) -> Optional[ConfigSource]:
        """Source of the dump currently being extracted, if known."""
        return self._source_stack[-1] if self._source_stack else None

    def on_error(self, exc: Exception, extractor: Extractor) -> None:
        """
        Handler for all exceptions raised by :py:meth:`Extractor.handle_yara`.

        .. deprecated:: 2.1.0
           Look at :py:meth:`ExtractManager.on_extractor_error` instead.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor object which raised the exception
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        self.on_extractor_error(exc, extractor, "handle_yara")

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all exceptions raised by extractor methods (including :py:meth:`Extractor.handle_yara`).

        Override this method if you want to set your own error handler.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which raised the exception
        :type method_name: str
        """
        import traceback

        log.warning(
            "%s.%s raised an exception: %s",
            extractor.__class__.__name__,
            method_name,
            traceback.format_exc(),
        )

    def push_file(
        self,
        filepath: str,
        base: int = 0,
        source: Optional[str] = None,
        decoy: bool = False,
    ) -> Optional[str]:
        """
        Pushes file for extraction. Config extractor entrypoint.

        :param filepath: Path to extracted file
        :type filepath: str
        :param base: Memory dump base address
        :type base: int
        :param source: Optional source label attached to every ripped field.
            Defaults to the file path, which is also the provenance used when
            merging configs from subsequent dumps.
        :type source: str
        :param decoy: Flag the whole configuration ripped from this dump as a
            suspected decoy. Decoy observations are retained but never promoted
            to trusted values.
        :type decoy: bool
        :return: Detected family if configuration looks better than already stored one
        """
        log.debug("Started extraction of file %s:%x", filepath, base)
        dump_source = ConfigSource(source or filepath, decoy=decoy)
        with ProcessMemory.from_file(filepath, base=base) as p:
            return self.push_procmem(
                p, rip_binaries=True, source=dump_source
            )

    def match_procmem(self, p: ProcessMemory) -> YaraRulesetMatch:
        """
        Performs Yara matching on ProcessMemory using modules
        bound with current ExtractManager.
        """
        matches = p.yarap(self.rules, extended=True)
        log.debug("Matched rules: %s", ",".join(list(matches.keys())))
        return matches

    def carve_procmem(self, p: ProcessMemory) -> Iterator[ProcessMemoryBinary]:
        """
        Carves binaries from ProcessMemory to try configuration extraction
        using every possible address mapping.
        """
        for binclass in self.binary_classes:
            carved_bins = binclass.load_binaries_from_memory(p)
            for carved_bin in carved_bins:
                log.debug(
                    f"carve: Found {carved_bin.__class__.__name__} "
                    f"at offset {carved_bin.regions[0].offset}"
                )
                yield carved_bin

    def push_config(
        self,
        config: Config,
        source: Optional[ConfigSource] = None,
        decoy: Optional[bool] = None,
    ) -> bool:
        """
        Merge a complete configuration ripped from one dump into the stored
        configuration of its family.

        Contrary to a plain replacement, no previously collected value is
        overwritten: equivalent fields are merged, contradictory values are
        preserved with their sources and flagged for review, and type
        inconsistencies / decoys / missing sources are handled by
        :class:`~malduck.extractor.config_merger.MergedConfig`.

        :param config: Configuration dict (must contain a ``family`` key). It
            may carry a ``__meta__`` dict with a ``decoy`` flag.
        :type config: dict
        :param source: Provenance of the configuration. When ``None``, the
            current dump source is used; if that is also unknown, the
            provenance gap is recorded rather than silently accepted.
        :type source: :class:`~malduck.extractor.config_merger.ConfigSource`
        :param decoy: Explicit decoy flag taking precedence over ``__meta__``
        :type decoy: bool, optional
        :return: True if the family configuration was collected/updated
        """
        if not config.get("family"):
            return False

        family = config["family"]
        source = source if source is not None else self.current_source

        if family in self.merged_configs:
            log.debug("Merging new %s config from source %s", family, source)
            self.merged_configs[family].merge(config, source=source, decoy=decoy)
            return True

        if family in self.modules.override_paths:
            # 'citadel' > 'zeus'
            # If 'zeus' appears but we have already 'citadel', we should ignore 'zeus'
            # Otherwise we should get 'citadel' instead of 'zeus'
            for stored_family in list(self.merged_configs.keys()):
                if stored_family == family:
                    continue
                score = self.modules.compare_family_overrides(family, stored_family)
                if score == -1:
                    del self.merged_configs[stored_family]
                    log.debug(
                        "%s config looks better (overrides %s)", family, stored_family
                    )
                    break
                elif score == 1:
                    log.debug(
                        "%s config doesn't look better than previous one (overridden by %s)",
                        family,
                        stored_family,
                    )
                    return False

        log.debug("New %s config collected", family)
        merged = MergedConfig(family)
        merged.merge(config, source=source, decoy=decoy)
        self.merged_configs[family] = merged
        return True

    def _extract_procmem(self, p: ProcessMemory, matches) -> Optional[str]:
        log.debug("%s - ripping...", repr(p))
        # Create extraction context for single file
        manager = ExtractionContext(parent=self)
        # Map offset matches to VA using procmem address mapping
        va_matches = matches.remap(p.p2v)
        # Push ProcessMemory for extraction with mapped Yara matches
        manager.push_procmem(p, _matches=va_matches)
        # Get final configurations
        config = manager.collected_config
        if config.get("family"):
            log.debug("%s - found %s!", repr(p), config.get("family"))
            if self.push_config(config):
                return config["family"]
            else:
                return None
        else:
            log.debug("%s - no luck.", repr(p))
            return None

    def push_procmem(
        self,
        p: ProcessMemory,
        rip_binaries: bool = False,
        source: Optional[ConfigSource] = None,
        decoy: bool = False,
    ) -> Optional[str]:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param rip_binaries: Look for binaries (PE, ELF) in provided ProcessMemory and try to perform extraction using
            specialized variants (ProcessMemoryPE, ProcessMemoryELF)
        :type rip_binaries: bool (default: False)
        :param source: Optional source label (e.g. dump path) used as
            provenance for every field ripped from this object. When omitted
            and no :meth:`push_file` context is active, ripped fields carry a
            recorded provenance gap; an anonymous observation that contradicts
            a sourced one blocks the field pending review instead of resolving
            the conflict.
        :type source: str or :class:`~malduck.extractor.config_merger.ConfigSource`, optional
        :param decoy: Flag configurations ripped from this object as suspected
            decoys. Decoy values are retained but never silently trusted.
        :type decoy: bool (default: False)
        :return: Detected family if configuration looks better than already stored one
        """
        if source is None:
            dump_source = self.current_source
            if dump_source is not None and decoy and not dump_source.decoy:
                dump_source = ConfigSource(dump_source.name, decoy=True)
        elif isinstance(source, ConfigSource):
            dump_source = source
            if decoy and not dump_source.decoy:
                dump_source = ConfigSource(dump_source.name, decoy=True)
        else:
            # Accept plain string labels as well
            dump_source = ConfigSource(str(source), decoy=decoy)

        if dump_source is not None:
            self._source_stack.append(dump_source)
        try:
            matches = self.match_procmem(p)
            if not matches:
                log.debug("No Yara matches.")
                return None

            binaries = self.carve_procmem(p) if rip_binaries else iter([])

            family = self._extract_procmem(p, matches)
            for binary in binaries:
                family = self._extract_procmem(binary, matches) or family
            return family
        finally:
            if dump_source is not None:
                self._source_stack.pop()

    @property
    def config(self) -> List[Config]:
        """
        Extracted configuration (list of configs for each extracted family)

        Returns the trusted view of each merged configuration: fields
        conflicting between dumps, type-inconsistent fields, decoy-only fields
        and conflicts involving an unattributed source are omitted. Use
        :attr:`merged_configs` (or :attr:`merged`) to access them together
        with their provenance, confidence and review status.
        """
        return [
            merged.trusted_dict() for merged in self.merged_configs.values()
        ]

    @property
    def merged(self) -> List[MergedConfig]:
        """
        Provenance-preserving merged configurations, one per extracted family.

        :rtype: List[:class:`~malduck.extractor.config_merger.MergedConfig`]
        """
        return list(self.merged_configs.values())


class ExtractionContext:
    """
    Single-dump extraction context (single family)
    """

    def __init__(self, parent: ExtractManager) -> None:
        #: Collected configuration so far (especially useful for "final" extractors)
        self.collected_config: Config = {}
        self.globals: Dict[str, Any] = {}
        self.parent = parent  #: Bound ExtractManager instance

    @property
    def family(self) -> Optional[str]:
        """Matched family"""
        return self.collected_config.get("family")

    def on_extractor_error(
        self, exc: Exception, extractor: Extractor, method_name: str
    ) -> None:
        """
        Handler for all exceptions raised by extractor methods.

        :param exc: Exception object
        :type exc: :class:`Exception`
        :param extractor: Extractor instance
        :type extractor: :class:`extractor.Extractor`
        :param method_name: Name of method which raised the exception
        :type method_name: str
        """
        self.parent.on_extractor_error(exc, extractor, method_name)

    def push_procmem(
        self, p: ProcessMemory, _matches: Optional[YaraRulesetMatch] = None
    ) -> None:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param _matches: YaraRulesetMatch object (used internally)
        :type _matches: :class:`malduck.yara.YaraRulesetMatch`
        """
        matches = _matches or p.yarav(self.parent.rules, extended=True)
        used_matches = set()  # Which yara rules had a matching extractor
        # For each extractor...
        for ext_class in self.parent.extractors:
            extractor = ext_class(self)

            if type(extractor.yara_rules) is str:
                raise TypeError(
                    f'"{extractor.__class__.__name__}.yara_rules" cannot be a string, convert it into a list of strings'
                )

            # For each rule identifier in extractor.yara_rules...
            for rule in extractor.yara_rules:
                if rule in matches:
                    used_matches.add(rule)
                    try:
                        if hasattr(extractor, "handle_yara"):
                            warnings.warn(
                                "Extractor.handle_yara is deprecated, use Extractor.handle_match",
                                DeprecationWarning,
                            )
                            getattr(extractor, "handle_yara")(
                                p, YaraRuleOffsets(matches[rule])
                            )
                        else:
                            extractor.handle_match(p, matches[rule])
                    except Exception as exc:
                        self.parent.on_error(exc, extractor)

        log.info("The following matches were used: %s", list(used_matches))
        if not used_matches:
            log.warning("YARA rules didn't trigger any extractor! Is there a typo?")

    def push_config(self, config: Config, extractor: Extractor) -> None:
        """
        Pushes new partial config

        If strong config provides different family than stored so far
        and that family overrides stored family - set stored family
        Example: citadel overrides zeus

        Per-config flags can be passed through the reserved ``__meta__`` key
        (currently ``{"decoy": True}``); they are consumed later by the
        cross-dump merger and never stored in the config itself.

        :param config: Partial config object
        :type config: dict
        :param extractor: Extractor object reference
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        config = encode_for_json(config)
        try:
            json.dumps(config)
        except (TypeError, OverflowError) as e:
            log.debug("Config is not JSON-encodable (%s): %s", str(e), repr(config))
            raise RuntimeError("Config must be JSON-encodable")

        raw_meta = config.get(CONFIG_META_KEY)
        meta = raw_meta if isinstance(raw_meta, dict) and raw_meta else None
        if CONFIG_META_KEY in config:
            config = {k: v for k, v in config.items() if k != CONFIG_META_KEY}

        config = sanitize_config(config)

        if not config and not meta:
            return

        log.debug(
            "%s found the following config parts: %s",
            extractor.__class__.__name__,
            sorted(config.keys()),
        )

        if meta:
            # Merge reserved per-config flags instead of running them through
            # apply_config_part, which would treat differing dicts as an
            # illegal override.
            base_meta = self.collected_config.get(CONFIG_META_KEY, {})
            merged_meta = dict(base_meta)
            for flag, flag_value in meta.items():
                if flag == "decoy":
                    merged_meta[flag] = bool(merged_meta.get(flag, False)) or bool(
                        flag_value
                    )
                elif flag not in merged_meta:
                    merged_meta[flag] = flag_value
            self.collected_config[CONFIG_META_KEY] = merged_meta

        if not config:
            return

        if "family" in config:
            log.debug(
                "%s tells it's %s", extractor.__class__.__name__, config["family"]
            )
            if (
                "family" in self.collected_config
                and self.collected_config["family"] != config["family"]
            ):
                overrides = self.parent.modules.compare_family_overrides(
                    config["family"], self.collected_config["family"]
                )
                if not overrides:
                    raise RuntimeError(
                        f"Ripped both {self.collected_config['family']} and {config['family']} "
                        f"from the same ProcessMemory which is not expected"
                    )
                if overrides == -1:
                    self.collected_config["family"] = config["family"]
                else:
                    config["family"] = self.collected_config["family"]
        self.collected_config = apply_config_part(self.collected_config, config)

    @property
    def config(self) -> Config:
        """
        Returns collected config, but if family is not matched - returns empty dict.
        Family is not included in config itself, look at :py:attr:`ProcmemExtractManager.family`.
        """
        if self.family is None:
            return {}
        return self.collected_config
