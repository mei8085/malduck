import hashlib
import json
import logging
import warnings
from typing import Any, Dict, Iterator, List, Optional, Type

from ..procmem import ProcessMemory, ProcessMemoryELF, ProcessMemoryPE
from ..procmem.binmem import ProcessMemoryBinary
from ..yara import Yara, YaraRuleOffsets, YaraRulesetMatch
from .config_utils import (
    Config,
    apply_config_part,
    encode_for_json,
    is_config_better,
    sanitize_config,
)
from .extractor import Extractor
from .modules import ExtractorModules

log = logging.getLogger(__name__)

__all__ = ["ExtractManager"]


class ExtractManager:
    """
    Multi-dump extraction context. Handles merging configs from different dumps, additional dropped families etc.

    :param modules: Object with loaded extractor modules
    :type modules: :class:`ExtractorModules`
    :param max_payload_depth: Maximal nesting depth for recursively extracted payloads
        (nested payloads pushed by extractors). Deeper branches are stopped.
    :type max_payload_depth: int (default: 8)
    :param max_payloads: Maximal number of nested payloads extracted from a single
        pushed file/dump. Further branches are stopped.
    :type max_payloads: int (default: 256)
    :param max_payload_bytes: Maximal total size (in bytes) of nested payloads extracted
        from a single pushed file/dump. Protects against malicious samples declaring
        unbounded payload counts/sizes. Further branches are stopped.
    :type max_payload_bytes: int (default: 64 MiB)
    """

    def __init__(
        self,
        modules: ExtractorModules,
        max_payload_depth: int = 8,
        max_payloads: int = 256,
        max_payload_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.modules = modules
        self.binary_classes: List[Type[ProcessMemoryBinary]] = [
            ProcessMemoryPE,
            ProcessMemoryELF,
        ]
        self.configs: Dict[str, Config] = {}
        #: Limits guarding recursive extraction of nested payloads
        self.max_payload_depth = max_payload_depth
        self.max_payloads = max_payloads
        self.max_payload_bytes = max_payload_bytes
        #: Provenance trail of nested payloads seen during extraction.
        #: Each entry describes a single nested payload: its hash, size, nesting
        #: depth, source family, resolved family, extraction status and optional
        #: extractor-provided details (e.g. offset, length, encoding).
        self.payloads: List[Config] = []
        self._payload_count = 0
        self._payload_bytes = 0

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

    def push_file(self, filepath: str, base: int = 0) -> Optional[str]:
        """
        Pushes file for extraction. Config extractor entrypoint.

        :param filepath: Path to extracted file
        :type filepath: str
        :param base: Memory dump base address
        :type base: int
        :return: Detected family if configuration looks better than already stored one
        """
        log.debug("Started extraction of file %s:%x", filepath, base)
        with ProcessMemory.from_file(filepath, base=base) as p:
            return self.push_procmem(p, rip_binaries=True)

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

    def push_config(self, config: Config) -> bool:
        if not config.get("family"):
            return False

        family = config["family"]
        if family in self.configs:
            if is_config_better(base_config=self.configs[family], new_config=config):
                self.configs[family] = config
                log.debug("%s config looks better than previous one", family)
                return True
            else:
                log.debug("%s config doesn't look better than previous one", family)
                return False

        if family in self.modules.override_paths:
            # 'citadel' > 'zeus'
            # If 'zeus' appears but we have already 'citadel', we should ignore 'zeus'
            # Otherwise we should get 'citadel' instead of 'zeus'
            for stored_family in self.configs.keys():
                if stored_family == family:
                    continue
                score = self.modules.compare_family_overrides(family, stored_family)
                if score == -1:
                    del self.configs[stored_family]
                    self.configs[family] = config
                    log.debug(
                        "%s config looks better (overrides %s)", family, stored_family
                    )
                    return True
                elif score == 1:
                    log.debug(
                        "%s config doesn't look better than previous one (overridden by %s)",
                        family,
                        stored_family,
                    )
                    return False

        log.debug("New %s config collected", family)
        self.configs[family] = config
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
        self, p: ProcessMemory, rip_binaries: bool = False
    ) -> Optional[str]:
        """
        Pushes ProcessMemory object for extraction

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param rip_binaries: Look for binaries (PE, ELF) in provided ProcessMemory and try to perform extraction using
            specialized variants (ProcessMemoryPE, ProcessMemoryELF)
        :type rip_binaries: bool (default: False)
        :return: Detected family if configuration looks better than already stored one
        """
        # Reset the nested payload budget for each top-level sample
        self._payload_count = 0
        self._payload_bytes = 0
        matches = self.match_procmem(p)
        if not matches:
            log.debug("No Yara matches.")
            return None

        binaries = self.carve_procmem(p) if rip_binaries else iter([])

        family = self._extract_procmem(p, matches)
        for binary in binaries:
            family = self._extract_procmem(binary, matches) or family
        return family

    @property
    def config(self) -> List[Config]:
        """
        Extracted configuration (list of configs for each extracted family)
        """
        return [config for family, config in self.configs.items()]


class ExtractionContext:
    """
    Single-dump extraction context (single family)

    Contexts form a tree that mirrors the nesting structure of extracted
    payloads: nested payloads pushed by extractors are analyzed in child
    contexts, so the payload boundary, encoding and family identifier of each
    layer are resolved independently. Configurations produced by a child layer
    are merged back into the parent only when they belong to the same (or an
    overriding) family - configurations of unrelated families are kept isolated
    and reported separately.
    """

    def __init__(
        self,
        parent: ExtractManager,
        parent_context: Optional["ExtractionContext"] = None,
        isolated: bool = False,
    ) -> None:
        #: Collected configuration so far (especially useful for "final" extractors)
        self.collected_config: Config = {}
        self.parent = parent  #: Bound ExtractManager instance
        #: Context of the layer this payload was extracted from (None for top-level)
        self.parent_context = parent_context
        #: Hash of the buffer handled by this context (set on first push)
        self.payload_hash: Optional[str] = None
        #: Configurations of nested payloads, absorbed once extraction of
        #: this layer finishes and the family of this layer is known
        self._pending_child_configs: List[Any] = []
        if parent_context is None:
            self.globals: Dict[str, Any] = {}
            #: Nesting depth of the payload handled by this context
            self.depth = 0
        else:
            # Nested layers share the globals container with their parent layer
            # (backwards-compatible scratch space for extractors). Contexts
            # isolated because of a family mismatch get a fresh container, so
            # unrelated families can't leak state into each other.
            self.globals = {} if isolated else parent_context.globals
            self.depth = parent_context.depth + (0 if isolated else 1)

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

        If the buffer matches structures of multiple unrelated families, each
        family is handled in an isolated context so that configuration
        semantics of different families are not mixed together.

        :param p: ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param _matches: YaraRulesetMatch object (used internally)
        :type _matches: :class:`malduck.yara.YaraRulesetMatch`
        """
        matches = _matches or p.yarav(self.parent.rules, extended=True)
        if self.payload_hash is None:
            self.payload_hash = hashlib.sha256(p.readp(0)).hexdigest()

        # Group matching extractor classes by family
        family_groups: Dict[Optional[str], List[Type[Extractor]]] = {}
        for ext_class in self.parent.extractors:
            if type(ext_class.yara_rules) is str:
                raise TypeError(
                    f'"{ext_class.__name__}.yara_rules" cannot be a string, convert it into a list of strings'
                )
            if any(rule in matches for rule in ext_class.yara_rules):
                family_groups.setdefault(ext_class.family, []).append(ext_class)

        if not family_groups:
            log.warning("YARA rules didn't trigger any extractor! Is there a typo?")
            return

        current_family = self.family
        matched_families = [family for family in family_groups if family is not None]
        if current_family is None and len(matched_families) > 1:
            # Fresh context and buffer matches structures of multiple families:
            # isolate each family in its own context
            foreign_families = matched_families
        elif current_family is not None:
            # Context already identified the family: isolate structures of
            # unrelated families mixed into the same buffer
            foreign_families = [
                family
                for family in matched_families
                if family != current_family
                and not self.parent.modules.compare_family_overrides(
                    family, current_family
                )
            ]
        else:
            foreign_families = []

        foreign_configs: List[Config] = []
        for family in foreign_families:
            group = family_groups.pop(family)
            isolated = ExtractionContext(
                self.parent, parent_context=self, isolated=True
            )
            isolated.payload_hash = self.payload_hash
            isolated._run_extractors(p, matches, group)
            isolated._absorb_pending_child_configs()
            foreign_configs.append(isolated.collected_config)

        self._run_extractors(
            p, matches, [ext for group in family_groups.values() for ext in group]
        )

        for config in foreign_configs:
            self._absorb_child_config(config)

        # Absorb configurations of nested payloads pushed by extractor methods.
        # This is deferred until the family of the current layer is known, so
        # that unrelated families can be told apart and kept isolated.
        self._absorb_pending_child_configs()

    def _run_extractors(
        self,
        p: ProcessMemory,
        matches: YaraRulesetMatch,
        extractor_classes: List[Type[Extractor]],
    ) -> None:
        used_matches = set()  # Which yara rules had a matching extractor
        # For each extractor...
        for ext_class in extractor_classes:
            extractor = ext_class(self)

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

    def push_nested_procmem(
        self, p: ProcessMemory, _extractor: Optional[Extractor] = None, **info
    ) -> None:
        """
        Pushes nested payload extracted from the currently analyzed buffer
        for recursive extraction (used internally by
        :py:meth:`Extractor.push_procmem`).

        The payload is analyzed in a fresh child context, so its boundary,
        encoding and family identifier are resolved independently from the
        current layer. Extraction of the current branch is stopped (keeping
        the provenance information collected so far) when:

        * the same payload was already seen on this branch (circular nesting),
        * the nesting depth exceeds ``ExtractManager.max_payload_depth``,
        * the payload budget is exhausted (``ExtractManager.max_payloads`` /
          ``ExtractManager.max_payload_bytes``), which protects against
          malicious samples declaring unbounded payload counts/sizes,
        * the payload can't be analyzed (e.g. truncated or undecodable data
          making the extraction fail).

        :param p: Nested payload as a ProcessMemory object
        :type p: :class:`malduck.procmem.ProcessMemory`
        :param _extractor: Extractor instance pushing the payload (used internally)
        :param info: Additional provenance info about the payload
            (e.g. offset, length, encoding)
        """
        manager = self.parent
        payload_hash = hashlib.sha256(p.readp(0)).hexdigest()
        # The family of the layer the payload was carved from. At this point
        # the collected config may not be resolved yet, so prefer the family
        # declared by the extractor pushing the payload.
        source_family: Optional[str]
        if _extractor is not None and _extractor.family:
            source_family = _extractor.family
        else:
            source_family = self.family
        record: Config = {
            "sha256": payload_hash,
            "depth": self.depth + 1,
            "size": p.length,
            "source_family": source_family,
            "family": None,
            "status": "ok",
        }
        for key, value in info.items():
            if key not in record:
                try:
                    record[key] = encode_for_json(value)
                except Exception:
                    record[key] = repr(value)
        # Provenance is recorded even if the branch has to be stopped
        manager.payloads.append(record)

        # Guard against excessive nesting depth
        if self.depth + 1 > manager.max_payload_depth:
            record["status"] = "max-depth"
            log.debug("Nested payload skipped: maximal nesting depth exceeded")
            return
        # Guard against circular nesting (payload already seen on this branch)
        ctx: Optional[ExtractionContext] = self
        while ctx is not None:
            if ctx.payload_hash == payload_hash:
                record["status"] = "circular"
                log.debug("Nested payload skipped: circular nesting detected")
                return
            ctx = ctx.parent_context
        # Guard against unbounded resource consumption
        if (
            manager._payload_count + 1 > manager.max_payloads
            or manager._payload_bytes + p.length > manager.max_payload_bytes
        ):
            record["status"] = "budget-exceeded"
            log.debug("Nested payload skipped: payload budget exceeded")
            return
        manager._payload_count += 1
        manager._payload_bytes += p.length

        child = ExtractionContext(manager, parent_context=self)
        child.payload_hash = payload_hash
        try:
            child.push_procmem(p)
        except Exception as exc:
            # Stop the branch but keep whatever was collected so far
            record["status"] = "error"
            if _extractor is not None:
                self.on_extractor_error(exc, _extractor, "push_procmem")
            else:
                log.warning("Nested payload extraction failed: %s", exc)
        config = child.collected_config
        record["family"] = config.get("family")
        # Defer absorption until this layer finished extraction and its
        # family is known (see push_procmem)
        self._pending_child_configs.append((config, _extractor))

    def _absorb_pending_child_configs(self) -> None:
        for child_config, child_extractor in self._pending_child_configs:
            self._absorb_child_config(child_config, child_extractor)
        self._pending_child_configs = []

    def _absorb_child_config(
        self, config: Config, extractor: Optional[Extractor] = None
    ) -> None:
        """
        Merges configuration extracted from a child layer back into this
        context. Configurations of unrelated families are not merged - they
        are reported to ExtractManager as separate configs, so structures of
        other families are not misattributed to the current family.
        """
        if not config:
            return
        child_family = config.get("family")
        current_family = self.collected_config.get("family")
        if (
            child_family
            and current_family
            and child_family != current_family
            and not self.parent.modules.compare_family_overrides(
                child_family, current_family
            )
        ):
            log.debug(
                "Keeping %s config isolated from %s (unrelated families)",
                child_family,
                current_family,
            )
            self.parent.push_config(config)
            return
        try:
            self.push_config(config, extractor)
        except RuntimeError as exc:
            log.warning("Dropping incompatible nested config part (%s)", exc)

    def push_config(
        self, config: Config, extractor: Optional[Extractor] = None
    ) -> None:
        """
        Pushes new partial config

        If strong config provides different family than stored so far
        and that family overrides stored family - set stored family
        Example: citadel overrides zeus

        :param config: Partial config object
        :type config: dict
        :param extractor: Extractor object reference (optional)
        :type extractor: :class:`malduck.extractor.Extractor`
        """
        extractor_name = (
            extractor.__class__.__name__ if extractor is not None else "nested layer"
        )
        config = encode_for_json(config)
        try:
            json.dumps(config)
        except (TypeError, OverflowError) as e:
            log.debug("Config is not JSON-encodable (%s): %s", str(e), repr(config))
            raise RuntimeError("Config must be JSON-encodable")

        config = sanitize_config(config)

        if not config:
            return

        log.debug(
            "%s found the following config parts: %s",
            extractor_name,
            sorted(config.keys()),
        )

        if "family" in config:
            log.debug("%s tells it's %s", extractor_name, config["family"])
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
