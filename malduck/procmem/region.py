import logging
from typing import Dict, List, Optional, Union

__all__ = [
    "Region",
    "normalize_regions",
    "PAGE_NOACCESS",
    "PAGE_READONLY",
    "PAGE_READWRITE",
    "PAGE_WRITECOPY",
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
    "PAGE_GUARD",
    "PAGE_NOCACHE",
    "PAGE_WRITECOMBINE",
]

log = logging.getLogger(__name__)

# Region addresses come from 64-bit dump headers. A virtual/physical range that
# would not fit in 64 bits is an overflowing descriptor and must be rejected
# rather than silently wrapped.
_MAX_U64 = (1 << 64) - 1

PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
# Protection modifier bits. They are OR-ed onto the base protection by the
# loader and must never be interpreted as a protection of their own.
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400

# Mask that keeps only the base access rights, dropping guard/cache modifiers.
_PAGE_PROTECT_MASK = 0xFF

page_access = {
    PAGE_NOACCESS: "-",
    PAGE_READONLY: "r",
    PAGE_READWRITE: "rw",
    PAGE_WRITECOPY: "rwc",
    PAGE_EXECUTE: "rx",
    PAGE_EXECUTE_READ: "rx",
    PAGE_EXECUTE_READWRITE: "rwx",
    PAGE_EXECUTE_WRITECOPY: "rwxc",
}


def page_protect_to_access(protect: Optional[int]) -> Optional[str]:
    """
    Resolves a raw Windows ``Protect`` value into an access-rights string.

    Modifier bits (:data:`PAGE_GUARD`, :data:`PAGE_NOCACHE`,
    :data:`PAGE_WRITECOMBINE`) are stripped before the lookup, so a region
    carrying an exceptional protection (e.g. ``PAGE_READWRITE | PAGE_GUARD``)
    is still reported with the access rights of its base protection. Unknown
    values resolve to ``None`` instead of raising.
    """
    if not isinstance(protect, int) or protect < 0:
        return None
    return page_access.get(protect & _PAGE_PROTECT_MASK)


class Region:
    """Represents single mapped region in :class:`ProcessMemory`"""

    def __init__(
        self, addr: int, size: int, state: int, type_: int, protect: int, offset: int
    ) -> None:
        self.addr = addr
        self.size = size
        self.state = state
        self.type_ = type_
        self.protect = protect
        self.offset = offset

    def to_json(self) -> Dict[str, Union[int, Optional[str]]]:
        """
        Returns JSON-like dict representation
        """
        return {
            "addr": "0x%08x" % self.addr,
            "end": "0x%08x" % (self.addr + self.size),
            "size": self.size,
            "state": self.state,
            "type": self.type_,
            "protect": page_protect_to_access(self.protect),
            "offset": self.offset,
        }

    @property
    def end(self) -> int:
        """
        Virtual address of region end (first unmapped byte)
        """
        return self.addr + self.size

    @property
    def end_offset(self) -> int:
        """
        Offset of region end (first unmapped byte)
        """
        return self.offset + self.size

    @property
    def last(self) -> int:
        """
        Virtual address of last region byte
        """
        return self.addr + self.size - 1

    @property
    def last_offset(self) -> int:
        """
        Offset of last region byte
        """
        return self.offset + self.size - 1

    def v2p(self, addr: int) -> int:
        """
        Virtual address to physical offset translation. Assumes that address is valid within Region.
        :param addr: Virtual address
        :return: Physical offset
        """
        return self.offset + addr - self.addr

    def p2v(self, off: int) -> int:
        """
        Physical offset to translation. Assumes that offset is valid within Region.
        :param off: Physical offset
        :return: Virtual address
        """
        return self.addr + off - self.offset

    def contains_offset(self, offset: int) -> bool:
        """
        Checks whether region contains provided physical offset
        """
        return self.offset <= offset < self.offset + self.size

    def contains_addr(self, addr: int) -> bool:
        """
        Checks whether region contains provided virtual address
        """
        return self.addr <= addr < self.end

    def intersects_range(self, addr: int, length: int) -> bool:
        """
        Checks whether region mapping intersects with provided range
        """
        return self.addr < addr + length and addr < self.end

    def trim_range(self, addr: int, length: Optional[int] = None) -> Optional["Region"]:
        """
        Returns region intersection with provided range
        :param addr: Virtual address of starting point
        :param length: Length of range (optional)
        :rtype: :class:`Region`
        """
        new_addr = max(self.addr, addr)
        new_end = min(self.end, addr + length) if length is not None else self.end
        if new_end <= new_addr:
            return None
        new_offset = self.v2p(new_addr)
        return Region(
            new_addr,
            new_end - new_addr,
            self.state,
            self.type_,
            self.protect,
            new_offset,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Region):
            raise ValueError("Not a region object!")

        return (
            self.addr == other.addr
            and self.size == other.size
            and self.state == other.state
            and self.type_ == other.type_
            and self.protect == other.protect
            and self.offset == other.offset
        )


def normalize_regions(
    regions: Optional[List[Region]],
    buffer_size: Optional[int] = None,
) -> List[Region]:
    """
    Canonicalizes a region table parsed from an untrusted process memory dump.

    Region descriptors (e.g. the Cuckoo dump header, or a caller-supplied
    mapping) originate from attacker-controlled data and must never be trusted
    as-is. This function turns them into a canonical table that upholds the
    invariants expected by :class:`ProcessMemory`:

    * regions are **sorted by virtual address** (stable on ties),
    * virtual ranges do not **overlap** (first region wins, later ones clipped),
    * every region is backed by an in-bounds part of the underlying buffer
      (no **physical overflow**; truncated regions are clipped),
    * no virtual range wraps the address space (**address overflow**) and no
      region has a negative size or offset,
    * zero-size regions are dropped.

    Fields carried by the descriptor (``state``, ``type_``, ``protect``) are
    treated as metadata only. Exceptional protection bits such as
    :data:`PAGE_GUARD` never cause a region to be discarded or trusted: the
    raw value is preserved on the resulting :class:`Region`.

    :param regions: Raw list of :class:`Region` objects, or ``None``
    :param buffer_size: Size of the buffer backing the regions. When provided,
        regions reaching past it are clipped instead of pointing at bytes that
        do not exist.
    :return: A new, canonicalized list of regions (input list is not mutated)
    """
    if not regions:
        return []

    normalized: List[Region] = []
    # Stable sort keeps the original order (and therefore the original
    # first-wins precedence) for regions sharing the same address.
    for index, region in enumerate(regions):
        if not isinstance(region, Region):
            log.warning("Dropping region #%d: not a Region object", index)
            continue

        addr, size, offset = region.addr, region.size, region.offset
        if not all(isinstance(v, int) for v in (addr, size, offset)):
            log.warning(
                "Dropping region #%d at 0x%x: non-integer addr/size/offset",
                index,
                getattr(region, "addr", 0),
            )
            continue
        if addr < 0 or offset < 0 or size <= 0:
            log.warning(
                "Dropping region #%d at 0x%x: negative or zero-size descriptor "
                "(addr=%#x size=%#x offset=%#x)",
                index,
                addr,
                addr,
                size,
                offset,
            )
            continue
        # Virtual range must not wrap the 64-bit address space.
        if addr > _MAX_U64 or size - 1 > _MAX_U64 - addr:
            log.warning(
                "Dropping region #%d at 0x%x: virtual range overflows the "
                "64-bit address space (size=%#x)",
                index,
                addr,
                size,
            )
            continue
        # Physical backing range must not wrap either.
        if size - 1 > _MAX_U64 - offset:
            log.warning(
                "Dropping region #%d at 0x%x: physical range overflows "
                "(offset=%#x size=%#x)",
                index,
                addr,
                offset,
                size,
            )
            continue
        # Clip regions that run past the end of the backing buffer. The
        # attacker's claimed size can never invent bytes that are not present.
        if buffer_size is not None and offset >= buffer_size:
            log.warning(
                "Dropping region #%d at 0x%x: offset %#x is outside the "
                "backing buffer (size=%#x)",
                index,
                addr,
                offset,
                buffer_size,
            )
            continue
        if buffer_size is not None and offset + size > buffer_size:
            clipped_size = buffer_size - offset
            log.warning(
                "Clipping region at 0x%x: claimed size %#x exceeds buffer, "
                "truncated to %#x bytes",
                addr,
                size,
                clipped_size,
            )
            size = clipped_size
            if size <= 0:
                continue

        normalized.append(
            Region(addr, size, region.state, region.type_, region.protect, offset)
        )

    # Canonical virtual-address order. Python's sort is stable, which preserves
    # the dump's original precedence among descriptors sharing an address.
    normalized.sort(key=lambda r: r.addr)

    # Resolve overlaps with a first-wins policy: the earliest region in virtual
    # order keeps its full mapping, every later region is clipped to the still
    # unclaimed part of the address space. Each virtual address therefore maps
    # to exactly one physical offset.
    resolved: List[Region] = []
    for region in normalized:
        if not resolved or region.addr >= resolved[-1].end:
            resolved.append(region)
            continue
        new_addr = resolved[-1].end
        if new_addr >= region.end:
            log.warning(
                "Dropping region at 0x%x: fully shadowed by an earlier region",
                region.addr,
            )
            continue
        shift = new_addr - region.addr
        log.warning(
            "Resolving overlap: clipping region at 0x%x to 0x%x-0x%x",
            region.addr,
            new_addr,
            region.end,
        )
        resolved.append(
            Region(
                new_addr,
                region.size - shift,
                region.state,
                region.type_,
                region.protect,
                region.offset + shift,
            )
        )
    return resolved
