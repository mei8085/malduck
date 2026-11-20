import logging
import struct
from typing import Optional

from .procmem import ProcessMemory, ProcessMemoryBuffer
from .region import Region, normalize_regions

__all__ = ["CuckooProcessMemory", "cuckoomem"]

log = logging.getLogger(__name__)

# Cuckoo 2.x memory region descriptor: Q addr, I size, I state, I type, I protect
_REGION_HEADER_SIZE = 24
_REGION_HEADER = struct.Struct("QIIII")


class CuckooProcessMemory(ProcessMemory):
    """
    Wrapper object to operate on process memory dumps in Cuckoo 2.x format.

    The region table embedded in the dump is attacker-controlled data. Every
    descriptor is therefore validated and canonicalized through
    :func:`normalize_regions` before it becomes part of the address mapping:
    truncated headers stop the parse, descriptors whose claimed size runs past
    the end of the file are clipped or dropped, and overlapping or unsorted
    descriptors are resolved instead of being trusted.
    """

    def __init__(
        self, buf: ProcessMemoryBuffer, base: Optional[int] = None, **_
    ) -> None:
        super(CuckooProcessMemory, self).__init__(buf)
        ptr = 0
        regions = []

        while ptr < self.length:
            # A truncated trailing header cannot describe any bytes: stop
            # before consuming it instead of unpacking short data or treating
            # header bytes as payload of the previous region.
            if ptr + _REGION_HEADER_SIZE > self.length:
                log.warning(
                    "Truncated region header at offset %#x (%d bytes left), "
                    "stopping region table parse",
                    ptr,
                    self.length - ptr,
                )
                break

            hdr = self.readp(ptr, _REGION_HEADER_SIZE)
            addr, size, state, typ, protect = _REGION_HEADER.unpack(hdr)
            data_offset = ptr + _REGION_HEADER_SIZE

            # The claimed payload must exist in the file. A descriptor
            # reaching past EOF is kept only for its actually present part by
            # normalize_regions; anything beyond it cannot hold another
            # descriptor, so the table walk stops here.
            if size > self.length - data_offset:
                log.warning(
                    "Region at 0x%x claims %#x bytes and reaches past the end "
                    "of the dump (data offset %#x), stopping region table parse",
                    addr,
                    size,
                    data_offset,
                )
                regions.append(
                    Region(addr, size, state, typ, protect, data_offset)
                )
                break

            regions.append(Region(addr, size, state, typ, protect, data_offset))
            ptr = data_offset + size

        # Enforce sorted, non-overlapping, in-bounds mappings.
        self.regions = normalize_regions(regions, self.length)
        if base is None:
            if self.regions:
                self.imgbase = self.regions[0].addr
            else:
                self.imgbase = 0


cuckoomem = CuckooProcessMemory
