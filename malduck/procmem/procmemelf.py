import io
from typing import List, Optional

import elftools
import elftools.elf.elffile

from .binmem import ProcessMemoryBinary
from .procmem import ProcessMemoryBuffer
from .region import Region

__all__ = ["ProcessMemoryELF", "procmemelf"]


class ProcessMemoryELF(ProcessMemoryBinary):
    """
    Representation of memory-mapped ELF file

    Short name: `procmemelf`

    ELF files can be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).
    """

    __magic__ = b"\x7fELF"

    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        self._elf: Optional[elftools.elf.elffile.ELFFile] = None
        super().__init__(
            buf, base=base, regions=regions, image=image, detect_image=detect_image
        )

    def _elf_direct_load(self) -> elftools.elf.elffile.ELFFile:
        offset = self.v2p(self.imgbase)
        if offset is None:
            raise RuntimeError("imgbase out of regions")
        # Stream required for ELFFile()
        stream = io.BytesIO(self.readp(offset))
        elf = elftools.elf.elffile.ELFFile(stream)
        # Try to iter_segments to check whether ELFFile is really correct
        list(elf.iter_segments())
        return elf

    def is_valid(self) -> bool:
        if self.readv(self.imgbase, 4) != self.__magic__:
            return False
        try:
            self._elf_direct_load()
            return True
        except Exception:
            return False

    def _reload_as_image(self) -> None:
        page_size = 0x1000
        # Buffer offset where the image starts. All regions created below
        # keep offsets in the coordinate system of the underlying buffer,
        # so address translation stays consistent with the ProcessMemory
        # object the image was carved from.
        img_offset = self.v2p(self.imgbase)
        if img_offset is None:
            raise elftools.elf.elffile.ELFError("imgbase out of regions")
        # If mmap: close all descriptors (or nullify references if mmap
        # is not owned by current object), copying the contents, so the
        # image view stays valid after the original dump is closed.
        self.close(copy=True)
        # Reset regions
        imgbase = None
        regions = []
        buf_len = self.length
        # Load image segments
        for segment in self.elf.iter_segments():
            if segment.header["p_type"] == "PT_LOAD":
                if segment.header["p_offset"] == 0:
                    # virtual address of ELF file header
                    imgbase = segment.header["p_vaddr"]
                if page_size is None:
                    presegment_len = 0
                    postsegment_len = 0
                else:
                    presegment_len = segment.header["p_vaddr"] % page_size
                    postsegment_len = (
                        page_size
                        - (segment.header["p_vaddr"] + segment.header["p_filesz"])
                        % page_size
                    )
                region_offset = img_offset + segment.header["p_offset"] - presegment_len
                if region_offset < 0 or region_offset >= buf_len:
                    # Segment points beyond available data (truncated
                    # or inconsistent metadata): don't map bytes that
                    # don't exist.
                    continue
                region_size = min(
                    segment.header["p_filesz"] + presegment_len + postsegment_len,
                    buf_len - region_offset,
                )
                regions.append(
                    Region(
                        segment.header["p_vaddr"] - presegment_len,
                        region_size,
                        0,
                        segment.header["p_type"],
                        0,  # TODO: protect flags
                        region_offset,
                    )
                )
        if len(regions) == 0:
            raise elftools.elf.elffile.ELFError("No regions in ELF file!")
        if imgbase is None:
            raise elftools.elf.elffile.ELFError("Can't find ELF image base!")
        self.imgbase = imgbase
        self.regions = regions

    @property
    def elf(self) -> elftools.elf.elffile.ELFFile:
        """Related :class:`ELFFile` object"""
        if not self._elf:
            self._elf = self._elf_direct_load()
        return self._elf

    def is_image_loaded_as_memdump(self):
        raise NotImplementedError()

    @property
    def imgend(self) -> int:
        """Address where ELF image ends"""
        lastSegment = self.elf.get_segment(self.elf.num_segments() - 1)
        return lastSegment.header["p_vaddr"] + lastSegment.header["p_memsz"]


procmemelf = ProcessMemoryELF
