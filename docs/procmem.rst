Memory model objects (procmem)
==============================

.. automodule:: malduck.procmem

ProcessMemory (procmem)
-----------------------

.. autoclass:: malduck.procmem

.. autoclass:: malduck.procmem.procmem.ProcessMemory
    :members:

.. autoclass:: malduck.procmem.procmem.Region
    :members:

.. autofunction:: malduck.procmem.normalize_regions

.. autofunction:: malduck.procmem.page_protect_to_access

Hardening against hostile region tables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The region descriptors embedded in a process memory dump (Cuckoo headers,
caller-supplied ``regions`` lists and, for image loads, PE/ELF section and
segment headers) originate from **attacker-controlled data**. They are never
trusted as a valid mapping. Every table is canonicalized through
:func:`malduck.procmem.normalize_regions` before it is used, which guarantees
that the resulting mapping:

* is **sorted by virtual address** (descriptors may arrive in arbitrary order),
* is **non-overlapping** — on overlap the earliest region wins and later
  regions are clipped to the still-unclaimed part of the address space,
* is **fully backed by the buffer** — regions reaching past the end of the
  dump are clipped to the bytes actually present, and regions with no backing
  bytes are dropped,
* never **overflows** the 64-bit virtual address space or the physical range
  (wrapping ``addr + size`` / ``offset + size`` descriptors are dropped),
* contains no zero- or negative-sized entries.

The descriptor's metadata fields (``state``, ``type_`` and ``protect``) do not
influence the mapping at all. Exceptional protection modifiers such as
``PAGE_GUARD``, ``PAGE_NOCACHE`` and ``PAGE_WRITECOMBINE`` are preserved raw on
the :class:`~malduck.procmem.procmem.Region`; they are only stripped when an
access-rights string is rendered (see
:func:`~malduck.procmem.page_protect_to_access`). A guard page is therefore
neither trusted as privileged nor discarded — it is mapped like any other
region.

Impact on YARA matching
^^^^^^^^^^^^^^^^^^^^^^^

:py:meth:`~malduck.procmem.procmem.ProcessMemory.yarav` scans the raw buffer and
maps every physical match offset back to a virtual address through ``p2v``.
Because the canonical table assigns each virtual address to exactly one
physical offset, a match is reported at a single, deterministic address even
when the hostile table described overlapping aliases for the same bytes.
Bytes that only existed inside a clipped or dropped descriptor are no longer
reachable, so a rule cannot be satisfied against memory that the dump does not
actually contain. As before, matches do not cross region borders.

Impact on PE / ELF parsing
^^^^^^^^^^^^^^^^^^^^^^^^^^

PE section and ELF ``PT_LOAD`` headers go through the same canonicalization
when an image is loaded. Overlapping sections can no longer establish
conflicting virtual-to-physical translations, and a section claiming more data
than the image holds is clipped instead of causing out-of-bounds reads. The
address/length handed to the parser therefore always correspond to real bytes,
which keeps ``readv``/``v2p`` lookups and the reconstructed image consistent.
Canonicalization only hardens the address mapping; the structural validation of
the binary itself (magic, headers, directories) is still performed by the PE/ELF
parser, so a structurally invalid image is rejected regardless of its region
table.

ProcessMemoryPE (procmempe)
---------------------------

.. autoclass:: malduck.procmempe

.. autoclass:: malduck.procmem.procmempe.ProcessMemoryPE
    :members:

ProcessMemoryELF (procmemelf)
-----------------------------

.. autoclass:: malduck.procmemelf

.. autoclass:: malduck.procmem.procmemelf.ProcessMemoryELF
    :members:

CuckooProcessMemory (cuckoomem)
-------------------------------

.. autoclass:: malduck.cuckoomem

.. autoclass:: malduck.procmem.cuckoomem.CuckooProcessMemory
    :members:

IDAProcessMemory (idamem)
-------------------------

.. autoclass:: malduck.idamem

.. autoclass:: malduck.procmem.idamem.IDAProcessMemory
    :members:
