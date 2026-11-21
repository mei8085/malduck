Memory model objects (procmem)
==============================

.. automodule:: malduck.procmem

ProcessMemory (procmem)
-----------------------

.. autoclass:: malduck.procmem

.. autoclass:: malduck.procmem.procmem.ProcessMemory
    :members:

Key material (import_key / scan_keys)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:py:meth:`ProcessMemory.import_key` and :py:meth:`ProcessMemory.scan_keys`
strictly recover Windows key blobs from an attacker-controlled dump. They
validate the origin region, the declared length and the structure version,
bind accepted keys to their region and algorithm family, and return
distinguishable :class:`~malduck.crypto.keyblob.KeyImportStatus` failures
(overlapping regions, truncated structures, overflowing lengths, ambiguous
competing keys) instead of a bare ``None``.

.. code-block:: python

    from malduck import procmem

    with procmem.from_file("dump.bin", regions=regions) as p:
        for hit in p.findv(b"\x08\x02\x00\x00"):
            result = p.import_key(hit)
            if result:
                print(result.material.family, hex(result.addr))

.. autoclass:: malduck.procmem.procmem.Region
    :members:

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
