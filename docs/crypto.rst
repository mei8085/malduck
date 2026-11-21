Cryptography
=======================

.. automodule:: malduck.crypto

Common cryptography algorithms used in malware.

AES
--------------

AES (Advanced Encryption Standard) block cipher.

Supported modes: CBC, ECB, CTR.

.. code-block:: python

    from malduck import aes

    key = b'A'*16
    iv = b'B'*16
    plaintext = b'data'*16
    ciphertext = aes.cbc.encrypt(key, iv, plaintext)


AES-CBC mode
~~~~~~~~~~~~
.. autofunction:: malduck.aes.cbc.encrypt
.. autofunction:: malduck.aes.cbc.decrypt

AES-ECB mode
~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: malduck.aes.ecb.encrypt
.. autofunction:: malduck.aes.ecb.decrypt

AES-CTR mode
~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: malduck.aes.ctr.encrypt
.. autofunction:: malduck.aes.ctr.decrypt

Blowfish (ECB only)
-------------------

Blowfish block cipher.

Supported modes: ECB.

.. code-block:: python

    from malduck import blowfish

    key = b'blowfish'
    plaintext = b'data'*16
    ciphertext = blowfish.ecb.encrypt(key, plaintext)


.. autofunction:: malduck.blowfish.ecb.encrypt
.. autofunction:: malduck.blowfish.ecb.decrypt

Camellia
--------------

Camellia block cipher.

Supported modes: ECB, CBC, CTR, CFB, OFB.

.. code-block:: python

    from malduck import camellia

    key = b'A'*16
    iv = b'B'*16
    plaintext = b'data'*16
    ciphertext = camellia.ecb.encrypt(key, iv, plaintext)


Camellia-ECB mode
~~~~~~~~~~~~
.. autofunction:: malduck.camellia.ecb.encrypt
.. autofunction:: malduck.camellia.ecb.decrypt

Camellia-CBC mode
~~~~~~~~~~~~
.. autofunction:: malduck.camellia.cbc.encrypt
.. autofunction:: malduck.camellia.cbc.decrypt

Camellia-CTR mode
~~~~~~~~~~~~
.. autofunction:: malduck.camellia.ctr.encrypt
.. autofunction:: malduck.camellia.ctr.decrypt

Camellia-CFB mode
~~~~~~~~~~~~
.. autofunction:: malduck.camellia.cfb.encrypt
.. autofunction:: malduck.camellia.cfb.decrypt

Camellia-OFB mode
~~~~~~~~~~~~
.. autofunction:: malduck.camellia.ofb.encrypt
.. autofunction:: malduck.camellia.ofb.decrypt

ChaCha20
--------

ChaCha20 stream cipher.

Assumes empty nonce if none given.

.. code-block:: python

    from malduck import chacha20

    key = b'chachaKeyHereNow' * 2
    nonce = b'\x01\x02\x03\x04\x05\0x6\0x7'
    plaintext = b'data'*16
    ciphertext = chacha20.decrypt(key, plaintext, nonce)

.. autofunction:: malduck.chacha20.encrypt
.. autofunction:: malduck.chacha20.decrypt

DES/DES3 (CBC only)
-------------------

Triple DES block cipher.

Fallbacks to single DES for 8 byte keys.

Supported modes: CBC.

.. code-block:: python

    from malduck import des3

    key = b'des3des3'
    iv = b'3des3des'
    plaintext = b'data' * 16
    ciphertext = des3.cbc.encrypt(key, plaintext)

.. autofunction:: malduck.des3.cbc.encrypt
.. autofunction:: malduck.des3.cbc.decrypt

Salsa20
--------

Salsa20 stream cipher.

Assumes empty nonce if none given.

.. code-block:: python

    from malduck import salsa20

    key = b'salsaFTW' * 4
    nonce = b'\x01\x02\x03\x04\x05\0x6\0x7'
    plaintext = b'data' * 16
    ciphertext = salsa20.decrypt(key, plaintext, nonce)

.. autofunction:: malduck.salsa20.encrypt
.. autofunction:: malduck.salsa20.decrypt


Serpent (CBC only)
------------------

Serpent block cipher.

Supported modes: CBC

.. code-block:: python

    from malduck import serpent

    key = b'a'*16
    iv = b'b'*16
    plaintext = b'data'*16
    ciphertext = serpent.cbc.encrypt(key, plaintext, iv=iv)

.. autofunction:: malduck.serpent.cbc.encrypt
.. autofunction:: malduck.serpent.cbc.decrypt

Rabbit
--------------

Rabbit stream cipher.

.. code-block:: python

    from malduck import rabbit

    key = b'a'*16
    iv = b'b'*16
    plaintext = b'data'*16
    ciphertext = rabbit(key, iv, plaintext)

.. autofunction:: malduck.rabbit

RC4
--------------

RC4 stream cipher.

.. code-block:: python

    from malduck import rc4

    key = b'a'*16
    plaintext = b'data'*16
    ciphertext = rc4(key, plaintext)

.. autofunction:: malduck.rc4

XOR
--------------

XOR "stream cipher".

.. code-block:: python

    from malduck import xor

    key = b'a'*16
    xored = b'data'*16
    unxored = xor(key, xored)

.. autofunction:: malduck.xor

RSA (BLOB parser)
-----------------

.. autoclass:: malduck.rsa
    :members:

.. autoclass:: malduck.crypto.rsa.RSA
    :members:

BLOB struct
-----------

.. autoclass:: malduck.crypto.winhdr.BLOBHEADER
    :members:

.. autoclass:: malduck.crypto.aes.PlaintextKeyBlob
    :members:

.. autoclass:: malduck.crypto.rsa.PublicKeyBlob
    :members:

.. autoclass:: malduck.crypto.rsa.PrivateKeyBlob
    :members:

Key material recovered from process memory dumps
------------------------------------------------

Key blobs carved out of a Windows process memory dump are attacker-controlled
input. ``ProcessMemory.import_key()`` and ``ProcessMemory.scan_keys()`` only
accept a key when its region address, its declared length and its structure
version all validate, and they bind accepted keys to the origin region and
algorithm family. Failures are reported as distinct
:class:`~malduck.crypto.keyblob.KeyImportStatus` values (overlapping regions,
truncated structures, overflowing lengths, ambiguous competing keys, ...) so a
caller cannot mistake one failure mode for another and ``if result:`` fails
closed.

.. code-block:: python

    from malduck import procmem

    with procmem.from_file("dump.bin", regions=regions) as p:
        result = p.import_key(0x41410000)
        if result:
            # KeyMaterial carries its region/address provenance and family.
            plaintext = result.material.decrypt(ciphertext, iv=iv)
        else:
            print("key import failed:", result.status)

.. autoclass:: malduck.crypto.keyblob.KeyFamily
    :members:

.. autoclass:: malduck.crypto.keyblob.KeyImportStatus
    :members:

.. autoclass:: malduck.crypto.keyblob.KeyImportResult
    :members:

.. autoclass:: malduck.crypto.keyblob.KeyMaterial
    :members:

.. autofunction:: malduck.crypto.keyblob.parse_key_blob

.. autofunction:: malduck.crypto.keyblob.scan_key_blobs

.. autofunction:: malduck.crypto.keyblob.plan_key_blob
