# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

r"""
Strict import of Windows cryptographic key blobs (``BLOBHEADER`` structures).

Memory dumps are attacker-controlled input. A key blob recovered from one is
therefore untrusted until it has been validated against the trust boundary it
was found in:

* the structure must be fully contained in a single, well-formed memory region
  (no crossing region borders, no reading through overlapping descriptors),
* declared length fields must be representable and must fit the bytes that are
  actually present (no truncated structures, no overflowing lengths),
* the structure version and reserved fields must be the expected ones,
* the algorithm identifier must agree with the blob type and the key size.

A successfully imported key (:class:`KeyMaterial`) is bound to the
:class:`~malduck.procmem.Region` it was recovered from and to its algorithm
family, so later configuration decryption keeps receiving an object that is
consistent with the key's origin.

Failures are reported as :class:`KeyImportResult` objects carrying a
:class:`KeyImportStatus`, and are intentionally *distinguishable*: an
overlapping region table, a truncated structure, an overflowing length field
and several competing keys do not collapse into a single ``None``. A result is
truthy only for :attr:`KeyImportStatus.OK`, so callers that merely check the
result fail closed.

.. code-block:: python

    from malduck import procmem

    with procmem.from_file("dump.bin", regions=regions) as p:
        result = p.import_key(0x41410000)
        if result:
            print(result.material.family, result.material.export_key())
        else:
            print("key import failed:", result.status)
"""

import struct
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..string.bin import bigint
from .winhdr import BLOBHEADER

__all__ = [
    "KeyFamily",
    "KeyImportStatus",
    "KeyMaterial",
    "KeyImportResult",
    "KeyImportError",
    "KeyBlobPlan",
    "parse_key_blob",
    "plan_key_blob",
    "scan_key_blobs",
    "material_from_plan",
    "merge_key_results",
    "CUR_BLOB_VERSION",
    "MAX_KEY_BLOB_SIZE",
    "MAX_RSA_BITS",
]


#: Structure version written by Windows into ``BLOBHEADER.bVersion``.
CUR_BLOB_VERSION = 2

#: Versions accepted by the parser unless a caller requests an exact one.
ACCEPTED_BLOB_VERSIONS = frozenset({CUR_BLOB_VERSION})

#: Hard cap on the total size of a single key blob. Anything larger is treated
#: as an overflowing length field instead of being read or allocated.
MAX_KEY_BLOB_SIZE = 1 << 20  # 1 MiB

#: Hard cap on RSA modulus size (in bits). 16384-bit keys are already exotic;
#: larger values are attacker-controlled resource exhaustion attempts.
MAX_RSA_BITS = 16384

#: Hard cap on PLAINTEXTKEYBLOB key material size.
MAX_PLAINTEXT_KEY_SIZE = 4096

#: Upper bound on how many distinct competitors an ambiguous scan reports.
_MAX_REPORTED_CANDIDATES = 16

#: Upper bound on how many candidate structure offsets a single region scan
#: enumerates before concluding that the region is hostile.
_MAX_CANDIDATE_OFFSETS = 4096

BLOBHEADER_SIZE = BLOBHEADER.sizeof()

BLOTYPE_KEY_DATA = 8  # PLAINTEXTKEYBLOB
BLOB_PUBLICKEY = 6  # PUBLICKEYBLOB
BLOB_PRIVATEKEY = 7  # PRIVATEKEYBLOB

CALG_AES_128 = 0x0000660E
CALG_AES_192 = 0x0000660F
CALG_AES_256 = 0x00006610
CALG_AES = 0x00006611
CALG_RSA_KEYX = 0x0000A400
CALG_RSA_SIGN = 0x00002400

RSAPUBKEY_SIZE = 12
RSA1_MAGIC = b"RSA1"
RSA2_MAGIC = b"RSA2"

_AES_ALGORITHMS = {
    CALG_AES_128: ("AES", 16),
    CALG_AES_192: ("AES", 24),
    CALG_AES_256: ("AES", 32),
    # CALG_AES is generic: the key size comes from the blob itself.
    CALG_AES: ("AES", 0),
}

_RSA_ALGORITHMS = (CALG_RSA_KEYX, CALG_RSA_SIGN)

#: Byte signatures used to locate candidate key structures in a memory region.
#: Each signature is the little-endian ``aiKeyAlg`` field; the structure starts
#: four bytes before it. Neither a matching bType nor a valid version is assumed
#: here: those are validated by the importer, so malformed candidates still
#: produce a distinguishable failure instead of being silently skipped.
CANDIDATE_SIGNATURES = (
    struct.pack("<I", CALG_AES_128),
    struct.pack("<I", CALG_AES_192),
    struct.pack("<I", CALG_AES_256),
    struct.pack("<I", CALG_AES),
    struct.pack("<I", CALG_RSA_KEYX),
    struct.pack("<I", CALG_RSA_SIGN),
)


class KeyFamily(str, Enum):
    """Algorithm family a key material belongs to."""

    AES = "aes"
    RSA = "rsa"

    def __str__(self) -> str:
        return self.value


class KeyImportStatus(str, Enum):
    """
    Outcome of a key blob import.

    Every failure mode that a caller may need to react to differently has its
    own value; they are never collapsed into ``None``.
    """

    #: All checks passed and a :class:`KeyMaterial` is attached.
    OK = "ok"
    #: No BLOBHEADER (or a body that is not a key blob) at the requested place.
    NO_HEADER = "no_header"
    #: Blob type / algorithm pair is not a supported key blob.
    UNSUPPORTED = "unsupported"
    #: ``bVersion`` is not an accepted structure version.
    BAD_VERSION = "bad_version"
    #: ``wReserved`` is not zero.
    BAD_RESERVED = "bad_reserved"
    #: Declared structure is longer than the bytes available in the region.
    TRUNCATED = "truncated"
    #: Declared length field is not representable / exceeds resource bounds.
    LENGTH_OVERFLOW = "length_overflow"
    #: Declared length is shorter than the buffer passed to a strict import.
    LENGTH_MISMATCH = "length_mismatch"
    #: Structure is complete but its key material is inconsistent.
    INVALID_KEY = "invalid_key"
    #: Parsed key belongs to a different family than the caller expected.
    FAMILY_MISMATCH = "family_mismatch"
    #: Address is not mapped by a single, buffer-backed region.
    REGION_MISMATCH = "region_mismatch"
    #: Structure is covered by more than one region mapping (ambiguous bytes).
    REGION_OVERLAP = "region_overlap"
    #: More than one distinct key candidate was found; the choice is ambiguous.
    AMBIGUOUS = "ambiguous"

    def __str__(self) -> str:
        return self.value

    @property
    def is_success(self) -> bool:
        """True only for :attr:`OK`."""
        return self is KeyImportStatus.OK


#: Failure preference for aggregated (scan) results: the most trust-relevant
#: condition is reported when several candidates failed for different reasons.
_STATUS_PRIORITY = (
    KeyImportStatus.REGION_OVERLAP,
    KeyImportStatus.LENGTH_OVERFLOW,
    KeyImportStatus.TRUNCATED,
    KeyImportStatus.BAD_VERSION,
    KeyImportStatus.BAD_RESERVED,
    KeyImportStatus.FAMILY_MISMATCH,
    KeyImportStatus.INVALID_KEY,
    KeyImportStatus.UNSUPPORTED,
    KeyImportStatus.LENGTH_MISMATCH,
    KeyImportStatus.NO_HEADER,
)


class KeyImportError(Exception):
    """Internal/public signal carrying a structured import failure."""

    def __init__(
        self,
        status: KeyImportStatus,
        detail: str,
        size: Optional[int] = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        #: Declared structure size, filled in for TRUNCATED failures so callers
        #: can reason about what part of the declaration did not fit.
        self.size = size


class KeyBlobPlan:
    """Description of a validated key blob layout inside a buffer."""

    def __init__(
        self,
        blob_type: int,
        version: int,
        key_alg: int,
        family: KeyFamily,
        algorithm: str,
        expected_size: int,
        bitsize: int = 0,
        private: bool = False,
        key_size: int = 0,
        pubexp: int = 0,
    ) -> None:
        self.blob_type = blob_type
        self.version = version
        self.key_alg = key_alg
        self.family = family
        self.algorithm = algorithm
        self.expected_size = expected_size
        self.bitsize = bitsize
        self.private = private
        self.key_size = key_size
        self.pubexp = pubexp

    def __repr__(self) -> str:
        return "KeyBlobPlan(family=%s, algorithm=%s, size=%#x)" % (
            self.family,
            self.algorithm,
            self.expected_size,
        )


class KeyMaterial:
    """
    A validated key bound to its algorithm family and origin region.

    The object is produced only for :attr:`KeyImportStatus.OK` results. Passing
    it to :meth:`decrypt` / :meth:`encrypt` routes to the cipher implementation
    of its own family, so configuration decryption cannot silently use an AES
    key as an RSA key (or vice versa).

    :ivar family: :class:`KeyFamily` of the key
    :ivar algorithm: human readable algorithm name (e.g. ``"AES-128"``)
    :ivar key: raw key bytes for AES, PEM-encoded key for RSA
    :ivar key_alg: Windows ``aiKeyAlg`` identifier
    :ivar blob_type: Windows blob type
    :ivar region: origin :class:`~malduck.procmem.Region` (``None`` when the key
        was imported from a plain buffer)
    :ivar addr: virtual address the structure starts at
    :ivar offset: buffer (physical) offset the structure starts at
    :ivar size: size of the validated structure in bytes
    """

    def __init__(
        self,
        family: KeyFamily,
        algorithm: str,
        key: bytes,
        key_alg: int,
        blob_type: int,
        bitsize: int = 0,
        private: bool = False,
        region: Optional[Any] = None,
        addr: Optional[int] = None,
        offset: Optional[int] = None,
        size: Optional[int] = None,
    ) -> None:
        self.family = family
        self.algorithm = algorithm
        self.key = key
        self.key_alg = key_alg
        self.blob_type = blob_type
        self.bitsize = bitsize
        self.private = private
        self.region = region
        self.addr = addr
        self.offset = offset
        self.size = size

    @property
    def bits(self) -> int:
        """Key size in bits."""
        return self.bitsize

    @property
    def end(self) -> Optional[int]:
        """Virtual address of the first byte after the structure."""
        if self.addr is None or self.size is None:
            return None
        return self.addr + self.size

    def export_key(self) -> bytes:
        """Returns cipher-ready key material (raw bytes for AES, PEM for RSA)."""
        return self.key

    def _bind(
        self,
        region: Optional[Any],
        addr: Optional[int],
        offset: Optional[int],
        size: Optional[int],
    ) -> "KeyMaterial":
        self.region = region
        self.addr = addr
        self.offset = offset
        self.size = size
        return self

    def decrypt(self, data: bytes, **kwargs: Any) -> bytes:
        """
        Decrypts ``data`` using the family this key belongs to.

        AES keys accept ``mode`` (``"cbc"``, ``"ecb"``, ``"ctr"``) and the
        matching ``iv`` / ``nonce`` argument. RSA keys accept ``mode``
        (``"pkcs1v15"`` or ``"oaep"``) and require a private key.
        """
        return self._cipher(decrypt=True, data=data, **kwargs)

    def encrypt(self, data: bytes, **kwargs: Any) -> bytes:
        """Counterpart of :meth:`decrypt`."""
        return self._cipher(decrypt=False, data=data, **kwargs)

    def _cipher(self, decrypt: bool, data: bytes, **kwargs: Any) -> bytes:
        mode = kwargs.pop("mode", None)
        if self.family == KeyFamily.AES:
            from .aes import aes

            if mode is None:
                mode = "cbc"
            if mode not in ("cbc", "ecb", "ctr"):
                raise ValueError("Unsupported AES mode: %r" % (mode,))
            if kwargs:
                unexpected = set(kwargs)
                if mode == "cbc":
                    unexpected.discard("iv")
                if mode == "ctr":
                    unexpected.discard("nonce")
                if unexpected:
                    raise TypeError(
                        "Unexpected arguments: %s" % ", ".join(sorted(unexpected))
                    )
            if mode == "cbc":
                iv = kwargs.get("iv")
                if iv is None:
                    raise ValueError("AES-CBC requires 'iv'")
                if decrypt:
                    return aes.cbc.decrypt(self.key, iv, data)
                return aes.cbc.encrypt(self.key, iv, data)
            if mode == "ecb":
                if decrypt:
                    return aes.ecb.decrypt(self.key, data)
                return aes.ecb.encrypt(self.key, data)
            if mode == "ctr":
                nonce = kwargs.get("nonce")
                if nonce is None:
                    raise ValueError("AES-CTR requires 'nonce'")
                if decrypt:
                    return aes.ctr.decrypt(self.key, nonce, data)
                return aes.ctr.encrypt(self.key, nonce, data)
            raise ValueError("Unsupported AES mode: %r" % (mode,))

        if self.family == KeyFamily.RSA:
            return self._rsa_cipher(decrypt, data, mode or "pkcs1v15", **kwargs)

        raise ValueError("Unsupported key family: %r" % (self.family,))

    def _rsa_cipher(
        self, decrypt: bool, data: bytes, mode: str, **kwargs: Any
    ) -> bytes:
        from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5
        from Cryptodome.PublicKey import RSA as RSA_

        if kwargs:
            raise TypeError("Unexpected arguments: %s" % ", ".join(sorted(kwargs)))
        if not self.private:
            raise ValueError("RSA operation requires a private key")
        try:
            rsa_key = RSA_.import_key(self.key)
        except (ValueError, IndexError, TypeError):
            raise ValueError("Invalid RSA key material")
        if mode in ("pkcs1v15", "pkcs1_v1_5"):
            impl: Any = PKCS1_v1_5.new(rsa_key)
            if decrypt:
                sentinel = None
                return impl.decrypt(data, sentinel)
            return impl.encrypt(data)
        if mode == "oaep":
            impl = PKCS1_OAEP.new(rsa_key)
            if decrypt:
                return impl.decrypt(data)
            return impl.encrypt(data)
        raise ValueError("Unsupported RSA mode: %r" % (mode,))

    def to_json(self) -> Dict[str, Any]:
        """JSON-like representation; key material itself is not included."""
        data: Dict[str, Any] = {
            "family": self.family.value,
            "algorithm": self.algorithm,
            "key_alg": "0x%08x" % self.key_alg,
            "blob_type": self.blob_type,
            "bits": self.bitsize,
            "private": self.private,
            "size": self.size,
        }
        if self.addr is not None:
            data["addr"] = "0x%08x" % self.addr
        if self.end is not None:
            data["end"] = "0x%08x" % self.end
        if self.offset is not None:
            data["offset"] = self.offset
        if self.region is not None:
            data["region"] = self.region.to_json()
        return data

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyMaterial):
            return NotImplemented
        return (self.family, self.key) == (other.family, other.key)

    def __hash__(self) -> int:
        return hash((self.family, self.key))

    def __repr__(self) -> str:
        origin = ""
        if self.addr is not None:
            origin = " @ 0x%x" % self.addr
        return "KeyMaterial(%s%s)" % (self.algorithm, origin)


class KeyImportResult:
    """
    Result of a strict key blob import.

    A result is truthy only when the import succeeded; failure results carry a
    :class:`KeyImportStatus` and a human readable ``detail``. Ambiguous scans
    additionally expose the competing keys through :attr:`candidates`.

    :ivar status: :class:`KeyImportStatus`
    :ivar material: imported :class:`KeyMaterial` (``None`` unless successful)
    :ivar region: region the structure was recovered from (if known)
    :ivar addr: virtual address of the structure (if known)
    :ivar offset: buffer offset of the structure (if known)
    :ivar size: validated structure size (if known)
    :ivar candidates: competing key materials for ambiguous results
    :ivar detail: human readable explanation
    """

    def __init__(
        self,
        status: KeyImportStatus,
        material: Optional[KeyMaterial] = None,
        region: Optional[Any] = None,
        addr: Optional[int] = None,
        offset: Optional[int] = None,
        size: Optional[int] = None,
        candidates: Optional[List[KeyMaterial]] = None,
        detail: str = "",
    ) -> None:
        self.status = status
        self.material = material
        self.region = region
        self.addr = addr
        self.offset = offset
        self.size = size
        self.candidates = candidates if candidates is not None else []
        self.detail = detail

    @classmethod
    def success(cls, material: KeyMaterial, **kwargs: Any) -> "KeyImportResult":
        kwargs.setdefault("region", material.region)
        kwargs.setdefault("addr", material.addr)
        kwargs.setdefault("offset", material.offset)
        kwargs.setdefault("size", material.size)
        return cls(KeyImportStatus.OK, material, **kwargs)

    @classmethod
    def failure(
        cls, status: KeyImportStatus, detail: str, **kwargs: Any
    ) -> "KeyImportResult":
        if status is KeyImportStatus.OK:
            raise ValueError("Failure result cannot have OK status")
        return cls(status, None, detail=detail, **kwargs)

    @property
    def ok(self) -> bool:
        """True when a key was imported successfully."""
        return self.status.is_success and self.material is not None

    @property
    def failed(self) -> bool:
        """True for every non-successful outcome."""
        return not self.ok

    @property
    def ambiguous(self) -> bool:
        """True when several distinct keys competed for the same request."""
        return self.status is KeyImportStatus.AMBIGUOUS

    def export_key(self) -> Optional[bytes]:
        """Returns key material for a successful result, otherwise ``None``."""
        return self.material.export_key() if self.material is not None else None

    def with_origin(
        self,
        region: Optional[Any],
        addr: Optional[int] = None,
        offset: Optional[int] = None,
        size: Optional[int] = None,
    ) -> "KeyImportResult":
        """Attaches region/address provenance to the result and its material."""
        self.region = region
        if addr is not None:
            self.addr = addr
        if offset is not None:
            self.offset = offset
        if size is not None:
            self.size = size
        if self.material is not None:
            self.material._bind(region, self.addr, self.offset, self.size)
        return self

    def to_json(self) -> Dict[str, Any]:
        """JSON-like representation of the outcome."""
        data: Dict[str, Any] = {"status": self.status.value, "detail": self.detail}
        if self.addr is not None:
            data["addr"] = "0x%08x" % self.addr
        if self.offset is not None:
            data["offset"] = self.offset
        if self.size is not None:
            data["size"] = self.size
        if self.material is not None:
            data["material"] = self.material.to_json()
        if self.candidates:
            data["candidates"] = [c.to_json() for c in self.candidates]
        return data

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        if self.ok:
            return "KeyImportResult(OK, %r)" % (self.material,)
        return "KeyImportResult(%s, %r)" % (self.status.value, self.detail)


def _reject(status: KeyImportStatus, detail: str, size: Optional[int] = None) -> None:
    raise KeyImportError(status, detail, size=size)


def _read_header(data: bytes) -> Tuple[int, int, int, int]:
    if len(data) < BLOBHEADER_SIZE:
        _reject(
            KeyImportStatus.TRUNCATED,
            "BLOBHEADER truncated: %d < %d bytes" % (len(data), BLOBHEADER_SIZE),
        )
    btype, version, reserved, key_alg = struct.unpack_from("<BBHI", data, 0)
    return btype, version, reserved, key_alg


def _check_header(
    btype: int,
    version: int,
    reserved: int,
    key_alg: int,
    expected_version: Optional[int],
) -> KeyFamily:
    if btype not in (BLOTYPE_KEY_DATA, BLOB_PUBLICKEY, BLOB_PRIVATEKEY):
        _reject(
            KeyImportStatus.UNSUPPORTED,
            "Unsupported blob type: %#x" % btype,
        )

    if expected_version is not None:
        if version != expected_version:
            _reject(
                KeyImportStatus.BAD_VERSION,
                "Structure version %d does not match expected %d"
                % (version, expected_version),
            )
    elif version not in ACCEPTED_BLOB_VERSIONS:
        _reject(
            KeyImportStatus.BAD_VERSION,
            "Unsupported structure version %d (accepted: %s)"
            % (version, sorted(ACCEPTED_BLOB_VERSIONS)),
        )

    if reserved != 0:
        _reject(
            KeyImportStatus.BAD_RESERVED,
            "BLOBHEADER.wReserved is %#x, expected 0" % reserved,
        )

    if btype == BLOTYPE_KEY_DATA:
        if key_alg not in _AES_ALGORITHMS:
            _reject(
                KeyImportStatus.UNSUPPORTED,
                "Algorithm %#x is not a supported AES plaintext key algorithm"
                % key_alg,
            )
        return KeyFamily.AES
    if key_alg not in _RSA_ALGORITHMS:
        _reject(
            KeyImportStatus.UNSUPPORTED,
            "Algorithm %#x is not a supported RSA key algorithm" % key_alg,
        )
    return KeyFamily.RSA


def plan_key_blob(
    data: bytes,
    available: Optional[int] = None,
    *,
    allow_trailing: bool = False,
    expected_family: Optional[Any] = None,
    expected_version: Optional[int] = None,
    max_size: int = MAX_KEY_BLOB_SIZE,
) -> KeyBlobPlan:
    r"""
    Validates a BLOBHEADER prefix and computes the exact structure size.

    Only the bytes needed to learn the declared size are inspected (header plus
    ``cbKey`` for plaintext blobs, header plus ``RSAPUBKEY`` for RSA blobs), so
    an attacker-controlled length can never make the parser read or allocate an
    unbounded amount of data. The returned plan is guaranteed to describe a
    structure whose declared size fits both ``available`` and ``max_size``.

    :param data: At least the structure prefix bytes
    :param available: Number of bytes actually present after ``data[0]``.
        Defaults to ``len(data)``.
    :param allow_trailing: If False, a buffer longer than the declared structure
        is rejected with :attr:`KeyImportStatus.LENGTH_MISMATCH`
    :param expected_family: Optional :class:`KeyFamily` the key must belong to
    :param expected_version: Optional exact ``bVersion`` to require
    :param max_size: Upper bound for the declared structure size
    :raises KeyImportError: on every validation failure
    :rtype: :class:`KeyBlobPlan`
    """
    if available is None:
        available = len(data)
    if available < 0:
        _reject(KeyImportStatus.REGION_MISMATCH, "Negative available length")

    btype, version, reserved, key_alg = _read_header(data)
    family = _check_header(btype, version, reserved, key_alg, expected_version)

    if expected_family is not None:
        if KeyFamily(expected_family) != family:
            _reject(
                KeyImportStatus.FAMILY_MISMATCH,
                "Key family %s does not match expected %s"
                % (family.value, KeyFamily(expected_family).value),
            )

    if btype == BLOTYPE_KEY_DATA:
        header_size = BLOBHEADER_SIZE + 4
        if available < header_size or len(data) < header_size:
            _reject(
                KeyImportStatus.TRUNCATED,
                "PLAINTEXTKEYBLOB key length field truncated: %d < %d bytes"
                % (available, header_size),
            )
        key_size = struct.unpack_from("<I", data, BLOBHEADER_SIZE)[0]
        if key_size > MAX_PLAINTEXT_KEY_SIZE:
            _reject(
                KeyImportStatus.LENGTH_OVERFLOW,
                "Declared key length %#x exceeds limit %#x"
                % (key_size, MAX_PLAINTEXT_KEY_SIZE),
            )
        expected_size = header_size + key_size
        algorithm, alg_size = _AES_ALGORITHMS[key_alg]
        if alg_size and key_size != alg_size:
            _reject(
                KeyImportStatus.INVALID_KEY,
                "Key length %d does not match algorithm %#x (%d bytes)"
                % (key_size, key_alg, alg_size),
            )
        if not alg_size and key_size not in (16, 24, 32):
            # Generic CALG_AES: the size comes from the blob, but only the
            # supported AES key sizes are acceptable.
            _reject(
                KeyImportStatus.INVALID_KEY,
                "Generic AES blob carries unsupported key length %d" % key_size,
            )
        algorithm_name = "AES-%d" % (key_size * 8) if key_size else algorithm
        if expected_size > max_size:
            _reject(
                KeyImportStatus.LENGTH_OVERFLOW,
                "Declared structure size %#x exceeds limit %#x"
                % (expected_size, max_size),
            )
        if expected_size > available:
            _reject(
                KeyImportStatus.TRUNCATED,
                "PLAINTEXTKEYBLOB declares %#x bytes, only %#x available"
                % (expected_size, available),
                size=expected_size,
            )
        if not allow_trailing and expected_size < available:
            _reject(
                KeyImportStatus.LENGTH_MISMATCH,
                "PLAINTEXTKEYBLOB declares %#x bytes, buffer has %#x"
                % (expected_size, available),
            )
        return KeyBlobPlan(
            btype,
            version,
            key_alg,
            family,
            algorithm_name,
            expected_size,
            bitsize=key_size * 8,
            key_size=key_size,
        )

    # PUBLICKEYBLOB / PRIVATEKEYBLOB share the RSAPUBKEY prefix.
    prefix_size = BLOBHEADER_SIZE + RSAPUBKEY_SIZE
    if available < prefix_size or len(data) < prefix_size:
        _reject(
            KeyImportStatus.TRUNCATED,
            "RSAPUBKEY truncated: %d < %d bytes" % (available, prefix_size),
        )
    magic, bitsize, pubexp = struct.unpack_from("<4sII", data, BLOBHEADER_SIZE)
    expected_magic = RSA2_MAGIC if btype == BLOB_PRIVATEKEY else RSA1_MAGIC
    if magic != expected_magic:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA blob magic %r does not match blob type %d (expected %r)"
            % (magic, btype, expected_magic),
        )
    if bitsize == 0 or bitsize % 8 != 0:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA modulus size %d is not a non-zero multiple of 8 bits" % bitsize,
        )
    if bitsize > MAX_RSA_BITS:
        _reject(
            KeyImportStatus.LENGTH_OVERFLOW,
            "RSA modulus size %d bits exceeds limit %d bits" % (bitsize, MAX_RSA_BITS),
        )
    if pubexp < 3 or pubexp % 2 == 0:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA public exponent %#x is not an odd integer >= 3" % pubexp,
        )
    if btype == BLOB_PRIVATEKEY and bitsize % 16 != 0:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA private key modulus size %d bits does not split into "
            "equal-sized primes" % bitsize,
        )

    bytes_mod = bitsize // 8
    expected_size = prefix_size + bytes_mod
    if btype == BLOB_PRIVATEKEY:
        # p1, p2, exp1, exp2, coeff (bitsize/16 each) + private exponent.
        expected_size += 5 * (bitsize // 16) + bytes_mod

    if expected_size > max_size:
        _reject(
            KeyImportStatus.LENGTH_OVERFLOW,
            "Declared structure size %#x exceeds limit %#x" % (expected_size, max_size),
        )
    if expected_size > available:
        _reject(
            KeyImportStatus.TRUNCATED,
            "RSA blob declares %#x bytes, only %#x available"
            % (expected_size, available),
            size=expected_size,
        )
    if not allow_trailing and expected_size < available:
        _reject(
            KeyImportStatus.LENGTH_MISMATCH,
            "RSA blob declares %#x bytes, buffer has %#x" % (expected_size, available),
        )

    algorithm = "RSA-PRIVATE" if btype == BLOB_PRIVATEKEY else "RSA-PUBLIC"
    return KeyBlobPlan(
        btype,
        version,
        key_alg,
        family,
        algorithm,
        expected_size,
        bitsize=bitsize,
        private=btype == BLOB_PRIVATEKEY,
        key_size=bytes_mod,
        pubexp=pubexp,
    )


def _build_aes_material(plan: KeyBlobPlan, blob: bytes) -> KeyMaterial:
    key = blob[BLOBHEADER_SIZE + 4 : BLOBHEADER_SIZE + 4 + plan.key_size]
    key = bytes(key)
    if len(key) != plan.key_size or plan.key_size not in (16, 24, 32):
        _reject(
            KeyImportStatus.INVALID_KEY,
            "AES key material has unsupported size %d" % len(key),
        )
    algorithm = "AES-%d" % (len(key) * 8)
    return KeyMaterial(
        KeyFamily.AES,
        algorithm,
        key,
        plan.key_alg,
        plan.blob_type,
        bitsize=len(key) * 8,
        size=plan.expected_size,
    )


def _build_rsa_material(plan: KeyBlobPlan, blob: bytes) -> KeyMaterial:
    from .rsa import RSA

    bitsize = plan.bitsize
    bytes_mod = bitsize // 8
    off = BLOBHEADER_SIZE + RSAPUBKEY_SIZE
    n = bigint.unpack(blob[off : off + bytes_mod])
    off += bytes_mod
    if not plan.private:
        if n < 3 or n.bit_length() > bitsize or n & 1 == 0:
            _reject(
                KeyImportStatus.INVALID_KEY,
                "RSA modulus is not a valid %d-bit odd integer" % bitsize,
            )
        try:
            pem = RSA.export_key(n, plan.pubexp)
        except (ValueError, IndexError, TypeError):
            _reject(
                KeyImportStatus.INVALID_KEY,
                "RSA public key material could not be exported",
            )
        return KeyMaterial(
            KeyFamily.RSA,
            "RSA-PUBLIC",
            pem,
            plan.key_alg,
            plan.blob_type,
            bitsize=bitsize,
            private=False,
            size=plan.expected_size,
        )

    half = bytes_mod // 2
    p1 = bigint.unpack(blob[off : off + half])
    off += half
    p2 = bigint.unpack(blob[off : off + half])
    off += half
    # exp1, exp2, coeff are not needed to rebuild the key; skip them.
    off += 3 * half
    d = bigint.unpack(blob[off : off + bytes_mod])

    if n < 3 or n.bit_length() > bitsize or n & 1 == 0:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA modulus is not a valid %d-bit odd integer" % bitsize,
        )
    if p1 < 2 or p2 < 2:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA private key contains an invalid prime factor",
        )
    if p1 * p2 != n:
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA private key factors do not multiply to the modulus",
        )
    e = plan.pubexp
    try:
        import math

        lam = (p1 - 1) * (p2 - 1) // math.gcd(p1 - 1, p2 - 1)
        if int(e) * int(d) % lam != 1:
            _reject(
                KeyImportStatus.INVALID_KEY,
                "RSA private exponent is inconsistent with the public exponent",
            )
    except KeyImportError:
        raise
    except (ValueError, ZeroDivisionError, OverflowError):
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA private key parameters are invalid",
        )

    try:
        pem = RSA.export_key(n, e, d)
    except (ValueError, IndexError, TypeError):
        _reject(
            KeyImportStatus.INVALID_KEY,
            "RSA private key material could not be exported",
        )
    return KeyMaterial(
        KeyFamily.RSA,
        "RSA-PRIVATE",
        pem,
        plan.key_alg,
        plan.blob_type,
        bitsize=bitsize,
        private=True,
        size=plan.expected_size,
    )


def _material_from_plan(plan: KeyBlobPlan, blob: bytes) -> KeyMaterial:
    if plan.family == KeyFamily.AES:
        return _build_aes_material(plan, blob)
    return _build_rsa_material(plan, blob)


def material_from_plan(
    plan: KeyBlobPlan,
    blob: bytes,
    *,
    region: Optional[Any] = None,
    addr: Optional[int] = None,
    offset: Optional[int] = None,
) -> KeyImportResult:
    """
    Builds key material from an already validated :class:`KeyBlobPlan`.

    ``blob`` must contain at least ``plan.expected_size`` bytes. Used by
    :meth:`malduck.procmem.ProcessMemory.import_key` after the region and
    length constraints have been enforced. The returned material is bound to
    ``region`` / ``addr`` / ``offset``, so later decryption keeps a provenance
    consistent with the origin.
    """
    if len(blob) < plan.expected_size:
        return KeyImportResult.failure(
            KeyImportStatus.TRUNCATED,
            "Blob is %#x bytes, declared structure needs %#x"
            % (len(blob), plan.expected_size),
            region=region,
            addr=addr,
            offset=offset,
            size=plan.expected_size,
        )
    blob = bytes(blob[: plan.expected_size])
    try:
        material = _material_from_plan(plan, blob)
    except KeyImportError as exc:
        return KeyImportResult.failure(
            exc.status,
            exc.detail,
            region=region,
            addr=addr,
            offset=offset,
            size=plan.expected_size,
        )
    except Exception:  # noqa: BLE001 - attacker-controlled input must not raise
        return KeyImportResult.failure(
            KeyImportStatus.INVALID_KEY,
            "Key blob could not be parsed",
            region=region,
            addr=addr,
            offset=offset,
            size=plan.expected_size,
        )
    material._bind(region, addr, offset, plan.expected_size)
    return KeyImportResult.success(material)


def merge_key_results(results: "List[KeyImportResult]") -> KeyImportResult:
    """
    Merges per-region scan results into one outcome.

    A region whose bytes are ambiguous (overlapping descriptors,
    :attr:`KeyImportStatus.REGION_OVERLAP`) makes the whole scan fail closed:
    no key recovered from the dump can be trusted if part of the dump is
    ambiguous, and the ambiguous overlap is the reported reason.
    :attr:`KeyImportStatus.AMBIGUOUS` is reserved for several *distinct*,
    individually valid keys competing across unambiguous regions (all are
    preserved in ``candidates``). A single distinct key is returned as
    :attr:`KeyImportStatus.OK`. Otherwise the most trust-relevant failure
    reason wins, so callers can distinguish truncation and overflowing lengths
    instead of receiving an empty result.
    """
    if any(result.status is KeyImportStatus.REGION_OVERLAP for result in results):
        return KeyImportResult.failure(
            KeyImportStatus.REGION_OVERLAP,
            "Scanned range contains overlapping region descriptors",
        )

    successes: List[KeyMaterial] = []
    failures: List[KeyImportStatus] = []
    for result in results:
        if result.ok and result.material is not None:
            material = result.material
            if all(
                (material.family, material.key) != (existing.family, existing.key)
                for existing in successes
            ):
                successes.append(material)
            continue
        if result.status is KeyImportStatus.AMBIGUOUS:
            # A range already established ambiguity; keep every competitor so
            # the merged result cannot silently resolve it by picking one.
            for candidate in result.candidates:
                if all(
                    (candidate.family, candidate.key) != (existing.family, existing.key)
                    for existing in successes
                ):
                    successes.append(candidate)
            continue
        failures.append(result.status)

    if len(successes) > 1:
        return KeyImportResult(
            KeyImportStatus.AMBIGUOUS,
            candidates=successes,
            detail="Found %d distinct key candidates; selection is ambiguous"
            % len(successes),
        )
    if len(successes) == 1:
        return KeyImportResult.success(successes[0])
    if failures:
        return KeyImportResult.failure(
            _aggregate_status(failures),
            "No valid key structure found in %d range(s)" % len(failures),
        )
    return KeyImportResult.failure(
        KeyImportStatus.NO_HEADER, "No memory regions contained key candidates"
    )


def parse_key_blob(
    data: bytes,
    *,
    allow_trailing: bool = False,
    expected_family: Optional[Any] = None,
    expected_version: Optional[int] = None,
    max_size: int = MAX_KEY_BLOB_SIZE,
) -> KeyImportResult:
    r"""
    Strictly parses a single Windows key blob held in ``data``.

    Region constraints are not applicable to a plain buffer, but all other
    constraints are: structure version/reserved fields, declared lengths,
    truncation, algorithm/type agreement and key material consistency. Use
    :meth:`malduck.procmem.ProcessMemory.import_key` when the blob lives in a
    process memory dump and must be bound to its origin region.

    :param data: Buffer containing the key blob
    :param allow_trailing: Accept extra bytes after the declared structure
    :param expected_family: Optional :class:`KeyFamily` the key must belong to
    :param expected_version: Optional exact ``bVersion`` to require
    :param max_size: Upper bound for the declared structure size
    :rtype: :class:`KeyImportResult`
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return KeyImportResult.failure(
            KeyImportStatus.NO_HEADER,
            "Key blob data must be a bytes-like object, got %s" % type(data).__name__,
        )
    data = bytes(data)

    if len(data) < BLOBHEADER_SIZE:
        return KeyImportResult.failure(
            KeyImportStatus.NO_HEADER,
            "Buffer too short for BLOBHEADER: %d < %d bytes"
            % (len(data), BLOBHEADER_SIZE),
        )

    try:
        plan = plan_key_blob(
            data,
            len(data),
            allow_trailing=allow_trailing,
            expected_family=expected_family,
            expected_version=expected_version,
            max_size=max_size,
        )
    except KeyImportError as exc:
        return KeyImportResult.failure(exc.status, exc.detail, size=exc.size)

    blob = data[: plan.expected_size]
    try:
        material = _material_from_plan(plan, blob)
    except KeyImportError as exc:
        return KeyImportResult.failure(exc.status, exc.detail, size=plan.expected_size)
    except Exception:  # noqa: BLE001 - attacker-controlled input must not raise
        return KeyImportResult.failure(
            KeyImportStatus.INVALID_KEY,
            "Key blob could not be parsed",
            size=plan.expected_size,
        )
    return KeyImportResult.success(material, offset=0, size=plan.expected_size)


def _candidate_offsets(data: bytes, start: int, end: int) -> List[int]:
    """Structure start offsets whose ``aiKeyAlg`` matches a key blob family."""
    offsets = set()
    for signature in CANDIDATE_SIGNATURES:
        idx = data.find(signature, start, end)
        while idx >= 0:
            candidate = idx - (BLOBHEADER_SIZE - 4)
            if candidate >= start:
                offsets.add(candidate)
            if len(offsets) >= _MAX_CANDIDATE_OFFSETS:
                # Enough candidates to establish ambiguity; bounded work.
                return sorted(offsets)
            idx = data.find(signature, idx + 1, end)
    return sorted(offsets)


def _aggregate_status(statuses: List[KeyImportStatus]) -> KeyImportStatus:
    for status in _STATUS_PRIORITY:
        if status in statuses:
            return status
    return KeyImportStatus.INVALID_KEY


def scan_key_blobs(
    data: bytes,
    *,
    available: Optional[int] = None,
    expected_family: Optional[Any] = None,
    expected_version: Optional[int] = None,
    max_size: int = MAX_KEY_BLOB_SIZE,
    region: Optional[Any] = None,
    addr_base: Optional[int] = None,
) -> KeyImportResult:
    r"""
    Locates and imports every candidate key structure inside ``data``.

    Candidate structures are found by their algorithm identifier, then each is
    validated with the same strict rules as :func:`parse_key_blob`. The result
    is:

    * :attr:`KeyImportStatus.OK` with the single distinct valid key,
    * :attr:`KeyImportStatus.AMBIGUOUS` (with every competing key in
      :attr:`KeyImportResult.candidates`) if two or more *different* valid keys
      are present - the scan never picks one arbitrarily,
    * a distinguishable failure (:attr:`KeyImportStatus.NO_HEADER` if nothing
      looked like a key, otherwise the most trust-relevant failure reason) when
      no valid key was found.

    ``data`` must already be limited to the trusted byte range (e.g. a single
    memory region); the scan never reads beyond it.

    :param data: Buffer to scan
    :param available: Number of bytes considered present (default ``len(data)``)
    :param expected_family: Optional :class:`KeyFamily` the key must belong to
    :param expected_version: Optional exact ``bVersion`` to require
    :param max_size: Upper bound for a declared structure size
    :param region: Origin region attached to every result/candidate
    :param addr_base: Virtual address corresponding to ``data[0]``
    :rtype: :class:`KeyImportResult`
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return KeyImportResult.failure(
            KeyImportStatus.NO_HEADER,
            "Key scan data must be a bytes-like object, got %s" % type(data).__name__,
        )
    data = bytes(data)
    if available is None:
        available = len(data)
    available = max(0, min(available, len(data)))
    view = data[:available]

    if available < BLOBHEADER_SIZE:
        return KeyImportResult.failure(
            KeyImportStatus.NO_HEADER,
            "Buffer too short for BLOBHEADER: %d < %d bytes"
            % (available, BLOBHEADER_SIZE),
            region=region,
        )

    starts = _candidate_offsets(view, 0, available)
    if not starts:
        return KeyImportResult.failure(
            KeyImportStatus.NO_HEADER,
            "No key blob candidate found",
            region=region,
        )

    failures: List[KeyImportStatus] = []
    found: Dict[Tuple[KeyFamily, bytes], KeyMaterial] = {}
    for start in starts:
        # Trailing bytes after the declared structure are expected: the scan
        # looks at a whole region, not at an exactly-sized blob.
        result = parse_key_blob(
            view[start:],
            allow_trailing=True,
            expected_family=expected_family,
            expected_version=expected_version,
            max_size=max_size,
        )
        if not result.ok:
            failures.append(result.status)
            continue
        material = result.material
        assert material is not None
        material._bind(
            region,
            addr_base + start if addr_base is not None else None,
            start,
            material.size,
        )
        found.setdefault((material.family, material.key), material)
        if len(found) > _MAX_REPORTED_CANDIDATES:
            # Bound work: enough contenders to prove ambiguity.
            break

    if len(found) > 1:
        candidates = list(found.values())
        return KeyImportResult(
            KeyImportStatus.AMBIGUOUS,
            region=region,
            candidates=candidates,
            detail="Found %d distinct key candidates; selection is ambiguous"
            % len(candidates),
        )

    if len(found) == 1:
        material = next(iter(found.values()))
        return KeyImportResult.success(material, region=region)

    status = _aggregate_status(failures)
    return KeyImportResult.failure(
        status,
        "No valid key structure among %d candidate(s)" % len(failures),
        region=region,
    )
