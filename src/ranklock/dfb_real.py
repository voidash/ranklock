from __future__ import annotations

"""Executable Duty-Free-Bits affine switch system.

This is a Python port of the straight-line construction in
``alpenlabs/duty-free-bits`` (reference revision
``e2b45be8ceaea0d51e4e7a9ef862b91b59ff255e``).  It deliberately keeps two
objects distinct:

* ``DfbProgram`` is the canonical public join-payload bitstream.  Its length is
  exactly the switch-system join width used by the DFB cost model.
* ``DfbDecodeState`` contains the output masks needed when the affine switch is
  evaluated as a standalone primitive.  An application such as Embryo may fuse
  these masks into its downstream information-theoretic garbling instead of
  serializing them one-for-one.  Until that fusion is implemented, the public
  program length must not be confused with a self-contained evaluator bundle.

The implementation uses the same 128-bit labels, fixed-key AES CCRND/CCRH,
nonce domains, fused [8, 8, 6] extraction schedule, 128-member body batches and
LSB-first packed label representation as the reference implementation.

This is auditable research code, not constant-time production cryptography.
"""

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from typing import Iterable, Sequence

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


LAMBDA = 128
RESIDUE_BATCH_SIZE = 128
MAX_SUB_CHUNK_WIDTH = 8
BULK_NONCE_FLOOR = 1 << 32
BULK_DOMAIN = 1 << 63
NONCE_NAMESPACE_STRIDE = 1 << 48
SLOT_NONCE_NAMESPACE_COORDINATES = 4
BODY_PAD_CANDIDATE_BITS = 32
BODY_PAD_WATCHDOG_ATTEMPTS = 1 << 16
REFERENCE_REVISION = "e2b45be8ceaea0d51e4e7a9ef862b91b59ff255e"

FIRST_80_PRIMES: tuple[int, ...] = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
    397, 401, 409,
)

# The first 90 primes provide >=128 bits of statistical smudging headroom
# for the BN254 base field: M >= p^2 * 2^128.  The first-80 profile from the
# paper provides only 44 full bits for this exact field modulus.
FIRST_90_PRIMES: tuple[int, ...] = FIRST_80_PRIMES + (
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
)

_CCRH_KEY = bytes.fromhex("9e3779b97f4a7c15f39cc0605cedc834")
_CCRH_PUBLIC_S = bytes.fromhex("a09e667f3bcc908bb67ae8584caa73b2")
_PUBLIC_S_WORDS = np.frombuffer(_CCRH_PUBLIC_S, dtype="<u8").copy()

BoolLabel = np.ndarray  # shape (2,), dtype uint64
WideLabel = np.ndarray  # shape (128,), dtype uint32


class DfbError(ValueError):
    pass


def _u32_add(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return np.add(left, right, dtype=np.uint32)


def _u32_sub(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return np.subtract(left, right, dtype=np.uint32)


def _u32_madd(dst: np.ndarray, coefficient: int, src: np.ndarray) -> np.ndarray:
    if coefficient == 0:
        return dst.copy()
    product = np.multiply(src, np.uint32(coefficient), dtype=np.uint32)
    return np.add(dst, product, dtype=np.uint32)


def _u32_sum(values: np.ndarray) -> np.ndarray:
    if len(values) == 0:
        return np.zeros(LAMBDA, dtype=np.uint32)
    total = values.astype(np.uint64).sum(axis=0, dtype=np.uint64)
    return (total & np.uint64(0xFFFF_FFFF)).astype(np.uint32)


def _xor_reduce(values: np.ndarray) -> np.ndarray:
    if len(values) == 0:
        return np.zeros(2, dtype=np.uint64)
    return np.bitwise_xor.reduce(values, axis=0)


def _lg(value: int) -> int:
    if value <= 1:
        return 0
    return (value - 1).bit_length()


def _pow2_mod(exponent: int, modulus: int) -> int:
    return pow(2, exponent, modulus)


def _compute_sub_widths(ell: int, max_width: int = MAX_SUB_CHUNK_WIDTH) -> tuple[int, ...]:
    widths: list[int] = []
    remaining = ell
    while remaining:
        width = min(remaining, max_width)
        widths.append(width)
        remaining -= width
    if any(width < 2 for width in widths):
        raise DfbError(f"unsupported width-1 extraction stage: {widths}")
    return tuple(widths)


class DeterministicRng:
    """Counter-mode SHA-256 RNG for reproducible research fixtures."""

    def __init__(self, seed: bytes, *, domain: bytes = b"ranklock/dfb-real/rng/v1\x00"):
        if not seed:
            raise DfbError("deterministic RNG seed must be non-empty")
        self._seed = bytes(seed)
        self._domain = bytes(domain)
        self._counter = 0
        self._buffer = bytearray()

    def _refill(self) -> None:
        block = sha256(
            self._domain + len(self._seed).to_bytes(4, "big") + self._seed
            + self._counter.to_bytes(16, "big")
        ).digest()
        self._counter += 1
        self._buffer.extend(block)

    def bytes(self, length: int) -> bytes:
        if length < 0:
            raise DfbError("negative random-byte request")
        while len(self._buffer) < length:
            self._refill()
        out = bytes(self._buffer[:length])
        del self._buffer[:length]
        return out

    def bits(self, width: int) -> int:
        if width <= 0:
            raise DfbError("random bit width must be positive")
        raw = int.from_bytes(self.bytes((width + 7) // 8), "little")
        return raw & ((1 << width) - 1)

    def below(self, modulus: int) -> int:
        if modulus <= 0:
            raise DfbError("random modulus must be positive")
        width = modulus.bit_length()
        while True:
            value = self.bits(width)
            if value < modulus:
                return value

    def nonzero_below(self, modulus: int) -> int:
        while True:
            value = self.below(modulus)
            if value:
                return value


class BitWriter:
    """Canonical LSB-first packed bit writer."""

    def __init__(self) -> None:
        self._out = bytearray()
        self._acc = 0
        self._bits = 0
        self.total_bits = 0

    def write(self, value: int, width: int) -> None:
        if width < 0:
            raise DfbError("negative bit width")
        if width == 0:
            if value:
                raise DfbError("nonzero value with zero width")
            return
        if value < 0 or value >= (1 << width):
            raise DfbError(f"value {value} does not fit in {width} bits")
        self._acc |= value << self._bits
        self._bits += width
        self.total_bits += width
        while self._bits >= 8:
            self._out.append(self._acc & 0xFF)
            self._acc >>= 8
            self._bits -= 8

    def write_bool(self, label: np.ndarray) -> None:
        words = np.asarray(label, dtype=np.uint64)
        if words.shape != (2,):
            raise DfbError("boolean label must contain two u64 words")
        self.write(int(words[0]), 64)
        self.write(int(words[1]), 64)

    def write_wide(self, label: np.ndarray, width: int) -> None:
        lanes = np.asarray(label, dtype=np.uint32)
        if lanes.shape != (LAMBDA,):
            raise DfbError("wide label must contain 128 lanes")
        limit = 1 << width
        if np.any(lanes.astype(np.uint64) >= limit):
            raise DfbError("non-canonical wide label lane")
        for lane in lanes:
            self.write(int(lane), width)

    def finish(self) -> bytes:
        if self._bits:
            self._out.append(self._acc & 0xFF)
            self._acc = 0
            self._bits = 0
        return bytes(self._out)


class BitReader:
    """Strict inverse of :class:`BitWriter`."""

    def __init__(self, raw: bytes, *, total_bits: int):
        if total_bits < 0 or len(raw) != ceil(total_bits / 8):
            raise DfbError("bitstream length does not match declared bit length")
        self._raw = bytes(raw)
        self._total_bits = total_bits
        self._offset = 0
        if total_bits % 8 and raw:
            used = total_bits % 8
            if raw[-1] >> used:
                raise DfbError("nonzero canonical padding bits")

    @property
    def remaining(self) -> int:
        return self._total_bits - self._offset

    def read(self, width: int) -> int:
        if width < 0 or self._offset + width > self._total_bits:
            raise DfbError("truncated DFB bitstream")
        value = 0
        shift = 0
        remaining = width
        while remaining:
            byte_index = self._offset >> 3
            bit_index = self._offset & 7
            take = min(remaining, 8 - bit_index)
            chunk = (self._raw[byte_index] >> bit_index) & ((1 << take) - 1)
            value |= chunk << shift
            self._offset += take
            shift += take
            remaining -= take
        return value

    def read_bool(self) -> np.ndarray:
        return np.array([self.read(64), self.read(64)], dtype=np.uint64)

    def read_wide(self, width: int) -> np.ndarray:
        return np.array([self.read(width) for _ in range(LAMBDA)], dtype=np.uint32)

    def finish(self) -> None:
        if self.remaining:
            raise DfbError(f"unconsumed DFB bits: {self.remaining}")


class Ccrh:
    """Fixed-key AES CCRND/CCRH used by the reference implementation."""

    def __init__(self) -> None:
        self.block_calls = 0

    def reset(self) -> None:
        self.block_calls = 0

    @staticmethod
    def _validate_controls(controls: np.ndarray) -> np.ndarray:
        controls = np.asarray(controls, dtype=np.uint64)
        if controls.ndim == 1:
            controls = controls.reshape(1, 2)
        if controls.ndim != 2 or controls.shape[1] != 2:
            raise DfbError("CCRH controls must have shape (n,2)")
        return controls

    def expand_many(
        self,
        controls: np.ndarray,
        nonces: np.ndarray | Sequence[int],
        output_bytes: int,
    ) -> np.ndarray:
        controls = self._validate_controls(controls)
        nonce_array = np.asarray(nonces, dtype=np.uint64).reshape(-1)
        if len(nonce_array) != len(controls):
            raise DfbError("one CCRH nonce is required per control")
        if output_bytes < 0:
            raise DfbError("negative CCRH output length")
        if output_bytes == 0:
            return np.empty((len(controls), 0), dtype=np.uint8)

        block_count = ceil(output_bytes / 16)
        repeated = np.repeat(controls, block_count, axis=0)
        nonce_words = np.repeat(nonce_array, block_count)
        counters = np.tile(np.arange(block_count, dtype=np.uint64), len(controls))

        x0 = repeated[:, 0] ^ _PUBLIC_S_WORDS[0] ^ nonce_words
        x1 = repeated[:, 1] ^ _PUBLIC_S_WORDS[1] ^ counters
        sigma = np.empty((len(repeated), 2), dtype="<u8")
        sigma[:, 0] = x0 ^ x1
        sigma[:, 1] = x0

        plaintext = sigma.tobytes(order="C")
        encryptor = Cipher(algorithms.AES(_CCRH_KEY), modes.ECB()).encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        aes_words = np.frombuffer(encrypted, dtype="<u8").reshape(-1, 2)
        out_words = np.bitwise_xor(aes_words, sigma)
        out = out_words.view(np.uint8).reshape(len(controls), block_count * 16)
        self.block_calls += len(controls) * block_count
        return out[:, :output_bytes].copy()

    def hash_z2_many(self, controls: np.ndarray, group_ids: Sequence[int] | np.ndarray) -> np.ndarray:
        ids = np.asarray(group_ids, dtype=np.uint64).reshape(-1)
        if np.any(ids >= BULK_DOMAIN):
            raise DfbError("bulk group id uses the domain bit")
        raw = self.expand_many(controls, ids | np.uint64(BULK_DOMAIN), 16)
        return raw.view("<u8").reshape(-1, 2).astype(np.uint64, copy=True)

    def hash_cast_many(
        self,
        controls: np.ndarray,
        nonces: Sequence[int] | np.ndarray,
        width: int,
    ) -> np.ndarray:
        if not 2 <= width <= 32:
            raise DfbError("wide hash width must be in 2..32")
        ids = np.asarray(nonces, dtype=np.uint64).reshape(-1)
        if np.any(ids >= BULK_DOMAIN):
            raise DfbError("solo nonce uses the domain bit")
        raw = self.expand_many(controls, ids, LAMBDA * width // 8)
        bits = np.unpackbits(raw, axis=1, bitorder="little")[:, : LAMBDA * width]
        bits = bits.reshape(len(raw), LAMBDA, width).astype(np.uint32)
        weights = (np.uint32(1) << np.arange(width, dtype=np.uint32)).reshape(1, 1, width)
        return np.sum(bits * weights, axis=2, dtype=np.uint32)

    def hash_bulk_pads(
        self,
        controls: np.ndarray,
        group_ids: Sequence[int] | np.ndarray,
        members: int,
        modulus: int,
    ) -> np.ndarray:
        """Sample exact uniform body pads in ``Z_modulus``.

        Each 32-bit candidate is accepted below the largest multiple of the
        modulus contained in ``[0, 2^32)``.  Candidates are taken from a
        deterministic CCRH stream in rounds, one candidate per member per
        round.  Re-expanding a longer prefix after the overwhelmingly rare
        rejection is inefficient but keeps the stream definition simple and
        avoids a variable nonce schedule.  The watchdog is a fail-closed
        implementation bound, not a modulo fallback.
        """

        controls = self._validate_controls(controls)
        if members <= 0:
            raise DfbError("body batch must be non-empty")
        modulus = int(modulus)
        if not 1 < modulus < (1 << BODY_PAD_CANDIDATE_BITS):
            raise DfbError("body-pad modulus must fit a nontrivial u32 range")
        ids = np.asarray(group_ids, dtype=np.uint64).reshape(-1)
        if len(ids) != len(controls):
            raise DfbError("one body group id is required per control")
        if np.any(ids >= BULK_DOMAIN):
            raise DfbError("body group id uses the domain bit")

        domain = 1 << BODY_PAD_CANDIDATE_BITS
        limit = domain - (domain % modulus)
        accepted = np.zeros((len(controls), members), dtype=bool)
        result = np.zeros((len(controls), members), dtype=np.uint64)

        for round_index in range(BODY_PAD_WATCHDOG_ATTEMPTS):
            # Candidate (round, member) is the corresponding u32 word in this
            # control's CCRH output stream.  The first round is the common path.
            byte_count = (round_index + 1) * members * 4
            raw = self.expand_many(
                controls,
                ids | np.uint64(BULK_DOMAIN),
                byte_count,
            )
            words = raw[:, -members * 4 :].copy().view("<u4").reshape(
                len(controls), members
            )
            newly = (~accepted) & (words.astype(np.uint64) < np.uint64(limit))
            if np.any(newly):
                result[newly] = words[newly].astype(np.uint64) % np.uint64(modulus)
                accepted[newly] = True
            if bool(np.all(accepted)):
                return result

        raise DfbError("uniform body-pad rejection sampler watchdog exhausted")


def body_pad_width(modulus: int) -> int:
    """Candidate width used by the exact v0.24 rejection sampler."""

    modulus = int(modulus)
    if not 1 < modulus < (1 << BODY_PAD_CANDIDATE_BITS):
        raise DfbError("body-pad modulus must fit a nontrivial u32 range")
    return BODY_PAD_CANDIDATE_BITS


def body_pad_statistical_distance(modulus: int) -> float:
    """Exact TV distance of ``U({0,1}^w) mod modulus`` from uniform Z_modulus.

    This quantifies a known implementation/proof mismatch.  It is zero only
    when the modulus divides ``2^w``.  The function is accounting evidence,
    not a security repair.
    """

    modulus = int(modulus)
    width = body_pad_width(modulus)
    domain = 1 << width
    remainder = domain % modulus
    return remainder * (modulus - remainder) / (modulus * domain)


def ccrh_golden_vector() -> bytes:
    coords = np.array([1 if (i * 7 + 3) % 5 == 0 else 0 for i in range(LAMBDA)], dtype=np.uint8)
    words = np.packbits(coords, bitorder="little").view("<u8").astype(np.uint64)
    ccrh = Ccrh()
    raw = ccrh.expand_many(words.reshape(1, 2), np.array([BULK_DOMAIN | 7], dtype=np.uint64), 10)
    return bytes(raw[0])


@dataclass(frozen=True, slots=True)
class DfbProfile:
    input_bits: int = 256
    primes: tuple[int, ...] = FIRST_80_PRIMES
    batch_size: int = RESIDUE_BATCH_SIZE
    nonce_namespace: int = 0
    schema: str = "ranklock-dfb-uniform-profile-v2"

    def __post_init__(self) -> None:
        if self.input_bits <= 1:
            raise DfbError("DFB input width must exceed one bit")
        if not self.primes:
            raise DfbError("DFB prime list is empty")
        for i, prime in enumerate(self.primes):
            if prime <= 1:
                raise DfbError("DFB moduli must exceed one")
            for other in self.primes[:i]:
                if np.gcd(prime, other) != 1:
                    raise DfbError("DFB moduli must be pairwise coprime")
        if self.batch_size <= 0:
            raise DfbError("DFB batch size must be positive")
        if not 0 <= self.nonce_namespace < (1 << 14):
            raise DfbError("DFB nonce namespace must fit 14 bits")
        _compute_sub_widths(self.ell)

    def with_nonce_namespace(self, nonce_namespace: int) -> "DfbProfile":
        return DfbProfile(
            input_bits=self.input_bits,
            primes=self.primes,
            batch_size=self.batch_size,
            nonce_namespace=int(nonce_namespace),
        )

    @property
    def chunk_size(self) -> int:
        return (self.input_bits - 1).bit_length()

    @property
    def num_chunks(self) -> int:
        return ceil(self.input_bits / self.chunk_size)

    @property
    def ell(self) -> int:
        maximum = self.num_chunks * max(self.primes) * ((1 << self.chunk_size) - 1)
        return maximum.bit_length()

    @property
    def sub_widths(self) -> tuple[int, ...]:
        return _compute_sub_widths(self.ell)

    @property
    def fold_bits(self) -> int:
        return sum(self.sub_widths[1:])

    @property
    def crt_bits(self) -> int:
        return sum(_lg(prime) for prime in self.primes)

    @property
    def primorial(self) -> int:
        product = 1
        for prime in self.primes:
            product *= prime
        return product

    @property
    def body_pad_bias_frontier(self) -> tuple[int, float]:
        """Worst prime and TV distance of the current raw-slice pad sampler."""

        return max(
            ((prime, body_pad_statistical_distance(prime)) for prime in self.primes),
            key=lambda item: item[1],
        )

    def statistical_smudging_bits(self, field_modulus: int) -> int:
        """Maximum full rho with ``M >= field_modulus^2 * 2^rho``.

        This is the exact precondition used by DFB Theorem 5.2.  A negative
        result means the CRT primorial is not even large enough for the
        unmasked affine lift.
        """

        field_modulus = int(field_modulus)
        if field_modulus <= 2:
            raise DfbError("field modulus must exceed two")
        ratio = self.primorial // (field_modulus * field_modulus)
        return ratio.bit_length() - 1 if ratio else -1

    def require_statistical_smudging(self, field_modulus: int, rho: int) -> None:
        if rho < 0:
            raise DfbError("statistical security parameter cannot be negative")
        required = int(field_modulus) * int(field_modulus) * (1 << rho)
        if self.primorial < required:
            have = self.statistical_smudging_bits(field_modulus)
            raise DfbError(
                f"CRT profile supports only {have} full smudging bits; {rho} requested"
            )

    @property
    def chunk_join_bits(self) -> int:
        return self.num_chunks * (self.chunk_size - 1 + self.ell) * LAMBDA

    @property
    def extract_join_bits(self) -> int:
        remaining = self.ell
        per_prime = 0
        for index, width in enumerate(self.sub_widths):
            upcast = width if index == len(self.sub_widths) - 1 else remaining
            per_prime += (width - 1 + upcast) * LAMBDA
            remaining -= width
        return len(self.primes) * per_prime

    @property
    def fold_join_bits(self) -> int:
        return len(self.primes) * self.fold_bits * LAMBDA

    def coordinate_program_bits(self, dimension: int) -> int:
        if dimension <= 0:
            raise DfbError("DFB output dimension must be positive")
        return (
            self.chunk_join_bits
            + self.extract_join_bits
            + self.fold_join_bits
            + dimension * self.crt_bits
        )

    def coordinate_decode_bits(self, dimension: int) -> int:
        return dimension * self.crt_bits

    def document(self, dimensions: Sequence[int]) -> dict[str, object]:
        dims = tuple(int(value) for value in dimensions)
        program_bits = sum(self.coordinate_program_bits(value) for value in dims)
        decode_bits = sum(self.coordinate_decode_bits(value) for value in dims)
        return {
            "schema": self.schema,
            "reference_revision": REFERENCE_REVISION,
            "input_bits": self.input_bits,
            "nonce_namespace": self.nonce_namespace,
            "prime_count": len(self.primes),
            "largest_prime": max(self.primes),
            "chunk_size": self.chunk_size,
            "num_chunks": self.num_chunks,
            "ell": self.ell,
            "sub_widths": list(self.sub_widths),
            "fold_bits": self.fold_bits,
            "crt_bits": self.crt_bits,
            "dimensions": list(dims),
            "chunk_join_bits_per_coordinate": self.chunk_join_bits,
            "extract_join_bits_per_coordinate": self.extract_join_bits,
            "fold_join_bits_per_coordinate": self.fold_join_bits,
            "body_join_bits": sum(dims) * self.crt_bits,
            "program_bits": program_bits,
            "program_bytes": ceil(program_bits / 8),
            "standalone_decode_bits": decode_bits,
            "standalone_decode_bytes": ceil(decode_bits / 8),
            "standalone_bundle_bits": program_bits + decode_bits,
            "standalone_bundle_bytes": ceil((program_bits + decode_bits) / 8),
            "program_boundary": "join payload only; output masks are separate decode state",
            "body_pad_sampler": "exact 32-bit rejection sampling into each CRT group",
            "body_pad_candidate_bits": BODY_PAD_CANDIDATE_BITS,
            "body_pad_watchdog_attempts": BODY_PAD_WATCHDOG_ATTEMPTS,
            "body_pad_max_total_variation_distance": 0.0,
            "uniform_body_pad_sampling_implemented": True,
        }


@dataclass(frozen=True, slots=True)
class NonceLayout:
    chunk_solo_ids: int
    chunk_bulk_ids: int
    extract_solo_ids: int
    extract_bulk_ids: int
    solo_chunk_base: int
    solo_extract_base: int
    body_batches: int
    prime_bases: tuple[int, ...]
    prime_window_sizes: tuple[int, ...]
    bulk_chunk_base: int
    bulk_extract_base: int

    @classmethod
    def build(
        cls, profile: DfbProfile, dimension: int, *, coordinate_index: int = 0
    ) -> "NonceLayout":
        if coordinate_index < 0:
            raise DfbError("coordinate index cannot be negative")
        namespace_index = (
            profile.nonce_namespace * SLOT_NONCE_NAMESPACE_COORDINATES
            + coordinate_index
        )
        namespace = namespace_index * NONCE_NAMESPACE_STRIDE
        chunk_bulk = (1 << profile.chunk_size) - 2
        chunk_solo = 1 << profile.chunk_size
        extract_bulk = sum((1 << width) - 2 for width in profile.sub_widths)
        extract_solo = sum(1 << width for width in profile.sub_widths)
        solo_chunk_base = namespace
        solo_extract_base = solo_chunk_base + profile.num_chunks * chunk_solo
        batches = ceil(dimension / profile.batch_size)
        sizes = tuple((batches + profile.fold_bits) * prime for prime in profile.primes)
        bases: list[int] = []
        cursor = namespace + BULK_NONCE_FLOOR
        for size in sizes:
            bases.append(cursor)
            cursor += size
        bulk_chunk_base = cursor
        bulk_extract_base = bulk_chunk_base + profile.num_chunks * chunk_bulk
        if bulk_extract_base + len(profile.primes) * extract_bulk >= BULK_DOMAIN:
            raise DfbError("DFB bulk nonce space exhausted")
        if solo_extract_base + len(profile.primes) * extract_solo >= BULK_DOMAIN:
            raise DfbError("DFB solo nonce space exhausted")
        return cls(
            chunk_solo_ids=chunk_solo,
            chunk_bulk_ids=chunk_bulk,
            extract_solo_ids=extract_solo,
            extract_bulk_ids=extract_bulk,
            solo_chunk_base=solo_chunk_base,
            solo_extract_base=solo_extract_base,
            body_batches=batches,
            prime_bases=tuple(bases),
            prime_window_sizes=sizes,
            bulk_chunk_base=bulk_chunk_base,
            bulk_extract_base=bulk_extract_base,
        )


@dataclass(slots=True)
class ChunkMaterial:
    scale: np.ndarray  # (chunk_size-1, 2), u64
    pin: np.ndarray  # (128,), u32 in Z_2^ell


@dataclass(slots=True)
class ExtractStageMaterial:
    width: int
    upcast_width: int
    scale: np.ndarray  # (width-1, 2), u64
    pin: np.ndarray  # (128,), u32 in Z_2^upcast_width


@dataclass(slots=True)
class ExtractMaterial:
    stages: tuple[ExtractStageMaterial, ...]


@dataclass(slots=True)
class FoldMaterial:
    diffs: np.ndarray  # (fold_bits, 2), u64


@dataclass(slots=True)
class BodyMaterial:
    batches: tuple[np.ndarray, ...]  # each (batch,), residues mod p


@dataclass(slots=True)
class CoordinateMaterial:
    dimension: int
    chunks: tuple[ChunkMaterial, ...]
    extracts: tuple[ExtractMaterial, ...]
    folds: tuple[FoldMaterial, ...]
    bodies: tuple[BodyMaterial, ...]


@dataclass(slots=True)
class CoordinateDecodeState:
    output_masks: tuple[np.ndarray, ...]  # per prime, shape (dimension,)


@dataclass(slots=True)
class CoordinateInputEncoding:
    masks: np.ndarray  # (input_bits,2)
    labels: np.ndarray  # (input_bits,2)
    # Present only in trusted setup/template state; never serialized with the
    # evaluator labels.  Each input component receives an independent delta.
    delta: int | None = None

    @property
    def encoded_labels(self) -> bytes:
        words = np.asarray(self.labels, dtype="<u8")
        return words.tobytes(order="C")

    @property
    def root(self) -> bytes:
        return sha256(b"ranklock/dfb-input-labels/v1\x00" + self.encoded_labels).digest()


@dataclass(slots=True)
class DfbProgram:
    profile: DfbProfile
    coordinates: tuple[CoordinateMaterial, ...]
    encoded: bytes
    bit_length: int

    @property
    def sha256(self) -> str:
        return sha256(self.encoded).hexdigest()

    @property
    def dimensions(self) -> tuple[int, ...]:
        return tuple(coordinate.dimension for coordinate in self.coordinates)


@dataclass(slots=True)
class DfbDecodeState:
    coordinates: tuple[CoordinateDecodeState, ...]

    def canonical_bytes(self, profile: DfbProfile) -> bytes:
        writer = BitWriter()
        for coordinate in self.coordinates:
            for prime, masks in zip(profile.primes, coordinate.output_masks, strict=True):
                width = _lg(prime)
                for value in masks:
                    writer.write(int(value), width)
        return writer.finish()


@dataclass(slots=True)
class DfbGeneration:
    program: DfbProgram
    decode_state: DfbDecodeState
    input_encodings: tuple[CoordinateInputEncoding, ...]
    garbler_hash_blocks: int
    # Effective integer-lift coefficients used by the DFB switch program.
    # When field_modulus is set, b includes the required mu*p smudging term.
    effective_coefficients: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...] | None = None
    field_modulus: int | None = None
    statistical_security_bits: int = 0


@dataclass(slots=True)
class DfbEvaluation:
    decoded_residues: tuple[np.ndarray, ...]  # per coordinate: (prime_count, dimension)
    evaluator_hash_blocks: int


@dataclass(slots=True)
class DfbLabelEvaluation:
    """Raw DFB output-label residues before standalone mask subtraction.

    Applications that algebraically absorb the final output masks (such as the
    Embryo fusion prototype) need these labels rather than the standalone
    plaintext affine outputs.  The shape matches :class:`DfbEvaluation`.
    """

    label_residues: tuple[np.ndarray, ...]
    evaluator_hash_blocks: int


def _delta_bool(delta: int) -> np.ndarray:
    return np.array([delta & ((1 << 64) - 1), delta >> 64], dtype=np.uint64)


def _delta_wide(delta: int, width: int) -> np.ndarray:
    return np.array([(delta >> index) & 1 for index in range(LAMBDA)], dtype=np.uint32)


def _pack_lane_bit(lanes: np.ndarray, bit: int) -> np.ndarray:
    values = ((np.asarray(lanes, dtype=np.uint32) >> np.uint32(bit)) & np.uint32(1)).astype(np.uint8)
    return np.packbits(values, bitorder="little").view("<u8").astype(np.uint64)


def _tree_garble(
    first_level: np.ndarray,
    width: int,
    bulk_base: int,
    ccrh: Ccrh,
) -> tuple[np.ndarray, np.ndarray]:
    level = np.asarray(first_level, dtype=np.uint64).reshape(2, 2).copy()
    sums: list[np.ndarray] = []
    for depth in range(1, width):
        count = 1 << depth
        ids = bulk_base + ((1 << depth) - 2) + np.arange(count, dtype=np.uint64)
        pads = ccrh.hash_z2_many(level, ids)
        sums.append(_xor_reduce(pads))
        next_level = np.empty((count * 2, 2), dtype=np.uint64)
        next_level[:count] = np.bitwise_xor(level, pads)
        next_level[count:] = pads
        level = next_level
    return level, np.stack(sums) if sums else np.empty((0, 2), dtype=np.uint64)


def _peel_chain(casts: np.ndarray) -> tuple[list[np.ndarray], np.ndarray]:
    accumulator = np.asarray(casts, dtype=np.uint32).copy()
    width = len(accumulator).bit_length() - 1
    highs: list[np.ndarray] = []
    while len(accumulator) > 2:
        midpoint = len(accumulator) // 2
        low = accumulator[:midpoint]
        high_values = accumulator[midpoint:]
        highs.append(_u32_sum(high_values))
        accumulator = _u32_add(low, high_values)
    result = accumulator[1].copy()
    chain = [result.copy()]
    for index, high in zip(range(1, width), reversed(highs), strict=True):
        result = _u32_madd(result, 1 << index, high)
        chain.append(result.copy())
    root = _u32_add(accumulator[0], accumulator[1])
    return chain, root


def _chunk_garble(
    bit_masks: np.ndarray,
    profile: DfbProfile,
    delta: int,
    bulk_base: int,
    solo_base: int,
    ccrh: Ccrh,
) -> tuple[np.ndarray, ChunkMaterial]:
    width = len(bit_masks)
    d2 = _delta_bool(delta)
    first = bit_masks[0]
    level1 = np.stack((np.bitwise_xor(first, d2), first))
    leaves, y_sums = _tree_garble(level1, width, bulk_base, ccrh)
    casts = ccrh.hash_cast_many(
        leaves,
        solo_base + np.arange(1 << width, dtype=np.uint64),
        profile.ell,
    )
    chain, root = _peel_chain(casts)
    mask = (1 << profile.ell) - 1
    word_mask = chain[width - 1] & np.uint32(mask)
    scale = np.bitwise_xor(y_sums, bit_masks[1:])
    pin = _u32_add(root, _delta_wide(delta, profile.ell)) & np.uint32(mask)
    return word_mask, ChunkMaterial(scale=scale, pin=pin)


def _chunk_eval(
    bit_labels: np.ndarray,
    value: int,
    material: ChunkMaterial,
    profile: DfbProfile,
    bulk_base: int,
    solo_base: int,
    ccrh: Ccrh,
) -> np.ndarray:
    width = len(bit_labels)
    first = bit_labels[0]
    level = np.stack((first, first)).astype(np.uint64)
    for depth in range(1, width):
        count = 1 << depth
        hot = value & (count - 1)
        nonhot = np.array([index for index in range(count) if index != hot], dtype=np.int64)
        ids = bulk_base + ((1 << depth) - 2) + nonhot.astype(np.uint64)
        pads = ccrh.hash_z2_many(level[nonhot], ids)
        y_sum = _xor_reduce(pads)
        next_level = np.zeros((count * 2, 2), dtype=np.uint64)
        next_level[nonhot] = np.bitwise_xor(level[nonhot], pads)
        next_level[nonhot + count] = pads
        bit_label = bit_labels[depth]
        y_hot = bit_label ^ material.scale[depth - 1] ^ y_sum
        next_level[hot] = level[hot] ^ y_hot
        next_level[hot + count] = y_hot
        level = next_level

    hot = value & ((1 << width) - 1)
    nonhot = np.array([index for index in range(1 << width) if index != hot], dtype=np.int64)
    casts = ccrh.hash_cast_many(
        level[nonhot],
        solo_base + nonhot.astype(np.uint64),
        profile.ell,
    )
    word = np.zeros(LAMBDA, dtype=np.uint32)
    total = np.zeros(LAMBDA, dtype=np.uint32)
    for slot, cast in zip(nonhot, casts, strict=True):
        word = _u32_madd(word, int(slot), cast)
        total = _u32_add(total, cast)
    hot_cast = _u32_sub(material.pin, total)
    word = _u32_madd(word, hot, hot_cast)
    return word & np.uint32((1 << profile.ell) - 1)


def _stage_plan(profile: DfbProfile, bulk_base: int, solo_base: int) -> list[tuple[int, int, int, int]]:
    remaining = profile.ell
    bulk = bulk_base
    solo = solo_base
    plans: list[tuple[int, int, int, int]] = []
    for index, width in enumerate(profile.sub_widths):
        upcast = width if index == len(profile.sub_widths) - 1 else remaining
        plans.append((width, upcast, bulk, solo))
        bulk += (1 << width) - 2
        solo += 1 << width
        remaining -= width
    return plans


def _extract_garble(
    chunk_masks: Sequence[np.ndarray],
    coefficients: Sequence[int],
    profile: DfbProfile,
    delta: int,
    bulk_base: int,
    solo_base: int,
    ccrh: Ccrh,
) -> tuple[np.ndarray, np.ndarray, ExtractMaterial]:
    remainder = np.zeros(LAMBDA, dtype=np.uint32)
    mask_ell = (1 << profile.ell) - 1
    for mask, coefficient in zip(chunk_masks, coefficients, strict=True):
        remainder = _u32_madd(remainder, coefficient & mask_ell, mask)
    d2 = _delta_bool(delta)
    stages: list[ExtractStageMaterial] = []
    first_hot: np.ndarray | None = None
    fold_bits: list[np.ndarray] = []
    remaining_bits = profile.ell

    for stage_index, (width, upcast, stage_bulk, stage_solo) in enumerate(
        _stage_plan(profile, bulk_base, solo_base)
    ):
        mask_width = (1 << width) - 1
        sub = remainder & np.uint32(mask_width)
        bit0 = _pack_lane_bit(sub, 0)
        level1 = np.stack((bit0 ^ d2, bit0))
        leaves, y_sums = _tree_garble(level1, width, stage_bulk, ccrh)
        casts = ccrh.hash_cast_many(
            leaves,
            stage_solo + np.arange(1 << width, dtype=np.uint64),
            upcast,
        )
        chain, root = _peel_chain(casts)
        bit_masks = [bit0]
        for bit in range(1, width):
            difference = _u32_sub(sub, chain[bit - 1]) & np.uint32(mask_width)
            bit_masks.append(_pack_lane_bit(difference, bit))
        scale = np.bitwise_xor(y_sums, np.stack(bit_masks[1:]))
        pin = _u32_add(root, _delta_wide(delta, upcast)) & np.uint32((1 << upcast) - 1)
        stages.append(
            ExtractStageMaterial(width=width, upcast_width=upcast, scale=scale, pin=pin)
        )
        if stage_index == 0:
            first_hot = leaves.copy()
        else:
            fold_bits.extend(bit_masks)
        if stage_index != len(profile.sub_widths) - 1:
            upcast_value = chain[width - 1]
            remainder = _u32_sub(remainder, upcast_value)
            remainder = (remainder & np.uint32((1 << remaining_bits) - 1)) >> np.uint32(width)
            remaining_bits -= width

    assert first_hot is not None
    return (
        first_hot,
        np.stack(fold_bits) if fold_bits else np.empty((0, 2), dtype=np.uint64),
        ExtractMaterial(stages=tuple(stages)),
    )


def _expand_and_fold_class(
    *,
    stage_width: int,
    upcast_width: int,
    stage_bulk: int,
    stage_solo: int,
    zero_class: int,
    level_width: int,
    levels: list[np.ndarray],
    y_sums: np.ndarray,
    acc_r: np.ndarray,
    acc_t: np.ndarray,
    ccrh: Ccrh,
) -> None:
    width = stage_width
    for depth in range(level_width, width):
        count = 1 << (depth - level_width)
        indices = zero_class + (np.arange(count, dtype=np.int64) << level_width)
        base = stage_bulk + ((1 << depth) - 2)
        pads = ccrh.hash_z2_many(levels[depth][indices], base + indices.astype(np.uint64))
        y_sums[depth] ^= _xor_reduce(pads)
        levels[depth + 1][indices] = levels[depth][indices] ^ pads
        levels[depth + 1][indices + (1 << depth)] = pads

    class_count = 1 << (width - level_width)
    leaves = zero_class + (np.arange(class_count, dtype=np.int64) << level_width)
    sums = ccrh.hash_cast_many(
        levels[width][leaves],
        stage_solo + leaves.astype(np.uint64),
        upcast_width,
    )
    highs: list[np.ndarray] = []
    while len(sums) > 1:
        midpoint = len(sums) // 2
        low = sums[:midpoint]
        high_values = sums[midpoint:]
        highs.append(_u32_sum(high_values))
        sums = _u32_add(low, high_values)
    total = sums[0]
    w_chain = [np.zeros(LAMBDA, dtype=np.uint32)]
    for index, high in enumerate(reversed(highs)):
        w_chain.append(_u32_madd(w_chain[-1], 1 << index, high))
    for depth in range(level_width, width + 1):
        index = depth - 1
        acc_r[index] = _u32_madd(acc_r[index], zero_class, total)
        acc_r[index] = _u32_madd(acc_r[index], 1 << level_width, w_chain[depth - level_width])
        acc_t[index] = _u32_add(acc_t[index], total)


def _extract_eval(
    chunk_labels: Sequence[np.ndarray],
    coefficients: Sequence[int],
    r_value: int,
    material: ExtractMaterial,
    profile: DfbProfile,
    bulk_base: int,
    solo_base: int,
    ccrh: Ccrh,
) -> tuple[np.ndarray, np.ndarray]:
    remainder = np.zeros(LAMBDA, dtype=np.uint32)
    mask_ell = (1 << profile.ell) - 1
    for label, coefficient in zip(chunk_labels, coefficients, strict=True):
        remainder = _u32_madd(remainder, coefficient & mask_ell, label)
    remaining_value = r_value
    remaining_bits = profile.ell
    first_hot: np.ndarray | None = None
    fold_bits: list[np.ndarray] = []

    plans = _stage_plan(profile, bulk_base, solo_base)
    for stage_index, ((width, upcast, stage_bulk, stage_solo), stage) in enumerate(
        zip(plans, material.stages, strict=True)
    ):
        if stage.width != width or stage.upcast_width != upcast:
            raise DfbError("extract stage profile mismatch")
        mask_width = (1 << width) - 1
        sub_value = remaining_value & mask_width
        sub = remainder & np.uint32(mask_width)
        bit0 = _pack_lane_bit(sub, 0)

        levels = [np.zeros((1 << depth, 2), dtype=np.uint64) for depth in range(width + 1)]
        levels[1][0] = bit0
        levels[1][1] = bit0
        y_sums = np.zeros((width, 2), dtype=np.uint64)
        acc_r = np.zeros((width, LAMBDA), dtype=np.uint32)
        acc_t = np.zeros((width, LAMBDA), dtype=np.uint32)
        root = stage.pin.copy()
        bit_labels = [bit0]

        _expand_and_fold_class(
            stage_width=width,
            upcast_width=upcast,
            stage_bulk=stage_bulk,
            stage_solo=stage_solo,
            zero_class=(sub_value & 1) ^ 1,
            level_width=1,
            levels=levels,
            y_sums=y_sums,
            acc_r=acc_r,
            acc_t=acc_t,
            ccrh=ccrh,
        )

        for bit in range(1, width):
            residue = sub_value & ((1 << bit) - 1)
            index = bit - 1
            root_minus_total = _u32_sub(root, acc_t[index])
            residue_label = _u32_madd(acc_r[index], residue, root_minus_total)
            difference = _u32_sub(sub, residue_label) & np.uint32(mask_width)
            bit_label = _pack_lane_bit(difference, bit)
            bit_labels.append(bit_label)

            hot = residue
            y_hot = bit_label ^ stage.scale[index] ^ y_sums[bit]
            parent = levels[bit][hot]
            levels[bit + 1][hot] = parent ^ y_hot
            levels[bit + 1][hot + (1 << bit)] = y_hot

            bit_value = (sub_value >> bit) & 1
            _expand_and_fold_class(
                stage_width=width,
                upcast_width=upcast,
                stage_bulk=stage_bulk,
                stage_solo=stage_solo,
                zero_class=residue | ((bit_value ^ 1) << bit),
                level_width=bit + 1,
                levels=levels,
                y_sums=y_sums,
                acc_r=acc_r,
                acc_t=acc_t,
                ccrh=ccrh,
            )

        if stage_index == 0:
            first_hot = levels[width].copy()
        else:
            fold_bits.extend(bit_labels)

        if stage_index != len(material.stages) - 1:
            index = width - 1
            hot_part = _u32_sub(root, acc_t[index])
            upcast_label = _u32_madd(acc_r[index], sub_value, hot_part)
            remainder = _u32_sub(remainder, upcast_label)
            remainder = (remainder & np.uint32((1 << remaining_bits) - 1)) >> np.uint32(width)
            remaining_value >>= width
            remaining_bits -= width

    assert first_hot is not None
    return first_hot, np.stack(fold_bits) if fold_bits else np.empty((0, 2), dtype=np.uint64)


def _fold_garble(
    prime: int,
    first_hot_masks: np.ndarray,
    bit_masks: np.ndarray,
    first_width: int,
    nonce_base: int,
    ccrh: Ccrh,
) -> tuple[np.ndarray, FoldMaterial]:
    h = np.zeros((prime, 2), dtype=np.uint64)
    for index, mask in enumerate(first_hot_masks):
        h[index % prime] ^= mask
    diffs: list[np.ndarray] = []
    for bit_index, bit_mask in enumerate(bit_masks):
        shift = _pow2_mod(first_width + bit_index, prime)
        ids = nonce_base + bit_index * prime + np.arange(prime, dtype=np.uint64)
        h_prime = ccrh.hash_z2_many(h, ids)
        total = _xor_reduce(h_prime)
        diffs.append(total ^ bit_mask)
        source = (np.arange(prime) - shift) % prime
        h ^= h_prime ^ h_prime[source]
    return h, FoldMaterial(diffs=np.stack(diffs) if diffs else np.empty((0, 2), dtype=np.uint64))


def _fold_eval(
    prime: int,
    r_value: int,
    first_hot_labels: np.ndarray,
    bit_labels: np.ndarray,
    material: FoldMaterial,
    first_width: int,
    nonce_base: int,
    ccrh: Ccrh,
) -> np.ndarray:
    h = np.zeros((prime, 2), dtype=np.uint64)
    for index, label in enumerate(first_hot_labels):
        h[index % prime] ^= label
    hot = (r_value & ((1 << first_width) - 1)) % prime
    for bit_index, (bit_label, diff) in enumerate(zip(bit_labels, material.diffs, strict=True)):
        shift = _pow2_mod(first_width + bit_index, prime)
        nonhot = np.array([index for index in range(prime) if index != hot], dtype=np.int64)
        ids = nonce_base + bit_index * prime + nonhot.astype(np.uint64)
        pads = ccrh.hash_z2_many(h[nonhot], ids)
        h_prime = np.zeros((prime, 2), dtype=np.uint64)
        h_prime[nonhot] = pads
        known_sum = _xor_reduce(pads)
        h_prime[hot] = bit_label ^ diff ^ known_sum
        source = (np.arange(prime) - shift) % prime
        h ^= h_prime ^ h_prime[source]
        if (r_value >> (first_width + bit_index)) & 1:
            hot = (hot + shift) % prime
    if hot != r_value % prime:
        raise DfbError("fold hot-slot tracking diverged")
    return h


def _body_garble(
    prime: int,
    h_masks: np.ndarray,
    a_values: np.ndarray,
    b_values: np.ndarray,
    group_base: int,
    ccrh: Ccrh,
) -> tuple[np.ndarray, np.ndarray]:
    members = len(a_values)
    ids = group_base + np.arange(prime, dtype=np.uint64)
    pads = ccrh.hash_bulk_pads(h_masks, ids, members, prime)
    weights = np.arange(prime, dtype=np.uint64).reshape(prime, 1)
    pad_sum = pads.sum(axis=0, dtype=np.uint64) % np.uint64(prime)
    readout = (pads * weights).sum(axis=0, dtype=np.uint64) % np.uint64(prime)
    joins = (pad_sum + a_values.astype(np.uint64)) % np.uint64(prime)
    masks = (readout + np.uint64(prime) - b_values.astype(np.uint64)) % np.uint64(prime)
    return joins.astype(np.uint64), masks.astype(np.uint64)


def _body_eval(
    prime: int,
    hot: int,
    h_labels: np.ndarray,
    joins: np.ndarray,
    group_base: int,
    ccrh: Ccrh,
) -> np.ndarray:
    members = len(joins)
    nonhot = np.array([index for index in range(prime) if index != hot], dtype=np.int64)
    ids = group_base + nonhot.astype(np.uint64)
    pads = ccrh.hash_bulk_pads(h_labels[nonhot], ids, members, prime)
    weights = nonhot.astype(np.uint64).reshape(len(nonhot), 1)
    pad_sum = pads.sum(axis=0, dtype=np.uint64) % np.uint64(prime)
    readout = (pads * weights).sum(axis=0, dtype=np.uint64) % np.uint64(prime)
    hidden_plus_a = (joins.astype(np.uint64) + np.uint64(prime) - pad_sum) % np.uint64(prime)
    return (readout + np.uint64(hot) * hidden_plus_a) % np.uint64(prime)


def _chunk_values(value: int, profile: DfbProfile) -> list[int]:
    mask = (1 << profile.chunk_size) - 1
    return [(value >> (index * profile.chunk_size)) & mask for index in range(profile.num_chunks)]


def _prime_coefficients(prime: int, profile: DfbProfile) -> list[int]:
    return [_pow2_mod(index * profile.chunk_size, prime) for index in range(profile.num_chunks)]


def _r_value(chunks: Sequence[int], coefficients: Sequence[int]) -> int:
    return sum(value * coefficient for value, coefficient in zip(chunks, coefficients, strict=True))


def _random_bool_labels(rng: DeterministicRng, count: int) -> np.ndarray:
    raw = rng.bytes(count * 16)
    return np.frombuffer(raw, dtype="<u8").reshape(count, 2).astype(np.uint64, copy=True)


def generate_coordinate(
    *,
    value: int,
    a_values: Sequence[int],
    b_values: Sequence[int],
    profile: DfbProfile,
    delta: int,
    rng: DeterministicRng,
    ccrh: Ccrh,
    coordinate_index: int = 0,
) -> tuple[CoordinateMaterial, CoordinateDecodeState, CoordinateInputEncoding]:
    if not 0 <= value < (1 << profile.input_bits):
        raise DfbError("coordinate input does not fit profile")
    if len(a_values) != len(b_values) or not a_values:
        raise DfbError("affine coefficient vectors must be non-empty and equal length")
    dimension = len(a_values)
    layout = NonceLayout.build(profile, dimension, coordinate_index=coordinate_index)
    masks = _random_bool_labels(rng, profile.input_bits)
    labels = masks.copy()
    d2 = _delta_bool(delta)
    for bit in range(profile.input_bits):
        if (value >> bit) & 1:
            labels[bit] ^= d2

    chunk_values = _chunk_values(value, profile)
    chunk_masks: list[np.ndarray] = []
    chunk_materials: list[ChunkMaterial] = []
    for index in range(profile.num_chunks):
        start = index * profile.chunk_size
        end = min(start + profile.chunk_size, profile.input_bits)
        # The production profile is exactly divisible.  For smaller profiles,
        # pad a final short chunk with zero-valued/masked wires to keep the
        # straight-line width fixed.
        bit_masks = masks[start:end]
        if len(bit_masks) < profile.chunk_size:
            padding = np.zeros((profile.chunk_size - len(bit_masks), 2), dtype=np.uint64)
            bit_masks = np.concatenate((bit_masks, padding), axis=0)
        word_mask, material = _chunk_garble(
            bit_masks,
            profile,
            delta,
            layout.bulk_chunk_base + index * layout.chunk_bulk_ids,
            layout.solo_chunk_base + index * layout.chunk_solo_ids,
            ccrh,
        )
        chunk_masks.append(word_mask)
        chunk_materials.append(material)

    extracts: list[ExtractMaterial] = []
    folds: list[FoldMaterial] = []
    bodies: list[BodyMaterial] = []
    output_masks: list[np.ndarray] = []
    a_full = np.array(a_values, dtype=object)
    b_full = np.array(b_values, dtype=object)

    for prime_index, prime in enumerate(profile.primes):
        coefficients = _prime_coefficients(prime, profile)
        first_masks, fold_masks, extract_material = _extract_garble(
            chunk_masks,
            coefficients,
            profile,
            delta,
            layout.bulk_extract_base + prime_index * layout.extract_bulk_ids,
            layout.solo_extract_base + prime_index * layout.extract_solo_ids,
            ccrh,
        )
        h_masks, fold_material = _fold_garble(
            prime,
            first_masks,
            fold_masks,
            profile.sub_widths[0],
            layout.prime_bases[prime_index],
            ccrh,
        )
        a_mod = np.array([int(value) % prime for value in a_full], dtype=np.uint64)
        b_mod = np.array([int(value) % prime for value in b_full], dtype=np.uint64)
        batch_materials: list[np.ndarray] = []
        masks_for_prime: list[np.ndarray] = []
        for batch_index, start in enumerate(range(0, dimension, profile.batch_size)):
            end = min(start + profile.batch_size, dimension)
            group_base = (
                layout.prime_bases[prime_index]
                + profile.fold_bits * prime
                + batch_index * prime
            )
            joins, result_masks = _body_garble(
                prime,
                h_masks,
                a_mod[start:end],
                b_mod[start:end],
                group_base,
                ccrh,
            )
            batch_materials.append(joins)
            masks_for_prime.append(result_masks)
        extracts.append(extract_material)
        folds.append(fold_material)
        bodies.append(BodyMaterial(batches=tuple(batch_materials)))
        output_masks.append(np.concatenate(masks_for_prime))

    return (
        CoordinateMaterial(
            dimension=dimension,
            chunks=tuple(chunk_materials),
            extracts=tuple(extracts),
            folds=tuple(folds),
            bodies=tuple(bodies),
        ),
        CoordinateDecodeState(output_masks=tuple(output_masks)),
        CoordinateInputEncoding(masks=masks, labels=labels, delta=delta),
    )


def evaluate_coordinate_labels(
    *,
    value: int,
    material: CoordinateMaterial,
    input_encoding: CoordinateInputEncoding,
    profile: DfbProfile,
    ccrh: Ccrh,
    coordinate_index: int = 0,
) -> np.ndarray:
    """Evaluate one coordinate and retain its raw output labels.

    The returned residues are the labels produced by the final information-
    theoretic one-hot scaling.  No ``DfbDecodeState`` is consulted.
    """

    if len(material.extracts) != len(profile.primes):
        raise DfbError("coordinate material prime count mismatch")
    layout = NonceLayout.build(profile, material.dimension, coordinate_index=coordinate_index)
    chunk_values = _chunk_values(value, profile)
    chunk_labels: list[np.ndarray] = []
    for index, chunk_material in enumerate(material.chunks):
        begin = index * profile.chunk_size
        end = min(begin + profile.chunk_size, profile.input_bits)
        bit_labels = input_encoding.labels[begin:end]
        if len(bit_labels) < profile.chunk_size:
            padding = np.zeros((profile.chunk_size - len(bit_labels), 2), dtype=np.uint64)
            bit_labels = np.concatenate((bit_labels, padding), axis=0)
        chunk_labels.append(
            _chunk_eval(
                bit_labels,
                chunk_values[index],
                chunk_material,
                profile,
                layout.bulk_chunk_base + index * layout.chunk_bulk_ids,
                layout.solo_chunk_base + index * layout.chunk_solo_ids,
                ccrh,
            )
        )

    labels = np.empty((len(profile.primes), material.dimension), dtype=np.uint64)
    for prime_index, prime in enumerate(profile.primes):
        coefficients = _prime_coefficients(prime, profile)
        r = _r_value(chunk_values, coefficients)
        first_labels, fold_labels = _extract_eval(
            chunk_labels,
            coefficients,
            r,
            material.extracts[prime_index],
            profile,
            layout.bulk_extract_base + prime_index * layout.extract_bulk_ids,
            layout.solo_extract_base + prime_index * layout.extract_solo_ids,
            ccrh,
        )
        h_labels = _fold_eval(
            prime,
            r,
            first_labels,
            fold_labels,
            material.folds[prime_index],
            profile.sub_widths[0],
            layout.prime_bases[prime_index],
            ccrh,
        )
        labels_for_prime: list[np.ndarray] = []
        for batch_index, joins in enumerate(material.bodies[prime_index].batches):
            group_base = (
                layout.prime_bases[prime_index]
                + profile.fold_bits * prime
                + batch_index * prime
            )
            labels_for_prime.append(
                _body_eval(prime, r % prime, h_labels, joins, group_base, ccrh)
            )
        labels[prime_index] = np.concatenate(labels_for_prime)
    return labels


def evaluate_coordinate(
    *,
    value: int,
    material: CoordinateMaterial,
    input_encoding: CoordinateInputEncoding,
    decode_state: CoordinateDecodeState,
    profile: DfbProfile,
    ccrh: Ccrh,
    coordinate_index: int = 0,
) -> np.ndarray:
    labels = evaluate_coordinate_labels(
        value=value,
        material=material,
        input_encoding=input_encoding,
        profile=profile,
        ccrh=ccrh,
        coordinate_index=coordinate_index,
    )
    if len(decode_state.output_masks) != len(profile.primes):
        raise DfbError("coordinate decode-state prime count mismatch")
    decoded = np.empty_like(labels)
    for prime_index, prime in enumerate(profile.primes):
        masks = decode_state.output_masks[prime_index]
        if masks.shape != (material.dimension,):
            raise DfbError("coordinate output-mask dimension mismatch")
        decoded[prime_index] = (
            labels[prime_index] + np.uint64(prime) - masks.astype(np.uint64)
        ) % np.uint64(prime)
    return decoded


def _serialize_coordinate(writer: BitWriter, coordinate: CoordinateMaterial, profile: DfbProfile) -> None:
    if len(coordinate.chunks) != profile.num_chunks:
        raise DfbError("coordinate chunk count mismatch")
    for chunk in coordinate.chunks:
        if chunk.scale.shape != (profile.chunk_size - 1, 2):
            raise DfbError("chunk scale shape mismatch")
        for diff in chunk.scale:
            writer.write_bool(diff)
        writer.write_wide(chunk.pin, profile.ell)

    if not (
        len(coordinate.extracts)
        == len(coordinate.folds)
        == len(coordinate.bodies)
        == len(profile.primes)
    ):
        raise DfbError("coordinate prime material count mismatch")
    plans = _stage_plan(profile, 0, 0)
    for extract in coordinate.extracts:
        if len(extract.stages) != len(plans):
            raise DfbError("extract stage count mismatch")
        for stage, (width, upcast, _, _) in zip(extract.stages, plans, strict=True):
            if stage.width != width or stage.upcast_width != upcast:
                raise DfbError("extract stage width mismatch")
            for diff in stage.scale:
                writer.write_bool(diff)
            writer.write_wide(stage.pin, upcast)
    for fold in coordinate.folds:
        if fold.diffs.shape != (profile.fold_bits, 2):
            raise DfbError("fold diff shape mismatch")
        for diff in fold.diffs:
            writer.write_bool(diff)
    for prime, body in zip(profile.primes, coordinate.bodies, strict=True):
        width = _lg(prime)
        count = 0
        for batch in body.batches:
            for value in batch:
                writer.write(int(value), width)
                count += 1
        if count != coordinate.dimension:
            raise DfbError("body dimension mismatch")


def serialize_program(coordinates: Sequence[CoordinateMaterial], profile: DfbProfile) -> DfbProgram:
    writer = BitWriter()
    for coordinate in coordinates:
        _serialize_coordinate(writer, coordinate, profile)
    expected = sum(profile.coordinate_program_bits(c.dimension) for c in coordinates)
    if writer.total_bits != expected:
        raise DfbError(f"DFB bit accounting mismatch: {writer.total_bits} != {expected}")
    raw = writer.finish()
    return DfbProgram(
        profile=profile,
        coordinates=tuple(coordinates),
        encoded=raw,
        bit_length=expected,
    )


def _parse_coordinate(reader: BitReader, dimension: int, profile: DfbProfile) -> CoordinateMaterial:
    chunks: list[ChunkMaterial] = []
    for _ in range(profile.num_chunks):
        scale = np.stack([reader.read_bool() for _ in range(profile.chunk_size - 1)])
        pin = reader.read_wide(profile.ell)
        chunks.append(ChunkMaterial(scale=scale, pin=pin))

    extracts: list[ExtractMaterial] = []
    plans = _stage_plan(profile, 0, 0)
    for _ in profile.primes:
        stages: list[ExtractStageMaterial] = []
        for width, upcast, _, _ in plans:
            scale = np.stack([reader.read_bool() for _ in range(width - 1)])
            pin = reader.read_wide(upcast)
            stages.append(
                ExtractStageMaterial(
                    width=width,
                    upcast_width=upcast,
                    scale=scale,
                    pin=pin,
                )
            )
        extracts.append(ExtractMaterial(stages=tuple(stages)))

    folds = [
        FoldMaterial(
            diffs=(
                np.stack([reader.read_bool() for _ in range(profile.fold_bits)])
                if profile.fold_bits
                else np.empty((0, 2), dtype=np.uint64)
            )
        )
        for _ in profile.primes
    ]
    bodies: list[BodyMaterial] = []
    for prime in profile.primes:
        width = _lg(prime)
        batches: list[np.ndarray] = []
        for start in range(0, dimension, profile.batch_size):
            count = min(profile.batch_size, dimension - start)
            values = [reader.read(width) for _ in range(count)]
            if any(value >= prime for value in values):
                raise DfbError("non-canonical body residue")
            batches.append(np.array(values, dtype=np.uint64))
        bodies.append(BodyMaterial(batches=tuple(batches)))
    return CoordinateMaterial(
        dimension=dimension,
        chunks=tuple(chunks),
        extracts=tuple(extracts),
        folds=tuple(folds),
        bodies=tuple(bodies),
    )


def parse_program(raw: bytes, *, dimensions: Sequence[int], profile: DfbProfile) -> DfbProgram:
    dims = tuple(int(value) for value in dimensions)
    if any(value <= 0 for value in dims):
        raise DfbError("DFB dimensions must be positive")
    total_bits = sum(profile.coordinate_program_bits(value) for value in dims)
    reader = BitReader(raw, total_bits=total_bits)
    coordinates = tuple(_parse_coordinate(reader, value, profile) for value in dims)
    reader.finish()
    canonical = serialize_program(coordinates, profile)
    if canonical.encoded != bytes(raw):
        raise DfbError("non-canonical DFB program encoding")
    return canonical


def parse_decode_state(
    raw: bytes,
    *,
    dimensions: Sequence[int],
    profile: DfbProfile,
) -> DfbDecodeState:
    """Parse the final output masks required by standalone public decoding."""

    dims = tuple(int(value) for value in dimensions)
    if any(value <= 0 for value in dims):
        raise DfbError("DFB dimensions must be positive")
    total_bits = sum(profile.coordinate_decode_bits(value) for value in dims)
    reader = BitReader(raw, total_bits=total_bits)
    coordinates: list[CoordinateDecodeState] = []
    for dimension in dims:
        masks_per_prime: list[np.ndarray] = []
        for prime in profile.primes:
            width = _lg(prime)
            values = [reader.read(width) for _ in range(dimension)]
            if any(value >= prime for value in values):
                raise DfbError("non-canonical output-mask residue")
            masks_per_prime.append(np.array(values, dtype=np.uint64))
        coordinates.append(CoordinateDecodeState(output_masks=tuple(masks_per_prime)))
    reader.finish()
    state = DfbDecodeState(coordinates=tuple(coordinates))
    if state.canonical_bytes(profile) != bytes(raw):
        raise DfbError("non-canonical DFB decode-state encoding")
    return state


def parse_input_labels(raw: bytes, *, profile: DfbProfile) -> CoordinateInputEncoding:
    """Parse one future-input label string (exactly one 128-bit label per bit)."""

    expected = profile.input_bits * 16
    if len(raw) != expected:
        raise DfbError(f"input-label string must be {expected} bytes")
    labels = np.frombuffer(raw, dtype="<u8").reshape(profile.input_bits, 2).astype(
        np.uint64, copy=True
    )
    # The evaluator never receives the garbler masks; keep an explicit zero
    # placeholder so the existing typed carrier cannot accidentally use them.
    masks = np.zeros_like(labels)
    return CoordinateInputEncoding(masks=masks, labels=labels, delta=None)


def serialize_standalone_bundle(program: DfbProgram, decode_state: DfbDecodeState) -> bytes:
    """Canonical fixed-profile bundle: join program followed by final masks."""

    if len(program.coordinates) != len(decode_state.coordinates):
        raise DfbError("program/decode coordinate count mismatch")
    return program.encoded + decode_state.canonical_bytes(program.profile)


def parse_standalone_bundle(
    raw: bytes,
    *,
    dimensions: Sequence[int],
    profile: DfbProfile,
) -> tuple[DfbProgram, DfbDecodeState]:
    dims = tuple(int(value) for value in dimensions)
    program_bits = sum(profile.coordinate_program_bits(value) for value in dims)
    decode_bits = sum(profile.coordinate_decode_bits(value) for value in dims)
    program_bytes = ceil(program_bits / 8)
    expected_bytes = ceil(program_bits / 8) + ceil(decode_bits / 8)
    if len(raw) != expected_bytes:
        raise DfbError(f"standalone DFB bundle must be {expected_bytes} bytes")
    program = parse_program(raw[:program_bytes], dimensions=dims, profile=profile)
    state = parse_decode_state(raw[program_bytes:], dimensions=dims, profile=profile)
    if serialize_standalone_bundle(program, state) != bytes(raw):
        raise DfbError("non-canonical standalone DFB bundle")
    return program, state


def _smudge_coefficients(
    coefficients: Sequence[tuple[Sequence[int], Sequence[int]]],
    *,
    profile: DfbProfile,
    field_modulus: int | None,
    statistical_security_bits: int,
    rng: DeterministicRng,
) -> tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]:
    """Lift F_p affine maps to Z_M exactly as in DFB Theorem 5.2."""

    if field_modulus is None:
        if statistical_security_bits:
            raise DfbError("statistical bits require a target field modulus")
        return tuple(
            (tuple(int(a) for a in a_values), tuple(int(b) for b in b_values))
            for a_values, b_values in coefficients
        )

    field_modulus = int(field_modulus)
    profile.require_statistical_smudging(field_modulus, statistical_security_bits)
    mu_bound = (profile.primorial - field_modulus * field_modulus) // field_modulus
    if mu_bound <= 0:
        raise DfbError("CRT primorial leaves no statistical-smudging domain")

    lifted: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    for a_values, b_values in coefficients:
        if len(a_values) != len(b_values) or not a_values:
            raise DfbError("affine coefficient vectors must be non-empty and equal length")
        a_lift = tuple(int(value) % field_modulus for value in a_values)
        b_lift = tuple(
            (int(value) % field_modulus) + rng.below(mu_bound) * field_modulus
            for value in b_values
        )
        if any(value >= profile.primorial for value in b_lift):
            raise DfbError("smudged affine intercept exceeds CRT primorial")
        lifted.append((a_lift, b_lift))
    return tuple(lifted)


def generate_program(
    *,
    values: Sequence[int],
    coefficients: Sequence[tuple[Sequence[int], Sequence[int]]],
    profile: DfbProfile = DfbProfile(),
    seed: bytes = b"ranklock-dfb-real-default-seed",
    field_modulus: int | None = None,
    statistical_security_bits: int = 0,
) -> DfbGeneration:
    if len(values) != len(coefficients) or not values:
        raise DfbError("one affine coefficient pair is required per coordinate")
    rng = DeterministicRng(seed)
    effective = _smudge_coefficients(
        coefficients,
        profile=profile,
        field_modulus=field_modulus,
        statistical_security_bits=statistical_security_bits,
        rng=rng,
    )
    ccrh = Ccrh()
    materials: list[CoordinateMaterial] = []
    states: list[CoordinateDecodeState] = []
    encodings: list[CoordinateInputEncoding] = []
    for coordinate_index, (value, (a_values, b_values)) in enumerate(
        zip(values, effective, strict=True)
    ):
        if field_modulus is not None and not 0 <= int(value) < int(field_modulus):
            raise DfbError("coordinate input is not a canonical target-field element")
        delta = rng.bits(LAMBDA) | 1
        material, state, encoding = generate_coordinate(
            value=int(value),
            a_values=a_values,
            b_values=b_values,
            profile=profile,
            delta=delta,
            rng=rng,
            ccrh=ccrh,
            coordinate_index=coordinate_index,
        )
        materials.append(material)
        states.append(state)
        encodings.append(encoding)
    program = serialize_program(materials, profile)
    parsed = parse_program(program.encoded, dimensions=program.dimensions, profile=profile)
    return DfbGeneration(
        program=parsed,
        decode_state=DfbDecodeState(coordinates=tuple(states)),
        input_encodings=tuple(encodings),
        garbler_hash_blocks=ccrh.block_calls,
        effective_coefficients=effective,
        field_modulus=field_modulus,
        statistical_security_bits=statistical_security_bits,
    )


def bind_input_values(generation: DfbGeneration, *, values: Sequence[int]) -> DfbGeneration:
    """Bind clear inputs after the public DFB program has been generated.

    Every coordinate uses its own Free-XOR delta and disjoint nonce namespace.
    For a smudged F_p lift, non-canonical values are rejected before labels are
    formed; the Bitcoin label-release layer must enforce the same rule.
    """

    if len(values) != len(generation.input_encodings):
        raise DfbError("coordinate value count mismatch")
    encodings: list[CoordinateInputEncoding] = []
    for value, original in zip(values, generation.input_encodings, strict=True):
        value = int(value)
        if not 0 <= value < (1 << generation.program.profile.input_bits):
            raise DfbError("coordinate input does not fit profile")
        if generation.field_modulus is not None and value >= generation.field_modulus:
            raise DfbError("coordinate input is not a canonical target-field element")
        if original.delta is None:
            raise DfbError("input template does not contain trusted binding state")
        d2 = _delta_bool(original.delta)
        labels = original.masks.copy()
        for bit in range(generation.program.profile.input_bits):
            if (value >> bit) & 1:
                labels[bit] ^= d2
        encodings.append(
            CoordinateInputEncoding(
                masks=original.masks.copy(), labels=labels, delta=original.delta
            )
        )
    return DfbGeneration(
        program=generation.program,
        decode_state=generation.decode_state,
        input_encodings=tuple(encodings),
        garbler_hash_blocks=generation.garbler_hash_blocks,
        effective_coefficients=generation.effective_coefficients,
        field_modulus=generation.field_modulus,
        statistical_security_bits=generation.statistical_security_bits,
    )


def generate_program_template(
    *,
    coefficients: Sequence[tuple[Sequence[int], Sequence[int]]],
    profile: DfbProfile = DfbProfile(),
    seed: bytes = b"ranklock-dfb-real-default-seed",
    field_modulus: int | None = None,
    statistical_security_bits: int = 0,
) -> DfbGeneration:
    """Generate a DFB program before the evaluator chooses its inputs."""

    return generate_program(
        values=tuple(0 for _ in coefficients),
        coefficients=coefficients,
        profile=profile,
        seed=seed,
        field_modulus=field_modulus,
        statistical_security_bits=statistical_security_bits,
    )


def evaluate_program(
    generation: DfbGeneration,
    *,
    values: Sequence[int],
) -> DfbEvaluation:
    if len(values) != len(generation.program.coordinates):
        raise DfbError("coordinate value count mismatch")
    ccrh = Ccrh()
    decoded: list[np.ndarray] = []
    for coordinate_index, (value, material, encoding, state) in enumerate(
        zip(
            values,
            generation.program.coordinates,
            generation.input_encodings,
            generation.decode_state.coordinates,
            strict=True,
        )
    ):
        value = int(value)
        if generation.field_modulus is not None and value >= generation.field_modulus:
            raise DfbError("coordinate input is not a canonical target-field element")
        decoded.append(
            evaluate_coordinate(
                value=value,
                material=material,
                input_encoding=encoding,
                decode_state=state,
                profile=generation.program.profile,
                ccrh=ccrh,
                coordinate_index=coordinate_index,
            )
        )
    return DfbEvaluation(decoded_residues=tuple(decoded), evaluator_hash_blocks=ccrh.block_calls)


def evaluate_program_labels(
    generation: DfbGeneration,
    *,
    values: Sequence[int],
) -> DfbLabelEvaluation:
    """Evaluate a program without serializing or consuming final masks."""

    if len(values) != len(generation.program.coordinates):
        raise DfbError("coordinate value count mismatch")
    ccrh = Ccrh()
    labels: list[np.ndarray] = []
    for coordinate_index, (value, material, encoding) in enumerate(
        zip(
            values,
            generation.program.coordinates,
            generation.input_encodings,
            strict=True,
        )
    ):
        value = int(value)
        if generation.field_modulus is not None and value >= generation.field_modulus:
            raise DfbError("coordinate input is not a canonical target-field element")
        labels.append(
            evaluate_coordinate_labels(
                value=value,
                material=material,
                input_encoding=encoding,
                profile=generation.program.profile,
                ccrh=ccrh,
                coordinate_index=coordinate_index,
            )
        )
    return DfbLabelEvaluation(
        label_residues=tuple(labels), evaluator_hash_blocks=ccrh.block_calls
    )


def verify_affine_residues(
    evaluation: DfbEvaluation,
    *,
    values: Sequence[int],
    coefficients: Sequence[tuple[Sequence[int], Sequence[int]]],
    profile: DfbProfile,
) -> None:
    for coordinate_index, (value, (a_values, b_values), residues) in enumerate(
        zip(values, coefficients, evaluation.decoded_residues, strict=True)
    ):
        for prime_index, prime in enumerate(profile.primes):
            expected = np.array(
                [(int(a) * value + int(b)) % prime for a, b in zip(a_values, b_values, strict=True)],
                dtype=np.uint64,
            )
            if not np.array_equal(residues[prime_index], expected):
                mismatch = int(np.flatnonzero(residues[prime_index] != expected)[0])
                raise DfbError(
                    f"affine residue mismatch coordinate={coordinate_index} prime={prime} index={mismatch}"
                )


def reconstruct_crt_columns(residues: np.ndarray, profile: DfbProfile) -> list[int]:
    values = np.asarray(residues, dtype=np.uint64)
    if values.shape[0] != len(profile.primes):
        raise DfbError("CRT residue matrix has wrong prime count")
    modulus = profile.primorial
    coefficients: list[int] = []
    for prime in profile.primes:
        partial = modulus // prime
        coefficients.append(partial * pow(partial, -1, prime))
    outputs: list[int] = []
    for column in range(values.shape[1]):
        total = 0
        for row, coefficient in enumerate(coefficients):
            total += int(values[row, column]) * coefficient
        outputs.append(total % modulus)
    return outputs
