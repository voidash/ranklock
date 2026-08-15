from __future__ import annotations

"""Minimal BIP340 and Taproot hashing helpers for RankLock research code.

The implementation follows the Bitcoin BIP340 reference algorithm and uses the
existing :mod:`ranklock.real_secp` arithmetic.  It is intentionally variable-time
and is suitable for deterministic research fixtures, not production signing.
"""

from hashlib import sha256

from .real_secp import G, N, P, Point, add, base_multiply, is_on_curve, multiply, negate


class BIP340Error(ValueError):
    pass


def tagged_hash(tag: str | bytes, message: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8") if isinstance(tag, str) else bytes(tag)
    tag_digest = sha256(tag_bytes).digest()
    return sha256(tag_digest + tag_digest + bytes(message)).digest()


def lift_x(x: int) -> Point:
    """Return the unique secp256k1 point with x-coordinate ``x`` and even y."""

    x = int(x)
    if not 0 <= x < P:
        raise BIP340Error("x-coordinate is outside secp256k1 field")
    yy = (pow(x, 3, P) + 7) % P
    y = pow(yy, (P + 1) // 4, P)
    if y * y % P != yy:
        raise BIP340Error("x-coordinate does not lift to secp256k1")
    if y & 1:
        y = P - y
    point = (x, y)
    if not is_on_curve(point):  # pragma: no cover - defense in depth
        raise BIP340Error("lifted point is invalid")
    return point


def _normalized_secret(secret: int) -> tuple[int, Point]:
    d0 = int(secret) % N
    if d0 == 0:
        raise BIP340Error("BIP340 secret must be nonzero")
    point = base_multiply(d0)
    if point is None:  # pragma: no cover - guarded by d0
        raise BIP340Error("BIP340 public key is infinity")
    d = d0 if point[1] % 2 == 0 else N - d0
    normalized_point = base_multiply(d)
    if normalized_point is None:  # pragma: no cover
        raise BIP340Error("normalized public key is infinity")
    return d, normalized_point


def public_key(secret: int) -> bytes:
    _d, point = _normalized_secret(secret)
    return point[0].to_bytes(32, "big")


def sign(message: bytes, secret: int, aux_rand: bytes | None = None) -> bytes:
    """Create a deterministic BIP340 signature.

    ``aux_rand=None`` uses 32 zero bytes, matching the deterministic test-vector
    mode of the reference implementation.  Production callers should supply
    independent 32-byte auxiliary randomness.
    """

    message = bytes(message)
    aux = bytes(32) if aux_rand is None else bytes(aux_rand)
    if len(aux) != 32:
        raise BIP340Error("BIP340 auxiliary randomness must be 32 bytes")

    d, point = _normalized_secret(secret)
    d_bytes = d.to_bytes(32, "big")
    pubkey = point[0].to_bytes(32, "big")
    aux_hash = tagged_hash("BIP0340/aux", aux)
    t = bytes(a ^ b for a, b in zip(d_bytes, aux_hash, strict=True))
    nonce_digest = tagged_hash("BIP0340/nonce", t + pubkey + message)
    k0 = int.from_bytes(nonce_digest, "big") % N
    if k0 == 0:
        raise BIP340Error("BIP340 nonce generation returned zero")
    r_point = base_multiply(k0)
    if r_point is None:  # pragma: no cover
        raise BIP340Error("BIP340 nonce point is infinity")
    k = k0 if r_point[1] % 2 == 0 else N - k0
    r_point = base_multiply(k)
    if r_point is None:  # pragma: no cover
        raise BIP340Error("normalized nonce point is infinity")
    r_bytes = r_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", r_bytes + pubkey + message), "big"
    ) % N
    signature = r_bytes + ((k + challenge * d) % N).to_bytes(32, "big")
    if not verify(message, pubkey, signature):  # pragma: no cover
        raise BIP340Error("internally generated BIP340 signature did not verify")
    return signature


def verify(message: bytes, pubkey: bytes, signature: bytes) -> bool:
    message, pubkey, signature = bytes(message), bytes(pubkey), bytes(signature)
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    try:
        point = lift_x(int.from_bytes(pubkey, "big"))
    except BIP340Error:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + pubkey + message), "big"
    ) % N
    s_g = base_multiply(s)
    e_p = multiply(point, challenge)
    r_point = add(s_g, negate(e_p))
    return bool(
        r_point is not None
        and is_on_curve(r_point)
        and r_point[1] % 2 == 0
        and r_point[0] == r
    )


def _compact_size(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise BIP340Error("compact-size value is negative")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise BIP340Error("compact-size value exceeds u64")


def tapleaf_hash(script: bytes, *, leaf_version: int = 0xC0) -> bytes:
    script = bytes(script)
    if not 0 <= leaf_version <= 0xFE or leaf_version & 1:
        raise BIP340Error("TapLeaf version must be an even byte")
    return tagged_hash("TapLeaf", bytes((leaf_version,)) + _compact_size(len(script)) + script)


def tapbranch_hash(left: bytes, right: bytes) -> bytes:
    left, right = bytes(left), bytes(right)
    if len(left) != 32 or len(right) != 32:
        raise BIP340Error("TapBranch children must be 32-byte hashes")
    first, second = sorted((left, right))
    return tagged_hash("TapBranch", first + second)


def taproot_output_key(internal_key: bytes, merkle_root: bytes = b"") -> bytes:
    internal_key, merkle_root = bytes(internal_key), bytes(merkle_root)
    if len(internal_key) != 32:
        raise BIP340Error("Taproot internal key must be 32 bytes")
    if len(merkle_root) not in (0, 32):
        raise BIP340Error("Taproot Merkle root must be empty or 32 bytes")
    point = lift_x(int.from_bytes(internal_key, "big"))
    tweak = int.from_bytes(tagged_hash("TapTweak", internal_key + merkle_root), "big")
    if tweak >= N:
        raise BIP340Error("Taproot tweak is outside secp256k1 order")
    output = add(point, multiply(G, tweak))
    if output is None:
        raise BIP340Error("Taproot tweak produced infinity")
    return output[0].to_bytes(32, "big")
