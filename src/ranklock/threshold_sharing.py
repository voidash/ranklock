from __future__ import annotations

"""t-of-n verifiable secret sharing over secp256k1 (Feldman VSS).

Replaces the n-of-n XOR sharing used by the committee and two-phase modules.
The motivation is operator churn: under n-of-n, losing one participant makes
every retained slot bound to that committee permanently unopenable, so an
operator leaving is not a membership change but fund loss. Under t-of-n any
``threshold`` participants can reconstruct, and :func:`reshare` moves a secret
to a new committee *without changing the public commitment*, which is what
makes join/leave possible at all.

**This changes the security model, and the change is not free.** n-of-n XOR is
information-theoretically hiding: a coalition of n-1 is missing a genuine
one-time pad. Feldman VSS is only *computationally* hiding, because the
commitment publishes ``a_0·G`` — recovering the secret from it is the
secp256k1 discrete log (~128 bits), not impossible-in-principle. In exchange
the shares become publicly verifiable, so a participant serving a wrong share
is caught immediately and by name rather than anonymously halting the round.
If information-theoretic hiding must be preserved, Pedersen VSS is the
alternative; it needs a second generator with unknown discrete-log relation to
``G``, which is a setup artifact this module deliberately does not introduce.

Limbing: secrets are split into 128-bit limbs before sharing. A 32-byte secret
is not guaranteed to be less than the group order, so sharing it as a single
field element would be either lossy or rejection-sampled; 128-bit limbs are
always in range, and the scheme is linear so limbs share independently.
"""

from dataclasses import dataclass
from hashlib import sha256
import secrets
from typing import Callable, Sequence

from .real_secp import G, N, Point, add, base_multiply, multiply, negate

LIMB_BITS = 128
LIMB_BYTES = LIMB_BITS // 8


class ThresholdSharingError(RuntimeError):
    """Raised when sharing, verification, or reconstruction fails."""


def _limbs(secret: bytes) -> tuple[int, ...]:
    if not secret:
        raise ThresholdSharingError("secret must not be empty")
    if len(secret) % LIMB_BYTES:
        raise ThresholdSharingError(
            f"secret length {len(secret)} is not a multiple of {LIMB_BYTES} bytes"
        )
    return tuple(
        int.from_bytes(secret[offset : offset + LIMB_BYTES], "big")
        for offset in range(0, len(secret), LIMB_BYTES)
    )


def _unlimb(values: Sequence[int]) -> bytes:
    out = bytearray()
    for value in values:
        if not 0 <= value < 1 << LIMB_BITS:
            raise ThresholdSharingError("reconstructed limb is out of range")
        out.extend(int(value).to_bytes(LIMB_BYTES, "big"))
    return bytes(out)


def _point_bytes(point: Point | None) -> bytes:
    """Compressed SEC1, with the identity encoded as 33 zero bytes.

    The identity has no SEC1 encoding. It arises here only for a zero
    coefficient, which is possible though negligibly likely, so it needs *an*
    encoding rather than an exception.
    """

    if point is None:
        return bytes(33)
    x, y = point
    return bytes([2 + (y & 1)]) + int(x).to_bytes(32, "big")


@dataclass(frozen=True)
class FeldmanCommitment:
    """Public commitment to the sharing polynomial, one point per coefficient.

    ``coefficients[limb][j]`` commits to the degree-``j`` coefficient of the
    polynomial sharing limb ``limb``. ``coefficients[limb][0]`` therefore
    commits to that limb of the secret itself.
    """

    coefficients: tuple[tuple[Point | None, ...], ...]

    @property
    def threshold(self) -> int:
        return len(self.coefficients[0])

    @property
    def limb_count(self) -> int:
        return len(self.coefficients)

    @property
    def digest(self) -> bytes:
        """Stable identifier for this sharing, invariant under resharing.

        Only the constant terms are hashed. Resharing changes every higher
        coefficient but must leave ``a_0`` fixed, so this digest is what lets a
        new committee prove it holds the *same* secret as the old one.
        """

        body = b"".join(_point_bytes(row[0]) for row in self.coefficients)
        return sha256(b"ranklock/threshold-sharing/commitment/v1" + body).digest()


@dataclass(frozen=True)
class VssShare:
    """One participant's share. ``index`` is the evaluation point, never 0."""

    index: int
    limbs: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.index <= 0:
            raise ThresholdSharingError("share index must be positive; 0 is the secret")


def _evaluate(coefficients: Sequence[int], x: int) -> int:
    """Horner evaluation of a polynomial over Z_N."""

    acc = 0
    for coefficient in reversed(coefficients):
        acc = (acc * x + coefficient) % N
    return acc


def split_secret(
    secret: bytes,
    *,
    threshold: int,
    participants: int,
    randbelow: Callable[[int], int] | None = None,
) -> tuple[tuple[VssShare, ...], FeldmanCommitment]:
    """Split ``secret`` so any ``threshold`` of ``participants`` can recover it.

    ``randbelow`` exists for deterministic testing only and defaults to
    :func:`secrets.randbelow`. It is deliberately *not* a seed parameter with a
    literal default: an earlier defect in this codebase shipped garbling
    secrets derived from a hardcoded default seed, and a caller who forgets an
    argument must not silently get predictable coefficients.
    """

    if threshold < 1:
        raise ThresholdSharingError("threshold must be at least 1")
    if participants < threshold:
        raise ThresholdSharingError("participants must be at least the threshold")
    if participants >= N:
        raise ThresholdSharingError("participants exceeds the group order")

    draw = secrets.randbelow if randbelow is None else randbelow
    limbs = _limbs(secret)

    polynomials: list[list[int]] = []
    commitments: list[tuple[Point | None, ...]] = []
    for limb in limbs:
        coefficients = [limb % N] + [draw(N) for _ in range(threshold - 1)]
        polynomials.append(coefficients)
        commitments.append(tuple(base_multiply(c) for c in coefficients))

    shares = tuple(
        VssShare(
            index=index,
            limbs=tuple(_evaluate(poly, index) for poly in polynomials),
        )
        for index in range(1, participants + 1)
    )
    return shares, FeldmanCommitment(coefficients=tuple(commitments))


def verify_share(share: VssShare, commitment: FeldmanCommitment) -> bool:
    """Check a share against the public commitment.

    Verifies ``y·G == Σ_j C_j · i^j`` for each limb. This is what n-of-n XOR
    could not do: a participant serving a wrong share is identified here rather
    than causing an anonymous failure later.
    """

    if len(share.limbs) != commitment.limb_count:
        return False
    for value, coefficients in zip(share.limbs, commitment.coefficients, strict=True):
        expected: Point | None = None
        power = 1
        for point in coefficients:
            if point is not None:
                expected = add(expected, multiply(point, power))
            power = (power * share.index) % N
        if base_multiply(value % N) != expected:
            return False
    return True


def _lagrange_at_zero(indices: Sequence[int]) -> tuple[int, ...]:
    """Lagrange basis coefficients evaluated at x = 0, over Z_N."""

    unique = tuple(indices)
    if len(set(unique)) != len(unique):
        raise ThresholdSharingError("duplicate share indices cannot interpolate")
    weights: list[int] = []
    for i in unique:
        numerator = 1
        denominator = 1
        for j in unique:
            if i == j:
                continue
            numerator = (numerator * (-j)) % N
            denominator = (denominator * (i - j)) % N
        weights.append(numerator * pow(denominator, -1, N) % N)
    return tuple(weights)


def reconstruct(
    shares: Sequence[VssShare],
    *,
    threshold: int,
    commitment: FeldmanCommitment | None = None,
) -> bytes:
    """Recover the secret from any ``threshold`` shares.

    When ``commitment`` is supplied every share is verified first, so a bad
    share fails loudly and attributably instead of silently producing a wrong
    secret.
    """

    if len(shares) < threshold:
        raise ThresholdSharingError(
            f"need {threshold} shares to reconstruct, got {len(shares)}"
        )
    selected = tuple(shares[:threshold])

    if commitment is not None:
        for share in selected:
            if not verify_share(share, commitment):
                raise ThresholdSharingError(
                    f"share from participant index {share.index} failed verification"
                )

    limb_count = len(selected[0].limbs)
    if any(len(share.limbs) != limb_count for share in selected):
        raise ThresholdSharingError("shares disagree on limb count")

    weights = _lagrange_at_zero([share.index for share in selected])
    recovered = []
    for limb in range(limb_count):
        total = 0
        for weight, share in zip(weights, selected, strict=True):
            total = (total + weight * share.limbs[limb]) % N
        recovered.append(total)

    if commitment is not None:
        # Verify the *result*, not just the inputs. Individually valid shares
        # interpolated with the wrong threshold yield a wrong secret, and the
        # limb range check below only catches that probabilistically. Comparing
        # against the committed constant term catches it always.
        for value, coefficients in zip(recovered, commitment.coefficients, strict=True):
            if base_multiply(value) != coefficients[0]:
                raise ThresholdSharingError(
                    "reconstruction does not match the committed secret; "
                    "the share set is inconsistent or below the threshold"
                )

    return _unlimb(recovered)


def reshare(
    shares: Sequence[VssShare],
    *,
    threshold: int,
    new_threshold: int,
    new_participants: int,
    commitment: FeldmanCommitment,
    randbelow: Callable[[int], int] | None = None,
) -> tuple[tuple[VssShare, ...], FeldmanCommitment]:
    """Move a secret to a new committee, keeping its public commitment.

    This is the operation that makes operator churn possible. The constant
    terms of the new commitment equal the old ones, so ``commitment.digest`` is
    unchanged and any artifact already bound to it — a label commitment root,
    an on-chain hash-lock — stays valid across the membership change.

    Old shares are *not* invalidated by this call. Retiring them is an
    operational step: the outgoing participants must delete their material,
    and nothing here can enforce that. A departing operator who keeps its old
    share still counts toward the old threshold.
    """

    secret = reconstruct(shares, threshold=threshold, commitment=commitment)
    fresh, new_commitment = split_secret(
        secret,
        threshold=new_threshold,
        participants=new_participants,
        randbelow=randbelow,
    )
    if new_commitment.digest != commitment.digest:
        raise ThresholdSharingError(
            "resharing changed the public commitment; the secret was not preserved"
        )
    return fresh, new_commitment
