from __future__ import annotations

"""Formal Groth16 pairing predicate and projective-input envelope for RankLock.

This module is an executable *reduction certificate*, not a production witness-
encryption implementation.  It isolates the exact dynamic statement that the
conditional-disclosure layer has to consume after transparent proof recursion:

    one Groth16 pairing-product equation
    + two canonical 128-bit public scalars
    + three witness proof elements (A, B, C).

Group elements are represented by their discrete-log exponents so that equation
normalization, statement binding, collision attacks, and material accounting are
fully inspectable.  Exponent-space elements are never secure cryptographic
objects.
"""

from dataclasses import dataclass
import hashlib
from typing import Iterable

from .nonnative_field import BLS12_381_SCALAR_FIELD

SCALAR_MODULUS = BLS12_381_SCALAR_FIELD
CONTEXT_DIGEST_BYTES = 32
PUBLIC_INPUT_CHUNKS = 2
PUBLIC_INPUT_CHUNK_BYTES = 16
PUBLIC_INPUT_BITS = CONTEXT_DIGEST_BYTES * 8

_CONTEXT_DOMAIN = b"ranklock/recursive-ppe-context/v1\x00"


class Groth16ProjectiveLockError(ValueError):
    pass


def _field(value: int) -> int:
    return int(value) % SCALAR_MODULUS


def _length_prefix(value: bytes) -> bytes:
    value = bytes(value)
    return len(value).to_bytes(8, "big") + value


def recursive_context_digest(
    *,
    program_digest: bytes,
    statement_digest: bytes,
    transparent_verifier_digest: bytes,
    wrapper_verifying_key_digest: bytes,
    deployment_id: bytes,
    result_tag: bytes = b"invalid",
) -> bytes:
    """Bind every replay-sensitive component of the future RankLock statement."""

    digest = hashlib.sha256()
    digest.update(_CONTEXT_DOMAIN)
    for value in (
        bytes(program_digest),
        bytes(statement_digest),
        bytes(transparent_verifier_digest),
        bytes(wrapper_verifying_key_digest),
        bytes(deployment_id),
        bytes(result_tag),
    ):
        digest.update(_length_prefix(value))
    return digest.digest()


def split_context_digest(digest: bytes) -> tuple[int, int]:
    """Injectively encode one 256-bit digest as two canonical 128-bit scalars."""

    digest = bytes(digest)
    if len(digest) != CONTEXT_DIGEST_BYTES:
        raise Groth16ProjectiveLockError("context digest must be exactly 32 bytes")
    left = int.from_bytes(digest[:PUBLIC_INPUT_CHUNK_BYTES], "big")
    right = int.from_bytes(digest[PUBLIC_INPUT_CHUNK_BYTES:], "big")
    # Each half is < 2^128 and therefore strictly below BLS12-381 Fr.
    if left >= SCALAR_MODULUS or right >= SCALAR_MODULUS:  # pragma: no cover
        raise AssertionError("128-bit context chunk does not fit the scalar field")
    return left, right


def combine_context_scalars(public_inputs: Iterable[int]) -> bytes:
    values = tuple(int(value) for value in public_inputs)
    if len(values) != PUBLIC_INPUT_CHUNKS:
        raise Groth16ProjectiveLockError("exactly two public context scalars are required")
    if any(value < 0 or value >= 2**128 for value in values):
        raise Groth16ProjectiveLockError("context scalar is not a canonical 128-bit chunk")
    return b"".join(value.to_bytes(PUBLIC_INPUT_CHUNK_BYTES, "big") for value in values)


def unsafe_single_scalar_encoding(digest: bytes) -> int:
    """The tempting but non-injective 256-bit-to-one-field encoding."""

    digest = bytes(digest)
    if len(digest) != CONTEXT_DIGEST_BYTES:
        raise Groth16ProjectiveLockError("context digest must be exactly 32 bytes")
    return int.from_bytes(digest, "big") % SCALAR_MODULUS


def single_scalar_collision() -> tuple[bytes, bytes, int]:
    """Return a concrete collision for reduction of a 256-bit digest modulo Fr.

    The byte strings are input-space examples, not SHA-256 collisions.  They
    demonstrate why a *digest value* must not be mapped to one scalar by modular
    reduction: 0 and r are distinct 256-bit strings with the same field image.
    """

    first = bytes(CONTEXT_DIGEST_BYTES)
    second = SCALAR_MODULUS.to_bytes(CONTEXT_DIGEST_BYTES, "big")
    if first == second or unsafe_single_scalar_encoding(first) != unsafe_single_scalar_encoding(second):
        raise AssertionError("failed to construct the one-scalar reduction collision")
    return first, second, 0


@dataclass(frozen=True, slots=True)
class FormalGroth16VerifyingKey:
    """Exponent-space Groth16 VK for a two-public-input statement."""

    alpha_g1: int
    beta_g2: int
    gamma_g2: int
    delta_g2: int
    ic0_g1: int
    ic1_g1: int
    ic2_g1: int
    domain: bytes = b"ranklock-formal-groth16-vk"

    def __post_init__(self) -> None:
        if _field(self.gamma_g2) == 0:
            raise Groth16ProjectiveLockError("gamma must be nonzero")
        if _field(self.delta_g2) == 0:
            raise Groth16ProjectiveLockError("delta must be nonzero")
        if _field(self.ic1_g1) == 0 or _field(self.ic2_g1) == 0:
            raise Groth16ProjectiveLockError("both context coordinates must be bound")

    @classmethod
    def derive(cls, domain: bytes = b"ranklock-formal-groth16-vk") -> "FormalGroth16VerifyingKey":
        """Derive deterministic nonzero exponents for reproducible formal tests."""

        def scalar(label: bytes) -> int:
            counter = 0
            while True:
                raw = hashlib.sha256(
                    b"ranklock/formal-groth16-vk/v1\x00"
                    + _length_prefix(bytes(domain))
                    + _length_prefix(label)
                    + counter.to_bytes(4, "big")
                ).digest()
                value = int.from_bytes(raw, "big") % SCALAR_MODULUS
                if value:
                    return value
                counter += 1

        return cls(
            alpha_g1=scalar(b"alpha-g1"),
            beta_g2=scalar(b"beta-g2"),
            gamma_g2=scalar(b"gamma-g2"),
            delta_g2=scalar(b"delta-g2"),
            ic0_g1=scalar(b"ic0-g1"),
            ic1_g1=scalar(b"ic1-g1"),
            ic2_g1=scalar(b"ic2-g1"),
            domain=bytes(domain),
        )

    @property
    def digest(self) -> bytes:
        digest = hashlib.sha256(
            b"ranklock/formal-groth16-vk-digest/v1\x00" + _length_prefix(self.domain)
        )
        for value in (
            self.alpha_g1,
            self.beta_g2,
            self.gamma_g2,
            self.delta_g2,
            self.ic0_g1,
            self.ic1_g1,
            self.ic2_g1,
        ):
            digest.update(_field(value).to_bytes(32, "big"))
        return digest.digest()

    def public_input_accumulator(self, public_inputs: Iterable[int]) -> int:
        values = tuple(int(value) for value in public_inputs)
        if len(values) != PUBLIC_INPUT_CHUNKS:
            raise Groth16ProjectiveLockError("Groth16 wrapper expects two public inputs")
        if any(value < 0 or value >= 2**128 for value in values):
            raise Groth16ProjectiveLockError("public context coordinate is not canonical")
        return _field(self.ic0_g1 + values[0] * self.ic1_g1 + values[1] * self.ic2_g1)


@dataclass(frozen=True, slots=True)
class FormalGroth16Proof:
    """Exponent-space proof elements A in G1, B in G2, C in G1."""

    a_g1: int
    b_g2: int
    c_g1: int

    def canonical(self) -> "FormalGroth16Proof":
        return FormalGroth16Proof(_field(self.a_g1), _field(self.b_g2), _field(self.c_g1))


@dataclass(frozen=True, slots=True)
class FormalGroth16Ppe:
    """One normalized Groth16 pairing-product equation.

    In exponent space, e(g1^x, g2^y) is represented by x*y.  The normalized
    verifier equation is:

        A*B - alpha*beta - vk_x*gamma - C*delta = 0 mod r.
    """

    vk: FormalGroth16VerifyingKey
    public_inputs: tuple[int, int]
    proof: FormalGroth16Proof

    @property
    def residual(self) -> int:
        vk_x = self.vk.public_input_accumulator(self.public_inputs)
        proof = self.proof.canonical()
        return _field(
            proof.a_g1 * proof.b_g2
            - self.vk.alpha_g1 * self.vk.beta_g2
            - vk_x * self.vk.gamma_g2
            - proof.c_g1 * self.vk.delta_g2
        )

    @property
    def satisfied(self) -> bool:
        return self.residual == 0

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-formal-groth16-ppe-v1",
            "public_input_count": PUBLIC_INPUT_CHUNKS,
            "public_inputs_are_canonical_128_bit_chunks": all(
                0 <= value < 2**128 for value in self.public_inputs
            ),
            "residual": self.residual,
            "satisfied": self.satisfied,
            "warning": (
                "Exponent-space normalization only. Discrete-log exponents are visible; "
                "this is not a secure Groth16 implementation or a conditional lock."
            ),
        }


def synthesize_formal_proof(
    vk: FormalGroth16VerifyingKey,
    public_inputs: Iterable[int],
    *,
    a_g1: int,
    b_g2: int,
) -> FormalGroth16Proof:
    """Solve for C to create a satisfying formal equation.

    This is useful only for executable equation/statement tests.  It is not a
    Groth16 prover and makes no knowledge-soundness claim.
    """

    values = tuple(int(value) for value in public_inputs)
    vk_x = vk.public_input_accumulator(values)
    numerator = _field(
        int(a_g1) * int(b_g2)
        - vk.alpha_g1 * vk.beta_g2
        - vk_x * vk.gamma_g2
    )
    c_g1 = numerator * pow(_field(vk.delta_g2), -1, SCALAR_MODULUS) % SCALAR_MODULUS
    return FormalGroth16Proof(_field(a_g1), _field(b_g2), c_g1)


@dataclass(frozen=True, slots=True)
class ProjectiveInputEnvelope:
    """Conservative retained-material budget for future context selection."""

    component_bytes: int = 96
    components_per_bit: int = 32
    fixed_overhead_bytes: int = 65_536
    groth16_verifying_key_bytes: int = 480
    cap_bytes: int = 1 << 20
    digest_bits: int = PUBLIC_INPUT_BITS

    def __post_init__(self) -> None:
        if min(
            self.component_bytes,
            self.components_per_bit,
            self.groth16_verifying_key_bytes,
            self.cap_bytes,
            self.digest_bits,
        ) <= 0:
            raise Groth16ProjectiveLockError("projective envelope parameters must be positive")
        if self.fixed_overhead_bytes < 0:
            raise Groth16ProjectiveLockError("fixed overhead must be nonnegative")

    @property
    def catalog_bytes(self) -> int:
        return self.digest_bits * self.components_per_bit * self.component_bytes

    @property
    def total_bytes(self) -> int:
        return self.fixed_overhead_bytes + self.groth16_verifying_key_bytes + self.catalog_bytes

    @property
    def fits_cap(self) -> bool:
        return self.total_bytes <= self.cap_bytes

    @property
    def maximum_components_per_bit(self) -> int:
        available = self.cap_bytes - self.fixed_overhead_bytes - self.groth16_verifying_key_bytes
        if available < 0:
            return -1
        return available // (self.digest_bits * self.component_bytes)

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-projective-input-envelope-v1",
            "digest_bits": self.digest_bits,
            "algebraic_public_input_scalars": PUBLIC_INPUT_CHUNKS,
            "component_bytes": self.component_bytes,
            "components_per_bit": self.components_per_bit,
            "catalog_bytes": self.catalog_bytes,
            "fixed_overhead_bytes": self.fixed_overhead_bytes,
            "groth16_verifying_key_bytes": self.groth16_verifying_key_bytes,
            "total_bytes": self.total_bytes,
            "cap_bytes": self.cap_bytes,
            "fits_cap": self.fits_cap,
            "maximum_components_per_bit_under_cap": self.maximum_components_per_bit,
            "warning": (
                "This is a byte envelope, not a construction or security proof for the "
                "projective input catalog. The component count must be justified by the "
                "eventual maliciously secure PPE conditional-disclosure protocol."
            ),
        }


def projective_ppe_reduction_report() -> dict[str, object]:
    first, second, image = single_scalar_collision()
    envelope = ProjectiveInputEnvelope()
    return {
        "schema": "ranklock-groth16-projective-ppe-reduction-v1",
        "status": "FORMAL_RECURSIVE_REDUCTION_CANDIDATE",
        "dynamic_predicate": {
            "pairing_product_equations": 1,
            "witness_group_elements": {
                "G1": 2,
                "G2": 1,
                "names": ["A", "B", "C"],
            },
            "public_context_scalars": PUBLIC_INPUT_CHUNKS,
            "public_context_bits": PUBLIC_INPUT_BITS,
        },
        "context_encoding": {
            "method": "split SHA-256 digest into two canonical 128-bit scalars",
            "injective_on_digest_values": True,
            "one_scalar_modular_reduction_is_injective": False,
            "executable_one_scalar_collision": {
                "first_hex": first.hex(),
                "second_hex": second.hex(),
                "common_field_image": image,
            },
        },
        "retained_material_envelope_ESTIMATE": envelope.document(),
        "legacy_input_comparison": {
            "legacy_selected_bytes": 132,
            "legacy_byte_value_choices": 132 * 256,
            "digest_bit_value_choices": PUBLIC_INPUT_BITS * 2,
            "choice_count_reduction": (132 * 256) / (PUBLIC_INPUT_BITS * 2),
            "legacy_one_component_per_byte_value_bytes": 132 * 256 * envelope.component_bytes,
            "digest_catalog_components": PUBLIC_INPUT_BITS * envelope.components_per_bit,
            "digest_catalog_bytes": envelope.catalog_bytes,
            "warning": (
                "Choice-count comparison only. The two catalogs have different "
                "cryptographic component semantics and security amplification."
            ),
        },
        "reduction_claim": (
            "After transparent proof recursion, the conditional-disclosure layer no "
            "longer consumes the full trace or sparse R1CS. It consumes one Groth16 PPE "
            "and a 256-bit replay-bound context."
        ),
        "remaining_assumptions": [
            "knowledge-sound transparent proof for the complete RankVM relation",
            "knowledge-sound recursive Groth16 wrapper over BLS12-381 Fr",
            "maliciously secure projective conditional disclosure / witness encryption for one PPE",
            "distributed or otherwise acceptable setup security for the wrapper and lock",
        ],
        "warning": (
            "The exponent-space equation and digest encoding are executable. The projective "
            "component count is an estimate, and no production transparent proof, wrapper "
            "SNARK, or PPE conditional-disclosure scheme is implemented here."
        ),
    }
