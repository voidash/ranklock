from __future__ import annotations

"""The fixed-statement RankLock relation is a hard YES instance.

A setup-time RankLock statement fixes the program, deposit, epoch, verifier key,
and projective-authentication parameters, while the future public values and
counterproof remain witness variables.  Because malformed/invalid counterproofs
exist and the projective layer is intended to authenticate every future byte
choice, the fixed statement normally has *some* accepting witness before the
actual bridge event happens.

Standard witness-encryption secrecy is normally required only for NO instances.
It therefore does not, by itself, imply that the fault secret is hidden on this
fixed but hard-to-witness YES instance.  RankLock needs a stronger property:
hard-YES witness pseudorandomness/extractability (equivalently, a suitable
witness PRF/predictable token), including the view of an adversary corrupting
all but one setup contributor.

The toy relation below makes the distinction executable.  Its public statement
contains commitments to one authentication token for each future value and an
``INVALID`` predicate.  A witness exists at setup, but guessing a token does not
produce it.  This is a semantic model, not a cryptographic construction for
RankLock.
"""

from dataclasses import dataclass
from hashlib import sha256
from itertools import product
from typing import Sequence


class FixedYesInstanceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FixedDepositLanguageProfile:
    future_counterproof_bytes: int = 128
    future_public_value_bytes: int = 36
    projective_layer_supports_every_byte: bool = True
    at_least_one_invalid_counterproof_exists: bool = True
    fixed_statement_excludes_future_bytes: bool = True
    schema: str = "ranklock-fixed-deposit-language-profile-v1"

    def __post_init__(self) -> None:
        if self.future_counterproof_bytes <= 0 or self.future_public_value_bytes <= 0:
            raise FixedYesInstanceError("future input widths must be positive")

    @property
    def future_input_bytes(self) -> int:
        return self.future_counterproof_bytes + self.future_public_value_bytes

    @property
    def future_input_bits(self) -> int:
        return 8 * self.future_input_bytes

    @property
    def fixed_statement_is_yes_before_event(self) -> bool:
        return (
            self.fixed_statement_excludes_future_bytes
            and self.projective_layer_supports_every_byte
            and self.at_least_one_invalid_counterproof_exists
        )

    @property
    def standard_no_instance_we_hiding_applies(self) -> bool:
        return not self.fixed_statement_is_yes_before_event

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "future_counterproof_bytes": self.future_counterproof_bytes,
            "future_public_value_bytes": self.future_public_value_bytes,
            "future_input_bytes": self.future_input_bytes,
            "future_input_bits": self.future_input_bits,
            "future_input_domain": f"2^{self.future_input_bits}",
            "projective_layer_supports_every_byte": (
                self.projective_layer_supports_every_byte
            ),
            "at_least_one_invalid_counterproof_exists": (
                self.at_least_one_invalid_counterproof_exists
            ),
            "fixed_statement_excludes_future_bytes": (
                self.fixed_statement_excludes_future_bytes
            ),
            "fixed_statement_is_YES_before_event": (
                self.fixed_statement_is_yes_before_event
            ),
            "standard_NO_instance_WE_hiding_applies": (
                self.standard_no_instance_we_hiding_applies
            ),
        }


@dataclass(frozen=True, slots=True)
class ToyAuthenticatedInvalidityStatement:
    """Tiny fixed hard-YES relation used as an executable semantic witness."""

    token_commitments: tuple[bytes, ...]
    valid_value: int
    schema: str = "ranklock-toy-authenticated-invalidity-statement-v1"

    def __post_init__(self) -> None:
        if len(self.token_commitments) < 2:
            raise FixedYesInstanceError("toy statement needs at least two values")
        if not 0 <= self.valid_value < len(self.token_commitments):
            raise FixedYesInstanceError("valid value is outside the toy domain")
        if any(len(commitment) != 32 for commitment in self.token_commitments):
            raise FixedYesInstanceError("toy token commitment must be 32 bytes")

    def accepts(self, value: int, token: bytes) -> bool:
        value = int(value)
        return (
            0 <= value < len(self.token_commitments)
            and value != self.valid_value
            and sha256(b"ranklock/toy-token/v1\x00" + bytes(token)).digest()
            == self.token_commitments[value]
        )

    def has_witness(self, candidate_tokens: Sequence[bytes]) -> bool:
        if len(candidate_tokens) != len(self.token_commitments):
            return False
        return any(
            self.accepts(value, token)
            for value, token in enumerate(candidate_tokens)
        )


@dataclass(frozen=True, slots=True)
class ToyHardYesFixture:
    statement: ToyAuthenticatedInvalidityStatement
    private_tokens: tuple[bytes, ...]

    @classmethod
    def deterministic(cls, *, domain_size: int = 4, valid_value: int = 0) -> "ToyHardYesFixture":
        if domain_size < 2:
            raise FixedYesInstanceError("toy domain must contain invalid values")
        tokens = tuple(
            sha256(b"ranklock/toy-token-seed/v1\x00" + index.to_bytes(4, "big")).digest()
            for index in range(domain_size)
        )
        commitments = tuple(
            sha256(b"ranklock/toy-token/v1\x00" + token).digest()
            for token in tokens
        )
        return cls(
            ToyAuthenticatedInvalidityStatement(commitments, valid_value),
            tokens,
        )

    @property
    def statement_is_yes(self) -> bool:
        return self.statement.has_witness(self.private_tokens)

    @property
    def first_accepting_witness(self) -> tuple[int, bytes]:
        for value, token in enumerate(self.private_tokens):
            if self.statement.accepts(value, token):
                return value, token
        raise FixedYesInstanceError("toy fixture unexpectedly has no witness")

    def brute_force_short_tokens(self, token_bytes: int = 2) -> bool:
        """Return whether a deliberately tiny guess space finds a valid token.

        The real tokens are 32 bytes, so this deterministic search is expected
        to fail.  Its purpose is only to make ``YES`` versus ``known witness``
        visibly different in the executable model.
        """

        if not 1 <= token_bytes <= 2:
            raise FixedYesInstanceError("toy brute-force width must be one or two bytes")
        for raw in product(range(256), repeat=token_bytes):
            token = bytes(raw)
            for value in range(len(self.statement.token_commitments)):
                if self.statement.accepts(value, token):
                    return True
        return False


@dataclass(frozen=True, slots=True)
class HardYesSecurityRequirement:
    setup_contributors: int = 3
    corrupt_contributors: int = 2
    output_bytes: int = 32
    schema: str = "ranklock-hard-yes-security-requirement-v1"

    def __post_init__(self) -> None:
        if self.setup_contributors < 2:
            raise FixedYesInstanceError("at least two setup contributors are required")
        if not 0 <= self.corrupt_contributors < self.setup_contributors:
            raise FixedYesInstanceError("invalid setup corruption threshold")
        if self.output_bytes <= 0:
            raise FixedYesInstanceError("output width must be positive")

    @property
    def one_honest_contributor(self) -> bool:
        return self.corrupt_contributors == self.setup_contributors - 1

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "setup_contributors": self.setup_contributors,
            "corrupt_contributors": self.corrupt_contributors,
            "one_honest_contributor_model": self.one_honest_contributor,
            "output_bytes": self.output_bytes,
            "challenge_game": [
                "fix one program/deposit/epoch context x whose RankVM-invalidity relation is a YES instance",
                "run distributed setup and give the adversary the public artifact, all corrupted contributor states, abort transcripts, and erasure receipts",
                "withhold every complete authenticated RankVM INVALID witness",
                "challenge the adversary to distinguish F_k(x) from a uniform output or recover the committed Bitcoin fault scalar",
            ],
            "required_guarantees": {
                "hard_YES_pseudorandomness": (
                    "the fixed per-deposit output remains pseudorandom without a complete authenticated witness even though x is in the language"
                ),
                "extractability": (
                    "any algorithm that recovers or non-negligibly predicts the output yields a complete authenticated RankVM INVALID witness"
                ),
                "witness_invariance": (
                    "all accepting witnesses for the same context produce the identical output"
                ),
                "partial_setup_corruption": (
                    "the guarantees survive corruption of every contributor except one, including malicious abort/restart attempts"
                ),
            },
            "standard_WE_gap": (
                "ordinary NO-instance witness-encryption secrecy alone makes no claim for this already-YES statement"
            ),
        }


def fixed_yes_instance_gap() -> dict[str, object]:
    profile = FixedDepositLanguageProfile()
    fixture = ToyHardYesFixture.deterministic()
    witness_value, witness_token = fixture.first_accepting_witness
    requirement = HardYesSecurityRequirement()
    return {
        "schema": "ranklock-fixed-yes-instance-gap-v1",
        "language_profile": profile.document(),
        "executable_toy_separation": {
            "fixed_statement_is_YES": fixture.statement_is_yes,
            "accepting_witness_value": witness_value,
            "accepting_witness_token_bytes": len(witness_token),
            "two_byte_public_guess_space_finds_witness": fixture.brute_force_short_tokens(2),
            "interpretation": (
                "language membership and adversarial witness availability are different facts"
            ),
        },
        "required_security": requirement.document(),
        "decision": (
            "STANDARD_WE_DEFINITION_INSUFFICIENT: target a hard-YES secure, extractable "
            "RankVM witness PRF/predictable token (or an enhanced WE notion proving the same game)."
        ),
        "breakthrough_target_met": False,
    }
