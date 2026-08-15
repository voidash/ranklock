from __future__ import annotations

"""Target definition for a hard-YES RankVM witness PRF.

For a deposit/session context fixed before funding, the current RankLock design
would expose one pseudorandom value ``F_k(x)`` to anybody holding a future,
authenticated witness that the selected counterproof is invalid.  The output is
fixed per context and independent of which accepting witness is used, so it can
be committed as a Bitcoin Taproot key before the counterproof exists.

The fixed relation is already a YES instance: some future byte choice is an
invalid counterproof.  Consequently ordinary witness-encryption secrecy for NO
instances is insufficient.  The required primitive is a hard-YES secure,
extractable witness PRF/predictable token whose distributed setup remains safe
when all but one contributor are corrupted.

The alternative validity-first transaction graph is recorded separately.  It
can align Strata with a concrete positive-predicate projective backend such as
BABE/Embryo, potentially avoiding the need to invent this stronger WPRF, but it
is not yet an integrated replacement.
"""

from dataclasses import dataclass

from .fixed_yes_instance_gap import (
    FixedDepositLanguageProfile,
    HardYesSecurityRequirement,
)


class WPRFTargetError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FixedRankVMInstance:
    context_bytes: int = 96
    future_counterproof_bytes: int = 128
    future_public_value_bytes: int = 36
    schema: str = "ranklock-fixed-rankvm-wprf-instance-v2"

    def __post_init__(self) -> None:
        if min(
            self.context_bytes,
            self.future_counterproof_bytes,
            self.future_public_value_bytes,
        ) <= 0:
            raise WPRFTargetError("instance widths must be positive")

    @property
    def future_input_bytes(self) -> int:
        return self.future_counterproof_bytes + self.future_public_value_bytes

    @property
    def future_input_bits(self) -> int:
        return 8 * self.future_input_bytes

    @property
    def naive_truth_table_log2_entries(self) -> int:
        return self.future_input_bits

    def document(self) -> dict[str, object]:
        profile = FixedDepositLanguageProfile(
            future_counterproof_bytes=self.future_counterproof_bytes,
            future_public_value_bytes=self.future_public_value_bytes,
        )
        return {
            "schema": self.schema,
            "fixed_context_bytes": self.context_bytes,
            "future_counterproof_bytes": self.future_counterproof_bytes,
            "future_public_value_bytes": self.future_public_value_bytes,
            "future_input_bytes": self.future_input_bytes,
            "future_input_bits": self.future_input_bits,
            "naive_truth_table_entries": f"2^{self.naive_truth_table_log2_entries}",
            "language_profile": profile.document(),
        }


@dataclass(frozen=True, slots=True)
class RankVMWPRFTarget:
    instance: FixedRankVMInstance = FixedRankVMInstance()
    security: HardYesSecurityRequirement = HardYesSecurityRequirement()
    output_bytes: int = 32
    schema: str = "ranklock-rankvm-wprf-target-v2"

    def __post_init__(self) -> None:
        if self.output_bytes <= 0:
            raise WPRFTargetError("WPRF output must be positive")
        if self.output_bytes != self.security.output_bytes:
            raise WPRFTargetError("WPRF and hard-YES game output widths must match")

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "instance": self.instance.document(),
            "target_interface": {
                "DistributedKeyGen": (
                    "n contributors create a public evaluation artifact and one fixed per-context output commitment; no contributor learns the aggregate output scalar"
                ),
                "Activate": (
                    "publicly verify contribution consistency, context/epoch binding, one-honest-contributor security, erasure, and burn-on-abort"
                ),
                "PublicEval": (
                    "given the fixed context, selected future bytes with authentic projective tokens, and a complete RankVM INVALID witness, recover the identical 32-byte output"
                ),
                "hard_YES_pseudorandomness": (
                    "without a complete authenticated INVALID witness, the output is pseudorandom even though the fixed setup-time statement is already in the language"
                ),
                "extractability": (
                    "predicting or recovering the output implies extraction of the selected future bytes, their authentication evidence, and a complete accepting RankVM-invalidity witness"
                ),
                "witness_invariance": (
                    "all accepting witnesses for the same program/deposit/epoch context yield the same output"
                ),
                "partial_setup_corruption": (
                    "security holds against corruption of n-1 setup contributors, including malicious abort/restart transcripts"
                ),
            },
            "security_game": self.security.document(),
            "why_standard_WE_is_not_enough": (
                "the artifact is generated before future proof bytes are selected, while some invalid future proof always exists; ordinary WE only promises secrecy for NO instances"
            ),
            "why_vector_commitment_WPRF_does_not_directly_finish_it": (
                "Its public language is a local opening of one setup-time vector commitment. Encoding every future 164-byte bridge input as a position requires a 2^1312 truth table, while one local opening does not prove complete RankVM execution."
            ),
            "missing_compiler": (
                "Compress authenticated future-input selection plus complete RankVM invalidity into the language of a standard-assumption hard-YES WPRF with polylogarithmic retained material and near-linear public evaluation."
            ),
            "protocol_level_escape_hatch": {
                "name": "validity-first counterproof graph",
                "idea": (
                    "swap the connector outcomes so a positive valid-proof projective backend authorises immediate ACK and pre-signed N/N authorises timeout NACK"
                ),
                "potential_backend": "BABE + Duty-Free-Bits Embryo",
                "status": "promising but not integrated or security-proved for Strata",
                "eliminates_need_for_new_hard_YES_WPRF": "candidate only",
            },
            "output_bytes": self.output_bytes,
            "breakthrough_target_met": False,
        }


def rankvm_wprf_target() -> dict[str, object]:
    return RankVMWPRFTarget().document()
