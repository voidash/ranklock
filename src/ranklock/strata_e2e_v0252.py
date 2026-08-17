from __future__ import annotations

"""STRATA-010..020: the ACK/NACK execution phase.

Case wording is taken verbatim from the handoff's ``03_ACCEPTANCE_MATRIX.md``
rather than paraphrased, so this module cannot quietly redefine what a case
means.

Nothing here fabricates a result. Each case declares what it needs; a case
whose prerequisites are absent is reported ``not_executed`` with the specific
thing that is missing, never skipped and never assumed. The build phase
(STRATA-001..009) must have fully passed before any of this is meaningful --
the schema calls that a cross-report dependency and the verifier enforces it.

Why this exists separately from the build matrix: STRATA-001..009 qualify a
tree that compiles and whose tests pass. These eleven qualify *behaviour* --
that a valid RankLock unlock produces an ACK that the existing slash path
still accepts, that its absence produces a CSV-gated NACK and a contested
payout, and that neither can be forced by a malformed, replayed, mutated or
concurrently-raced input. A green build phase says nothing about any of that.
"""

from dataclasses import dataclass
from typing import Final

# Verbatim from 03_ACCEPTANCE_MATRIX.md lines 53-63.
CASE_DEFINITIONS: Final[tuple[tuple[str, str, str], ...]] = (
    ("STRATA-010", "Valid proof", "Immediate ACK is reconstructed and broadcast"),
    ("STRATA-011", "ACK downstream", "Existing slash path remains valid"),
    ("STRATA-012", "Invalid/no proof", "No immediate ACK; timeout NACK after CSV"),
    ("STRATA-013", "NACK downstream", "Existing contested-payout path remains valid"),
    ("STRATA-014", "Malformed unlock", "Hard rejection; no broadcast"),
    ("STRATA-015", "Wrong hash/context", "Hard rejection"),
    (
        "STRATA-016",
        "Alternate transaction/fee mutation",
        "Exact pre-signatures/classification reject it",
    ),
    (
        "STRATA-017",
        "Replay",
        "Cannot authorize another game, deposit, slot or transaction",
    ),
    ("STRATA-018", "Bridge restart", "Duties resume without duplicate terminal action"),
    (
        "STRATA-019",
        "Core reorg",
        "State converges and consumed RankLock slots do not reopen",
    ),
    ("STRATA-020", "Concurrent watchtowers", "Exactly one canonical outcome"),
)


@dataclass(frozen=True)
class Prerequisite:
    """One thing an E2E case needs before it can execute.

    ``probe`` names how absence is detected, so a ``not_executed`` row says
    what was actually checked instead of asserting a bare claim.
    """

    name: str
    probe: str


#: A running bridge is the prerequisite every execution case shares. It is
#: listed once rather than repeated per case so that when it becomes
#: available, exactly one thing changes.
RUNNING_BRIDGE: Final = Prerequisite(
    name="a running strata-bridge node driving the pinned game graph",
    probe="bin/strata-bridge started against the pinned Core regtest and a "
    "reachable FoundationDB cluster",
)

EXPORTER_WIRED: Final = Prerequisite(
    name="the RankLock ACK exporter wired to that bridge's context",
    probe="StrataAckExporter publishing to the path bridge-exec's "
    "graph/ranklock.rs reads via load_ack_preimage",
)

#: Which prerequisites each case needs beyond the shared two. Kept explicit
#: rather than inferred, because "what would have to be true for this to run"
#: is the part a reviewer needs to check.
EXTRA_PREREQUISITES: Final[dict[str, tuple[Prerequisite, ...]]] = {
    "STRATA-018": (
        Prerequisite(
            name="a restartable bridge with durable duty state",
            probe="bridge stopped and restarted on the same datadir mid-duty",
        ),
    ),
    "STRATA-019": (
        Prerequisite(
            name="controlled reorg capability on the pinned Core",
            probe="invalidateblock/reconsiderblock around the release point",
        ),
    ),
    "STRATA-020": (
        Prerequisite(
            name="two or more watchtower instances racing the same slot",
            probe="concurrent counterproof submissions against one game",
        ),
    ),
}


def prerequisites_for(case_id: str) -> tuple[Prerequisite, ...]:
    """Every prerequisite for a case, shared ones first."""

    if case_id not in {case for case, _, _ in CASE_DEFINITIONS}:
        raise KeyError(f"{case_id} is not a STRATA E2E case")
    return (RUNNING_BRIDGE, EXPORTER_WIRED) + EXTRA_PREREQUISITES.get(case_id, ())


def blocked_by_text(case_id: str) -> str:
    """The ``blocked_by`` string for a case that could not execute.

    Names the missing prerequisites rather than saying "not implemented", so
    the evidence records what is actually absent.
    """

    missing = "; ".join(item.name for item in prerequisites_for(case_id))
    return f"requires {missing}"
