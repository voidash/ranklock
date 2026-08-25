"""Machine-checkable gate for v0.26 stage-1 (regtest) readiness.

`58_V026_FUNDS_SAFETY_PROTOCOL.md` §13.1 defines five deployment stages. Stage 1
is regtest: "deterministic fixtures permitted; zero economic value." That is a
materially lower bar than stage 2 (signet), which requires "production binaries,
topology, policy, and ceremony path" — and far below stage 4, bounded
activation.

This gate exists because "is it safe for funds" is not a question a single
session can answer, while "does the v0.26 graph behave correctly against a real
Bitcoin Core in regtest" is. It converts the next milestone into a command.

**Scope.** Regtest coins are valueless. Passing every check here means the graph
and connector behave correctly against real Core under deterministic fixtures.
It says nothing about the security floor, the release profile, the ceremony, the
proof suite, or funds. It is not, and must never be cited as, evidence of funds
safety or of signet readiness.

Deliberately excluded, because §13.1 permits fixtures at this stage:
the audited BN462 backend, the security-floor report, the S-DFB/C-DIRECT
ratification, external audits, the safety-registry BFT deployment, and every
governance decision. Those gate later stages.

Run:

    python3 scripts/check_v026_regtest_readiness.py
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
STRATA = Path("/Users/cdjk/github/llm/ranklock/tmp/strata-v026-f94c")


class Check:
    """One regtest-stage gate with an exact pass condition."""

    def __init__(self, ident: str, description: str, blocks: str) -> None:
        self.ident = ident
        self.description = description
        self.blocks = blocks
        self.passed = False
        self.detail = ""

    def record(self, passed: bool, detail: str) -> "Check":
        self.passed = passed
        self.detail = detail
        return self

    def document(self) -> dict[str, object]:
        return {
            "id": self.ident,
            "description": self.description,
            "blocks": self.blocks,
            "passed": self.passed,
            "detail": self.detail,
        }


def _core_evidence() -> dict:
    """Loads the existing generated Core evidence, or raises."""
    path = ROOT / "results" / "v026_rust_graph_core.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing Core evidence: {path}")
    return json.loads(path.read_text())


def _branch_acceptance() -> Check:
    """RT-001: every intended terminal branch is accepted by real Core."""
    check = Check(
        "RT-001",
        "real Bitcoin Core accepts every intended v0.26 terminal branch",
        "§12 Bitcoin connector",
    )
    try:
        branches = _core_evidence()["bitcoin_core"]["branch_acceptance"]
    except (KeyError, FileNotFoundError) as error:
        return check.record(False, f"evidence unavailable: {error}")
    failing = sorted(name for name, ok in branches.items() if not ok)
    return check.record(
        not failing and len(branches) >= 6,
        f"{len(branches) - len(failing)}/{len(branches)} branches accepted"
        + (f"; failing: {', '.join(failing)}" if failing else ""),
    )


def _conflict_topology() -> Check:
    """RT-002: intended shared-input conflicts reproduce under Core.

    `stake_exclusivity_proved` is excluded on purpose. It is false because a
    counterexample was *executed* — a demonstrated protocol hole, not missing
    regtest coverage. RT-003 tracks it separately so it cannot be silently
    absorbed into a coverage percentage.
    """
    check = Check(
        "RT-002",
        "intended shared-input conflicts and ancestry reproduce under Core",
        "§12 Bitcoin connector",
    )
    try:
        checks = dict(_core_evidence()["bitcoin_core"]["conflict_and_ancestry_checks"])
    except (KeyError, FileNotFoundError) as error:
        return check.record(False, f"evidence unavailable: {error}")
    checks.pop("stake_exclusivity_proved", None)
    failing = sorted(name for name, ok in checks.items() if not ok)
    return check.record(
        not failing,
        f"{len(checks) - len(failing)}/{len(checks)} conflict checks hold"
        + (f"; failing: {', '.join(failing)}" if failing else ""),
    )


def _stake_exclusivity_is_a_known_hole() -> Check:
    """RT-003: stake non-exclusivity is demonstrated, not merely untested.

    This check PASSES when the counterexample has been executed. That is not an
    endorsement: it records that the hole is proved and tracked rather than
    unknown. Closing the hole is protocol work, not regtest work.
    """
    check = Check(
        "RT-003",
        "stake non-exclusivity is a demonstrated counterexample, not an untested gap",
        "protocol defect tracked; not a stage-1 blocker",
    )
    try:
        core = _core_evidence()["bitcoin_core"]
    except (KeyError, FileNotFoundError) as error:
        return check.record(False, f"evidence unavailable: {error}")
    executed = bool(core.get("stake_non_exclusivity_counterexample_executed"))
    proved = bool(core.get("conflict_and_ancestry_checks", {}).get("stake_exclusivity_proved"))
    return check.record(
        executed and not proved,
        "counterexample executed and exclusivity correctly reported false"
        if executed and not proved
        else f"counterexample_executed={executed}, exclusivity_proved={proved}",
    )


def _relay_policy() -> Check:
    """RT-004: v3 relay policy behaves as the design requires."""
    check = Check(
        "RT-004",
        "confirmed-parent requirement and v3 child weight limit hold under Core",
        "§12 Bitcoin connector",
    )
    try:
        relay = _core_evidence()["bitcoin_core"]["relay_policy"]
    except (KeyError, FileNotFoundError) as error:
        return check.record(False, f"evidence unavailable: {error}")
    accepts = bool(relay.get("confirmed_contest_parent_accepts_same_signed_counterproof"))
    rejects = bool(relay.get("unconfirmed_v3_contest_parent_rejects_same_signed_counterproof"))
    limit = relay.get("unconfirmed_v3_child_weight_limit_wu")
    return check.record(
        accepts and rejects and isinstance(limit, int) and limit > 0,
        f"confirmed-parent accept={accepts}, unconfirmed reject={rejects}, "
        f"child weight limit={limit} WU",
    )


def _focused_tests_green() -> Check:
    """RT-005: the focused Core suite has no failures."""
    check = Check(
        "RT-005",
        "focused Bitcoin Core test suite reports zero failures",
        "§12 E2E",
    )
    try:
        core = _core_evidence()["bitcoin_core"]
    except (KeyError, FileNotFoundError) as error:
        return check.record(False, f"evidence unavailable: {error}")
    passed = core.get("focused_tests_passed", 0)
    failed = core.get("focused_tests_failed", None)
    return check.record(
        failed == 0 and isinstance(passed, int) and passed > 0,
        f"{passed} passed, {failed} failed",
    )


def _rust_vector_hash_connector_exists() -> Check:
    """RT-006: the vector-hash connector exists in Rust, not only Python.

    §1.4 item 3 requires v0.26 to carry 2..64 raw SHA-256 commitments and check
    every preimage on chain. §12's Bitcoin-connector gate requires real Core to
    accept a *complete vector* ACK. Python enforces 2..64
    (`split_scalar_lock.py:946`), but until the Rust connector exists the
    enforced path cannot produce that ACK, and §4.2's shared golden vectors
    cannot exist either.
    """
    check = Check(
        "RT-006",
        "Rust vector-hash connector accepting 2..64 preimages exists",
        "§12 Bitcoin connector; §15 step 3",
    )
    if not STRATA.is_dir():
        return check.record(False, f"Rust checkout not present at {STRATA}")
    connectors = STRATA / "crates" / "connectors" / "src"
    if not connectors.is_dir():
        return check.record(False, f"connector sources not found under {connectors}")
    # Must be enforcement, not prose. An earlier version of this check matched
    # a `//!` doc comment describing the requirement and reported PASS on a
    # file it had not actually verified; comments are stripped first.
    lower = re.compile(r"MIN_\w*PREIMAGES\s*:\s*usize\s*=\s*2\b")
    upper = re.compile(r"MAX_\w*PREIMAGES\s*:\s*usize\s*=\s*64\b")
    guard = re.compile(r"\(\s*MIN_\w*PREIMAGES\s*\.\.=\s*MAX_\w*PREIMAGES\s*\)")
    hits = []
    for path in sorted(connectors.rglob("*.rs")):
        code = "\n".join(
            line
            for line in path.read_text(errors="ignore").splitlines()
            if not line.lstrip().startswith("//")
        )
        if lower.search(code) and upper.search(code) and guard.search(code):
            hits.append(path.relative_to(STRATA).as_posix())
    return check.record(
        bool(hits),
        f"bounds and range guard enforced in: {', '.join(hits)}"
        if hits
        else "no Rust connector enforces a 2..64 preimage vector in code; "
        "only the Python model does",
    )


def _nums_profile_is_canonical() -> Check:
    """RT-007: NUMS derivation is canonical, not a research profile.

    §12's Bitcoin-connector gate requires a *fixed* NUMS derivation for every
    script-only output, and kill criterion 36 makes an arbitrary internal key
    fatal. The current module declares itself research-only and its roles
    `funding_eligible() == false`; §16 decision 4 must ratify the role registry
    and `output_index` semantics first (see doc 60 §4.6).
    """
    check = Check(
        "RT-007",
        "NUMS role/index derivation is canonical rather than research-only",
        "§12 Bitcoin connector; §16 decision 4",
    )
    source = STRATA / "crates" / "connectors" / "src" / "ranklock_nums.rs"
    if not source.is_file():
        return check.record(False, f"NUMS source not found at {source}")
    text = source.read_text(errors="ignore")
    research = "ResearchV0NumsRole" in text or "research wire profile" in text
    return check.record(
        not research,
        "still the research profile: roles are funding-ineligible and "
        "output_index semantics are undefined (doc 60 §4.6)"
        if research
        else "no research-profile markers found",
    )


def _funding_gate_still_closed() -> Check:
    """RT-008: nothing in this gate may flip a funding flag.

    Stage 1 is regtest. If any evidence artifact this gate reads has become
    funding-eligible, something has gone badly wrong and the gate must fail
    loudly rather than report readiness.
    """
    check = Check(
        "RT-008",
        "no evidence artifact claims funding eligibility or funds safety",
        "invariant",
    )
    offenders: list[str] = []
    for path in sorted((ROOT / "results").glob("v026*.json")):
        try:
            blob = path.read_text()
        except OSError as error:
            return check.record(False, f"unreadable evidence {path.name}: {error}")
        if '"funding_eligible": true' in blob or '"safe_for_funds": true' in blob:
            offenders.append(path.name)
    status = ROOT / "STATUS.json"
    if status.is_file() and '"safe_for_funds": true' in status.read_text():
        offenders.append("STATUS.json")
    return check.record(
        not offenders,
        "all v0.26 evidence reports funding_eligible/safe_for_funds false"
        if not offenders
        else f"UNEXPECTED funding claim in: {', '.join(offenders)}",
    )


CHECKS = (
    _branch_acceptance,
    _conflict_topology,
    _stake_exclusivity_is_a_known_hole,
    _relay_policy,
    _focused_tests_green,
    _rust_vector_hash_connector_exists,
    _nums_profile_is_canonical,
    _funding_gate_still_closed,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "v026_regtest_readiness.json",
    )
    args = parser.parse_args()

    results = []
    for check in CHECKS:
        try:
            results.append(check())
        except Exception as error:  # noqa: BLE001 - a gate must never fail open
            failed = Check(getattr(check, "__name__", "unknown"), "check raised", "unknown")
            results.append(failed.record(False, f"{type(error).__name__}: {error}"))

    ready = all(result.passed for result in results)
    remaining = [result.ident for result in results if not result.passed]

    document = {
        "schema": "ranklock-v026-regtest-readiness-v1",
        "stage": "1-regtest",
        "regtest_ready": ready,
        "remaining_checks": remaining,
        "checks": [result.document() for result in results],
        "funding_eligible": False,
        "safe_for_funds": False,
        "scope_note": (
            "v0.26 stage-1 (regtest) readiness only. Protocol §13.1 permits "
            "deterministic fixtures at this stage and assigns zero economic "
            "value to it. Passing every check means the graph and connector "
            "behave correctly against real Bitcoin Core under fixtures. It "
            "establishes nothing about the security floor, release profile, "
            "ceremony, proof suite, or funds, and it is not signet readiness — "
            "stage 2 additionally requires production binaries, topology, "
            "policy, and the ceremony path. It must never be cited as evidence "
            "of funds safety."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

    print(f"wrote {args.output}\n")
    for result in results:
        mark = "PASS" if result.passed else "FAIL"
        print(f"  [{mark}] {result.ident}  {result.description}")
        print(f"         {result.detail}")
        if not result.passed:
            print(f"         blocks: {result.blocks}")
    print(
        f"\nstage-1 regtest ready: {ready}"
        + ("" if ready else f"  ({len(remaining)} remaining: {', '.join(remaining)})")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
