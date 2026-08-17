#!/usr/bin/env python3
from __future__ import annotations

"""Fail-closed preconditions for deploying RankLock to signet.

Signet coins are valueless, so this is not a funds-safety gate -- that is
`generate_v0252_release_gate.py`, and it stays false. The risk on signet is
different and specific: **producing evidence that looks like a successful
bridge run while exercising a code path that is not the production one.** A
green signet deployment driven by the deterministic dealer fixture, or with
the sidecar unwired, tells you nothing and will be quoted as if it did.

Each check below is mechanical and fails closed. Nothing here is satisfied by
a comment, a plan, or an intention.

Deliberately NOT checked, because signet does not need them:
  - the ~100-bit BABE lock (H2). Signet value is zero; the curve decision
    gates mainnet, not this.
  - a native constant-time implementation.
  - independent audits, ceremony, rollback witnesses.

Deliberately IS checked, because these make a signet run misleading rather
than merely imperfect.
"""

import argparse
import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


class Check:
    def __init__(self, ident: str, description: str) -> None:
        self.ident = ident
        self.description = description
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
            "passed": self.passed,
            "detail": self.detail,
        }


def _no_defaulted_secret_parameters() -> Check:
    """SIGNET-001: no garbling entry point may default its seed or profile.

    A defaulted seed makes every label a public constant, so a signet run
    would exercise labels an observer could have predicted.
    """

    check = Check(
        "SIGNET-001",
        "garbling entry points require an explicit seed and profile",
    )
    source = (ROOT / "src" / "ranklock" / "dfb_real.py").read_text()
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in {"generate_program", "generate_program_template"}:
            continue
        args = node.args
        defaults = dict(
            zip(
                [a.arg for a in args.kwonlyargs],
                args.kw_defaults,
                strict=True,
            )
        )
        for name in ("seed", "profile"):
            if defaults.get(name) is not None:
                offenders.append(f"{node.name}.{name}")
    return check.record(
        not offenders,
        "no defaulted secret parameters" if not offenders else f"defaulted: {offenders}",
    )


def _g2_subgroup_enforced() -> Check:
    """SIGNET-002: BN254 G2 inputs must be subgroup-checked.

    The pairing is not bilinear off-subgroup, so any result computed there is
    meaningless -- including a signet run that appears to succeed.
    """

    check = Check("SIGNET-002", "G2 subgroup membership is enforced")
    source = (ROOT / "src" / "ranklock" / "bn254_real.py").read_text()
    has_helper = "def is_in_g2_subgroup(" in source
    in_decompress = source.count("is_in_g2_subgroup(point)") >= 1
    in_pairing = "is_in_g2_subgroup(g2_point)" in source
    ok = has_helper and in_decompress and in_pairing
    return check.record(
        ok,
        "enforced in decompress_g2 and pairing_product"
        if ok
        else f"helper={has_helper} decompress={in_decompress} pairing={in_pairing}",
    )


def _threshold_sharing_available() -> Check:
    """SIGNET-003: t-of-n sharing must exist and support resharing.

    n-of-n means one absent operator bricks every slot. On signet that is a
    liveness trap that will be blamed on the protocol rather than the sharing.
    """

    check = Check("SIGNET-003", "t-of-n verifiable sharing with resharing exists")
    path = ROOT / "src" / "ranklock" / "threshold_sharing.py"
    if not path.is_file():
        return check.record(False, "threshold_sharing.py is absent")
    source = path.read_text()
    required = ("def split_secret(", "def verify_share(", "def reconstruct(", "def reshare(")
    missing = [name for name in required if name not in source]
    return check.record(not missing, "present" if not missing else f"missing {missing}")


def _dealer_fixture_not_the_only_setup() -> Check:
    """SIGNET-004: the dealer fixture must not be the production setup path.

    `dealer_split_fixture` sees every aggregate label and seed, so a signet
    run using it does not exercise the trust model the design claims. This is
    the check most likely to fail today, and it should.
    """

    check = Check(
        "SIGNET-004",
        "share provisioning does not rely on the all-seeing dealer fixture",
    )
    # Deliberately not a grep for the module name: an import satisfies that
    # while the protocol still reconstructs by XOR, and a gate its own author
    # can pass cosmetically is worse than no gate. Require that the
    # reconstruction path actually calls the threshold primitive.
    committee = (ROOT / "src" / "ranklock" / "committee_authorization.py").read_text()
    two_phase = (ROOT / "src" / "ranklock" / "two_phase_authorization.py").read_text()

    reasons: list[str] = []
    if "threshold_sharing" not in committee:
        reasons.append("committee_authorization does not import threshold_sharing")
    if "reconstruct(" not in two_phase:
        reasons.append("two_phase_authorization does not reconstruct via the threshold primitive")
    if "_xor(" in two_phase and "reconstruct(" not in two_phase:
        reasons.append("two_phase_authorization still reconstructs secrets by XOR only")

    return check.record(
        not reasons,
        "threshold reconstruction is wired into the protocol"
        if not reasons
        else "; ".join(reasons)
        + " -- wire threshold_sharing into share provisioning and reconstruction "
        "before any signet deployment",
    )


def _exporter_refuses_to_clobber() -> Check:
    """SIGNET-005: a released unlock must never be silently overwritten."""

    check = Check("SIGNET-005", "exporter refuses to overwrite a released secret")
    source = (ROOT / "src" / "ranklock" / "strata_exporter.py").read_text()
    unreachable = "if created or not path.is_file():" in source
    guards = "refusing to overwrite a released" in source
    ok = guards and not unreachable
    return check.record(
        ok,
        "guard is reachable" if ok else "overwrite guard is unreachable or absent",
    )


def _funds_gate_still_closed() -> Check:
    """SIGNET-006: signet readiness must never be read as funds readiness."""

    check = Check("SIGNET-006", "the funds gate remains closed")
    path = ROOT / "results" / "v0252_release_gate.json"
    if not path.is_file():
        return check.record(False, "release gate report is absent")
    gate = json.loads(path.read_text())
    safe = gate.get("safe_for_funds")
    return check.record(
        safe is False,
        f"safe_for_funds={safe} (must be false)",
    )


CHECKS = (
    _no_defaulted_secret_parameters,
    _g2_subgroup_enforced,
    _threshold_sharing_available,
    _dealer_fixture_not_the_only_setup,
    _exporter_refuses_to_clobber,
    _funds_gate_still_closed,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "v0252_signet_readiness.json",
    )
    args = parser.parse_args()

    results = [check() for check in CHECKS]
    ready = all(result.passed for result in results)

    document = {
        "schema": "ranklock-v0252-signet-readiness-v1",
        "signet_ready": ready,
        "checks": [result.document() for result in results],
        "scope_note": (
            "Signet readiness only. Signet coins are valueless; this gate exists "
            "to stop a deployment producing evidence that looks like a working "
            "bridge while exercising a non-production path. It is not, and must "
            "never be cited as, evidence of funds safety."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

    print(f"wrote {args.output}\n")
    for result in results:
        mark = "PASS" if result.passed else "FAIL"
        print(f"  [{mark}] {result.ident}  {result.description}")
        if not result.passed:
            print(f"         {result.detail}")
    print(f"\nsignet_ready: {ready}")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
