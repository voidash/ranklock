"""Execute the v0.26 graph against real Bitcoin Core and emit one evidence file.

Goal this serves: run the complete v0.26 transaction graph against a real
Bitcoin Core regtest node -- deposit through counterproof, ACK with the full
2..=64 preimage vector, timeout, and slash -- and record every acceptance and
rejection in a single reproducible artifact.

Before this script the coverage existed but was scattered across Rust test
suites in two crates, so "did the graph work end to end" could only be answered
by reading several test names. This runs them all and writes one JSON.

Every test named below drives a real `bitcoind` regtest node. None of them is a
model, a mock, or a fixture replay. If `bitcoind` is absent they fail, and this
script reports the failure rather than degrading to a simulated pass.

Scope. Protocol 13.1 stage 1 is regtest: "deterministic fixtures permitted;
zero economic value." Passing everything here says the graph and connectors
behave correctly against Core. It says nothing about the security floor, the
release profile, the ceremony, the proof suite, or funds, and it must never be
cited as evidence of funds safety.

Run:

    python3 scripts/generate_v026_regtest_e2e_results.py
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
STRATA = Path("/Users/cdjk/github/llm/ranklock/tmp/strata-v026-f94c")

# Each entry: (stage, crate, exact test filter, what the graph step proves).
# The stage names follow the goal sentence so the artifact reads as a path
# through the graph rather than as an alphabetical test list.
SUITES: tuple[tuple[str, str, str, str], ...] = (
    (
        "funding-and-counterproof",
        "strata-bridge-tx-graph",
        "v026_graph::tests::core_each_counterproof_sibling_is_independently_valid",
        "each counterproof alternative is independently valid against Core",
    ),
    (
        "funding-and-counterproof",
        "strata-bridge-tx-graph",
        "v026_graph::tests::core_selected_counterproof_invalidates_sibling_and_owner_paths",
        "selecting one counterproof invalidates its siblings and the owner path",
    ),
    (
        "relay-policy",
        "strata-bridge-tx-graph",
        "v026_graph::tests::core_requires_confirmed_contest_for_atomic_research_counterproof_relay",
        "an oversized v3 child is rejected under an unconfirmed Contest and accepted after it confirms",
    ),
    (
        "owner-payout",
        "strata-bridge-tx-graph",
        "v026_graph::tests::core_mature_owner_payout_is_valid_and_blocks_every_counterproof",
        "the mature owner payout is valid and blocks every counterproof",
    ),
    (
        "ack-and-timeout",
        "strata-bridge-tx-graph",
        "v026_graph::tests::core_ack_and_timeout_share_resolution_with_exact_csv_boundary",
        "ACK and timeout contend for one resolution outpoint at the exact CSV boundary",
    ),
    (
        "slash",
        "strata-bridge-tx-graph",
        "v026_graph::tests::core_slash_requires_ack_created_authorization_and_k_is_not_exclusive",
        "slash requires the ACK-created authorization; stake is demonstrably not exclusive",
    ),
    (
        "ack-vector",
        "strata-bridge-connectors",
        "counterproof_resolution_v2::tests::immediate_vector_ack_spend_is_accepted_by_core",
        "Core accepts a complete ordered preimage-vector ACK",
    ),
    (
        "ack-vector",
        "strata-bridge-connectors",
        "counterproof_resolution_v2::tests::maximum_vector_ack_spend_weight_is_recorded_against_core",
        "Core accepts the declared maximum vector against a confirmed parent",
    ),
    (
        "ack-vector",
        "strata-bridge-connectors",
        "counterproof_resolution_v2::tests::vector_ack_truc_child_crossover_is_measured_against_core",
        "the exact vector length at which an ACK stops relaying under an unconfirmed v3 parent",
    ),
    (
        "ack-vector-negatives",
        "strata-bridge-connectors",
        "counterproof_resolution_v2::tests::malformed_reordered_missing_and_key_path_witnesses_fail_in_core",
        "Core rejects missing, reordered, malformed and key-path-bypass ACK witnesses",
    ),
    (
        "timeout",
        "strata-bridge-connectors",
        "counterproof_resolution_v2::tests::timeout_spend_is_accepted_by_core",
        "Core accepts the timeout spend of the resolution outpoint",
    ),
    (
        "slash",
        "strata-bridge-connectors",
        "slash_authorization_v2::tests::slash_path_is_accepted_by_core",
        "Core accepts the slash path from its authorization outpoint",
    ),
    (
        "threshold-v3-release",
        "strata-bridge-connectors",
        "counterproof_resolution_threshold_v3::tests::both_declared_paths_are_accepted_by_core",
        "both declared threshold-v3 release paths are accepted by Core",
    ),
    (
        "threshold-v3-release",
        "strata-bridge-connectors",
        "counterproof_resolution_threshold_v3::tests::core_enforces_each_two_of_three_quorum_and_rejects_bad_raw_shapes",
        "Core enforces each 2-of-3 release quorum and rejects malformed share shapes",
    ),
    (
        "threshold-v3-release",
        "strata-bridge-connectors",
        "counterproof_resolution_threshold_v3::tests::core_rejects_a_control_block_for_a_different_selected_commitment",
        "Core rejects a control block bound to a different selected commitment",
    ),
    (
        "threshold-v3-release",
        "strata-bridge-connectors",
        "counterproof_resolution_threshold_v3::tests::timeout_obeys_exact_csv_boundary_in_core",
        "the threshold-v3 timeout obeys its exact CSV boundary in Core",
    ),
    (
        "contest-gates",
        "strata-bridge-connectors",
        "contest_payout_gate_v2::tests::both_declared_leaves_are_accepted_by_core",
        "both declared contest-payout-gate leaves are accepted by Core",
    ),
    (
        "contest-gates",
        "strata-bridge-connectors",
        "contest_slash_gate_v2::tests::both_declared_leaves_are_accepted_by_core",
        "both declared contest-slash-gate leaves are accepted by Core",
    ),
    (
        "contest-counterproof",
        "strata-bridge-connectors",
        "contest_counterproof_v2::tests::consensus_maximum_complete_v2_witness_is_accepted_by_core",
        "Core accepts the consensus-maximum complete v2 contest-counterproof witness",
    ),
    (
        "contest-counterproof",
        "strata-bridge-connectors",
        "contest_counterproof_v2::tests::reserve_recovery_path_is_independently_accepted_by_core",
        "the reserve recovery path is independently accepted by Core",
    ),
)

# Lines the tests print that carry a measured number worth preserving verbatim.
MEASUREMENT = re.compile(r"^\s*(n=\s*\d+.*|maximum vector ACK:.*|TRUC crossover:.*)$")


def _bitcoind() -> dict[str, object]:
    """Records the Core binary actually on PATH, or reports its absence."""
    found = subprocess.run(
        ["which", "bitcoind"], capture_output=True, text=True, check=False
    )
    if found.returncode != 0:
        return {"present": False, "path": None, "version": None}
    path = found.stdout.strip()
    version = subprocess.run(
        [path, "--version"], capture_output=True, text=True, check=False
    )
    first = version.stdout.splitlines()[0].strip() if version.stdout else None
    return {"present": True, "path": path, "version": first}


def _run(crate: str, test_filter: str) -> tuple[bool, list[str], str]:
    """Runs one exact test and returns (passed, measurements, summary)."""
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            crate,
            test_filter,
            "--",
            "--exact",
            "--nocapture",
        ],
        cwd=STRATA,
        capture_output=True,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    measurements = [
        line.strip()
        for line in output.splitlines()
        if MEASUREMENT.match(line) and "weight_wu" in line or "crossover" in line
    ]
    summary = ""
    for line in output.splitlines():
        if line.startswith("test result:"):
            summary = line.strip()
            break
    return completed.returncode == 0, measurements, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "v026_regtest_e2e.json",
    )
    args = parser.parse_args()

    if not STRATA.is_dir():
        print(f"Rust checkout absent at {STRATA}", file=sys.stderr)
        return 1

    core = _bitcoind()
    if not core["present"]:
        print("bitcoind is not on PATH; these tests drive a real node", file=sys.stderr)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=STRATA,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()

    executions = []
    for stage, crate, test_filter, proves in SUITES:
        passed, measurements, summary = _run(crate, test_filter)
        executions.append(
            {
                "stage": stage,
                "crate": crate,
                "test": test_filter,
                "proves": proves,
                "passed": passed,
                "summary": summary,
                "measurements": measurements,
            }
        )
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {stage:24s} {test_filter.split('::')[-1]}")
        for measurement in measurements:
            print(f"         {measurement}")

    all_passed = all(entry["passed"] for entry in executions)
    stages = sorted({entry["stage"] for entry in executions})

    document = {
        "schema": "ranklock-v026-regtest-e2e-v1",
        "stage": "1-regtest",
        "strata_commit": commit,
        "bitcoin_core": core,
        "graph_stages_covered": stages,
        "executions": executions,
        "executions_total": len(executions),
        "executions_passed": sum(1 for entry in executions if entry["passed"]),
        "all_passed": all_passed,
        "funding_eligible": False,
        "safe_for_funds": False,
        "known_gap": (
            "The v0.26 threshold-v3 graph assembler "
            "(crates/tx-graph/src/v026_threshold_graph_v3.rs) has no Core test of "
            "its own; its release connector does. Assembler-level Core coverage "
            "for the live 17-blocker path is still absent."
        ),
        "scope_note": (
            "v0.26 stage-1 regtest execution evidence. Protocol 13.1 permits "
            "deterministic fixtures at this stage and assigns it zero economic "
            "value. Every execution listed drives a real bitcoind regtest node. "
            "This establishes nothing about the security floor, release profile, "
            "ceremony, proof suite, or funds, and must never be cited as "
            "evidence of funds safety."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

    print(f"\nwrote {args.output}")
    print(
        f"{document['executions_passed']}/{document['executions_total']} executions passed "
        f"across {len(stages)} graph stages"
    )
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
