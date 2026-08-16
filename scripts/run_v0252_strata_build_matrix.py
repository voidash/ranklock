#!/usr/bin/env python3
from __future__ import annotations

"""Run the STRATA-001..009 build matrix against a clean pinned checkout.

STRATA-001..004 (provenance, patch preflight, patch scope, formatting) need
only git, python and the repo's own rustfmt, so they execute here.
STRATA-005..009 additionally need the full dependency graph -- 1,176 crates
including 16 git-sourced families -- and, for the complete workspace, a
FoundationDB client library.  When those are absent the cases are recorded
``unavailable`` with the exact probe output rather than skipped silently.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

from ranklock.acceptance_matrix_v0252 import STRATA_BUILD_CASE_IDS
from ranklock.evidence_v0252 import CaseResult, MatrixReport, run_recorded_command

ROOT = Path(__file__).resolve().parents[1]
PINNED_COMMIT = "f94c06d08ff29eee746f3e20bd63078d2949b304"
INSTALLER = ROOT / "integration" / "alpen-validity-first-f94c-v025" / "apply_validity_first.py"

# Declared patch scope: 23 edited + 4 added. The three extra edits over the
# original PATCH_SCOPE.md are stale bridge-sm tests retargeted to
# validity-first semantics, without which the crate does not compile.
EXPECTED_CHANGED_FILES = 24
EXPECTED_NEW_FILES = 4


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, timeout=300
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout", type=Path, help="clean strata-bridge checkout at the pinned commit")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "v0252_strata_build_matrix.json")
    parser.add_argument("--log-dir", type=Path, default=ROOT / "results" / "v0252_logs")
    parser.add_argument(
        "--already-applied",
        action="store_true",
        help="the checkout already has the patch applied (skip the apply step)",
    )
    args = parser.parse_args()

    repo = args.checkout.resolve()
    cases: list[CaseResult] = []

    # ---- STRATA-001: base provenance --------------------------------------
    head = run_recorded_command(
        ["git", "rev-parse", "HEAD"], cwd=repo, log_dir=args.log_dir, label="strata-head", timeout=120
    )
    observed = Path(head.stdout_path).read_text().strip()
    porcelain = _git(repo, "status", "--porcelain")
    was_clean = not porcelain.stdout.strip()
    provenance = {
        "expected_commit": PINNED_COMMIT,
        "observed_commit": observed,
        "checkout_path": str(repo),
        "clean_before_patch": was_clean or args.already_applied,
    }
    if observed == PINNED_COMMIT and head.exit_code == 0:
        cases.append(
            CaseResult(
                case_id="STRATA-001",
                status="passed",
                description="checkout is exactly the pinned base commit",
                commands=(head,),
                evidence=provenance,
            )
        )
    else:
        cases.append(
            CaseResult(
                case_id="STRATA-001",
                status="failed",
                description="checkout is exactly the pinned base commit",
                commands=(head,),
                evidence=provenance,
            )
        )

    # ---- STRATA-002: patch preflight --------------------------------------
    if args.already_applied:
        cases.append(
            CaseResult(
                case_id="STRATA-002",
                status="not_executed",
                description="apply_validity_first.py --check passes",
                blocked_by="checkout was supplied already patched; rerun on a pristine tree",
            )
        )
    else:
        preflight = run_recorded_command(
            [sys.executable, str(INSTALLER), str(repo), "--check"],
            cwd=ROOT,
            log_dir=args.log_dir,
            label="strata-preflight",
            timeout=600,
        )
        builder = "passed" if preflight.exit_code == 0 else "failed"
        cases.append(
            CaseResult(
                case_id="STRATA-002",
                status=builder,  # type: ignore[arg-type]
                description="apply_validity_first.py --check passes at the pinned commit",
                commands=(preflight,),
                evidence={"exit_code": preflight.exit_code},
            )
        )
        if preflight.exit_code == 0:
            applied = run_recorded_command(
                [sys.executable, str(INSTALLER), str(repo)],
                cwd=ROOT,
                log_dir=args.log_dir,
                label="strata-apply",
                timeout=900,
            )
            if applied.exit_code != 0:
                cases.append(
                    CaseResult(
                        case_id="STRATA-003",
                        status="failed",
                        description="patch applies within the declared scope",
                        commands=(applied,),
                        evidence={"exit_code": applied.exit_code},
                    )
                )

    # ---- STRATA-003: patch scope ------------------------------------------
    if not any(case.case_id == "STRATA-003" for case in cases):
        scope_cmd = run_recorded_command(
            ["git", "status", "--porcelain"],
            cwd=repo,
            log_dir=args.log_dir,
            label="strata-scope",
            timeout=120,
        )
        status_lines = [
            line for line in Path(scope_cmd.stdout_path).read_text().splitlines() if line.strip()
        ]
        modified = [line for line in status_lines if not line.startswith("??")]
        added = [line for line in status_lines if line.startswith("??")]
        whitespace = _git(repo, "diff", "--check")
        scope_evidence = {
            "modified_files": len(modified),
            "new_files": len(added),
            "expected_modified": EXPECTED_CHANGED_FILES,
            "expected_new": EXPECTED_NEW_FILES,
            "paths": sorted(line[3:] if not line.startswith("??") else line[3:] for line in status_lines),
            "git_diff_check_clean": whitespace.returncode == 0,
        }
        in_scope = (
            len(modified) == EXPECTED_CHANGED_FILES
            and len(added) == EXPECTED_NEW_FILES
            and whitespace.returncode == 0
        )
        cases.append(
            CaseResult(
                case_id="STRATA-003",
                status="passed" if in_scope else "failed",
                description="patch changes exactly the declared 24-file scope",
                commands=(scope_cmd,),
                evidence=scope_evidence,
            )
        )

    # ---- STRATA-004: formatting -------------------------------------------
    if shutil.which("cargo") is None:
        cases.append(
            CaseResult(
                case_id="STRATA-004",
                status="unavailable",
                description="cargo fmt --all -- --check passes",
                blocked_by="cargo is not installed",
            )
        )
    else:
        fmt = run_recorded_command(
            ["cargo", "fmt", "--all", "--", "--check"],
            cwd=repo,
            log_dir=args.log_dir,
            label="strata-fmt",
            timeout=900,
        )
        cases.append(
            CaseResult(
                case_id="STRATA-004",
                status="passed" if fmt.exit_code == 0 else "failed",
                description="cargo fmt --all -- --check passes on the patched tree",
                commands=(fmt,),
                evidence={"exit_code": fmt.exit_code},
            )
        )

    # ---- STRATA-005..009: real cargo runs -----------------------------
    # Each is executed rather than asserted. A crate that fails to build or
    # test is a `failed` row; only a genuinely absent prerequisite (e.g. the
    # FoundationDB client library the full workspace links against) yields
    # `unavailable`.
    build_cases = [
        ("STRATA-005", "cargo check --workspace --all-targets passes",
         ["cargo", "check", "--workspace", "--all-targets", "--locked", "--offline"]),
        ("STRATA-006", "validity-first connector tests pass",
         ["cargo", "test", "--offline", "-p", "strata-bridge-connectors",
          "validity_first_counterproof", "--", "--test-threads=1"]),
        ("STRATA-007", "ACK/NACK game-graph tests pass",
         ["cargo", "test", "--offline", "-p", "strata-bridge-tx-graph",
          "game_graph", "--", "--test-threads=1"]),
        ("STRATA-008", "counterproof state-machine transition tests pass",
         ["cargo", "test", "--offline", "-p", "strata-bridge-sm",
          "counterproof", "--", "--test-threads=1"]),
        ("STRATA-009", "the complete intended workspace test suite passes",
         ["cargo", "test", "--workspace", "--locked", "--offline"]),
    ]
    for case_id, description, argv in build_cases:
        record = run_recorded_command(
            argv, cwd=repo, log_dir=args.log_dir,
            label=f"strata-{case_id.lower()}", timeout=3600,
        )
        combined = (
            Path(record.stdout_path).read_text(errors="replace")
            + Path(record.stderr_path).read_text(errors="replace")
        )
        evidence = {"exit_code": record.exit_code, "argv": list(argv)}
        if record.exit_code == 0:
            status, blocked = "passed", None
        elif "foundationdb" in combined and "No such file or directory" in combined:
            # A missing system library is an absent prerequisite, not a defect
            # in the patch.
            status = "unavailable"
            blocked = (
                "the FoundationDB client library is not installed; "
                "foundationdb-gen reads /usr/local/include/foundationdb/fdb.options"
            )
            evidence["reason"] = blocked
        else:
            status, blocked = "failed", None
        cases.append(
            CaseResult(
                case_id=case_id, status=status, description=description,
                commands=(record,), evidence=evidence, blocked_by=blocked,
            )
        )

    toolchain = (repo / "rust-toolchain.toml").read_text() if (repo / "rust-toolchain.toml").is_file() else ""
    report = MatrixReport(
        schema_name="ranklock-v0252-strata-build-matrix-v1",
        required_case_ids=STRATA_BUILD_CASE_IDS,
        identity={
            "strata_commit": PINNED_COMMIT,
            "checkout_path": str(repo),
            "rust_toolchain": toolchain.strip(),
        },
        cases=tuple(cases),
    )
    report.write(args.output)

    counts = report.status_counts
    print(f"wrote {args.output}")
    for status in ("passed", "failed", "not_executed", "unavailable", "modeled_only"):
        print(f"  {status:<13} {counts.get(status, 0)}")
    return 1 if report.any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
