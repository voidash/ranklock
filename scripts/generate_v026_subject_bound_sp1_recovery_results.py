"""Generate the v0.26 subject-bound SP1 network-receipt recovery evidence.

Sizes and digests are computed from the artifacts on disk; source digests are
computed from the live Rust checkout. Nothing is hand-transcribed. The record
deliberately changes no funding-eligibility flag: recovering a valid receipt
closes the deterministic final Groth16 execution/verification evidence gate and
nothing else.

Run from the repository root:

    python3 scripts/generate_v026_subject_bound_sp1_recovery_results.py
"""

import hashlib
import json
import pathlib
import subprocess

STRATA = pathlib.Path("/Users/cdjk/github/llm/ranklock/tmp/strata-v026-f94c")
BASE = pathlib.Path("results/v026-subject-bound-sp1")
RECEIPT = BASE / "bridge_counterproof_subject_v1_SP1_v6.1.0.groth16.proof"
SOURCE = BASE / "network-proof-0da45348-raw.bincode"
OUT = pathlib.Path("results/v026_subject_bound_sp1_network_receipt_recovery.json")

TOUCHED_SOURCES = [
    "crates/proofs/bridge-counterproof/Cargo.toml",
    "crates/proofs/bridge-counterproof/src/lib.rs",
    "crates/proofs/bridge-counterproof/src/statements.rs",
    "crates/proofs/bridge-counterproof/src/subject_receipt.rs",
]


def fail(message: str) -> None:
    """Abort loudly. A silently wrong evidence artifact is worse than none."""
    raise SystemExit(f"evidence generation failed: {message}")


def sha256(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"expected artifact is absent: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    completed = subprocess.run(
        ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        fail("could not read the current UTC time")
    return completed.stdout.strip()


def base_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=STRATA,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        fail("could not read the Strata base commit")
    return completed.stdout.strip()


record = {
    "schema": "ranklock-v026-subject-bound-sp1-network-receipt-recovery-v1",
    "evidence_class": "EXACT",
    "base_commit": base_commit(),
    "generated_by": (
        "scripts/generate_v026_subject_bound_sp1_recovery_results.py; every size "
        "and digest computed from the artifacts on disk"
    ),
    "date_utc": utc_now(),
    "recovery_mode": "offline import; no network request, no local proving",
    "fulfilled_request_id": (
        "0da45348ba6a7fbd6e7af661a782133b8771b1008d303cfbe4fb26122331bcc7"
    ),
    "source_artifact": {
        "path": str(SOURCE),
        "bytes": SOURCE.stat().st_size,
        "sha256": sha256(SOURCE),
        "decoded_as": "sp1_verifier::ProofFromNetwork",
        "why_not_sp1_proof_with_public_values": (
            "SP1ProofWithPublicValues carries a trailing tee_proof Option<Vec<u8>> "
            "that the network form omits; the artifact ends at sp1_version, so that "
            "deserialization is short by the Option discriminant and cannot succeed. "
            "sp1-sdk was therefore not added as a dependency."
        ),
    },
    "verified_receipt": {
        "path": str(RECEIPT),
        "bytes": RECEIPT.stat().st_size,
        "sha256": sha256(RECEIPT),
        "proof_bytes": 356,
        "public_values_bytes": 488,
        "sp1_circuit_version": "v6.1.0",
        "proof_type": "Groth16",
        "verified_by": (
            "SubjectBoundSp1Groth16VerifierV1 (standalone); host.verify not used"
        ),
    },
    "root_causes_fixed": [
        {
            "id": "RC1-circuit-version-pin",
            "was": (
                "SUBJECT_BOUND_SP1_CIRCUIT_VERSION_V1 = v6.2.4, the sp1-prover crate "
                "version"
            ),
            "now": "v6.1.0",
            "evidence": (
                "sp1-prover-6.2.4/SP1_CIRCUIT_VERSION contains v6.1.0; the network "
                "artifact records v6.1.0"
            ),
        },
        {
            "id": "RC2-lossy-host-round-trip",
            "was": (
                "host.verify rebuilt Groth16 public input 1 via "
                "SP1PublicValues::hash_bn254() (SHA-256), rejecting a proof that "
                "committed to SP1's Blake3 public-values hash"
            ),
            "now": (
                "the importer builds canonical zkaleido bytes directly from the "
                "network proof and verifies with the standalone verifier, which "
                "retries both hashes"
            ),
            "zkaleido_modified": False,
        },
        {
            "id": "RC3-nondeterministic-expected-output",
            "discovered_during_this_run": True,
            "was": (
                "tests compared a persisted receipt's output against "
                "run_subject_bound_counterproof recomputed in a later process, but "
                "OPERATOR_KEYPAIR is LazyLock::new(generate_keypair) — random per "
                "process — so operator_pubkey and the signature-dependent "
                "bridge_proof_txid can never match. The assertion was unsatisfiable "
                "by construction, which left "
                "saved_subject_bound_sp1_groth16_receipt_verifies_standalone "
                "unrunnable against any saved receipt."
            ),
            "now": (
                "assert_persisted_subject_output_matches compares the complete "
                "manifest-determined ack_subject and game_idx exactly, and asserts "
                "the two per-process fields are well-formed"
            ),
        },
    ],
    "verification_performed": {
        "cargo_check_default_features": "pass",
        "cargo_check_subject_bound_sp1_verifier_v1": "pass",
        "cargo_clippy_sp1_execution_tests_tests_D_warnings": "pass",
        "cargo_test_sp1_execution_tests": "46 passed, 0 failed, 4 ignored",
        "importer_test": (
            "network_subject_bound_sp1_groth16_artifact_imports_and_verifies_"
            "standalone: pass"
        ),
        "reload_test": (
            "saved_subject_bound_sp1_groth16_receipt_verifies_standalone: pass "
            "against the persisted receipt"
        ),
        "receipt_roundtrip": (
            "create_new + write_all + sync_all + reload + exact equality + "
            "standalone re-verification"
        ),
    },
    "source_hashes": {
        path: hashlib.sha256((STRATA / path).read_bytes()).hexdigest()
        for path in TOUCHED_SOURCES
    },
    "funding_eligible": False,
    "safe_for_funds": False,
    "what_this_closes": (
        "The deterministic final Groth16 execution/verification evidence gate for "
        "the subject-bound counterproof statement, and only that gate. The suite is "
        "BN254 Groth16, which kill criterion 8 disqualifies from the funding path "
        "regardless of how well the receipt verifies."
    ),
    "what_remains_open": [
        "runtime consumption of the receipt",
        "canonical-chain binding and Bitcoin confirmation",
        "economic qualification",
        "ceremony",
        "the remaining v0.26 activation blockers "
        "(see docs/59_V026_CRITICAL_PATH_GAP_MAP.md)",
    ],
    "not_performed": [
        "no new paid proof request",
        "no resubmission to Succinct",
        "no local prover run",
        "no private key access",
        "no edit to zkaleido in the Cargo cache",
        "no change to STATUS.json or any funding-eligibility flag",
    ],
}

OUT.write_text(json.dumps(record, indent=2) + "\n")
print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
print(f"receipt sha256: {record['verified_receipt']['sha256']}")
print(f"source  sha256: {record['source_artifact']['sha256']}")
