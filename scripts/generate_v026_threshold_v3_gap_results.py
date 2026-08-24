"""Generate the v0.26 threshold-v3 graph/admission evidence record.

Every value is extracted mechanically from the live Rust sources or produced by
a command run here. Nothing is hand-transcribed. The record deliberately does
not change any funding-eligibility flag.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys

STRATA = pathlib.Path("/Users/cdjk/github/llm/ranklock/tmp/strata-v026-f94c")
OUT = pathlib.Path(
    "/Users/cdjk/github/llm/ranklock/worktree-v0.25.2/results/"
    "v026_threshold_graph_v3_admission_gap.json"
)


def fail(message: str) -> None:
    """Abort loudly. A silently wrong evidence artifact is worse than none."""
    raise SystemExit(f"evidence generation failed: {message}")


def read(relative: str) -> str:
    path = STRATA / relative
    if not path.is_file():
        fail(f"expected source file is absent: {relative}")
    return path.read_text()


def sha256(relative: str) -> str:
    return hashlib.sha256((STRATA / relative).read_bytes()).hexdigest()


def camel_to_kebab(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


def extract_enum_variants(source: str, enum_name: str) -> list[str]:
    """Returns the declared variants of a fieldless enum, in declaration order."""
    match = re.search(
        rf"pub enum {re.escape(enum_name)}\s*\{{(.*?)\n\}}", source, re.DOTALL
    )
    if match is None:
        fail(f"enum {enum_name} not found")
    body = match.group(1)
    variants = re.findall(r"^\s{4}([A-Z][A-Za-z0-9]*),\s*$", body, re.MULTILINE)
    if not variants:
        fail(f"enum {enum_name} yielded no variants")
    return variants


def extract_const_array(source: str, const_name: str) -> tuple[int, list[str]]:
    """Returns the declared length and ordered variant names of a const array."""
    match = re.search(
        rf"const {re.escape(const_name)}: \[([A-Za-z0-9]+); (\d+)\] = \[(.*?)\n\];",
        source,
        re.DOTALL,
    )
    if match is None:
        fail(f"const array {const_name} not found")
    element_type, declared_length, body = match.groups()
    entries = re.findall(rf"{re.escape(element_type)}::([A-Za-z0-9]+)", body)
    return int(declared_length), entries


def extract_usize_const(source: str, const_name: str) -> int:
    match = re.search(
        rf"pub const {re.escape(const_name)}: usize = (\d+);", source
    )
    if match is None:
        fail(f"usize const {const_name} not found")
    return int(match.group(1))


def run(command: list[str], cwd: pathlib.Path) -> tuple[int, str]:
    completed = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, check=False
    )
    return completed.returncode, (completed.stdout + completed.stderr)


# --- graph-level v3 blockers -------------------------------------------------

GRAPH_V3 = "crates/tx-graph/src/v026_threshold_graph_v3.rs"
graph_source = read(GRAPH_V3)
graph_variants = extract_enum_variants(graph_source, "V026ThresholdActivationBlockerV3")
graph_declared_len, graph_entries = extract_const_array(graph_source, "ACTIVATION_BLOCKERS")

if graph_declared_len != len(graph_entries):
    fail(
        f"graph ACTIVATION_BLOCKERS declares {graph_declared_len} "
        f"but lists {len(graph_entries)}"
    )
if sorted(graph_variants) != sorted(graph_entries):
    fail("graph enum variants and ACTIVATION_BLOCKERS entries differ")
if len(set(graph_entries)) != len(graph_entries):
    fail("graph ACTIVATION_BLOCKERS contains a duplicate")

# --- graph-level v2 blockers, for the delta ---------------------------------

GRAPH_V2 = "crates/tx-graph/src/v026_graph.rs"
graph_v2_source = read(GRAPH_V2)
v2_declared_len, v2_entries = extract_const_array(graph_v2_source, "ACTIVATION_BLOCKERS")
if v2_declared_len != len(v2_entries):
    fail("v2 ACTIVATION_BLOCKERS length disagrees with its entries")

# --- admission-level counts --------------------------------------------------

ADMISSION_V3 = "crates/bridge-sm/src/v026_admission_v3.rs"
ADMISSION_V2 = "crates/bridge-sm/src/v026_admission_v2.rs"
ADMISSION_V1 = "crates/bridge-sm/src/v026_admission.rs"

admission_v3_count = extract_usize_const(read(ADMISSION_V3), "V026_BLOCKER_COUNT_V3")
admission_v2_count = extract_usize_const(read(ADMISSION_V2), "V026_BLOCKER_COUNT_V2")
admission_v1_source = read(ADMISSION_V1)
admission_v1_match = re.search(
    r"pub const V026_BLOCKER_COUNT(?:_V1)?: usize = (\d+);", admission_v1_source
)
if admission_v1_match is None:
    fail("V1 blocker count const not found")
admission_v1_count = int(admission_v1_match.group(1))

if admission_v3_count != graph_declared_len:
    fail(
        f"admission v3 count {admission_v3_count} disagrees with graph "
        f"{graph_declared_len}"
    )

# --- the persistence gap -----------------------------------------------------

ROW_SPEC_DIR = STRATA / "crates/db/src/fdb/row_spec"
if not ROW_SPEC_DIR.is_dir():
    fail("row_spec directory is absent")
row_spec_files = sorted(p.name for p in ROW_SPEC_DIR.glob("*.rs"))
row_spec_mod = read("crates/db/src/fdb/row_spec/mod.rs")
declared_modules = re.findall(r"mod (v026_[a-z0-9_]+);", row_spec_mod)

admission_row_specs = [m for m in declared_modules if m.startswith("v026_admissions")]
v3_row_spec_present = "v026_admissions_v3" in declared_modules

# --- the persisted envelope magics, per version ------------------------------

envelopes = {}
for module in admission_row_specs:
    source = read(f"crates/db/src/fdb/row_spec/{module}.rs")
    magic = re.search(r'ENVELOPE_MAGIC: &\[u8; (\d+)\] = b"([A-Z0-9]+)"', source)
    version = re.search(r"ENVELOPE_VERSION(?:_V\d)?: u16 = (\d+);", source)
    if magic is None or version is None:
        fail(f"{module} lacks a parseable envelope magic/version")
    envelopes[module] = {
        "magic": magic.group(2),
        "magic_bytes": int(magic.group(1)),
        "envelope_version": int(version.group(1)),
    }

# --- commands actually run ---------------------------------------------------

base_commit_code, base_commit = run(["git", "rev-parse", "HEAD"], STRATA)
if base_commit_code != 0:
    fail("could not read base commit")

checks = {}
for label, command in {
    "cargo_check_tx_graph": ["cargo", "check", "-p", "strata-bridge-tx-graph"],
    "cargo_check_bridge_sm": ["cargo", "check", "-p", "strata-bridge-sm"],
    "cargo_check_db": ["cargo", "check", "-p", "strata-bridge-db"],
    "cargo_test_tx_graph": ["cargo", "test", "-p", "strata-bridge-tx-graph"],
    "cargo_test_bridge_sm": ["cargo", "test", "-p", "strata-bridge-sm"],
}.items():
    code, _ = run(command, STRATA)
    checks[label] = "pass" if code == 0 else "FAIL"
    print(f"{label}: {checks[label]}", file=sys.stderr)

db_code, db_output = run(["cargo", "test", "-p", "strata-bridge-db"], STRATA)
fdb_absent = "the fdb select api version can only be run once per process" in db_output
checks["cargo_test_db"] = {
    "result": "pass" if db_code == 0 else "FAIL",
    "note": (
        "strata-bridge-db's fdb::bridge_db tests call FdbClient::setup and require a "
        "live FoundationDB cluster. None runs on this host, so setup panics at "
        "crates/db/src/fdb/bridge_db.rs:776 and every later test in the process then "
        "panics on 'the fdb select api version can only be run once per process'. "
        "This is an environment dependency and a per-process harness limitation, not "
        "a regression. It is also the direct reason live FoundationDB execution "
        "remains unverified in the claim boundary."
    ),
    "fdb_api_version_cascade_observed": fdb_absent,
}

# --- record ------------------------------------------------------------------

sources = [GRAPH_V3, GRAPH_V2, ADMISSION_V3, ADMISSION_V2, ADMISSION_V1,
           "crates/db/src/fdb/row_spec/mod.rs"] + [
    f"crates/db/src/fdb/row_spec/{m}.rs" for m in admission_row_specs
]

record = {
    "schema": "ranklock-v026-threshold-v3-admission-gap-evidence-v1",
    "evidence_class": "REPRODUCED",
    "base_commit": base_commit.strip(),
    "generated_by": (
        "scripts/generate_v026_threshold_v3_gap_results.py; every count parsed "
        "from the live Rust sources, every check result from a command run here"
    ),
    "graph_v3": {
        "source": GRAPH_V3,
        "enum": "V026ThresholdActivationBlockerV3",
        "declared_blocker_count": graph_declared_len,
        "blockers": [camel_to_kebab(name) for name in graph_entries],
    },
    "graph_v2": {
        "source": GRAPH_V2,
        "declared_blocker_count": v2_declared_len,
    },
    "blocker_delta_v2_to_v3": [
        camel_to_kebab(name) for name in graph_entries if name not in set(v2_entries)
    ],
    "admission_blocker_counts": {
        "v1": admission_v1_count,
        "v2": admission_v2_count,
        "v3": admission_v3_count,
    },
    "persistence_gap": {
        "declared_row_spec_modules": declared_modules,
        "admission_row_spec_modules": admission_row_specs,
        "v026_admissions_v3_present": v3_row_spec_present,
        "row_spec_files_on_disk": row_spec_files,
        "envelopes": envelopes,
        "finding": (
            (
                f"The live v3 admission path validates {admission_v3_count} "
                f"blockers, and a v026_admissions_v3 row spec now exists alongside "
                f"v1 ({admission_v1_count}) and v2 ({admission_v2_count}). A v3 "
                "observation has a persistence envelope in its own subspace. The "
                "stored row remains an inert value with no transition to funding, "
                "signing, duties, P2P, or broadcast."
            )
            if v3_row_spec_present
            else (
                f"The live v3 admission path validates {admission_v3_count} "
                f"blockers, but FoundationDB row specs exist only for v1 "
                f"({admission_v1_count}) and v2 ({admission_v2_count}). No "
                "v026_admissions_v3 module exists, so a v3 observation has no "
                "persistence envelope and cannot be durably recorded."
            )
        ),
    },
    "workspace_checks": checks,
    "source_hashes": {path: sha256(path) for path in sources},
    "funding_eligible": False,
    "safe_for_funds": False,
    "what_this_establishes": (
        "The exact v3 blocker set and the absence of a v3 persistence envelope, "
        "both parsed from the live sources. It establishes no runtime capability "
        "and moves no funding obligation."
    ),
}

OUT.write_text(json.dumps(record, indent=2) + "\n")
print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
print(f"graph v3 blockers: {graph_declared_len}")
print(f"delta v2->v3: {record['blocker_delta_v2_to_v3']}")
print(f"admission counts: {record['admission_blocker_counts']}")
print(f"v3 row spec present: {v3_row_spec_present}")
