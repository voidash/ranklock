#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.25.1"
PREFIX = f"ranklock-v{VERSION}"
FIXED_ZIP_TIME = (2026, 8, 14, 0, 0, 0)
EXCLUDED_PARTS = {
    ".git", ".pytest_cache", "__pycache__", ".venv", "build", "dist",
    "v025-current-shards", "v025-shell-diagnostic",
    "v025-release-shards", "v025-complete-shards", "v025-final-shards",
    "v025-audit-shards", "v025-final-full-pytest.log",
}
EXCLUDED_NAMES = {
    # These v0.25.2 companion reports are produced only after this archive is
    # built. The clean report contains the archive digest, and the release
    # gate contains the clean-report digest; packaging either creates a
    # checksum cycle in which no final archive can match its own evidence.
    "clean_archive_verification_v0252.json",
    "v0252_release_gate.json",
    "v025_test_files_raw.json",
    "v025_split_scalar_qualification.pid",
    "v025_split_scalar_qualification.done",
    "v025_split_scalar_qualification.exit",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".log", ".pid", ".exit", ".done", ".rc"}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(
        part in EXCLUDED_PARTS
        or part.endswith(".egg-info")
        or "shard" in part
        or "diagnostic" in part
        for part in relative.parts
    ):
        return False
    if relative.as_posix() in {"MANIFEST.sha256", "SHA256SUMS"}:
        return False
    if path.name in EXCLUDED_NAMES:
        return False
    if any(path.name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return False
    # Qualification attempts create many timestamped/intermediate result files.
    # Keep only canonical evidence in the reproducible source archive.
    if relative.parts and relative.parts[0] == "results":
        transient_prefixes = (
            "v025-final", "v025-live", "v025-current", "v025-post-hardening",
            "v025-complete", "v025-audit", "v025-shell", "v0251-complete", "v0251-final",
            "v0251-current", "v025-full", "v025-test-runner", "v025_test_shard",
        )
        if path.name.startswith(transient_prefixes):
            return False
        if "raw" in path.stem or path.name.endswith(".txt.tmp"):
            return False
    return path.is_file()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def source_files() -> list[Path]:
    return sorted(
        (path for path in ROOT.rglob("*") if included(path)),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def write_manifests(files: list[Path]) -> None:
    (ROOT / "MANIFEST.sha256").write_text(
        "\n".join(
            f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}" for path in files
        ) + "\n"
    )
    keys = [
        ROOT / "MANIFEST.sha256",
        ROOT / "artifacts/v025-committee-conformance/ranklock-v025-two-slot-retained-object.bin",
        ROOT / "artifacts/v025-committee-conformance/authorization-transaction-plan.bin",
        ROOT / "artifacts/v025-split-scalar-conformance/ranklock-v025-split-scalar-bundle.bin",
        ROOT / "results/v025_committee_qualification.json",
        ROOT / "results/v025_split_scalar_qualification.json",
        ROOT / "results/v025_bitcoin_policy_envelope.json",
        ROOT / "results/v025_bitcoin_core_regtest.json",
        ROOT / "results/v025_test_files.json",
        ROOT / "results/v025_evidence_verification.json",
        ROOT / "results/v025_release_gate.json",
        ROOT / "results/v025_reproducibility.json",
        ROOT / "results/v0251_security_hardening.json",
        ROOT / "integration/alpen-validity-first-f94c-v025/MANIFEST.sha256",
    ]
    missing = [str(path.relative_to(ROOT)) for path in keys if not path.is_file()]
    if missing:
        raise RuntimeError(f"release evidence missing: {missing}")
    (ROOT / "SHA256SUMS").write_text(
        "\n".join(f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}" for path in keys)
        + "\n"
    )


def add_file(archive: zipfile.ZipFile, path: Path) -> None:
    relative = path.relative_to(ROOT).as_posix()
    info = zipfile.ZipInfo(f"{PREFIX}/{relative}", FIXED_ZIP_TIME)
    permissions = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
    info.external_attr = (stat.S_IFREG | permissions) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(
        info,
        path.read_bytes(),
        compress_type=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    )



def add_integration_file(archive: zipfile.ZipFile, base: Path, path: Path) -> None:
    relative = path.relative_to(base).as_posix()
    info = zipfile.ZipInfo(f"alpen-validity-first-f94c-v025/{relative}", FIXED_ZIP_TIME)
    permissions = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
    info.external_attr = (stat.S_IFREG | permissions) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(
        info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    initial = source_files()
    write_manifests(initial)
    files = sorted(
        set(source_files() + [ROOT / "MANIFEST.sha256", ROOT / "SHA256SUMS"]),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    archive_path = output / f"{PREFIX}-reproducible-source.zip"
    with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
        for path in files:
            add_file(archive, path)

    integration_base = ROOT / "integration/alpen-validity-first-f94c-v025"
    integration_archive = output / "alpen-validity-first-f94c-v025.zip"
    integration_files = sorted(
        (
            path for path in integration_base.rglob("*")
            if path.is_file()
            and ".pytest_cache" not in path.parts
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        ),
        key=lambda path: path.relative_to(integration_base).as_posix(),
    )
    with zipfile.ZipFile(integration_archive, "w", allowZip64=True) as archive:
        for path in integration_files:
            add_integration_file(archive, integration_base, path)

    report = {
        "schema": "ranklock-v0251-release-build-v1",
        "package_version": VERSION,
        "archive": archive_path.name,
        "archive_bytes": archive_path.stat().st_size,
        "archive_sha256": sha256(archive_path),
        "manifest_entries": len(initial),
        "fixed_zip_timestamp": "2026-08-14T00:00:00Z",
        "integration_archive": integration_archive.name,
        "integration_archive_bytes": integration_archive.stat().st_size,
        "integration_archive_sha256": sha256(integration_archive),
    }
    report_path = output / f"{PREFIX}-release-build.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    sums = output / f"{PREFIX}-SHA256SUMS.txt"
    sums.write_text(
        f"{sha256(archive_path)}  {archive_path.name}\n"
        f"{sha256(integration_archive)}  {integration_archive.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
