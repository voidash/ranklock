#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (2026, 8, 14, 0, 0, 0)
EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "build",
    "dist",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".egg-info"}
EXCLUDED_NAMES = {
    "MANIFEST.sha256",
    "SHA256SUMS",
    "v0241_reproduce.pid",
    "v0241_reproduce.done",
    "v0241_reproduce.exit",
    "v0241_reproduce.log",
    "v0241_generation_smoke.log",
    "v0241_verification_smoke.log",
    "v0241_full_test.pid",
    "v0241_full_test.done",
    "v0241_full_test.exit",
    "v0241_full_test.log",
    "v0241_manifest_verification.json",
}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return False
    if path.name in EXCLUDED_NAMES:
        return False
    if any(path.name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return False
    return path.is_file()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files() -> list[Path]:
    return sorted((path for path in ROOT.rglob("*") if included(path)), key=lambda p: p.relative_to(ROOT).as_posix())


def write_manifests(files: list[Path]) -> None:
    manifest_lines = [f"{digest(path)}  {path.relative_to(ROOT).as_posix()}" for path in files]
    (ROOT / "MANIFEST.sha256").write_text("\n".join(manifest_lines) + "\n")

    keys = [
        ROOT / "MANIFEST.sha256",
        ROOT / "artifacts/ranklock-v0241-two-slot-retained-object.bin",
        ROOT / "artifacts/ranklock-v0241-two-slot-manifest.bin",
        ROOT / "artifacts/ranklock-v0241-slot-0-authorized-label-release.bin",
        ROOT / "artifacts/ranklock-v0241-slot-1-authorized-label-release.bin",
        ROOT / "results/v0241_security_qualification.json",
        ROOT / "results/v0241_independent_verification.json",
        ROOT / "results/v0241_reproducibility.json",
    ]
    missing = [str(path.relative_to(ROOT)) for path in keys if not path.is_file()]
    if missing:
        raise RuntimeError(f"release evidence missing: {missing}")
    (ROOT / "SHA256SUMS").write_text(
        "\n".join(f"{digest(path)}  {path.relative_to(ROOT).as_posix()}" for path in keys) + "\n"
    )


def add_file(archive: zipfile.ZipFile, path: Path, prefix: str) -> None:
    relative = path.relative_to(ROOT).as_posix()
    info = zipfile.ZipInfo(f"{prefix}/{relative}", FIXED_ZIP_TIME)
    mode = path.stat().st_mode
    permissions = 0o755 if mode & stat.S_IXUSR else 0o644
    info.external_attr = (stat.S_IFREG | permissions) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT.parent / "release")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    initial = source_files()
    write_manifests(initial)
    final_files = source_files() + [ROOT / "MANIFEST.sha256", ROOT / "SHA256SUMS"]
    final_files = sorted(set(final_files), key=lambda p: p.relative_to(ROOT).as_posix())

    archive_path = output / "ranklock-v0.24.1-reproducible-source.zip"
    with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
        for path in final_files:
            add_file(archive, path, "ranklock-v0.24.1")

    report = {
        "schema": "ranklock-v0241-release-build-v1",
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "archive": str(archive_path),
        "archive_bytes": archive_path.stat().st_size,
        "archive_sha256": digest(archive_path),
        "source_files": len(final_files),
        "manifest_entries": len(initial),
        "fixed_zip_timestamp": "%04d-%02d-%02dT%02d:%02d:%02dZ" % FIXED_ZIP_TIME,
    }
    report_path = output / "ranklock-v0.24.1-release-build.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (output / "SHA256SUMS").write_text(
        f"{digest(archive_path)}  {archive_path.name}\n"
        f"{digest(report_path)}  {report_path.name}\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
