#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASS_RE = re.compile(r"(?P<count>\d+) passed")
FAIL_RE = re.compile(r"(?P<count>\d+) failed")


def run_one(path: Path, timeout: int) -> dict[str, object]:
    started = time.monotonic()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    # Each pytest file already runs in its own process.  Letting every worker
    # spawn a full BLAS thread pool can exhaust memory/CPU and make the release
    # qualification itself nondeterministically hang.  Force one native math
    # thread per worker and a deterministic Python hash seed.
    for name in (
        "OPENBLAS_NUM_THREADS",
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        env[name] = "1"
    env["PYTHONHASHSEED"] = "0"
    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest", "-q", str(path)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = proc.communicate(timeout=timeout)
        passed = sum(int(m.group("count")) for m in PASS_RE.finditer(output))
        failed = sum(int(m.group("count")) for m in FAIL_RE.finditer(output))
        return {
            "file": str(path.relative_to(ROOT)),
            "returncode": proc.returncode,
            "passed": passed,
            "failed": failed,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output": output,
        }
    except subprocess.TimeoutExpired:
        # Killing only the pytest parent is insufficient when a test has
        # spawned children that inherited the stdout pipe: communicate() can
        # otherwise wait forever and the release ledger is never written.
        # Every file runs in its own process group, so terminate the complete
        # tree and then drain the now-closed pipe.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = proc.communicate()
        return {
            "file": str(path.relative_to(ROOT)),
            "returncode": 124,
            "passed": 0,
            "failed": 1,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output": f"TIMEOUT after {timeout}s\n{output}",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--json", type=Path, default=ROOT / "results" / "test_files.json")
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    args = parser.parse_args()

    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        parser.error("shard index/count must satisfy 0 <= index < count")
    all_files = sorted((ROOT / "tests").glob("test_*.py"))
    files = [path for index, path in enumerate(all_files) if index % args.shard_count == args.shard_index]
    started = time.monotonic()
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(run_one, path, args.timeout): path for path in files}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            status = "PASS" if result["returncode"] == 0 else "FAIL"
            print(
                f"{status:4} {result['file']} passed={result['passed']} "
                f"failed={result['failed']} seconds={result['duration_seconds']}",
                flush=True,
            )

    results.sort(key=lambda item: str(item["file"]))
    summary = {
        "schema": "ranklock-per-file-test-run-v1",
        "files": len(results),
        "passed": sum(int(item["passed"]) for item in results),
        "failed": sum(int(item["failed"]) for item in results),
        "nonzero_files": sum(1 for item in results if int(item["returncode"]) != 0),
        "wall_seconds": round(time.monotonic() - started, 3),
        "workers": args.workers,
        "timeout_per_file_seconds": args.timeout,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "total_discovered_files": len(all_files),
        "results": results,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: summary[k] for k in ("files", "passed", "failed", "nonzero_files", "wall_seconds")}, sort_keys=True))
    return 0 if summary["nonzero_files"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
