#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shards", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = sorted(args.shards.glob("shard-*.json"))
    if not paths:
        raise SystemExit("no shard JSON files found")
    documents = [json.loads(path.read_text()) for path in paths]
    shard_count = documents[0]["shard_count"]
    indices = tuple(sorted(int(document["shard_index"]) for document in documents))
    if indices != tuple(range(shard_count)):
        raise SystemExit(f"incomplete shard set: {indices}; expected 0..{shard_count - 1}")
    if any(int(document["shard_count"]) != shard_count for document in documents):
        raise SystemExit("shard-count mismatch")
    result = {
        "schema": "ranklock-v025-complete-test-suite-v1",
        "shard_count": shard_count,
        "files": sum(int(document["files"]) for document in documents),
        "passed": sum(int(document["passed"]) for document in documents),
        "failed": sum(int(document["failed"]) for document in documents),
        "nonzero_files": sum(int(document["nonzero_files"]) for document in documents),
        "total_discovered_files": int(documents[0]["total_discovered_files"]),
        "shards": [
            {
                "index": int(document["shard_index"]),
                "files": int(document["files"]),
                "passed": int(document["passed"]),
                "failed": int(document["failed"]),
                "nonzero_files": int(document["nonzero_files"]),
            }
            for document in documents
        ],
    }
    result["complete"] = (
        result["files"] == result["total_discovered_files"]
        and result["failed"] == 0
        and result["nonzero_files"] == 0
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
