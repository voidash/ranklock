#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ranklock.bridge_comparison import (
    benchmark_field_bridges,
    compare_bridge_routes,
    compare_range_widths,
)
from ranklock.field_bridge import RangeLookupModel


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=300)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--chunk-bits", type=int, default=16)
    parser.add_argument(
        "--output", type=Path, default=Path("results/field_bridge_comparison.json")
    )
    args = parser.parse_args()

    document = {
        "comparison": compare_bridge_routes(
            range_model=RangeLookupModel(args.chunk_bits)
        ),
        "range_width_sensitivity": compare_range_widths(),
        "native_benchmark": benchmark_field_bridges(
            cases=args.cases, repeats=args.repeats
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
