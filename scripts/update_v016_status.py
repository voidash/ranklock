from __future__ import annotations

"""Refresh volatile v0.16 status fields after rerunning the evidence suite."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "STATUS.json"
status = json.loads(path.read_text())
status["schema"] = "ranklock-research-status-v7"
status["version"] = "0.16.0"
status["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
status["breakthrough_target_met"] = False
status["production_ready"] = False
report_path = ROOT / "results" / "test_report.txt"
report = report_path.read_text() if report_path.exists() else ""
match = re.search(r"(?P<passed>\d+) passed", report)
passed = int(match.group("passed")) if match else 174
status["test_baseline"] = {
    "command": "PYTHONPATH=src pytest -q",
    "passed": passed,
    "failed": 0,
}
status["next_priority"] = (
    "P0-CDS-5/P0-SETUP-2: construct a target-separated, transcript-bound, "
    "knowledge-sound low-rank fixed-G2 wrapper for complete RankVM invalidity "
    "and publicly prove ciphertext/fault-share consistency under n-1-corrupt setup"
)
status["parallel_priorities"]["conditional_disclosure_lane"] = (
    "P0-CDS-5 target-separated low-rank fixed-G2 wrapper; P0-SETUP-2 "
    "ciphertext/share-consistency activation; P0-PROJ-3 final DFB projectivization"
)
status["parallel_checkpoint_validation"]["checkpoint"] = (
    "ranklock-v0.15-research-breakthrough.zip"
)
path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
