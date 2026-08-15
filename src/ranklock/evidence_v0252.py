from __future__ import annotations

"""Recorded command execution and versioned evidence reports for v0.25.2.

Every command that produces qualification evidence must run through
:func:`run_recorded_command` so raw stdout/stderr are preserved on disk and
independently hashed, and every result carries its exact argv, exit code and
duration -- never a bare boolean.  Case results are restricted to the five
status values ``06_EVIDENCE_REQUIREMENTS.md`` mandates; nothing else may be
written into a case's ``status`` field, and a "passed" case is only
constructible if it actually recorded at least one successful command.

This module is a construction/loading layer.  It intentionally does *not*
re-hash log files from disk on load -- doing so belongs to the verifier
(``scripts/verify_v0252_evidence.py``), which must treat every report as
untrusted input and independently confirm nothing was tampered with after it
was written.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Any, Literal, Mapping, Sequence

CaseStatus = Literal["passed", "failed", "not_executed", "unavailable", "modeled_only"]
ALLOWED_STATUSES: frozenset[str] = frozenset(
    {"passed", "failed", "not_executed", "unavailable", "modeled_only"}
)


class EvidenceError(RuntimeError):
    """Raised when a command record, case result or matrix report is malformed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def _env_digest(env: Mapping[str, str], *, redact: Sequence[str]) -> str:
    redact_set = set(redact)
    redacted = {k: ("<redacted>" if k in redact_set else v) for k, v in sorted(env.items())}
    return _sha_bytes(json.dumps(redacted, sort_keys=True).encode())


@dataclass(frozen=True, slots=True)
class CommandRecord:
    """One executed (or attempted) command, with raw evidence on disk.

    ``stdout_sha256``/``stderr_sha256`` are computed from the bytes actually
    written to ``stdout_path``/``stderr_path`` at record-construction time.
    The verifier re-reads those files independently and must see the same
    hashes; a mismatch means the log was edited after the fact.
    """

    argv: tuple[str, ...]
    cwd: str
    started_at_utc: str
    finished_at_utc: str
    duration_ms: int
    exit_code: int
    timed_out: bool
    stdout_path: str
    stderr_path: str
    stdout_sha256: str
    stderr_sha256: str
    env_digest: str
    schema: str = "ranklock-v0252-command-record-v1"

    def __post_init__(self) -> None:
        if not self.argv:
            raise EvidenceError("command record has empty argv")
        if self.duration_ms < 0:
            raise EvidenceError("command record has negative duration")
        for value, name in ((self.stdout_sha256, "stdout"), (self.stderr_sha256, "stderr")):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise EvidenceError(f"command record {name} hash is not a lowercase hex sha256")

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "env_digest": self.env_digest,
        }

    @classmethod
    def from_document(cls, raw: Mapping[str, object]) -> "CommandRecord":
        try:
            return cls(
                argv=tuple(str(a) for a in raw["argv"]),  # type: ignore[index]
                cwd=str(raw["cwd"]),
                started_at_utc=str(raw["started_at_utc"]),
                finished_at_utc=str(raw["finished_at_utc"]),
                duration_ms=int(raw["duration_ms"]),  # type: ignore[arg-type]
                exit_code=int(raw["exit_code"]),  # type: ignore[arg-type]
                timed_out=bool(raw["timed_out"]),
                stdout_path=str(raw["stdout_path"]),
                stderr_path=str(raw["stderr_path"]),
                stdout_sha256=str(raw["stdout_sha256"]),
                stderr_sha256=str(raw["stderr_sha256"]),
                env_digest=str(raw["env_digest"]),
            )
        except KeyError as exc:
            raise EvidenceError(f"command record is missing field: {exc}") from exc


def run_recorded_command(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str],
    log_dir: str | os.PathLike[str],
    label: str,
    timeout: int = 600,
    env: Mapping[str, str] | None = None,
    redact_env: Sequence[str] = (),
) -> CommandRecord:
    """Run one command to completion, killing its whole process group on timeout.

    stdout and stderr are captured into *separate* files (unlike
    ``scripts/run_test_files.py``, which merges them for readability) so a
    zero exit code can never hide error-stream output from evidence.
    """

    log_root = Path(log_dir)
    log_root.mkdir(parents=True, exist_ok=True)
    stamp = _utc_now().translate(str.maketrans({":": "", ".": "", "-": ""}))
    stdout_path = log_root / f"{label}.{stamp}.stdout.log"
    stderr_path = log_root / f"{label}.{stamp}.stderr.log"

    run_env = dict(os.environ) if env is None else dict(env)
    started_wall = _utc_now()
    started_monotonic = time.monotonic()
    timed_out = False
    with stdout_path.open("wb") as out_f, stderr_path.open("wb") as err_f:
        proc = subprocess.Popen(
            [str(a) for a in argv],
            cwd=str(cwd),
            env=run_env,
            stdout=out_f,
            stderr=err_f,
            start_new_session=True,
        )
        try:
            exit_code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            exit_code = proc.wait()
    finished_wall = _utc_now()
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)

    return CommandRecord(
        argv=tuple(str(a) for a in argv),
        cwd=str(cwd),
        started_at_utc=started_wall,
        finished_at_utc=finished_wall,
        duration_ms=duration_ms,
        exit_code=int(exit_code),
        timed_out=timed_out,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        stdout_sha256=_sha_bytes(stdout_path.read_bytes()),
        stderr_sha256=_sha_bytes(stderr_path.read_bytes()),
        env_digest=_env_digest(run_env, redact=redact_env),
    )


@dataclass(frozen=True, slots=True)
class CaseResult:
    """The result of one acceptance-matrix case (e.g. ``CORE-014``).

    Construction itself enforces the core evidence-integrity rule: a case
    cannot claim ``passed`` without at least one recorded, successful,
    non-timed-out command backing that claim.  This still isn't sufficient on
    its own -- the verifier must additionally re-hash the referenced log
    files from disk, since a JSON file can be hand-edited after this
    dataclass validated it at write time.
    """

    case_id: str
    status: CaseStatus
    description: str
    commands: tuple[CommandRecord, ...] = ()
    evidence: dict[str, object] = field(default_factory=dict)
    blocked_by: str | None = None
    schema: str = "ranklock-v0252-case-result-v1"

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_STATUSES:
            raise EvidenceError(f"{self.case_id}: unknown status {self.status!r}")
        if self.status == "passed":
            if not self.commands:
                raise EvidenceError(f"{self.case_id}: passed case has no recorded commands")
            if any(cmd.exit_code != 0 or cmd.timed_out for cmd in self.commands):
                raise EvidenceError(
                    f"{self.case_id}: passed case has a nonzero-exit or timed-out command"
                )
        if self.status == "failed" and not self.commands:
            raise EvidenceError(f"{self.case_id}: failed case has no recorded commands")
        if self.status in {"not_executed", "unavailable"} and not self.blocked_by and not self.evidence:
            raise EvidenceError(
                f"{self.case_id}: {self.status} case must record why "
                "(blocked_by or an evidence explanation) rather than being silently empty"
            )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "case_id": self.case_id,
            "status": self.status,
            "description": self.description,
            "commands": [c.document() for c in self.commands],
            "evidence": self.evidence,
            "blocked_by": self.blocked_by,
        }

    @classmethod
    def from_document(cls, case_id: str, raw: Mapping[str, object]) -> "CaseResult":
        if str(raw.get("case_id")) != case_id:
            raise EvidenceError(
                f"case key {case_id!r} does not match embedded case_id {raw.get('case_id')!r}"
            )
        commands = tuple(
            CommandRecord.from_document(cmd) for cmd in raw.get("commands", [])  # type: ignore[arg-type]
        )
        evidence = raw.get("evidence", {})
        if not isinstance(evidence, dict):
            raise EvidenceError(f"{case_id}: evidence must be a JSON object")
        return cls(
            case_id=case_id,
            status=raw["status"],  # type: ignore[arg-type]
            description=str(raw["description"]),
            commands=commands,
            evidence=dict(evidence),
            blocked_by=None if raw.get("blocked_by") is None else str(raw["blocked_by"]),
        )


@dataclass(frozen=True, slots=True)
class MatrixReport:
    """A complete set of case results for one qualification phase.

    ``required_case_ids`` is always exactly the canonical list from
    ``acceptance_matrix_v0252`` -- a report may never cover a subset (a
    silently dropped case) or a superset (an invented case ID that isn't part
    of the handoff's matrix).
    """

    schema_name: str
    required_case_ids: tuple[str, ...]
    identity: dict[str, object]
    cases: tuple[CaseResult, ...]

    def __post_init__(self) -> None:
        present = tuple(case.case_id for case in self.cases)
        if len(set(present)) != len(present):
            raise EvidenceError("duplicate case IDs in matrix report")
        missing = set(self.required_case_ids) - set(present)
        if missing:
            raise EvidenceError(f"matrix report is missing required cases: {sorted(missing)}")
        extra = set(present) - set(self.required_case_ids)
        if extra:
            raise EvidenceError(f"matrix report has unexpected case IDs: {sorted(extra)}")

    @property
    def all_passed(self) -> bool:
        return bool(self.cases) and all(case.status == "passed" for case in self.cases)

    @property
    def any_failed(self) -> bool:
        return any(case.status == "failed" for case in self.cases)

    @property
    def status_counts(self) -> dict[str, int]:
        return {
            status: sum(1 for case in self.cases if case.status == status)
            for status in sorted(ALLOWED_STATUSES)
        }

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema_name,
            "identity": self.identity,
            "cases": {case.case_id: case.document() for case in self.cases},
            "all_passed": self.all_passed,
            "any_failed": self.any_failed,
            "status_counts": self.status_counts,
        }

    def write(self, path: str | os.PathLike[str]) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.document(), indent=2, sort_keys=True) + "\n")

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str],
        *,
        required_case_ids: tuple[str, ...],
        schema_name: str,
    ) -> "MatrixReport":
        raw = json.loads(Path(path).read_text())
        if not isinstance(raw, dict):
            raise EvidenceError(f"{path}: expected a JSON object")
        if raw.get("schema") != schema_name:
            raise EvidenceError(
                f"{path}: unexpected schema {raw.get('schema')!r}, expected {schema_name!r}"
            )
        cases_raw = raw.get("cases", {})
        if not isinstance(cases_raw, dict):
            raise EvidenceError(f"{path}: 'cases' must be a JSON object keyed by case ID")
        cases = tuple(
            CaseResult.from_document(case_id, case_doc) for case_id, case_doc in cases_raw.items()
        )
        identity = raw.get("identity", {})
        if not isinstance(identity, dict):
            raise EvidenceError(f"{path}: 'identity' must be a JSON object")
        return cls(
            schema_name=schema_name,
            required_case_ids=required_case_ids,
            identity=dict(identity),
            cases=cases,
        )
