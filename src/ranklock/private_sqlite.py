from __future__ import annotations

"""Private SQLite path preparation for one-shot authorization state.

SQLite's transaction semantics do not help when an attacker can replace the
pathname, read a world-readable database, or restore a sibling WAL file.  These
helpers require a caller-owned, non-writable parent directory and a private,
regular database file.  They also record the file identity so a pathname swap
between validation and ``sqlite3.connect`` is detected immediately.

This is host hardening, not anti-rollback storage.  Remote signed rollback
witnesses remain mandatory for funded deployments.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import TypeVar


E = TypeVar("E", bound=Exception)


@dataclass(frozen=True, slots=True)
class PrivateFileIdentity:
    device: int
    inode: int


def _raise(error_type: type[E], message: str) -> None:
    raise error_type(message)


def require_private_directory(path: Path, *, error_type: type[E], label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        _raise(error_type, f"{label} directory is unavailable: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _raise(error_type, f"{label} directory must be a real directory")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        _raise(error_type, f"{label} directory is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o022:
        _raise(error_type, f"{label} directory must not be group/world writable")


def validate_private_file(
    path: Path,
    *,
    error_type: type[E],
    label: str,
    expected: PrivateFileIdentity | None = None,
) -> PrivateFileIdentity:
    try:
        info = path.lstat()
    except OSError as exc:
        _raise(error_type, f"{label} database is unavailable: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _raise(error_type, f"{label} database must be a private regular file")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        _raise(error_type, f"{label} database is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        _raise(error_type, f"{label} database permissions must be 0600 or stricter")
    identity = PrivateFileIdentity(info.st_dev, info.st_ino)
    if expected is not None and identity != expected:
        _raise(error_type, f"{label} database pathname changed during open")
    return identity


def prepare_private_sqlite_path(
    path: str | os.PathLike[str],
    *,
    error_type: type[E],
    label: str,
) -> tuple[Path, PrivateFileIdentity, bool]:
    result = Path(path)
    parent_existed = result.parent.exists()
    result.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent_existed:
        os.chmod(result.parent, 0o700)
    require_private_directory(result.parent, error_type=error_type, label=label)

    created = False
    if not result.exists():
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(result, flags, 0o600)
        except OSError as exc:
            _raise(error_type, f"could not create private {label} database: {exc}")
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            directory_fd = os.open(result.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Some filesystems do not support directory fsync.  The database
            # transaction plus remote rollback witnesses remain the safety
            # boundary; callers record this host limitation separately.
            pass
        created = True

    identity = validate_private_file(
        result, error_type=error_type, label=label
    )
    return result, identity, created


def validate_sqlite_sidecars(
    path: Path,
    *,
    error_type: type[E],
    label: str,
) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(os.fspath(path) + suffix)
        if sidecar.exists():
            validate_private_file(sidecar, error_type=error_type, label=f"{label}{suffix}")
