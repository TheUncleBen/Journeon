# SPDX-License-Identifier: AGPL-3.0-only
import fcntl
import os
from dataclasses import dataclass
from pathlib import Path


def acquire(path: Path, *, exclusive: bool = False) -> int:
    descriptor = os.open(
        str(path) + ".maintenance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@dataclass(frozen=True)
class RestoreWriteIdentity:
    operation: str
    incarnation: str
    destination: str
