# SPDX-License-Identifier: AGPL-3.0-only
"""Rolling timestamp budgets; callers hold the service's outer writer transaction."""

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from journeon.models import AuthRateEvent


def available(session: Session, buckets: set[str], *, limit: int, now: int) -> bool:
    session.execute(delete(AuthRateEvent).where(AuthRateEvent.expires_at <= now))
    counts = session.execute(
        select(AuthRateEvent.bucket, func.sum(AuthRateEvent.weight))
        .where(AuthRateEvent.bucket.in_(buckets))
        .group_by(AuthRateEvent.bucket)
    )
    return all(count < limit for _, count in counts)


def record(session: Session, buckets: set[str], *, now: int, window: int) -> None:
    session.add_all(
        AuthRateEvent(bucket=bucket, observed_at=now, expires_at=now + window, weight=1)
        for bucket in sorted(buckets)
    )
    session.flush()
