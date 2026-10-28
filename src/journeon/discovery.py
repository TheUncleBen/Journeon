# SPDX-License-Identifier: AGPL-3.0-only
"""Paging mechanics; resource authorization stays with each canonical owner."""

import base64
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from pydantic import Field, ValidationError
from sqlalchemy import Engine, Select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import InstrumentedAttribute, Session

from journeon.contracts import Contract, DomainError, Identifier, SchemaVersion
from journeon.database import require_compatible_schema, transaction
from journeon.models import StoreIdentity
from journeon.permissions import AuthenticatedContext
from journeon.sessions import current_session

# Bound each read; an exhausted scan returns unavailable rather than a partial page.
SCAN_LIMIT = 1000


class Cursor(Contract):
    schema_version: SchemaVersion
    principal: Identifier
    epoch: int = Field(ge=1)
    incarnation: Identifier
    query: dict[str, str | None]
    after: Identifier


@contextmanager
def read_transaction(engine: Engine, actor: AuthenticatedContext) -> Iterator[Session]:
    try:
        with transaction(engine) as db:
            require_compatible_schema(db)
            current_session(
                db,
                actor.authentication_ref,
                principal_id=actor.principal_id,
                principal_epoch=actor.principal_epoch,
            )
            yield db
    except (ValidationError, json.JSONDecodeError):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Stored discovery state requires repair"
        ) from None
    except SQLAlchemyError as exc:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "The discovery store is unavailable") from exc


def allowed(check: Callable[[], object]) -> bool:
    try:
        check()
        return True
    except DomainError as error:
        if error.code in {"PERMISSION_DENIED", "NOT_FOUND"}:
            return False
        raise


def paginate[T: Contract](
    db: Session,
    actor: AuthenticatedContext,
    statement: Select[str],
    key: InstrumentedAttribute[str],
    reader: Callable[[str], T | None],
    *,
    limit: int,
    cursor: str | None,
    query: dict[str, str | None],
) -> dict[str, Any]:
    current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
    )
    if type(limit) is not int or not 1 <= limit <= 100:
        raise DomainError("VALIDATION_FAILED", "Discovery limit must be between 1 and 100")
    store = db.get(StoreIdentity, 1)
    if store is None or not store.security_reconciled:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Store security reconciliation is required")
    scope = dict(
        schema_version=1,
        principal=actor.principal_id,
        epoch=actor.principal_epoch,
        incarnation=store.incarnation,
        query=query,
    )
    after = ""
    if cursor is not None:
        try:
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
                raise ValueError
            data = base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
            parsed = Cursor.model_validate_json(data)
            if parsed.model_dump(exclude={"after"}) != scope:
                raise DomainError("REVISION_CONFLICT", "Discovery cursor requires a fresh read")
            after = parsed.after
        except (ValueError, UnicodeError, TypeError):
            raise DomainError("VALIDATION_FAILED", "Invalid discovery cursor") from None
    items: list[T] = []
    last_visible = ""
    more = False
    for scanned, identity in enumerate(
        db.scalars(statement.where(key > after).order_by(key).limit(SCAN_LIMIT + 1)), start=1
    ):
        if scanned > SCAN_LIMIT:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Discovery scan budget requires a narrower query"
            )
        try:
            item = reader(identity)
        except DomainError as error:
            if error.code in {"PERMISSION_DENIED", "NOT_FOUND"}:
                continue
            raise
        if item is None:
            continue
        if len(items) == limit:
            more = True
            break
        items.append(item)
        last_visible = identity
    next_cursor = None
    if more:
        next_cursor = base64.urlsafe_b64encode(
            Cursor.model_validate({**scope, "after": last_visible}).model_dump_json().encode()
        ).decode()
    return dict(
        items=items,
        next_cursor=next_cursor,
        has_more=more,
        observed_at=datetime.now(UTC).isoformat(),
        store_incarnation=store.incarnation,
    )
