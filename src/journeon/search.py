# SPDX-License-Identifier: AGPL-3.0-only
import base64
import unicodedata
from datetime import UTC, datetime
from typing import get_args

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from journeon.attempts import AttemptService
from journeon.contracts import DomainError, Identifier, RuntimeConfigurationUnavailable
from journeon.discovery import Cursor, read_transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.jobs import JobService
from journeon.models import Attempt, Job, Project, ProjectInstructionBinding, StoreIdentity, Task
from journeon.permissions import AuthenticatedContext
from journeon.project_instructions import ProjectInstructionService
from journeon.projects import ProjectService
from journeon.search_contracts import SearchItem, SearchKind, SearchPage
from journeon.work import WorkService

SCAN_LIMIT = 1000
COVERAGE: list[SearchKind] = list(get_args(SearchKind))


def normalized(value: str) -> str:
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", value).casefold())


class SearchCursor(Cursor):
    after_kind: SearchKind
    after: Identifier


class SearchService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration | None):
        self.engine = engine
        self.configuration = configuration

    def item(
        self, db: Session, actor: AuthenticatedContext, kind: SearchKind, identity: str
    ) -> SearchItem:
        provenance = "CANONICAL"
        if kind == "PROJECT":
            project = ProjectService(self.engine).read_in(db, actor, identity)
            project_id, revision = project.project_id, project.revision
            fields = [project.name, project.description]
            href = f"/api/v1/projects/{identity}"
        elif kind == "TASK":
            task = WorkService(self.engine).read_in(db, actor, identity)
            project_id, revision = task.project_id, task.revision
            fields = [task.objective]
            href = f"/api/v1/tasks/{identity}"
        elif kind == "ATTEMPT":
            attempt = AttemptService(self.engine, self.configuration).read_in(db, actor, identity)
            project_id, revision = attempt.project_id, attempt.revision
            fields = [attempt.state]
            href = f"/api/v1/attempts/{identity}"
        else:
            if self.configuration is None:
                raise RuntimeConfigurationUnavailable(
                    "Explicit instruction runtime configuration is required"
                )
            if kind == "JOB":
                job = JobService(self.engine, self.configuration).read_in(db, actor, identity)
                project_id, revision = job.project_id, job.revision
                fields = [job.kind, job.state, *([job.reason] if job.reason else [])]
                href = f"/api/v1/jobs/{identity}"
            else:
                metadata = ProjectInstructionService(
                    self.engine, self.configuration
                ).accepted_navigation_in(db, actor, identity)
                project_id, revision = metadata.project_id, metadata.revision
                fields = metadata.document_paths
                href = f"/api/v1/projects/{identity}/instructions"
                provenance = "ACCEPTED_INSTRUCTION_REVISION"
        return SearchItem.model_validate(
            dict(
                kind=kind,
                entity_id=identity,
                project_id=project_id,
                revision=revision,
                display_fields=fields,
                href=href,
                provenance=provenance,
            )
        )

    def read(
        self,
        actor: AuthenticatedContext,
        q: str,
        kinds: list[str],
        limit: int,
        cursor: str | None = None,
        project_id: str | None = None,
    ) -> SearchPage:
        if not isinstance(q, str) or not 1 <= len(q) <= 200 or not q.strip() or not kinds:
            raise DomainError(
                "VALIDATION_FAILED", "Search requires bounded text and explicit kinds"
            )
        if any(kind not in COVERAGE for kind in kinds):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "A requested search adapter is unavailable")
        selected: list[SearchKind] = [kind for kind in COVERAGE if kind in kinds]
        if type(limit) is not int or not 1 <= limit <= 100:
            raise DomainError("VALIDATION_FAILED", "Search limit must be between 1 and 100")
        with read_transaction(self.engine, actor) as db:
            if self.configuration is None and set(selected) - {"PROJECT", "TASK"}:
                raise RuntimeConfigurationUnavailable(
                    "Explicit instruction runtime configuration is required"
                )
            if "ATTEMPT" in selected and (
                self.configuration is None or self.configuration.attempts is None
            ):
                raise RuntimeConfigurationUnavailable("Attempt preparation is not configured")
            if "JOB" in selected and (
                self.configuration is None or self.configuration.jobs is None
            ):
                raise RuntimeConfigurationUnavailable(
                    "Explicit Job runtime configuration is required"
                )
            store = db.get(StoreIdentity, 1)
            if store is None or not store.security_reconciled:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Store security reconciliation is required"
                )
            scope = dict(
                schema_version=1,
                principal=actor.principal_id,
                epoch=actor.principal_epoch,
                incarnation=store.incarnation,
                query={"q": normalized(q), "kinds": ",".join(selected), "project_id": project_id},
            )
            after_kind, after = "", ""
            if cursor is not None:
                try:
                    if not 1 <= len(cursor) <= 4096:
                        raise ValueError
                    parsed = SearchCursor.model_validate_json(
                        base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
                    )
                    if parsed.model_dump(exclude={"after", "after_kind"}) != scope:
                        raise DomainError(
                            "REVISION_CONFLICT", "Search cursor requires a fresh read"
                        )
                    if parsed.after_kind not in selected:
                        raise ValueError
                    after_kind, after = parsed.after_kind, parsed.after
                except (ValueError, UnicodeError, TypeError):
                    raise DomainError("VALIDATION_FAILED", "Invalid search cursor") from None
            items: list[SearchItem] = []
            scanned, more = 0, False
            for kind in selected:
                if kind < after_kind:
                    continue
                key, project_key = {
                    "PROJECT": (Project.id, Project.id),
                    "TASK": (Task.id, Task.project_id),
                    "ATTEMPT": (Attempt.id, Attempt.project_id),
                    "JOB": (Job.id, Job.project_id),
                    "INSTRUCTION_NAVIGATION": (
                        ProjectInstructionBinding.project_id,
                        ProjectInstructionBinding.project_id,
                    ),
                }[kind]
                statement = select(key).where(key > (after if kind == after_kind else ""))
                if project_id is not None:
                    statement = statement.where(project_key == project_id)
                for identity in db.scalars(statement.order_by(key).limit(SCAN_LIMIT + 1 - scanned)):
                    scanned += 1
                    if scanned > SCAN_LIMIT:
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE", "Search scan budget requires a narrower query"
                        )
                    try:
                        item = self.item(db, actor, kind, identity)
                    except DomainError as error:
                        if error.code in {"PERMISSION_DENIED", "NOT_FOUND"}:
                            continue
                        raise
                    if not any(normalized(q) in normalized(field) for field in item.display_fields):
                        continue
                    if len(items) == limit:
                        more = True
                        break
                    items.append(item)
                if more:
                    break
            next_cursor = None
            if more:
                last = items[-1]
                next_cursor = base64.urlsafe_b64encode(
                    SearchCursor.model_validate(
                        scope | {"after_kind": last.kind, "after": last.entity_id}
                    )
                    .model_dump_json()
                    .encode()
                ).decode()
            return SearchPage(
                items=items,
                supported_coverage=COVERAGE,
                has_more=more,
                next_cursor=next_cursor,
                observed_at=datetime.now(UTC).isoformat(),
                store_incarnation=store.incarnation,
            )
