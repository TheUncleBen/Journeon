# SPDX-License-Identifier: AGPL-3.0-only
"""Authorized collection summaries and live keyset pages."""

from typing import Annotated, Literal

from pydantic import Field

from journeon.contracts import Contract, Identifier, Name, PositiveRevision, TaskState
from journeon.job_contracts import JobView


class DiscoveryLink(Contract):
    relation: Literal["tasks", "attempts", "jobs", "evidence"]
    href: Annotated[str, Field(max_length=1024)]


class ProjectSummary(Contract):
    project_id: Identifier
    revision: PositiveRevision
    name: Name
    links: list[DiscoveryLink]


class TaskSummary(Contract):
    task_id: Identifier
    project_id: Identifier
    revision: PositiveRevision
    objective: Name
    state: TaskState
    links: list[DiscoveryLink]


class AttemptSummary(Contract):
    attempt_id: Identifier
    project_id: Identifier
    task_id: Identifier
    revision: PositiveRevision
    state: Literal["PREPARING", "PREPARED", "RECOVERY_REQUIRED"]
    links: list[DiscoveryLink]


class JobSummary(JobView):
    attempt_id: Identifier | None
    links: list[DiscoveryLink]


class PageFields(Contract):
    next_cursor: str | None
    has_more: bool
    observed_at: str
    store_incarnation: Identifier


class ProjectPage(PageFields):
    items: list[ProjectSummary]


class TaskPage(PageFields):
    items: list[TaskSummary]


class AttemptPage(PageFields):
    items: list[AttemptSummary]


class JobPage(PageFields):
    items: list[JobSummary]
