# SPDX-License-Identifier: AGPL-3.0-only
from typing import Literal

from pydantic import Field

from journeon.contracts import Contract, Identifier, PositiveRevision
from journeon.discovery_contracts import PageFields
from journeon.job_contracts import JobView


class AttentionAction(Contract):
    operation: Literal["job.cancel.v1", "notification.dismiss.v1"]
    target_id: Identifier
    arguments: dict[str, str | int]


class AttentionItem(Contract):
    attention_id: Identifier
    project_id: Identifier
    source: JobView
    source_revision: PositiveRevision
    reason: str
    occurrences: int = Field(ge=1)
    canonical_disposition: Literal["OPEN", "DISMISSED", "RESOLVED"]
    presentation_disposition: Literal["UNACKNOWLEDGED", "DISMISSED"]
    presentation_revision: int = Field(ge=0)
    presentation_source_revision: PositiveRevision | None
    actions: list[AttentionAction]


class AttentionPage(PageFields):
    supported_coverage: list[Literal["JOB"]]
    items: list[AttentionItem]
