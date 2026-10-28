# SPDX-License-Identifier: AGPL-3.0-only
from typing import Literal

from journeon.contracts import Contract, Identifier, PositiveRevision
from journeon.discovery_contracts import PageFields

SearchKind = Literal["ATTEMPT", "INSTRUCTION_NAVIGATION", "JOB", "PROJECT", "TASK"]


class AcceptedNavigation(Contract):
    project_id: Identifier
    revision: PositiveRevision
    provenance: Literal["ACCEPTED_INSTRUCTION_REVISION"] = "ACCEPTED_INSTRUCTION_REVISION"
    document_paths: list[str]
    required_fragments: list[str]


class SearchItem(Contract):
    kind: SearchKind
    entity_id: Identifier
    project_id: Identifier
    revision: PositiveRevision
    display_fields: list[str]
    href: str
    provenance: Literal["CANONICAL", "ACCEPTED_INSTRUCTION_REVISION"]


class SearchPage(PageFields):
    supported_coverage: list[SearchKind]
    items: list[SearchItem]
