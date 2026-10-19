# SPDX-License-Identifier: AGPL-3.0-only
from typing import Literal

from pydantic import Field

from journeon.contracts import Contract, Identifier


class RestoreConfiguration(Contract):
    snapshot_root: str
    destination_root: str


class HistorySelection(Contract):
    project_id: Identifier
    revisions: list[int] = Field(min_length=1, max_length=100)


class RestorePreview(Contract):
    idempotency_key: Identifier
    snapshot: Identifier
    destination: Identifier
    data_class: Literal["PROJECT_INSTRUCTION_HISTORY"]
    selection: list[HistorySelection] = Field(min_length=1, max_length=100)


class RestorePlan(RestorePreview):
    kind: Literal["lifecycle.restore.authorize.v1"] = "lifecycle.restore.authorize.v1"
    snapshot_hash: str
    store_id: Identifier
    incarnation: Identifier
    current_versions_hash: str
    dependencies_hash: str
    platform: str
    schema_revision: str
    source_path: str
    destination_path: str
    security_effect: Literal["PRESERVE_CURRENT_DENY_OLD_PENDING_AUTHORITY"] = (
        "PRESERVE_CURRENT_DENY_OLD_PENDING_AUTHORITY"
    )


class RestoreAuthorization(Contract):
    operation_id: Identifier
    request_id: Identifier
    command: Literal["lifecycle.restore.authorize.v1"] = "lifecycle.restore.authorize.v1"
    status: Literal["AUTHORIZED_OFFLINE_ONLY"] = "AUTHORIZED_OFFLINE_ONLY"
    plan_hash: str
