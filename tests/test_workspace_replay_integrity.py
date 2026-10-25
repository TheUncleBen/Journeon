# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import select, text
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401

from journeon.database import transaction
from journeon.models import OutboxEvent, Principal, Receipt


@pytest.mark.parametrize(
    "corruption",
    ["result-json", "event-json", "typed-result", "lineage", "event-target", "schema", "type"],
)
@pytest.mark.parametrize("denied", [False, True])
def test_replay_preserves_authorized_repair_failure_and_hides_denied_rows(
    enrolled_owner,  # noqa: F811
    corruption,
    denied,
):
    owner = enrolled_owner
    receipt = official_effect(owner.client, owner.headers, owner.grant("project.create"))
    clean = owner.client.post(
        "/api/v1/events/replay", headers=owner.headers, json={"cursor": None, "limit": 100}
    )
    assert clean.status_code == 200
    if receipt["operation_id"] not in {item["operation_id"] for item in clean.json()["events"]}:
        pytest.fail("The real administration event must be visible before corruption")
    with transaction(owner.engine) as db:
        row = db.get(Receipt, receipt["operation_id"])
        event = db.scalar(select(OutboxEvent).where(OutboxEvent.operation_id == row.id))
        if corruption == "result-json":
            db.execute(
                text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
                {"id": row.id},
            )
        elif corruption == "event-json":
            db.execute(
                text("UPDATE outbox_events SET payload='invalid-json' WHERE sequence=:id"),
                {"id": event.sequence},
            )
        elif corruption == "typed-result":
            row.result = {**row.result, "grant": {**row.result["grant"], "enabled": "invalid"}}
        elif corruption == "lineage":
            row.payload_hash = "a" * 64
        elif corruption == "schema":
            event.schema_version = 2
        elif corruption == "type":
            event.event_type = "unknown.event.v1"
        else:
            event.target_id = "different-grant"
            if denied:
                db.execute(
                    text("UPDATE outbox_events SET payload='invalid-json' WHERE sequence=:id"),
                    {"id": event.sequence},
                )
        if denied:
            # Isolated denial fixture; not a supported Owner-role change.
            db.execute(text("DROP TRIGGER preserve_initialized_owner"))
            db.get(Principal, owner.principal_id).role = "SHARED_USER"
    response = owner.client.post(
        "/api/v1/events/replay", headers=owner.headers, json={"cursor": None, "limit": 100}
    )
    assert response.status_code == (200 if denied else 503)
    if denied:
        assert response.json()["events"] == []
