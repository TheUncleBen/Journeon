# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import subprocess
from pathlib import Path

import pytest
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401


@pytest.mark.parametrize("mode", ["confirm", "cancel", "expired"])
@pytest.mark.parametrize("kind", ["grant_set", "grant_revoke", "policy_initialize"])
def test_actual_confirmation_script_reports_real_administration_outcome(enrolled_owner, kind, mode):  # noqa: F811
    owner = enrolled_owner
    effect = owner.grant("project.create")
    if kind == "grant_revoke":
        first = official_effect(owner.client, owner.headers, effect)
        effect = {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "consumer-revoke",
            "grant_id": first["grant"]["grant_id"],
            "expected_revision": first["grant"]["revision"],
        }
    elif kind == "policy_initialize":
        effect = {
            "kind": "egress.policy.initialize.v1",
            "schema_version": 1,
            "idempotency_key": "consumer-policy",
            "expected_revision": 0,
            "provider_mode": "LOCAL_ONLY",
        }
    if mode == "confirm":
        receipt = official_effect(owner.client, owner.headers, effect)
    else:
        prepared = owner.prepare(effect)
        cancelled = owner.client.post(
            "/api/v1/protected-operations/cancel", headers=owner.headers, json=prepared
        )
        assert cancelled.status_code == 200
        receipt = cancelled.json()
    assert_consumer(receipt, mode)


def assert_consumer(receipt, mode):
    # Actual shipped handler with a minimal DOM shim; this is not a rendered-browser sweep.
    result = subprocess.run(
        [
            os.environ.get("JOURNEON_NODE_BINARY", "node"),
            str(Path(__file__).with_name("confirmation-consumer.cjs")),
        ],
        input=json.dumps({"mode": mode, "receipt": receipt}),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"Confirmation consumer exit {result.returncode}: {result.stderr.strip()}")


@pytest.mark.parametrize("kind", ["instruction", "abandoned", "restore"])
def test_confirmation_consumer_preserves_existing_contract_text(kind):
    from journeon.contracts import InstructionReceipt
    from journeon.restore_contracts import RestoreAuthorization

    if kind == "restore":
        receipt = RestoreAuthorization(
            operation_id="contract-operation",
            request_id="contract-request",
            plan_hash="a" * 64,
        ).model_dump(mode="json")
    else:
        receipt = InstructionReceipt(
            operation_id="contract-operation",
            command="project.instructions.bind.v1",
            target_kind="project_instructions",
            target_id="contract-project",
            revision=1,
            status="ABANDONED" if kind == "abandoned" else "CANONICAL_COMMITTED",
            committed_at="2026-01-01T00:00:00+00:00",
            content_hash="a" * 64,
            provenance="PROJECT",
        ).model_dump(mode="json")
    assert_consumer(receipt, kind)
