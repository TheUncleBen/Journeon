# SPDX-License-Identifier: AGPL-3.0-only
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from journeon.contracts import DomainError, ProjectCreate
from journeon.database import create_database, transaction
from journeon.models import AccessGrant, DeploymentPolicy, OutboxEvent, Principal, Project, Receipt
from journeon.projects import ProjectService


def counts(engine):
    with transaction(engine) as session:
        return tuple(
            session.scalar(select(func.count()).select_from(model))
            for model in (Project, Receipt, OutboxEvent)
        )


def changed(command, **updates):
    return ProjectCreate.model_validate({**command.model_dump(), **updates})


def test_create_persists_one_owner_and_historical_policy(database, actor, command):
    engine, _ = database
    result = ProjectService(engine).create(actor, command)
    assert result.project.instruction_owner == "ENVIRONMENT"
    assert result.project.resource_refs == []
    assert result.project.verification_policy_ref is None
    assert result.project.provider_allowance_at_creation.providers == ["provider-a", "provider-b"]
    assert (
        result.project.provider_allowance_at_creation.interpretation
        == "HISTORICAL_CREATION_SNAPSHOT"
    )
    assert counts(engine) == (1, 1, 1)
    with transaction(engine) as session:
        project = session.get(Project, result.project.project_id)
        receipt = session.get(Receipt, result.operation_id)
        assert project.created_by == actor.principal_id
        assert receipt.authentication_ref == actor.authentication_ref
        assert session.scalar(select(OutboxEvent)).operation_id == result.operation_id
        assert session.scalar(select(func.count()).select_from(AccessGrant)) == 2


@pytest.mark.parametrize(
    "mode,selection,expected",
    [
        ("NARROW", ["provider-b"], ["provider-b"]),
        ("NARROW", [], []),
        ("LOCAL_ONLY", None, []),
        ("INHERIT", None, ["provider-a", "provider-b"]),
    ],
)
def test_provider_selection(database, actor, command, mode, selection, expected):
    result = ProjectService(database[0]).create(
        actor, changed(command, provider_mode=mode, selected_providers=selection)
    )
    assert result.project.provider_allowance_at_creation.providers == expected


def test_unconfigured_allowance_does_not_inherit_connected_provider(database, actor, command):
    engine, _ = database
    with transaction(engine) as session:
        policy = session.get(DeploymentPolicy, 1)
        policy.approval_id = policy.approved_by = None
        policy.approved_providers = ["unapproved-provider"]
    result = ProjectService(engine).create(actor, command)
    assert result.project.provider_allowance_at_creation.providers == []
    with pytest.raises(DomainError, match="exceeds current approval"):
        ProjectService(engine).create(
            actor,
            changed(
                command,
                idempotency_key="bad",
                provider_mode="NARROW",
                selected_providers=["unapproved-provider"],
            ),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", " "),
        ("name", "x" * 201),
        ("description", "x" * 2001),
        ("schema_version", 2),
        ("expected_policy_revision", True),
        ("expected_policy_revision", "1"),
        ("principal_id", "forged"),
        ("instruction_owner", "PROJECT"),
        ("provider_mode", "ANY"),
        ("selected_providers", ["provider-a"]),
        ("idempotency_key", ""),
    ],
)
def test_strict_input_rejects_invalid_and_protected_fields(command, field, value):
    with pytest.raises(ValidationError):
        changed(command, **{field: value})


@pytest.mark.parametrize("selection", [None, ["provider-a", "provider-a"]])
def test_narrow_requires_exact_nonduplicate_selection(command, selection):
    with pytest.raises(ValidationError):
        changed(command, provider_mode="NARROW", selected_providers=selection)


def test_same_key_changed_payload_conflicts(database, actor, command):
    engine, _ = database
    service = ProjectService(engine)
    first = service.create(actor, command)
    assert service.create(actor, command) == first
    with pytest.raises(DomainError) as error:
        service.create(actor, changed(command, name="Different"))
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    assert counts(engine) == (1, 1, 1)


def test_semantically_identical_selection_order_reconciles(database, actor, command):
    service = ProjectService(database[0])
    one = service.create(
        actor,
        changed(command, provider_mode="NARROW", selected_providers=["provider-b", "provider-a"]),
    )
    two = service.create(
        actor,
        changed(command, provider_mode="NARROW", selected_providers=["provider-a", "provider-b"]),
    )
    assert one == two


def test_two_connections_concurrent_duplicate_creates_once(database, actor, command):
    engine, path = database
    other = create_database(path)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(lambda e: ProjectService(e).create(actor, command), [engine, other])
            )
        assert results[0] == results[1]
        assert counts(engine) == (1, 1, 1)
    finally:
        other.dispose()


@pytest.mark.parametrize("principal,epoch", [("unknown", 1), ("viewer-test", 1), ("owner-test", 2)])
def test_wrong_or_stale_actor_denied(database, actor, command, principal, epoch):
    with pytest.raises(DomainError) as error:
        ProjectService(database[0]).create(
            replace(actor, principal_id=principal, principal_epoch=epoch), command
        )
    assert error.value.code == "PERMISSION_DENIED"
    assert counts(database[0]) == (0, 0, 0)


@pytest.mark.parametrize("change", ["disabled", "expired", "wrong_resource", "wrong_action"])
def test_create_grant_is_current_and_exact(database, actor, command, change):
    engine, _ = database
    with transaction(engine) as session:
        grant = session.get(AccessGrant, "project.create")
        if change == "disabled":
            grant.enabled = False
        elif change == "expired":
            grant.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        elif change == "wrong_resource":
            grant.resource_id = "unrelated-deployment"
        else:
            grant.capability = "project.propose"
    with pytest.raises(DomainError) as error:
        ProjectService(engine).create(actor, command)
    assert error.value.code == "PERMISSION_DENIED"
    assert counts(engine) == (0, 0, 0)


def test_receipt_capability_is_not_creation_capability(database, actor, command):
    engine, _ = database
    with transaction(engine) as session:
        session.get(AccessGrant, "project.receipt.read").enabled = False
    with pytest.raises(DomainError):
        ProjectService(engine).create(actor, command)
    assert counts(engine) == (0, 0, 0)


def test_replay_requires_current_receipt_rights_but_not_new_creation(database, actor, command):
    engine, _ = database
    service = ProjectService(engine)
    result = service.create(actor, command)
    with transaction(engine) as session:
        session.get(AccessGrant, "project.create").enabled = False
    assert service.create(actor, command) == result
    with transaction(engine) as session:
        session.get(AccessGrant, "project.receipt.read").enabled = False
    for call in (
        lambda: service.create(actor, command),
        lambda: service.receipt(actor, result.operation_id),
    ):
        with pytest.raises(DomainError) as error:
            call()
        assert error.value.code == "PERMISSION_DENIED"
    assert counts(engine) == (1, 1, 1)


def test_replay_never_reapplies_historical_consent(database, actor, command):
    engine, _ = database
    service = ProjectService(engine)
    original = service.create(actor, command)
    with transaction(engine) as session:
        policy = session.get(DeploymentPolicy, 1)
        policy.revision = 2
        policy.approval_id = policy.approved_by = None
        policy.approved_providers = []
    assert service.create(actor, command) == original
    with transaction(engine) as session:
        assert session.get(DeploymentPolicy, 1).approved_providers == []
    with pytest.raises(DomainError) as error:
        service.create(actor, changed(command, idempotency_key="new"))
    assert error.value.code == "REVISION_CONFLICT"


@pytest.mark.parametrize("race", ["revoke", "policy"])
def test_waiting_transaction_observes_committed_revocation_or_policy(
    database, actor, command, race
):
    engine, path = database
    other = create_database(path)
    started = Event()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction(engine) as session:
                if race == "revoke":
                    session.get(AccessGrant, "project.create").enabled = False
                else:
                    session.get(DeploymentPolicy, 1).revision = 2
                session.flush()  # Hold the writer lock before the competing command starts.

                def competing():
                    started.set()
                    return ProjectService(other).create(actor, command)

                future = pool.submit(competing)
                assert started.wait(timeout=2)
            with pytest.raises(DomainError) as error:
                future.result(timeout=10)
            assert error.value.code == (
                "PERMISSION_DENIED" if race == "revoke" else "REVISION_CONFLICT"
            )
        assert counts(engine) == (0, 0, 0)
    finally:
        other.dispose()


def test_missing_policy_never_returns_success(database, actor, command):
    engine, _ = database
    with transaction(engine) as session:
        session.delete(session.get(DeploymentPolicy, 1))
    with pytest.raises(DomainError) as error:
        ProjectService(engine).create(actor, command)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert counts(engine) == (0, 0, 0)


def test_revoked_or_reactivated_principal_cannot_reuse_old_context(database, actor, command):
    engine, _ = database
    service = ProjectService(engine)
    original = service.create(actor, command)
    with transaction(engine) as session:
        principal = session.get(Principal, actor.principal_id)
        principal.authorization_epoch += 1
    with pytest.raises(DomainError):
        service.receipt(actor, original.operation_id)
