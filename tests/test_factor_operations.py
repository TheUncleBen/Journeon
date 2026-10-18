# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import func, select, text

from journeon.contracts import DomainError, PasskeyLabelCommand
from journeon.database import transaction
from journeon.factors import FactorService
from journeon.models import OutboxEvent, Passkey, Receipt
from journeon.receipts import OperationService


@pytest.fixture
def factor(database, actor):
    with transaction(database[0]) as db:
        db.add(
            Passkey(
                id="key-one",
                principal_id=actor.principal_id,
                label="First",
                credential_id="fixture-id",
                credential_data="fixture-data",
                sign_count=0,
                backup_eligible=False,
                backed_up=False,
                revoked=False,
            )
        )
    return FactorService(database[0])


def label_command(**changes):
    return PasskeyLabelCommand(
        schema_version=1,
        idempotency_key="label-one",
        passkey_id="key-one",
        expected_revision=1,
        label="Renamed",
        **changes,
    )


def test_label_receipt_is_canonical_and_retry_is_once(database, actor, factor):
    result = factor.label(actor, label_command())
    assert result == factor.label(actor, label_command())
    assert result == OperationService(database[0]).receipt(actor, result.operation_id)
    assert result.passkey.label == "Renamed"
    with transaction(database[0]) as db:
        receipt = db.get(Receipt, result.operation_id)
        assert receipt.project_id is None
        assert receipt.target_kind == "passkey"
        assert receipt.target_id == "key-one"
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == 1
        assert db.get(Passkey, "key-one").revision == 2


def test_denied_factor_receipt_never_decodes_corrupt_result(database, actor, factor):
    result = factor.label(actor, label_command())
    with database[0].begin() as connection:
        connection.execute(text("UPDATE operation_receipts SET result = 'broken'"))
        connection.execute(
            text("UPDATE principals SET enabled = 0 WHERE id = :id"), {"id": actor.principal_id}
        )
    with pytest.raises(DomainError) as error:
        OperationService(database[0]).receipt(actor, result.operation_id)
    assert error.value.code == "AUTHENTICATION_REQUIRED"


def test_factor_receipt_rejects_result_row_mismatch(database, actor, factor):
    result = factor.label(actor, label_command())
    with transaction(database[0]) as db:
        row = db.get(Receipt, result.operation_id)
        row.result = {**row.result, "operation_id": "other-operation"}
    with pytest.raises(DomainError) as error:
        OperationService(database[0]).receipt(actor, result.operation_id)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"


@pytest.mark.parametrize(
    "change", ["wrong_owner", "revoked_session", "stale", "weak", "revoked_key"]
)
def test_label_rechecks_current_authority(database, actor, factor, change):
    from journeon.models import BrowserSession

    with transaction(database[0]) as db:
        key = db.get(Passkey, "key-one")
        record = db.get(BrowserSession, actor.authentication_ref)
        if change == "wrong_owner":
            key.principal_id = "viewer-test"
        elif change == "revoked_session":
            record.revoked = True
        elif change == "stale":
            key.revision += 1
        elif change == "weak":
            record.strong_authenticated_at = None
        else:
            key.revoked = True
    with pytest.raises(DomainError):
        factor.label(actor, label_command())
    with transaction(database[0]) as db:
        assert db.scalar(select(func.count()).select_from(Receipt)) == 0
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == 0
        assert db.get(Passkey, "key-one").label == "First"


def test_label_changed_retry_conflicts(database, actor, factor):
    result = factor.label(actor, label_command())
    changed = label_command().model_copy(update={"label": "Other"})
    with pytest.raises(DomainError) as error:
        factor.label(actor, changed)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    assert OperationService(database[0]).receipt(actor, result.operation_id) == result


def test_label_atomic_rollback(database, actor, factor, monkeypatch):
    import journeon.factors as factors

    original = factors.owned_key
    calls = 0

    def fail_final(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("synthetic interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(factors, "owned_key", fail_final)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        factor.label(actor, label_command())
    with transaction(database[0]) as db:
        assert db.get(Passkey, "key-one").label == "First"
        assert db.scalar(select(func.count()).select_from(Receipt)) == 0
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == 0


def test_label_concurrent_retry_commits_once(database, actor, factor):
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: factor.label(actor, label_command()), range(2)))
    assert results[0] == results[1]
    with transaction(database[0]) as db:
        assert db.get(Passkey, "key-one").revision == 2
        assert db.scalar(select(func.count()).select_from(Receipt)) == 1
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == 1


def test_self_service_shared_principal_cannot_impersonate(database, actor, factor):
    from journeon.models import BrowserSession
    from journeon.permissions import AuthenticatedContext
    from journeon.sessions import issue_session

    with transaction(database[0]) as db:
        db.get(Passkey, "key-one").principal_id = "viewer-test"
        issued = issue_session(
            db, "viewer-test", authentication_method="fixture", client_label="Fixture", strong=True
        )
        assert db.get(BrowserSession, issued.session_id).audience == "unknown"
    shared = AuthenticatedContext("viewer-test", 1, issued.session_id)
    with pytest.raises(DomainError):
        factor.label(actor, label_command())
    result = factor.label(shared, label_command())
    assert result.passkey.principal_id == "viewer-test"
    with pytest.raises(DomainError):
        OperationService(database[0]).receipt(actor, result.operation_id)


def test_label_api_and_receipt_union(database, actor, factor):
    from fastapi.testclient import TestClient

    from journeon.api import authenticated_context, create_app

    app = create_app(database[0])
    app.dependency_overrides[authenticated_context] = lambda: actor
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/passkeys/label", json=label_command().model_dump())
        assert response.status_code == 200
        result = response.json()
        assert result["command"] == "passkey.label.v1"
        assert "project" not in result
        receipt = client.get("/api/v1/operations/" + result["operation_id"])
        assert receipt.status_code == 200
        assert receipt.json() == result
        invalid = {**label_command().model_dump(), "approved": True}
        assert client.post("/api/v1/auth/passkeys/label", json=invalid).status_code == 422
