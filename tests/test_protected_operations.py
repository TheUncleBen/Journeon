# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from test_factor_operations import factor, label_command  # noqa: F401

from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.models import BrowserSession
from journeon.protected import FixtureProtectedPolicy, ProtectedService


@pytest.fixture
def protected(database, actor, request):
    request.getfixturevalue("factor")
    with transaction(database[0]) as db:
        db.get(BrowserSession, actor.authentication_ref).audience = "official_browser"
    policy = FixtureProtectedPolicy(request_seconds=503, preview_seconds=97, fixture_only=True)
    return ProtectedService.for_fixtures(database[0], policy)


def test_separate_consent_and_once_only_commit(database, actor, protected):
    request = protected.prepare_label(actor, label_command())
    with pytest.raises(DomainError):
        protected.commit(actor, request)
    nonce = protected.preview(actor, request).nonce
    protected.approve(actor, request, nonce)
    result = protected.commit(actor, request)
    assert result == protected.commit(actor, request)
    with pytest.raises(DomainError):
        protected.approve(actor, request, nonce)


def test_rotation_cannot_transfer_pending_request(database, actor, protected):
    from journeon.permissions import AuthenticatedContext
    from journeon.sessions import rotate_session

    request = protected.prepare_label(actor, label_command())
    nonce = protected.preview(actor, request).nonce
    with transaction(database[0]) as db:
        replacement = rotate_session(db, actor.authentication_ref, strong=True)
    replacement_actor = AuthenticatedContext(
        actor.principal_id, actor.principal_epoch, replacement.session_id
    )
    for identity in (actor, replacement_actor):
        with pytest.raises(DomainError):
            protected.approve(identity, request, nonce)


def test_unqualified_audience_cannot_prepare(database, actor, protected):
    with transaction(database[0]) as db:
        db.get(BrowserSession, actor.authentication_ref).audience = "unknown"
    with pytest.raises(DomainError):
        protected.prepare_label(actor, label_command())


@pytest.mark.parametrize(
    "change", ["epoch", "policy", "credential", "payload", "idempotency", "revoked", "audience"]
)
def test_currentness_blocks_approved_effect(database, actor, protected, change):
    from journeon.models import Principal, ProtectedRequest

    request_id = protected.prepare_label(actor, label_command())
    nonce = protected.preview(actor, request_id).nonce
    protected.approve(actor, request_id, nonce)
    with transaction(database[0]) as db:
        if change == "epoch":
            db.get(Principal, actor.principal_id).authorization_epoch += 1
        elif change == "policy":
            db.get(BrowserSession, actor.authentication_ref).strong_freshness_seconds += 1
        elif change == "credential":
            db.get(Principal, actor.principal_id).credential_revision += 1
        elif change == "payload":
            row = db.get(ProtectedRequest, request_id)
            row.payload = {**row.payload, "label": "Altered"}
        elif change == "idempotency":
            row = db.get(ProtectedRequest, request_id)
            row.payload = {**row.payload, "idempotency_key": "altered-operation"}
        elif change == "revoked":
            db.get(BrowserSession, actor.authentication_ref).revoked = True
        else:
            db.get(BrowserSession, actor.authentication_ref).audience = "unknown"
    with pytest.raises(DomainError):
        protected.commit(actor, request_id)
    from journeon.models import Passkey

    with transaction(database[0]) as db:
        assert db.get(Passkey, "key-one").label == "First"


def test_preview_reissue_cannot_reuse_old_nonce(database, actor, protected):
    from journeon.models import ProtectedRequest

    request_id = protected.prepare_label(actor, label_command())
    first = protected.preview(actor, request_id).nonce
    with transaction(database[0]) as db:
        deadline = db.get(ProtectedRequest, request_id).deadline
    second = protected.preview(actor, request_id).nonce
    with pytest.raises(DomainError):
        protected.approve(actor, request_id, first)
    protected.approve(actor, request_id, second)
    with transaction(database[0]) as db:
        assert db.get(ProtectedRequest, request_id).deadline == deadline


@pytest.mark.parametrize("boundary", ["preview", "request", "approval", "strong"])
@pytest.mark.parametrize("offset", [-1, 0])
def test_independent_exact_deadlines(database, actor, protected, monkeypatch, boundary, offset):
    import journeon.protected as protocol
    import journeon.sessions as sessions

    with transaction(database[0]) as db:
        now = db.get(BrowserSession, actor.authentication_ref).issued_at
        db.get(BrowserSession, actor.authentication_ref).strong_freshness_seconds = (
            211 if boundary == "strong" else 1201
        )
    if boundary == "request":
        protected = ProtectedService.for_fixtures(
            database[0],
            FixtureProtectedPolicy(request_seconds=151, preview_seconds=97, fixture_only=True),
        )
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now)
    request_id = protected.prepare_label(actor, label_command())
    nonce = protected.preview(actor, request_id).nonce
    if boundary != "preview":
        protected.approve(actor, request_id, nonce)
    deadline = {"preview": 97, "request": 151, "approval": 300, "strong": 211}[boundary]
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now + deadline + offset)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + deadline + offset)

    def action():
        if boundary == "preview":
            protected.approve(actor, request_id, nonce)
        else:
            protected.commit(actor, request_id)

    if offset == 0:
        with pytest.raises(DomainError):
            action()
    else:
        action()


def test_cancel_commit_race_is_truthful(database, actor, protected):
    from concurrent.futures import ThreadPoolExecutor

    from journeon.models import Passkey, ProtectedRequest

    request_id = protected.prepare_label(actor, label_command())
    protected.approve(actor, request_id, protected.preview(actor, request_id).nonce)

    def commit():
        try:
            return protected.commit(actor, request_id)
        except DomainError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(commit), pool.submit(protected.cancel, actor, request_id)]
        results = [future.result() for future in futures]
    with transaction(database[0]) as db:
        row = db.get(ProtectedRequest, request_id)
        if row.state == "COMMITTED":
            assert results[0] == results[1]
            assert db.get(Passkey, "key-one").label == "Renamed"
        else:
            assert row.state == "CANCELLED"
            assert results == [None, None]
            assert db.get(Passkey, "key-one").label == "First"


def test_lost_response_reconciles_from_new_current_session(database, actor, protected):
    from journeon.permissions import AuthenticatedContext
    from journeon.sessions import rotate_session

    request_id = protected.prepare_label(actor, label_command())
    protected.approve(actor, request_id, protected.preview(actor, request_id).nonce)
    result = protected.commit(actor, request_id)
    with transaction(database[0]) as db:
        issued = rotate_session(db, actor.authentication_ref, strong=True)
    replacement = AuthenticatedContext(actor.principal_id, actor.principal_epoch, issued.session_id)
    assert protected.commit(replacement, request_id) == result
    with pytest.raises(DomainError):
        protected.commit(actor, request_id)


def test_fixture_passkey_protected_routes_remain_unavailable(database):
    from journeon.api import create_app

    with pytest.raises(TypeError):
        ProtectedService(database[0])
    with pytest.raises(ValueError):
        FixtureProtectedPolicy(request_seconds=503, preview_seconds=97, fixture_only=False)
    paths = create_app(database[0]).openapi()["paths"]
    assert {path for path in paths if "protected" in path} == {
        "/api/v1/protected-operations/prepare",
        "/api/v1/protected-operations/preview",
        "/api/v1/protected-operations/confirm",
        "/api/v1/protected-operations/cancel",
    }
    assert all("/add" not in path and "/remove" not in path for path in paths)
    effect = create_app(database[0]).openapi()["components"]["schemas"]["ProtectedPrepare"][
        "properties"
    ]["effect"]
    assert set(effect["discriminator"]["mapping"]) == {
        "project.root.admit.v1",
        "project.root.revoke.v1",
        "project.instructions.policy.configure.v1",
        "instruction.candidate.register.v1",
        "instruction.release.install.v1",
        "project.instructions.accept.v1",
        "project.instructions.recover.v1",
    }


def test_concurrent_protected_consumers_commit_once(database, actor, protected):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import func, select

    from journeon.models import OutboxEvent, Passkey, Receipt

    request_id = protected.prepare_label(actor, label_command())
    protected.approve(actor, request_id, protected.preview(actor, request_id).nonce)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: protected.commit(actor, request_id), range(2)))
    assert results[0] == results[1]
    with transaction(database[0]) as db:
        assert db.get(Passkey, "key-one").revision == 2
        assert db.scalar(select(func.count()).select_from(Receipt)) == 1
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == 1


def test_expiry_observation_survives_restart_and_clock_rollback(
    database, actor, protected, monkeypatch
):
    import journeon.protected as protocol
    import journeon.sessions as sessions
    from journeon.database import create_database

    with transaction(database[0]) as db:
        now = db.get(BrowserSession, actor.authentication_ref).issued_at
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now)
    request_id = protected.prepare_label(actor, label_command())
    nonce = protected.preview(actor, request_id).nonce
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now + 97)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 97)
    with pytest.raises(DomainError):
        protected.approve(actor, request_id, nonce)
    restarted = create_database(database[1])
    try:
        service = ProtectedService.for_fixtures(restarted, protected.policy)
        monkeypatch.setattr(protocol, "utc_seconds", lambda: now + 1)
        monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 1)
        with pytest.raises(DomainError):
            service.approve(actor, request_id, nonce)
    finally:
        restarted.dispose()


def test_prepare_retry_preserves_request_identity_and_deadline(database, actor, protected):
    from journeon.models import ProtectedRequest

    original = protected.prepare_label(actor, label_command())
    with transaction(database[0]) as db:
        deadline = db.get(ProtectedRequest, original).deadline
    retry = protected.prepare_label(actor, label_command())
    assert retry == original
    with transaction(database[0]) as db:
        assert db.get(ProtectedRequest, original).deadline == deadline
    with pytest.raises(DomainError):
        protected.prepare_label(actor, label_command().model_copy(update={"label": "Changed"}))


@pytest.mark.parametrize("preparation_delay", [0, 5])
def test_exact_service_view_and_terminal_status(
    database, actor, protected, monkeypatch, preparation_delay
):
    import journeon.protected as protocol
    import journeon.sessions as sessions

    with transaction(database[0]) as db:
        now = db.get(BrowserSession, actor.authentication_ref).issued_at + preparation_delay
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now)
    request_id = protected.prepare_label(actor, label_command())
    view = protected.preview(actor, request_id)
    assert view.command == label_command()
    assert view.request_id == request_id
    assert view.nonce not in repr(view)
    assert protected.status(actor, request_id) == "PENDING"
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now + 502)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 502)
    assert protected.status(actor, request_id) == "PENDING"
    monkeypatch.setattr(protocol, "utc_seconds", lambda: now + 503)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 503)
    assert protected.status(actor, request_id) == "EXPIRED"
    protected.cancel(actor, request_id)
    assert protected.status(actor, request_id) == "EXPIRED"
