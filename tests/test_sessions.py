# SPDX-License-Identifier: AGPL-3.0-only
from dataclasses import replace

import pytest
from fastapi import Response
from fastapi.testclient import TestClient
from sqlalchemy import text

from journeon import sessions
from journeon.api import create_app
from journeon.browser_auth import COOKIE_NAME, BrowserAuth
from journeon.contracts import DomainError
from journeon.database import create_database, transaction
from journeon.models import BrowserSession, Principal
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService
from journeon.sessions import (
    DEFAULT_SESSION_POLICY,
    SessionPolicy,
    current_session,
    digest,
    issue_session,
    resolve_cookie,
    revoke_session,
    rotate_session,
)


def test_unknown_authentication_reference_cannot_mutate(database, actor, command):
    with pytest.raises(DomainError):
        ProjectService(database[0]).create(
            replace(actor, authentication_ref="unverified-session"), command
        )


@pytest.fixture
def clock(monkeypatch):
    now = [2000000000]
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now[0])
    return now


def issue(engine, principal="owner-test", *, policy=DEFAULT_SESSION_POLICY, strong=True):
    with transaction(engine) as db:
        return issue_session(
            db,
            principal,
            authentication_method="test-fixture",
            client_label="Synthetic browser",
            strong=strong,
            policy=policy,
        )


@pytest.mark.parametrize(
    "field", ["absolute_seconds", "inactivity_seconds", "strong_freshness_seconds"]
)
@pytest.mark.parametrize("invalid", [0, -1, True, 1.5, float("inf"), "300"])
def test_policy_rejects_invalid_durations(field, invalid):
    with pytest.raises(ValueError):
        SessionPolicy(**{field: invalid})


def test_only_approved_defaults():
    assert SessionPolicy() == SessionPolicy(604800, 43200, 300)


def test_session_secrets_are_hashed_and_not_repr(database, clock):
    engine, path = database
    issued = issue(engine)
    assert issued.token not in repr(issued)
    assert issued.csrf_token not in repr(issued)
    with transaction(engine) as db:
        row = db.get(BrowserSession, issued.session_id)
        assert row.token_hash == digest(issued.token)
        assert row.csrf_hash == digest(issued.csrf_token)
    engine.dispose()
    assert issued.token.encode() not in path.read_bytes()
    assert issued.csrf_token.encode() not in path.read_bytes()


@pytest.mark.parametrize("deadline", ["idle", "absolute"])
def test_exact_deadlines_and_polling_do_not_extend_session(database, clock, deadline):
    engine, _ = database
    policy = SessionPolicy(10, 100, 5) if deadline == "absolute" else SessionPolicy(100, 10, 5)
    issued = issue(engine, policy=policy)
    for seconds in (1, 5, 9):
        clock[0] = 2000000000 + seconds
        with transaction(engine) as db:
            current_session(db, issued.session_id)
    clock[0] += 1
    with pytest.raises(DomainError), transaction(engine) as db:
        current_session(db, issued.session_id)


def test_activity_slides_only_idle_and_strong_freshness_is_independent(database, clock):
    engine, _ = database
    issued = issue(engine, policy=SessionPolicy(20, 10, 5))
    for seconds in (9, 18):
        clock[0] = 2000000000 + seconds
        with transaction(engine) as db:
            row = resolve_cookie(db, issued.token, csrf_token=issued.csrf_token, mutation=True)
            assert row.absolute_deadline == 2000000020
        with pytest.raises(DomainError), transaction(engine) as db:
            current_session(db, issued.session_id, strong=True)
    clock[0] = 2000000020
    with pytest.raises(DomainError), transaction(engine) as db:
        current_session(db, issued.session_id)


def test_rotation_invalidates_old_cookie_and_context_without_sliding_absolute(database, clock):
    engine, _ = database
    issued = issue(engine)
    clock[0] += 20
    with transaction(engine) as db:
        rotated = rotate_session(db, issued.session_id, strong=True)
        new = current_session(db, rotated.session_id, strong=True)
        assert new.absolute_deadline == 2000000000 + 604800
    for old in (issued.token, "X" * 43):
        with pytest.raises(DomainError), transaction(engine) as db:
            resolve_cookie(db, old)
    with pytest.raises(DomainError), transaction(engine) as db:
        current_session(db, issued.session_id)


def test_revoke_persists_across_restart_and_shared_user_cannot_revoke_owner(database, clock):
    engine, path = database
    owner = issue(engine)
    shared = issue(engine, "viewer-test")
    with pytest.raises(DomainError), transaction(engine) as db:
        revoke_session(db, shared.session_id, owner.session_id)
    with transaction(engine) as db:
        revoke_session(db, owner.session_id, shared.session_id)
        revoke_session(db, owner.session_id, owner.session_id)
    engine.dispose()
    reopened = create_database(path)
    try:
        for token in (owner.token, shared.token):
            with pytest.raises(DomainError), transaction(reopened) as db:
                resolve_cookie(db, token)
    finally:
        reopened.dispose()


@pytest.mark.parametrize("change", ["revoked", "disabled", "epoch", "clock_rollback"])
def test_current_identity_and_clock_are_rechecked(database, clock, change):
    engine, _ = database
    issued = issue(engine)
    with transaction(engine) as db:
        if change == "revoked":
            db.get(BrowserSession, issued.session_id).revoked = True
        elif change == "disabled":
            db.get(Principal, "owner-test").enabled = False
        elif change == "epoch":
            db.get(Principal, "owner-test").authorization_epoch += 1
        else:
            clock[0] -= 1
    with pytest.raises(DomainError), transaction(engine) as db:
        resolve_cookie(db, issued.token)


@pytest.mark.parametrize("operation", ["create", "retry", "receipt"])
def test_session_revoked_after_resolution_blocks_mutation_and_disclosure(
    database, command, operation
):
    engine, _ = database
    issued = issue(engine)
    actor = AuthenticatedContext("owner-test", 1, issued.session_id)
    service = ProjectService(engine)
    accepted = service.create(actor, command)
    with transaction(engine) as db:
        revoke_session(db, issued.session_id, issued.session_id)
        db.execute(text("UPDATE operation_receipts SET result = '{'"))
    with pytest.raises(DomainError) as error:
        if operation == "receipt":
            service.receipt(actor, accepted.operation_id)
        else:
            service.create(
                actor,
                command
                if operation == "retry"
                else command.model_copy(update={"idempotency_key": "second-operation"}),
            )
    assert error.value.code == "AUTHENTICATION_REQUIRED"


def test_cookie_binding_requires_origin_csrf_and_current_server_session(database, command):
    engine, _ = database
    issued = issue(engine)
    binding = BrowserAuth("https://example.test")
    app = create_app(engine, browser_auth=binding)
    with TestClient(app, base_url="https://example.test") as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        for headers in (
            {},
            {"Origin": "https://evil.test", "X-CSRF-Token": issued.csrf_token},
            {"Origin": binding.canonical_origin},
            {"Origin": binding.canonical_origin, "X-CSRF-Token": "X" * 43},
            {"X-Forwarded-Host": "example.test", "X-CSRF-Token": issued.csrf_token},
        ):
            assert (
                client.post(
                    "/api/v1/projects", json=command.model_dump(), headers=headers
                ).status_code
                == 401
            )
        response = client.post(
            "/api/v1/projects",
            json=command.model_dump(),
            headers={
                "Origin": binding.canonical_origin,
                "X-CSRF-Token": issued.csrf_token,
            },
        )
        assert response.status_code == 200
        operation_id = response.json()["operation_id"]
        assert client.get(f"/api/v1/operations/{operation_id}").status_code == 200
        assert (
            client.get(
                f"/api/v1/operations/{operation_id}", headers={"Origin": "https://evil.test"}
            ).status_code
            == 401
        )
    response = Response()
    binding.set_cookie(response, issued)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert "Domain=" not in cookie and "Path=/" in cookie
    assert response.headers["cache-control"] == "no-store"


def test_origin_configuration_cannot_enable_cleartext_or_arbitrary_paths():
    for origin in ("http://localhost", "https://example.test/", "https://a@b", "https://a?q=1"):
        with pytest.raises(ValueError):
            BrowserAuth(origin)


def test_missing_binding_still_denies_even_valid_cookie(database, command):
    issued = issue(database[0])
    with TestClient(create_app(database[0]), base_url="https://example.test") as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        assert (
            client.post(
                "/api/v1/projects",
                json=command.model_dump(),
                headers={
                    "Origin": "https://example.test",
                    "X-CSRF-Token": issued.csrf_token,
                },
            ).status_code
            == 401
        )


def test_expiration_at_final_commit_rolls_back_all_project_effects(database, clock, command):
    from sqlalchemy import event, func, select

    from journeon.models import OutboxEvent, Project, Receipt

    engine, _ = database
    issued = issue(engine, policy=SessionPolicy(10, 10, 5))
    actor = AuthenticatedContext("owner-test", 1, issued.session_id)

    def expire_after_outbox(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO outbox_events"):
            clock[0] += 10

    event.listen(engine, "after_cursor_execute", expire_after_outbox)
    try:
        with pytest.raises(DomainError):
            ProjectService(engine).create(actor, command)
    finally:
        event.remove(engine, "after_cursor_execute", expire_after_outbox)
    with transaction(engine) as db:
        for model in (Project, Receipt, OutboxEvent):
            assert db.scalar(select(func.count()).select_from(model)) == 0


def test_session_migration_preserves_existing_owner_and_project_records(tmp_path):
    from alembic import command as alembic_command

    from journeon.migrate import configuration, upgrade

    engine = create_database(tmp_path / "upgrade.db")
    config = configuration()
    try:
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            alembic_command.upgrade(config, "0001_foundation")
            connection.execute(
                text("INSERT INTO principals VALUES ('existing-owner', 'OWNER', 1, 7)")
            )
            connection.execute(
                text(
                    "INSERT INTO projects VALUES ('existing-project', 2, 'Kept', 'Kept', "
                    "'existing-owner', 'ENVIRONMENT', 'existing-ref', '{}', NULL, '[]', '2026')"
                )
            )
        upgrade(engine)
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT id, authorization_epoch FROM principals")
            ).all() == [("existing-owner", 7)]
            assert connection.execute(text("SELECT id, revision FROM projects")).all() == [
                ("existing-project", 2)
            ]
            assert connection.execute(text("SELECT count(*) FROM browser_sessions")).scalar() == 0
    finally:
        engine.dispose()


def test_rotation_rolls_back_both_records_on_failed_commit(database, clock):
    engine, _ = database
    issued = issue(engine)
    with pytest.raises(RuntimeError), transaction(engine) as db:
        rotated = rotate_session(db, issued.session_id, strong=True)
        raise RuntimeError("Synthetic rollback")
    with transaction(engine) as db:
        assert resolve_cookie(db, issued.token).id == issued.session_id
        assert db.get(BrowserSession, rotated.session_id) is None


def test_clock_rollback_after_restart_cannot_extend_observed_deadline(database, clock):
    engine, path = database
    issued = issue(engine)
    clock[0] += 50
    with transaction(engine) as db:
        resolve_cookie(db, issued.token)
    engine.dispose()
    clock[0] -= 1
    reopened = create_database(path)
    try:
        with pytest.raises(DomainError), transaction(reopened) as db:
            resolve_cookie(db, issued.token)
    finally:
        reopened.dispose()


def test_inventory_filters_shared_users_and_never_returns_verifiers(database, clock):
    from journeon.sessions import session_inventory

    engine, _ = database
    owner = issue(engine)
    shared = issue(engine, "viewer-test")
    with transaction(engine) as db:
        assert len(session_inventory(db, owner.session_id)) == 2
        rows = session_inventory(db, shared.session_id)
        assert len(rows) == 1 and rows[0]["principal_id"] == "viewer-test"
        assert "token_hash" not in rows[0] and "csrf_hash" not in rows[0]
        assert shared.token not in repr(rows) and shared.csrf_token not in repr(rows)


def test_rotation_cannot_cross_absolute_deadline(database, clock, monkeypatch):
    engine, _ = database
    issued = issue(engine, policy=SessionPolicy(10, 100, 5))
    times = iter([2000000009, 2000000010, 2000000010])
    monkeypatch.setattr(sessions, "utc_seconds", lambda: next(times))
    with pytest.raises(DomainError), transaction(engine) as db:
        rotate_session(db, issued.session_id, strong=True)
