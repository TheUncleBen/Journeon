# SPDX-License-Identifier: AGPL-3.0-only
import re

import pytest
from sqlalchemy import func, select
from test_workspace_provisioning import enrolled_owner  # noqa: F401

from journeon.database import transaction
from journeon.models import AccessGrant, BrowserSession, OutboxEvent, Receipt, StoreIdentity


def field_names(value):
    if isinstance(value, dict):
        return set(value).union(*(field_names(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(field_names(item) for item in value))
    return set()


def test_fresh_owner_reads_current_context_without_prolonging_session(
    enrolled_owner,  # noqa: F811
    monkeypatch,
):
    owner = enrolled_owner
    with transaction(owner.engine) as db:
        session = db.scalar(
            select(BrowserSession).where(
                BrowserSession.principal_id == owner.principal_id,
                BrowserSession.revoked.is_(False),
            )
        )
        expected = {
            "session_id": session.id,
            "authentication_method": session.authentication_method,
            "audience": session.audience,
            "issued_at": session.issued_at,
            "absolute_deadline": session.absolute_deadline,
            "inactivity_seconds": session.inactivity_seconds,
            "strong_authenticated_at": session.strong_authenticated_at,
            "strong_freshness_seconds": session.strong_freshness_seconds,
        }
        idle_activity = session.last_activity
        observed = session.last_observed
        incarnation = db.get(StoreIdentity, 1).incarnation
        assert db.scalar(select(func.count()).select_from(AccessGrant)) == 0
        receipts_before = db.scalar(select(func.count()).select_from(Receipt))
        events_before = db.scalar(select(func.count()).select_from(OutboxEvent))
    versions = []
    for offset in (5, 6):
        monkeypatch.setattr("journeon.sessions.utc_seconds", lambda now=observed + offset: now)
        response = owner.client.get("/api/v1/auth/context", headers=owner.headers)
        assert response.status_code == 200
        if response.headers.get("cache-control") != "no-store" or "set-cookie" in response.headers:
            pytest.fail("Context reads must not cache or rotate authentication")
        context = response.json()
        if context.get("principal_id") != owner.principal_id or context.get("role") != "OWNER":
            pytest.fail("Context must identify the currently authenticated human")
        if context.get("store_incarnation") != incarnation:
            pytest.fail("Context must identify the current store incarnation")
        current = context.get("session")
        if not isinstance(current, dict):
            pytest.fail("Context must include the verified current session metadata")
        for name, value in expected.items():
            if current.get(name) != value:
                pytest.fail("Context session metadata differs from the verified record")
        version = current.get("security_version")
        if not isinstance(version, str) or re.fullmatch(r"[a-f0-9]{64}", version) is None:
            pytest.fail("Context must include the session security version")
        versions.append(version)
        if {"token", "token_hash", "csrf_token", "csrf_hash", "enrollment_secret"} & field_names(
            context
        ):
            pytest.fail("Read-only context disclosed authentication material")
    if versions[0] != versions[1]:
        pytest.fail("Polling must not change the session security version")
    with transaction(owner.engine) as db:
        session = db.scalar(
            select(BrowserSession).where(
                BrowserSession.principal_id == owner.principal_id,
                BrowserSession.revoked.is_(False),
            )
        )
        assert session.last_activity == idle_activity
        assert session.last_observed >= observed + 6
        assert session.absolute_deadline == expected["absolute_deadline"]
        assert db.scalar(select(func.count()).select_from(AccessGrant)) == 0
        assert db.scalar(select(func.count()).select_from(Receipt)) == receipts_before
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == events_before
