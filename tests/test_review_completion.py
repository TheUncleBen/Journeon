# SPDX-License-Identifier: AGPL-3.0-only
from fastapi.testclient import TestClient
from test_work import work  # noqa: F401

from journeon.api import create_app
from journeon.browser_auth import COOKIE_NAME, BrowserAuth
from journeon.database import transaction
from journeon.models import AccessGrant


def test_review_policy_producer_replay_and_history(work):  # noqa: F811
    engine, _, actor, issued, create = work
    with transaction(engine) as db:
        for action in ("project.review.configure", "project.review.read", "project.receipt.read"):
            db.add(
                AccessGrant(
                    id="review:" + action,
                    principal_id=actor.principal_id,
                    capability=action,
                    resource_kind="project",
                    resource_id=create.project_id,
                    enabled=True,
                    revision=1,
                    provenance="fixture",
                )
            )
    command = dict(
        schema_version=1,
        idempotency_key="review-policy",
        project_id=create.project_id,
        expected_project_revision=1,
        expected_policy_revision=0,
        independent_review_required=True,
        minimum_independence=["FRESH_SESSION"],
        preferred_diversity=["DISTINCT_PROVIDER"],
        required_coverage=["source", "tests"],
        material_severities=["HIGH", "MEDIUM"],
        owner_override_severities=["HIGH"],
        automatic_round_limit=None,
        stop_on_cycle=True,
        stop_on_unchanged_target=True,
    )
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        headers = {"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token}
        response = client.post("/api/v1/projects/review-policy", json=command, headers=headers)
        assert response.status_code == 200, response.text
        first = response.json()
        assert first["policy"]["revision"] == 1
        assert (
            client.post("/api/v1/projects/review-policy", json=command, headers=headers).json()
            == first
        )
        assert client.get(f"/api/v1/operations/{first['operation_id']}").json() == first
        command.update(
            idempotency_key="review-policy-2",
            expected_project_revision=2,
            expected_policy_revision=1,
            required_coverage=["source", "tests", "callers"],
        )
        second = client.post("/api/v1/projects/review-policy", json=command, headers=headers)
        assert second.status_code == 200, second.text
        assert second.json()["policy"]["revision"] == 2
        assert (
            client.get(f"/api/v1/projects/{create.project_id}/review-policy").json()
            == second.json()["policy"]
        )
        assert client.get(f"/api/v1/operations/{first['operation_id']}").json() == first


def configured_policy(environment):
    from journeon.contracts import ReviewPolicyConfigure
    from journeon.reviews import ReviewService

    engine, _, actor, _, create = environment
    with transaction(engine) as db:
        for action in ("project.review.configure", "project.review.read", "project.receipt.read"):
            db.add(
                AccessGrant(
                    id="policy:" + action,
                    principal_id=actor.principal_id,
                    capability=action,
                    resource_kind="project",
                    resource_id=create.project_id,
                    enabled=True,
                    revision=1,
                    provenance="fixture",
                )
            )
    command = ReviewPolicyConfigure(
        schema_version=1,
        idempotency_key="explicit-policy",
        project_id=create.project_id,
        expected_project_revision=1,
        expected_policy_revision=0,
        independent_review_required=False,
        minimum_independence=[],
        preferred_diversity=[],
        required_coverage=[],
        material_severities=[],
        owner_override_severities=[],
        automatic_round_limit=None,
        stop_on_cycle=True,
        stop_on_unchanged_target=True,
    )
    service = ReviewService(engine)
    return service, command, service.configure(actor, command)


def test_policy_schema_requires_explicit_rules_and_consistent_coverage(work):  # noqa: F811
    import pytest
    from pydantic import ValidationError

    from journeon.contracts import ReviewPolicyConfigure

    _, command, _ = configured_policy(work)
    values = command.model_dump()
    for field in ("automatic_round_limit", "independent_review_required", "required_coverage"):
        with pytest.raises(ValidationError):
            ReviewPolicyConfigure.model_validate(
                {key: value for key, value in values.items() if key != field}
            )
    for change in (
        {"independent_review_required": True},
        {"independent_review_required": True, "minimum_independence": ["FRESH_SESSION"]},
        {"material_severities": ["HIGH", "HIGH"]},
        {"owner_override_severities": ["HIGH"]},
        {"automatic_round_limit": 0},
    ):
        with pytest.raises(ValidationError):
            ReviewPolicyConfigure.model_validate(values | change)


def test_policy_replay_authorizes_original_scope_before_corrupt_receipt(work):  # noqa: F811
    import pytest
    from sqlalchemy import select, text

    from journeon.contracts import DomainError

    engine, _, actor, _, _ = work
    service, command, receipt = configured_policy(work)
    with transaction(engine) as db:
        grant = db.scalar(
            select(AccessGrant).where(AccessGrant.id == "policy:project.review.configure")
        )
        grant.enabled = False
        db.execute(
            text("UPDATE operation_receipts SET result='not-json' WHERE id=:id"),
            {"id": receipt.operation_id},
        )
    with pytest.raises(DomainError) as caught:
        service.configure(actor, command.model_copy(update={"project_id": "different-project"}))
    assert caught.value.code == "PERMISSION_DENIED"


def test_policy_read_authorizes_before_corrupt_snapshot(work):  # noqa: F811
    import pytest
    from sqlalchemy import select, text

    from journeon.contracts import DomainError

    engine, _, actor, _, _ = work
    service, command, _ = configured_policy(work)
    with transaction(engine) as db:
        grant = db.scalar(select(AccessGrant).where(AccessGrant.id == "policy:project.review.read"))
        grant.enabled = False
        db.execute(text("DROP TRIGGER review_policy_no_update"))
        db.execute(text("UPDATE review_policy_revisions SET snapshot='not-json'"))
    with pytest.raises(DomainError) as caught:
        service.policy(actor, command.project_id)
    assert caught.value.code == "PERMISSION_DENIED"


def test_policy_history_is_immutable_and_rolls_back_on_revoked_commit(work, monkeypatch):  # noqa: F811
    import pytest
    from sqlalchemy import func, select, text
    from sqlalchemy.exc import IntegrityError

    from journeon import reviews
    from journeon.contracts import DomainError
    from journeon.models import OutboxEvent, Project, Receipt, ReviewPolicyRevision

    engine, _, actor, _, _ = work
    service, command, _ = configured_policy(work)
    with pytest.raises(IntegrityError), transaction(engine) as db:
        db.execute(text("UPDATE review_policy_revisions SET content_hash='changed'"))
    with pytest.raises(IntegrityError), transaction(engine) as db:
        db.execute(text("DELETE FROM review_policy_revisions"))
    actual = reviews.require_grant
    count = 0

    def revoke_at_commit(db, principal, capability, **scope):
        nonlocal count
        if capability == "project.review.configure":
            count += 1
            if count == 2:
                raise DomainError(
                    "PERMISSION_DENIED", "Disposable authorization expiry before commit"
                )
        return actual(db, principal, capability, **scope)

    monkeypatch.setattr(reviews, "require_grant", revoke_at_commit)
    with pytest.raises(DomainError) as caught:
        service.configure(
            actor,
            command.model_copy(
                update={
                    "idempotency_key": "next-policy",
                    "expected_project_revision": 2,
                    "expected_policy_revision": 1,
                }
            ),
        )
    assert caught.value.code == "PERMISSION_DENIED"
    with transaction(engine) as db:
        assert db.scalar(select(func.count()).select_from(ReviewPolicyRevision)) == 1
        assert db.get(Project, command.project_id).revision == 2
        assert (
            db.scalar(
                select(func.count())
                .select_from(Receipt)
                .where(Receipt.command == "project.review.configure.v1")
            )
            == 1
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(OutboxEvent)
                .where(OutboxEvent.event_type == "project.review.configured")
            )
            == 1
        )
