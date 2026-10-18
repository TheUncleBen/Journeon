# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from test_passkeys import Authenticator

from journeon.contracts import DomainError
from journeon.database import create_database
from journeon.migrate import upgrade
from journeon.passkeys import PasskeyPolicy, PasskeyService


@pytest.fixture
def policy_service(tmp_path, monkeypatch):
    clock = [1000]
    monkeypatch.setattr("journeon.passkeys.utc_seconds", lambda: clock[0])
    monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: clock[0])
    engine = create_database(tmp_path / "policy.db")
    upgrade(engine)
    service = PasskeyService(
        engine,
        rp_id="example.test",
        origin="https://example.test",
        policy=PasskeyPolicy(600, 900, 3, 3, 60, failures_per_window=3, failure_window_seconds=60),
    )
    yield service, clock
    engine.dispose()


def enroll(service):
    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="setup")
    issued = service.complete(
        challenge.ceremony_id,
        purpose="bootstrap",
        response=key.register(challenge.options),
        source="local",
    )
    return key, issued


def invalid_assertion(key, challenge):
    response = key.assert_key(challenge.options)
    response["response"]["signature"] = "aW52YWxpZA"
    return response


def test_source_starts_use_a_rolling_window(policy_service):
    service, clock = policy_service
    service.begin_login(source="shared-nat", label="Browser")
    clock[0] += 59
    for _ in range(2):
        service.begin_login(source="shared-nat", label="Browser")
    clock[0] += 1
    service.begin_login(source="shared-nat", label="Browser")
    with pytest.raises(DomainError):
        service.begin_login(source="shared-nat", label="Browser")


def test_failure_budget_shared_across_sources_purposes_and_renewals(policy_service):
    service, _ = policy_service
    key, issued = enroll(service)
    for index in range(3):
        if index == 1:
            challenge = service.begin_stepup(issued.session_id, source=f"source-{index}")
            purpose, session_id = "stepup", issued.session_id
        else:
            challenge = service.begin_login(source=f"source-{index}", label="Browser")
            purpose, session_id = "login", None
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id,
                purpose=purpose,
                session_id=session_id,
                response=invalid_assertion(key, challenge),
                source=f"source-{index}",
            )
    challenge = service.begin_login(source="another-source", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            response=key.assert_key(challenge.options),
            source="local",
        )


def failure_events(service):
    from sqlalchemy import select

    from journeon.database import transaction
    from journeon.models import AuthRateEvent

    with transaction(service.engine) as db:
        return [
            (row.bucket, row.observed_at, row.expires_at, row.weight)
            for row in db.scalars(
                select(AuthRateEvent)
                .where(~AuthRateEvent.bucket.startswith("source:"))
                .order_by(AuthRateEvent.id)
            )
        ]


def fail_login(service, key, source):
    challenge = service.begin_login(source=source, label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            source=source,
            response=invalid_assertion(key, challenge),
        )
    return challenge


def seed_key(service, key, principal_id):
    from uuid import uuid4

    from fido2.cose import ES256
    from fido2.utils import websafe_encode
    from fido2.webauthn import Aaguid, AttestedCredentialData

    from journeon.database import transaction
    from journeon.models import Passkey

    key.user_handle = principal_id.encode()
    credential = AttestedCredentialData.create(
        Aaguid.NONE, key.credential_id, ES256.from_cryptography_key(key.private.public_key())
    )
    with transaction(service.engine) as db:
        db.add(
            Passkey(
                id=str(uuid4()),
                principal_id=principal_id,
                credential_id=websafe_encode(key.credential_id),
                credential_data=websafe_encode(bytes(credential)),
                label="Independent test key",
                sign_count=0,
                backup_eligible=False,
                backed_up=False,
                revoked=False,
            )
        )


def test_family_aggregate_covers_multiple_keys_but_not_another_principal(policy_service):
    from journeon.database import transaction
    from journeon.models import BrowserSession, Principal

    service, _ = policy_service
    first, issued = enroll(service)
    with transaction(service.engine) as db:
        principal_id = db.get(BrowserSession, issued.session_id).principal_id
        db.add(
            Principal(id="another-person", role="SHARED_USER", enabled=True, authorization_epoch=1)
        )
    second, other = Authenticator(), Authenticator()
    seed_key(service, second, principal_id)
    seed_key(service, other, "another-person")
    for index, key in enumerate((first, second, first)):
        fail_login(service, key, f"failure-{index}")
    challenge = service.begin_login(source="second-healthy-key", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            source="second-healthy-key",
            response=second.assert_key(challenge.options),
        )
    other_challenge = service.begin_login(source="other-account", label="Browser")
    service.complete(
        other_challenge.ceremony_id,
        purpose="login",
        source="other-account",
        response=other.assert_key(other_challenge.options),
    )


def test_aliases_map_to_one_stored_credential_budget(policy_service):
    import base64

    service, _ = policy_service
    key, _ = enroll(service)
    for index in range(3):
        challenge = service.begin_login(source=f"alias-{index}", label="Browser")
        response = invalid_assertion(key, challenge)
        response["rawId"] = (
            base64.b64encode(key.credential_id).decode() if index % 2 else response["rawId"]
        )
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id, purpose="login", source=f"alias-{index}", response=response
            )
    challenge = service.begin_login(source="fresh-source", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            source="fresh-source",
            response=key.assert_key(challenge.options),
        )
    assert (
        len({event[0] for event in failure_events(service) if event[0].startswith("credential:")})
        == 1
    )


def test_throttled_requests_do_not_append_or_slide_refill(policy_service):
    service, clock = policy_service
    key, _ = enroll(service)
    fail_login(service, key, "one")
    clock[0] += 30
    fail_login(service, key, "two")
    fail_login(service, key, "three")
    before = failure_events(service)
    clock[0] += 29
    fail_login(service, key, "throttled")
    assert failure_events(service) == before
    clock[0] += 1
    fail_login(service, key, "released-slot")
    events = failure_events(service)
    assert all(event[1] >= 1030 for event in events)
    assert sum(event[3] for event in events if event[0].startswith("family:")) == 3
    assert sum(event[3] for event in events if event[0].startswith("credential:")) == 3


def test_anonymous_source_budget_is_shared_across_unknown_ids(policy_service):
    from fido2.utils import websafe_encode

    service, _ = policy_service
    for index in range(3):
        challenge = service.begin_login(source=f"start-{index}", label="Browser")
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id,
                purpose="login",
                source="actual-source",
                response={"rawId": websafe_encode(f"unknown-{index}".encode())},
            )
    before = failure_events(service)
    challenge = service.begin_login(source="fourth-start", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            source="actual-source",
            response={"rawId": websafe_encode(b"new-unknown")},
        )
    assert failure_events(service) == before
    assert len({event[0] for event in before if event[0].startswith("anonymous-source:")}) == 1


def test_unknown_credential_budget_is_shared_across_sources(policy_service):
    from fido2.utils import websafe_encode

    service, _ = policy_service
    for index in range(3):
        challenge = service.begin_login(source=f"source-{index}", label="Browser")
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id,
                purpose="login",
                source=f"source-{index}",
                response={"rawId": websafe_encode(b"same-unknown")},
            )
    before = failure_events(service)
    challenge = service.begin_login(source="new-source", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            source="new-source",
            response={"rawId": websafe_encode(b"same-unknown")},
        )
    assert failure_events(service) == before


def test_failure_budget_survives_restart_and_observed_clock_rollback(policy_service):
    service, clock = policy_service
    key, _ = enroll(service)
    for index in range(3):
        fail_login(service, key, f"source-{index}")
    service.engine.dispose()
    restarted = PasskeyService(
        service.engine, rp_id="example.test", origin=service.origin, policy=service.policy
    )
    challenge = restarted.begin_login(source="after-restart", label="Browser")
    with pytest.raises(DomainError):
        restarted.complete(
            challenge.ceremony_id,
            purpose="login",
            source="after-restart",
            response=key.assert_key(challenge.options),
        )
    clock[0] += 60
    restarted.begin_login(source="age-out", label="Browser")
    clock[0] -= 59
    with pytest.raises(DomainError):
        restarted.begin_login(source="rollback", label="Browser")


def test_policy_mismatch_cannot_reset_retained_budgets(policy_service):
    from dataclasses import replace

    service, _ = policy_service
    service.begin_login(source="one", label="Browser")
    changed = PasskeyService(
        service.engine,
        rp_id="example.test",
        origin=service.origin,
        policy=replace(service.policy, window_seconds=120),
    )
    with pytest.raises(DomainError) as error:
        changed.begin_login(source="one", label="Browser")
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    service.begin_login(source="one", label="Browser")
    service.begin_login(source="one", label="Browser")
    with pytest.raises(DomainError):
        service.begin_login(source="one", label="Browser")


def test_concurrent_failures_share_last_available_slot(policy_service):
    from concurrent.futures import ThreadPoolExecutor

    from journeon.database import transaction
    from journeon.models import AuthCeremony

    service, _ = policy_service
    key, _ = enroll(service)
    fail_login(service, key, "one")
    fail_login(service, key, "two")
    challenges = [service.begin_login(source=f"parallel-{i}", label="Browser") for i in range(2)]

    def finish(challenge):
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id,
                purpose="login",
                source="parallel",
                response=invalid_assertion(key, challenge),
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(finish, challenges))
    with transaction(service.engine) as db:
        assert sorted(db.get(AuthCeremony, c.ceremony_id).attempts for c in challenges) == [0, 1]
    assert sum(e[3] for e in failure_events(service) if e[0].startswith("family:")) == 3


def test_legacy_counts_survive_transactional_upgrade_and_restart(tmp_path, monkeypatch):
    from alembic import command
    from sqlalchemy import text

    from journeon.migrate import configuration
    from journeon.sessions import digest

    engine = create_database(tmp_path / "legacy.db")
    config = configuration()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0003_passkeys")
        connection.execute(text("INSERT INTO identity_state (id, last_observed) VALUES (1, 1000)"))
        connection.execute(
            text(
                "INSERT INTO auth_rates (key, window_start, last_observed, count) "
                "VALUES (:key, 1000, 1059, 3)"
            ),
            {"key": digest("legacy-source")},
        )
    with pytest.raises(RuntimeError):
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            raise RuntimeError("Injected migration rollback")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0003_passkeys"
        assert connection.scalar(text("SELECT count FROM auth_rates")) == 3
        assert (
            connection.scalar(
                text("SELECT count(*) FROM sqlite_master WHERE name='auth_rate_events'")
            )
            == 0
        )
    upgrade(engine)
    upgrade(engine)
    clock = [1060]
    monkeypatch.setattr("journeon.passkeys.utc_seconds", lambda: clock[0])
    policy = PasskeyPolicy(300, 900, 3, 3, 60, 3, 60)
    service = PasskeyService(
        engine, rp_id="example.test", origin="https://example.test", policy=policy
    )
    with pytest.raises(DomainError):
        service.begin_login(source="legacy-source", label="Browser")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT observed_at, expires_at, weight FROM auth_rate_events")
        ).one() == (1059, 1119, 3)
        assert connection.scalar(text("SELECT count FROM auth_rates")) == 3
    engine.dispose()
    clock[0] = 1118
    restarted = PasskeyService(engine, rp_id="example.test", origin=service.origin, policy=policy)
    with pytest.raises(DomainError):
        restarted.begin_login(source="legacy-source", label="Browser")
    clock[0] = 1119
    restarted.begin_login(source="legacy-source", label="Browser")
    engine.dispose()


def test_bootstrap_renewal_preserves_family_failures(policy_service):
    service, _ = policy_service
    for index in range(3):
        enrollment = service.prepare_bootstrap()
        challenge = service.begin_bootstrap(
            enrollment.secret, label="Test key", source=f"bootstrap-{index}"
        )
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id, purpose="bootstrap", source=f"bootstrap-{index}", response={}
            )
    before = failure_events(service)
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(
        enrollment.secret, label="Test key", source="renewed-bootstrap"
    )
    key = Authenticator()
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="bootstrap",
            source="renewed-bootstrap",
            response=key.register(challenge.options),
        )
    assert failure_events(service) == before


def test_success_and_preverification_denials_do_not_change_failure_history(policy_service):
    service, _ = policy_service
    key, _ = enroll(service)
    fail_login(service, key, "failed")
    before = failure_events(service)
    challenge = service.begin_login(source="success", label="Browser")
    service.complete(
        challenge.ceremony_id,
        purpose="login",
        source="success",
        response=key.assert_key(challenge.options),
    )
    assert failure_events(service) == before
    with pytest.raises(DomainError):
        service.complete(challenge.ceremony_id, purpose="login", source="replay", response={})
    with pytest.raises(DomainError):
        service.complete("absent", purpose="login", source="missing", response={})
    assert failure_events(service) == before


def test_exhausted_family_does_not_invoke_verifier(policy_service, monkeypatch):
    service, _ = policy_service
    key, _ = enroll(service)
    for index in range(3):
        fail_login(service, key, f"failure-{index}")

    def unexpected(*args):
        raise AssertionError("Throttled verification must not run")

    monkeypatch.setattr(service, "_verify", unexpected)
    challenge = service.begin_login(source="throttled", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="login",
            source="throttled",
            response=key.assert_key(challenge.options),
        )


def test_standard_profile_is_explicit_and_complete(policy_service):
    from journeon.passkeys import STANDARD_PASSKEY_POLICY

    assert STANDARD_PASSKEY_POLICY == PasskeyPolicy(300, 900, 5, 30, 300, 5, 300)
    service, _ = policy_service
    with pytest.raises(TypeError):
        PasskeyService(service.engine, rp_id="example.test", origin=service.origin)
