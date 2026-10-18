# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from journeon.contracts import DomainError
from journeon.database import create_database, transaction
from journeon.migrate import upgrade
from journeon.models import AuthCeremony, IdentityState, Principal
from journeon.passkeys import PasskeyPolicy, PasskeyService


@pytest.fixture
def service(tmp_path):
    engine = create_database(tmp_path / "passkeys.db")
    upgrade(engine)
    policy = PasskeyPolicy(
        ceremony_seconds=60,
        bootstrap_seconds=120,
        max_attempts=3,
        starts_per_window=5,
        window_seconds=60,
        failures_per_window=3,
        failure_window_seconds=60,
    )
    yield PasskeyService(engine, rp_id="example.test", origin="https://example.test", policy=policy)
    engine.dispose()


def test_bootstrap_start_is_durable_without_owner(service):
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    with transaction(service.engine) as db:
        state = db.get(IdentityState, 1)
        assert state.owner_id is None
        assert db.get(Principal, state.pending_principal_id) is None
        ceremony = db.get(AuthCeremony, challenge.ceremony_id)
        assert ceremony.purpose == "bootstrap"
        assert ceremony.state["challenge"] == challenge.options["publicKey"]["challenge"]
        assert enrollment.secret not in repr(enrollment)


def test_failed_verification_is_durably_bounded(service):
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    for _ in range(4):
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id, purpose="bootstrap", response={}, source="local"
            )
    with transaction(service.engine) as db:
        ceremony = db.get(AuthCeremony, challenge.ceremony_id)
        assert ceremony.attempts == 3
        assert ceremony.consumed
        assert db.get(IdentityState, 1).owner_id is None


def test_unconfigured_policy_has_no_defaults():
    with pytest.raises(TypeError):
        PasskeyPolicy()


class Authenticator:
    def __init__(self):
        import secrets

        from cryptography.hazmat.primitives.asymmetric import ec

        self.private = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.user_handle = None

    def register(self, options, *, origin="https://example.test", uv=True):
        import hashlib
        import json

        from fido2 import cbor
        from fido2.cose import ES256
        from fido2.utils import websafe_decode, websafe_encode
        from fido2.webauthn import Aaguid, AttestedCredentialData, AuthenticatorData

        public = options["publicKey"]
        self.user_handle = websafe_decode(public["user"]["id"])
        client = json.dumps(
            {"type": "webauthn.create", "challenge": public["challenge"], "origin": origin}
        ).encode()
        credential = AttestedCredentialData.create(
            Aaguid.NONE, self.credential_id, ES256.from_cryptography_key(self.private.public_key())
        )
        data = AuthenticatorData.create(
            hashlib.sha256(b"example.test").digest(), 0x41 | (4 if uv else 0), 0, credential
        )
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client),
                "attestationObject": websafe_encode(
                    cbor.encode({"fmt": "none", "attStmt": {}, "authData": bytes(data)})
                ),
            },
        }

    def assert_key(self, options, *, origin="https://example.test", uv=True, count=1):
        import hashlib
        import json

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from fido2.utils import websafe_encode
        from fido2.webauthn import AuthenticatorData

        client = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": options["publicKey"]["challenge"],
                "origin": origin,
            }
        ).encode()
        data = AuthenticatorData.create(
            hashlib.sha256(b"example.test").digest(), 1 | (4 if uv else 0), count
        )
        signature = self.private.sign(
            bytes(data) + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client),
                "authenticatorData": websafe_encode(bytes(data)),
                "signature": websafe_encode(signature),
                "userHandle": websafe_encode(self.user_handle),
            },
        }


def bootstrap(service):
    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    issued = service.complete(
        challenge.ceremony_id,
        purpose="bootstrap",
        response=key.register(challenge.options),
        source="local",
    )
    return key, issued


def test_real_registration_login_and_stepup(service):
    from journeon.models import BrowserSession

    key, first = bootstrap(service)
    login = service.begin_login(source="local", label="Browser")
    second = service.complete(
        login.ceremony_id, purpose="login", response=key.assert_key(login.options), source="local"
    )
    step = service.begin_stepup(second.session_id, source="local")
    third = service.complete(
        step.ceremony_id,
        purpose="stepup",
        session_id=second.session_id,
        response=key.assert_key(step.options, count=2),
        source="local",
    )
    with transaction(service.engine) as db:
        assert db.get(BrowserSession, first.session_id).audience == "official_browser"
        assert db.get(BrowserSession, second.session_id).audience == "official_browser"
        assert db.get(BrowserSession, third.session_id).audience == "official_browser"
        assert db.get(BrowserSession, second.session_id).revoked
        assert not db.get(BrowserSession, third.session_id).revoked
        assert (
            db.get(BrowserSession, first.session_id).principal_id
            == db.get(IdentityState, 1).owner_id
        )
    with pytest.raises(DomainError):
        service.prepare_bootstrap()
    with pytest.raises(DomainError):
        service.complete(
            login.ceremony_id,
            purpose="login",
            response=key.assert_key(login.options, count=3),
            source="local",
        )


@pytest.mark.parametrize(
    "change", ["origin", "uv", "signature", "challenge", "user", "credential", "purpose"]
)
def test_real_assertion_rejects_binding_tampering(service, change):
    import json

    from fido2.utils import websafe_decode, websafe_encode

    key, _ = bootstrap(service)
    login = service.begin_login(source="local", label="Browser")
    response = key.assert_key(
        login.options,
        origin="https://other.test" if change == "origin" else "https://example.test",
        uv=change != "uv",
    )
    if change == "signature":
        response["response"]["signature"] = websafe_encode(b"invalid")
    if change == "challenge":
        client = json.loads(websafe_decode(response["response"]["clientDataJSON"]))
        client["challenge"] = websafe_encode(b"wrong")
        response["response"]["clientDataJSON"] = websafe_encode(json.dumps(client).encode())
    if change == "user":
        response["response"]["userHandle"] = websafe_encode(b"wrong")
    if change == "credential":
        response["id"] = response["rawId"] = websafe_encode(b"wrong")
    with pytest.raises(DomainError):
        service.complete(
            login.ceremony_id,
            purpose="bootstrap" if change == "purpose" else "login",
            response=response,
            source="local",
        )
    with transaction(service.engine) as db:
        from sqlalchemy import func, select

        from journeon.models import BrowserSession

        assert db.scalar(select(func.count()).select_from(BrowserSession)) == 1


def test_bootstrap_concurrent_completion_has_one_owner_and_session(service):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import func, select

    from journeon.models import BrowserSession

    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    response = key.register(challenge.options)

    def finish():
        try:
            return service.complete(
                challenge.ceremony_id, purpose="bootstrap", response=response, source="local"
            )
        except DomainError:
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: finish(), range(2)))
    assert sum(result is not None for result in results) == 1
    with transaction(service.engine) as db:
        assert db.scalar(select(func.count()).select_from(Principal)) == 1
        assert db.scalar(select(func.count()).select_from(BrowserSession)) == 1


def test_observed_expiry_cannot_revive_after_clock_rollback(service, monkeypatch):
    from journeon import passkeys

    now = passkeys.utc_seconds()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now)
    monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: now)
    key, _ = bootstrap(service)
    challenge = service.begin_login(source="local", label="Browser")
    response = key.assert_key(challenge.options)
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 60)
    with pytest.raises(DomainError):
        service.complete(challenge.ceremony_id, purpose="login", response=response, source="local")
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 1)
    with pytest.raises(DomainError):
        service.complete(challenge.ceremony_id, purpose="login", response=response, source="local")


def test_http_configuration_origin_cookie_and_real_crypto(service):
    import json

    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth

    client = TestClient(
        create_app(service.engine, browser_auth=BrowserAuth(service.origin), passkeys=service),
        base_url=service.origin,
    )
    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    body = {"purpose": "bootstrap", "label": "Browser key", "enrollment_secret": enrollment.secret}
    assert client.post("/api/v1/auth/passkeys/begin", json=body).status_code == 401
    result = client.post(
        "/api/v1/auth/passkeys/begin", json=body, headers={"Origin": service.origin}
    )
    assert result.status_code == 200
    challenge = result.json()
    result = client.post(
        "/api/v1/auth/passkeys/finish",
        headers={"Origin": service.origin},
        json={
            "purpose": "bootstrap",
            "ceremony_id": challenge["ceremony_id"],
            "credential_json": json.dumps(key.register(json.loads(challenge["options_json"]))),
        },
    )
    assert result.status_code == 200
    assert "Secure" in result.headers["set-cookie"]
    assert "HttpOnly" in result.headers["set-cookie"]
    assert result.headers["cache-control"] == "no-store"
    assert len(result.json()["csrf_token"]) == 43
    disabled = TestClient(create_app(service.engine), base_url=service.origin)
    assert (
        disabled.post(
            "/api/v1/auth/passkeys/begin", json=body, headers={"Origin": service.origin}
        ).status_code
        == 503
    )


@pytest.mark.parametrize("change", ["origin", "uv", "rp", "up", "type", "raw_id", "cross_origin"])
def test_registration_rejects_binding_tampering(service, change):
    import json

    from fido2 import cbor
    from fido2.utils import websafe_decode, websafe_encode

    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    response = key.register(
        challenge.options,
        origin="https://other.test" if change == "origin" else "https://example.test",
        uv=change != "uv",
    )
    if change in {"rp", "up"}:
        attestation = cbor.decode(websafe_decode(response["response"]["attestationObject"]))
        data = bytearray(attestation["authData"])
        if change == "rp":
            data[0] ^= 1
        else:
            data[32] &= ~1
        attestation["authData"] = bytes(data)
        response["response"]["attestationObject"] = websafe_encode(cbor.encode(attestation))
    if change in {"type", "cross_origin"}:
        data = json.loads(websafe_decode(response["response"]["clientDataJSON"]))
        if change == "type":
            data["type"] = "webauthn.get"
        else:
            data["crossOrigin"] = True
        response["response"]["clientDataJSON"] = websafe_encode(json.dumps(data).encode())
    if change == "raw_id":
        response["id"] = response["rawId"] = websafe_encode(b"wrong")
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id, purpose="bootstrap", response=response, source="local"
        )
    with transaction(service.engine) as db:
        assert db.get(IdentityState, 1).owner_id is None


def test_counter_regression_and_revoked_key_cannot_issue_session(service):
    from sqlalchemy import select

    from journeon.models import Passkey

    key, _ = bootstrap(service)
    first = service.begin_login(source="local", label="Browser")
    service.complete(
        first.ceremony_id,
        purpose="login",
        response=key.assert_key(first.options, count=2),
        source="local",
    )
    second = service.begin_login(source="local", label="Browser")
    with pytest.raises(DomainError):
        service.complete(
            second.ceremony_id,
            purpose="login",
            response=key.assert_key(second.options, count=1),
            source="local",
        )
    with transaction(service.engine) as db:
        db.scalar(select(Passkey)).revoked = True
    with pytest.raises(DomainError):
        service.complete(
            second.ceremony_id,
            purpose="login",
            response=key.assert_key(second.options, count=3),
            source="local",
        )


def test_bootstrap_commit_failure_rolls_back_identity_credential_and_session(service, monkeypatch):
    from sqlalchemy import func, select

    from journeon import passkeys
    from journeon.models import BrowserSession, Passkey

    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    original = passkeys.issue_session

    def fail_after_issue(*args, **kwargs):
        original(*args, **kwargs)
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Synthetic persistence failure")

    monkeypatch.setattr(passkeys, "issue_session", fail_after_issue)
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="bootstrap",
            response=key.register(challenge.options),
            source="local",
        )
    with transaction(service.engine) as db:
        for model in (Principal, Passkey, BrowserSession):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.get(IdentityState, 1).owner_id is None
        assert db.get(AuthCeremony, challenge.ceremony_id).attempts == 0
        from journeon.models import AuthRateEvent

        assert (
            db.scalar(
                select(func.count())
                .select_from(AuthRateEvent)
                .where(~AuthRateEvent.bucket.startswith("source:"))
            )
            == 0
        )
    monkeypatch.setattr(passkeys, "issue_session", original)
    service.complete(
        challenge.ceremony_id,
        purpose="bootstrap",
        response=key.register(challenge.options),
        source="local",
    )


def test_stepup_requires_existing_session_and_same_challenge_binding(service):
    key, issued = bootstrap(service)
    with pytest.raises(DomainError):
        service.begin_stepup("unknown", source="local")
    step = service.begin_stepup(issued.session_id, source="local")
    with pytest.raises(DomainError):
        service.complete(
            step.ceremony_id,
            purpose="stepup",
            response=key.assert_key(step.options),
            source="local",
        )
    service.complete(
        step.ceremony_id,
        purpose="stepup",
        session_id=issued.session_id,
        response=key.assert_key(step.options),
        source="local",
    )


def test_rate_limit_survives_service_restart(service):
    for _ in range(5):
        with pytest.raises(DomainError):
            service.begin_bootstrap("wrong", label="Test", source="same")
    restarted = PasskeyService(
        service.engine, rp_id="example.test", origin=service.origin, policy=service.policy
    )
    with pytest.raises(DomainError):
        restarted.begin_login(source="same", label="Browser")
    restarted.begin_login(source="different", label="Browser")


def test_expired_session_issuance_observation_prevents_ceremony_revival(service, monkeypatch):
    from journeon import passkeys, sessions

    now = passkeys.utc_seconds()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now)
    monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: now)
    key, _ = bootstrap(service)
    login = service.begin_login(source="local", label="Browser")
    response = key.assert_key(login.options)
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 60)
    with pytest.raises(DomainError):
        service.complete(login.ceremony_id, purpose="login", response=response, source="local")
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 1)
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 1)
    with pytest.raises(DomainError):
        service.complete(login.ceremony_id, purpose="login", response=response, source="local")


def test_process_crash_during_bootstrap_leaves_reusable_uninitialized_state(service, tmp_path):
    import json
    import os
    import subprocess
    import sys

    from sqlalchemy import func, select

    from journeon.models import BrowserSession, Passkey

    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    response = key.register(challenge.options)
    fixture = tmp_path / "synthetic-credential.json"
    fixture.write_text(json.dumps(response))
    script = """
import json, os, sys
from pathlib import Path
from journeon import passkeys
from journeon.database import create_database
engine = create_database(Path(sys.argv[1]))
service = passkeys.PasskeyService(engine, rp_id='example.test', origin='https://example.test',
    policy=passkeys.PasskeyPolicy(60,120,3,5,60,3,60))
original = passkeys.issue_session
def crash(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(77)
passkeys.issue_session = crash
service.complete(sys.argv[2], source='local', purpose='bootstrap',
                 response=json.loads(Path(sys.argv[3]).read_text()))
"""
    environment = dict(os.environ, PYTHONPATH="src")
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            service.engine.url.database,
            challenge.ceremony_id,
            str(fixture),
        ],
        env=environment,
        capture_output=True,
        timeout=30,
    )
    assert child.returncode == 77
    service.engine.dispose()
    with transaction(service.engine) as db:
        for model in (Principal, Passkey, BrowserSession):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.get(IdentityState, 1).owner_id is None
        assert not db.get(AuthCeremony, challenge.ceremony_id).consumed
    service.complete(challenge.ceremony_id, purpose="bootstrap", response=response, source="local")


def test_initialized_owner_cannot_be_demoted_deleted_or_unbound(service):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    bootstrap(service)
    for statement in (
        "UPDATE principals SET role='SHARED_USER' WHERE role='OWNER'",
        "UPDATE principals SET enabled=0 WHERE role='OWNER'",
        "DELETE FROM principals WHERE role='OWNER'",
        "UPDATE identity_state SET owner_id=NULL",
        "DELETE FROM identity_state",
    ):
        with pytest.raises(IntegrityError), transaction(service.engine) as db:
            db.execute(text(statement))


def test_additive_migration_retains_existing_owner_session_and_grant(tmp_path):
    from alembic import command
    from sqlalchemy import text

    from journeon.migrate import configuration

    engine = create_database(tmp_path / "upgrade.db")
    with engine.begin() as connection:
        config = configuration()
        config.attributes["connection"] = connection
        command.upgrade(config, "0002_browser_sessions")
        connection.execute(
            text(
                "INSERT INTO principals(id, role, enabled, authorization_epoch) "
                "VALUES ('retained-owner','OWNER',1,1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO access_grants(id,principal_id,capability,resource_kind,"
                "resource_id,enabled,revision,provenance) VALUES "
                "('retained-grant','retained-owner','project.create','deployment',"
                "'deployment',1,1,'test')"
            )
        )
        from sqlalchemy import MetaData, Table

        from journeon.models import BrowserSession

        legacy_sessions = Table("browser_sessions", MetaData(), autoload_with=connection)
        connection.execute(
            legacy_sessions.insert().values(
                id="retained-session",
                token_hash="a" * 64,
                csrf_hash="b" * 64,
                principal_id="retained-owner",
                principal_epoch=1,
                authentication_method="synthetic-migration",
                client_label="Test",
                issued_at=1,
                last_activity=1,
                last_observed=1,
                absolute_deadline=100,
                inactivity_seconds=30,
                strong_authenticated_at=1,
                strong_freshness_seconds=10,
                revoked=False,
            )
        )
    upgrade(engine)
    with transaction(engine) as db:
        assert db.get(BrowserSession, "retained-session").token_hash == "a" * 64
        assert db.get(IdentityState, 1).owner_id == "retained-owner"
        assert db.scalar(text("SELECT count(*) FROM access_grants WHERE id='retained-grant'")) == 1
    engine.dispose()


def test_observed_enrollment_expiry_cannot_revive_from_another_source(service, monkeypatch):
    from journeon import passkeys

    now = passkeys.utc_seconds()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now)
    monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: now)
    enrollment = service.prepare_bootstrap()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 120)
    with pytest.raises(DomainError):
        service.begin_bootstrap(enrollment.secret, label="Test", source="first")
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 1)
    with pytest.raises(DomainError):
        service.begin_bootstrap(enrollment.secret, label="Test", source="second")


def test_bootstrap_session_issuance_cannot_cross_enrollment_deadline(service, monkeypatch):
    from journeon import passkeys, sessions

    now = passkeys.utc_seconds()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now)
    monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: now)
    enrollment = service.prepare_bootstrap()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 100)
    key = Authenticator()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test", source="local")
    monkeypatch.setattr(sessions, "utc_seconds", lambda: now + 120)
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id,
            purpose="bootstrap",
            response=key.register(challenge.options),
            source="local",
        )


@pytest.mark.parametrize("value", ["", "AA", "AAAA", "not!base64", None, 1, []])
def test_malformed_attestation_is_sanitized_and_counted(service, value):
    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test", source="local")
    response = key.register(challenge.options)
    response["response"]["attestationObject"] = value
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id, purpose="bootstrap", response=response, source="local"
        )
    with transaction(service.engine) as db:
        assert db.get(AuthCeremony, challenge.ceremony_id).attempts == 1


def test_registration_without_attested_credential_is_denied(service):
    import hashlib

    from fido2 import cbor
    from fido2.utils import websafe_encode
    from fido2.webauthn import AuthenticatorData

    key = Authenticator()
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test", source="local")
    response = key.register(challenge.options)
    data = AuthenticatorData.create(hashlib.sha256(b"example.test").digest(), 5, 0)
    response["response"]["attestationObject"] = websafe_encode(
        cbor.encode({"fmt": "none", "attStmt": {}, "authData": bytes(data)})
    )
    with pytest.raises(DomainError):
        service.complete(
            challenge.ceremony_id, purpose="bootstrap", response=response, source="local"
        )


def test_verifier_logging_does_not_disclose_credential_identifiers(service, caplog):
    import logging

    caplog.set_level(logging.DEBUG, logger="fido2.server")
    key, _ = bootstrap(service)
    login = service.begin_login(source="local", label="Browser")
    service.complete(
        login.ceremony_id, purpose="login", response=key.assert_key(login.options), source="local"
    )
    assert key.credential_id.hex() not in caplog.text


def test_denied_local_preparation_preserves_observed_identity_clock(service, monkeypatch):
    from journeon import passkeys

    now = passkeys.utc_seconds()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now)
    monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: now)
    bootstrap(service)
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 10)
    with pytest.raises(DomainError):
        service.prepare_bootstrap()
    monkeypatch.setattr(passkeys, "utc_seconds", lambda: now + 1)
    with pytest.raises(DomainError):
        service.begin_login(source="local", label="Browser")


def test_pending_challenge_is_invalid_after_relying_party_configuration_change(service):
    key, _ = bootstrap(service)
    login = service.begin_login(source="local", label="Browser")
    changed = PasskeyService(
        service.engine,
        rp_id="example.test",
        origin="https://example.test:8443",
        policy=service.policy,
    )
    with pytest.raises(DomainError):
        changed.complete(
            login.ceremony_id,
            purpose="login",
            response=key.assert_key(login.options, origin=changed.origin),
            source="local",
        )


def test_verifier_recursion_failure_preserves_attempt_budget(service, monkeypatch):
    from journeon import passkeys

    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    response = Authenticator().register(challenge.options)

    def decoder_limit(_response):
        raise RecursionError("Synthetic decoder limit")

    monkeypatch.setattr(passkeys.RegistrationResponse, "from_dict", decoder_limit)
    for _ in range(service.policy.max_attempts + 1):
        with pytest.raises(DomainError):
            service.complete(
                challenge.ceremony_id, purpose="bootstrap", response=response, source="local"
            )
    with transaction(service.engine) as db:
        row = db.get(AuthCeremony, challenge.ceremony_id)
        assert row.attempts == service.policy.max_attempts
        assert row.consumed
        assert db.get(IdentityState, 1).owner_id is None


def test_json_decoder_recursion_is_rejected_before_verification(service, monkeypatch):
    import json

    from fastapi.testclient import TestClient

    from journeon import passkey_api
    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth

    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    credential_json = json.dumps(Authenticator().register(challenge.options))
    original = json.loads

    def decoder_limit(value, *args, **kwargs):
        if isinstance(value, str) and value == credential_json:
            raise RecursionError("Synthetic decoder limit")
        return original(value, *args, **kwargs)

    monkeypatch.setattr(passkey_api.json, "loads", decoder_limit)
    client = TestClient(
        create_app(service.engine, browser_auth=BrowserAuth(service.origin), passkeys=service),
        base_url=service.origin,
    )
    result = client.post(
        "/api/v1/auth/passkeys/finish",
        headers={"Origin": service.origin},
        json={
            "purpose": "bootstrap",
            "ceremony_id": challenge.ceremony_id,
            "credential_json": credential_json,
        },
    )
    assert result.status_code == 422
    assert result.json() == {
        "schema_version": 1,
        "code": "VALIDATION_FAILED",
        "reason": "Invalid passkey response",
    }
    with transaction(service.engine) as db:
        assert db.get(AuthCeremony, challenge.ceremony_id).attempts == 0
        assert db.get(IdentityState, 1).owner_id is None


def test_bootstrap_options_supply_required_browser_user_display_name(service):
    enrollment = service.prepare_bootstrap()
    challenge = service.begin_bootstrap(enrollment.secret, label="Test key", source="local")
    user = challenge.options["publicKey"]["user"]
    assert user["name"] == "Owner"
    assert user["displayName"] == user["name"]
