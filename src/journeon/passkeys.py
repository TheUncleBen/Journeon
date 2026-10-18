# SPDX-License-Identifier: AGPL-3.0-only
"""Passkey ceremonies with explicit deployment policy and durable one-use challenges."""

import json
import logging
import secrets
import struct
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    CredentialCreationOptions,
    CredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from journeon.contracts import DomainError
from journeon.database import require_compatible_schema, transaction
from journeon.models import (
    AuthCeremony,
    AuthRate,
    BrowserSession,
    IdentityState,
    Passkey,
    Principal,
)
from journeon.sessions import (
    IssuedSession,
    current_session,
    digest,
    issue_session,
    rotate_session,
    utc_seconds,
)


class _VerifierLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = "WebAuthn verifier activity"
        record.args = ()
        return True


logging.getLogger("fido2.server").addFilter(_VerifierLogFilter())


def rejected() -> DomainError:
    return DomainError("AUTHENTICATION_REQUIRED", "Passkey verification failed")


@dataclass(frozen=True)
class PasskeyPolicy:
    ceremony_seconds: int
    bootstrap_seconds: int
    max_attempts: int
    starts_per_window: int
    window_seconds: int

    def __post_init__(self) -> None:
        for value in (
            self.ceremony_seconds,
            self.bootstrap_seconds,
            self.max_attempts,
            self.starts_per_window,
            self.window_seconds,
        ):
            if type(value) is not int or not 0 < value < 2**62:
                raise ValueError("Passkey policy requires finite positive integers")


@dataclass(frozen=True)
class Enrollment:
    secret: str = field(repr=False)


@dataclass(frozen=True)
class Challenge:
    ceremony_id: str
    options: dict[str, Any]


class PasskeyService:
    def __init__(self, engine: Engine, *, rp_id: str, origin: str, policy: PasskeyPolicy):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != rp_id
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Passkeys require the exact HTTPS relying-party origin")
        self.engine = engine
        self.policy = policy
        self.origin = origin
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name="Journeon"),
            verify_origin=lambda candidate: candidate == origin,
        )

    def _binding(self) -> dict[str, Any]:
        return {"origin": self.origin, "rp_id": self.server.rp.id, "policy": asdict(self.policy)}

    def _observe(self, db: Session, now: int) -> bool:
        require_compatible_schema(db)
        state = db.get(IdentityState, 1)
        if state is None:
            state = IdentityState(id=1, last_observed=0)
            db.add(state)
        valid = 0 <= now < 2**62 and now >= state.last_observed
        if 0 <= now < 2**62:
            state.last_observed = max(state.last_observed, now)
        db.flush()
        return valid

    def prepare_bootstrap(self) -> Enrollment:
        """Trusted local administration only; never expose this operation as a public route."""
        failure = None
        secret = None
        with transaction(self.engine) as db:
            now = utc_seconds()
            try:
                if not self._observe(db, now):
                    raise rejected()
                state = db.get(IdentityState, 1)
                assert state is not None
                if (
                    state.owner_id is not None
                    or db.scalar(select(Principal.id).where(Principal.role == "OWNER")) is not None
                ):
                    raise rejected()
                secret = secrets.token_urlsafe(32)
                state.pending_principal_id = str(uuid4())
                state.enrollment_hash = digest(secret)
                state.enrollment_deadline = now + self.policy.bootstrap_seconds
            except DomainError as exc:
                failure = exc
        if failure is not None:
            raise failure
        assert secret is not None
        return Enrollment(secret)

    def _rate(self, db: Session, source: str, now: int) -> None:
        key = digest(source)
        rate = db.get(AuthRate, key)
        if rate is None:
            rate = AuthRate(key=key, window_start=now, last_observed=now, count=0)
            db.add(rate)
        if now < rate.last_observed:
            raise rejected()
        rate.last_observed = now
        if now >= rate.window_start + self.policy.window_seconds:
            rate.window_start, rate.count = now, 0
        if rate.count >= self.policy.starts_per_window:
            raise rejected()
        rate.count += 1
        db.flush()

    def begin_bootstrap(self, secret: str, *, label: str, source: str) -> Challenge:
        return self._begin("bootstrap", source=source, label=label, secret=secret)

    def begin_login(self, *, source: str, label: str) -> Challenge:
        return self._begin("login", source=source, label=label)

    def begin_stepup(self, session_id: str, *, source: str) -> Challenge:
        return self._begin("stepup", source=source, label="", session_id=session_id)

    def _begin(
        self,
        purpose: str,
        *,
        source: str,
        label: str,
        secret: str = "",
        session_id: str | None = None,
    ) -> Challenge:
        failure = None
        result = None
        with transaction(self.engine) as db:
            now = utc_seconds()
            try:
                if not self._observe(db, now):
                    raise rejected()
                self._rate(db, source, now)
                if len(label) > 128 or (purpose == "bootstrap" and not label.strip()):
                    raise rejected()
                options: CredentialCreationOptions | CredentialRequestOptions
                subject = None
                enrollment_hash = None
                if purpose == "bootstrap":
                    identity = db.get(IdentityState, 1)
                    if (
                        identity is None
                        or identity.owner_id is not None
                        or identity.enrollment_hash is None
                        or identity.enrollment_deadline is None
                        or now >= identity.enrollment_deadline
                        or not secrets.compare_digest(identity.enrollment_hash, digest(secret))
                    ):
                        raise rejected()
                    subject = identity.pending_principal_id
                    assert subject is not None
                    enrollment_hash = identity.enrollment_hash
                    options, state = self.server.register_begin(
                        PublicKeyCredentialUserEntity(id=subject.encode(), name="Owner"),
                        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
                        user_verification=UserVerificationRequirement.REQUIRED,
                    )
                else:
                    if purpose == "stepup":
                        assert session_id is not None
                        subject = current_session(db, session_id).principal_id
                    options, state = self.server.authenticate_begin(
                        user_verification=UserVerificationRequirement.REQUIRED
                    )
                state["service_binding"] = self._binding()
                ceremony = AuthCeremony(
                    id=str(uuid4()),
                    purpose=purpose,
                    subject_id=subject,
                    session_id=session_id,
                    enrollment_hash=enrollment_hash,
                    label=label,
                    state=state,
                    issued_at=now,
                    last_observed=now,
                    deadline=now + self.policy.ceremony_seconds,
                    attempts=0,
                    consumed=False,
                )
                db.add(ceremony)
                result = Challenge(ceremony.id, json.loads(json.dumps(dict(options))))
            except DomainError as exc:
                failure = exc
        if failure is not None:
            raise failure
        assert result is not None
        return result

    def complete(
        self,
        ceremony_id: str,
        *,
        purpose: str,
        response: dict[str, Any],
        session_id: str | None = None,
    ) -> IssuedSession:
        failure = None
        result = None
        with transaction(self.engine) as db:
            row = db.get(AuthCeremony, ceremony_id)
            now = utc_seconds()
            if not self._observe(db, now) or row is None:
                failure = rejected()
            else:
                prior = row.last_observed
                row.last_observed = max(prior, now)
                invalid = (
                    row.state.get("service_binding") != self._binding()
                    or row.consumed
                    or row.purpose != purpose
                    or row.session_id != session_id
                    or now < prior
                    or now >= row.deadline
                    or row.attempts >= self.policy.max_attempts
                )
                if invalid:
                    failure = rejected()
                else:
                    row.attempts += 1
                    db.flush()
                    observed = now
                    completion_deadline = row.deadline
                    if row.purpose == "bootstrap":
                        identity = db.get(IdentityState, 1)
                        if identity is not None and identity.enrollment_deadline is not None:
                            completion_deadline = min(
                                completion_deadline, identity.enrollment_deadline
                            )
                    try:
                        with db.begin_nested():
                            result = self._verify(db, row, response)
                            issued = db.get(BrowserSession, result.session_id)
                            assert issued is not None
                            observed = max(observed, issued.issued_at)
                            if issued.issued_at < now or issued.issued_at >= completion_deadline:
                                raise rejected()
                            row.consumed = True
                            db.flush()
                    except (
                        ValueError,
                        KeyError,
                        TypeError,
                        IndexError,
                        OverflowError,
                        struct.error,
                        DomainError,
                        IntegrityError,
                    ):
                        failure = rejected()
                        if row.attempts >= self.policy.max_attempts:
                            row.consumed = True
                    row.last_observed = max(row.last_observed, observed)
                    self._observe(db, observed)
        if failure is not None:
            raise failure
        assert result is not None
        return result

    def _verify(self, db: Session, row: AuthCeremony, response: dict[str, Any]) -> IssuedSession:
        key: Passkey | None
        if row.purpose == "bootstrap":
            identity = db.get(IdentityState, 1)
            if (
                identity is None
                or identity.owner_id is not None
                or identity.enrollment_hash != row.enrollment_hash
                or identity.pending_principal_id != row.subject_id
                or identity.enrollment_deadline is None
                or row.last_observed >= identity.enrollment_deadline
            ):
                raise rejected()
            registration = RegistrationResponse.from_dict(response)
            candidate = registration.response.attestation_object.auth_data.credential_data
            if (
                registration.response.client_data.cross_origin
                or candidate is None
                or candidate.public_key.get(3)
                not in {algorithm.alg for algorithm in self.server.allowed_algorithms}
            ):
                raise rejected()
            auth_data = self.server.register_complete(row.state, registration)
            credential = auth_data.credential_data
            assert credential is not None
            if registration.raw_id != credential.credential_id:
                raise rejected()
            assert row.subject_id is not None
            principal = Principal(
                id=row.subject_id, role="OWNER", enabled=True, authorization_epoch=1
            )
            db.add(principal)
            db.flush()
            key = Passkey(
                id=str(uuid4()),
                credential_id=websafe_encode(credential.credential_id),
                credential_data=websafe_encode(bytes(credential)),
                principal_id=principal.id,
                label=row.label,
                sign_count=auth_data.counter,
                backup_eligible=auth_data.is_backup_eligible(),
                backed_up=auth_data.is_backed_up(),
                revoked=False,
            )
            db.add(key)
            identity.owner_id = principal.id
            identity.enrollment_hash = None
            identity.enrollment_deadline = None
            identity.pending_principal_id = None
        else:
            assertion = AuthenticationResponse.from_dict(response)
            key = db.scalar(
                select(Passkey).where(Passkey.credential_id == websafe_encode(assertion.raw_id))
            )
            if key is None or key.revoked or assertion.response.client_data.cross_origin:
                raise rejected()
            if assertion.response.user_handle != key.principal_id.encode() or (
                row.subject_id is not None and key.principal_id != row.subject_id
            ):
                raise rejected()
            self.server.authenticate_complete(
                row.state, [AttestedCredentialData(websafe_decode(key.credential_data))], assertion
            )
            auth_data = assertion.response.authenticator_data
            if auth_data.is_backup_eligible() != key.backup_eligible:
                raise rejected()
            if (
                auth_data.counter != 0 or key.sign_count != 0
            ) and auth_data.counter <= key.sign_count:
                raise rejected()
            key.sign_count = auth_data.counter
            key.backed_up = auth_data.is_backed_up()
        if key.backed_up and not key.backup_eligible:
            raise rejected()
        db.flush()
        if row.purpose == "stepup":
            assert row.session_id is not None
            result = rotate_session(db, row.session_id, strong=True)
            record = db.get(BrowserSession, result.session_id)
            assert record is not None
            record.authentication_method = "passkey:" + key.id
            return result
        return issue_session(
            db,
            key.principal_id,
            authentication_method="passkey:" + key.id,
            client_label=row.label,
            strong=True,
        )
