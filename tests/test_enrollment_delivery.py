# SPDX-License-Identifier: AGPL-3.0-only
import os

import pytest
from test_workspace_provisioning import enrolled_owner  # noqa: F401

from journeon.database import create_database, transaction
from journeon.migrate import upgrade
from journeon.models import IdentityState, Principal
from journeon.operations import main
from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService


@pytest.fixture
def empty_store(tmp_path):
    path = tmp_path / "enrollment.db"
    engine = create_database(path)
    upgrade(engine)
    try:
        yield engine, path
    finally:
        engine.dispose()


def invoke(monkeypatch, path, descriptor):
    monkeypatch.setattr(
        "sys.argv",
        [
            "journeon.operations",
            "prepare-enrollment",
            str(path),
            "--origin",
            "https://example.test",
            "--rp-id",
            "example.test",
            "--secret-fd",
            str(descriptor),
            "--json",
        ],
    )
    try:
        return main()
    except SystemExit as error:
        return error.code


def test_enrollment_secret_uses_only_explicit_pipe(empty_store, monkeypatch, capsys):
    engine, path = empty_store
    reader, writer = os.pipe()
    try:
        result = invoke(monkeypatch, path, writer)
        assert result == 0
        os.set_blocking(reader, False)
        secret = os.read(reader, 128).decode().strip()
        if len(secret) != 43:
            pytest.fail("Enrollment delivery length is invalid")
        captured = capsys.readouterr()
        if secret in captured.out or secret in captured.err:
            pytest.fail("Enrollment secret escaped its protected sink")
        service = PasskeyService(
            engine,
            rp_id="example.test",
            origin="https://example.test",
            policy=STANDARD_PASSKEY_POLICY,
        )
        challenge = service.begin_bootstrap(secret, label="Pipe enrollment", source="local")
        assert challenge.ceremony_id
        with transaction(engine) as db:
            state = db.get(IdentityState, 1)
            assert state.owner_id is None
            assert db.get(Principal, state.pending_principal_id) is None
    finally:
        os.close(reader)
        os.close(writer)


def test_closed_enrollment_pipe_leaves_no_usable_pending_secret(empty_store, monkeypatch):
    engine, path = empty_store
    reader, writer = os.pipe()
    os.close(reader)
    try:
        assert invoke(monkeypatch, path, writer) == 1
        with transaction(engine) as db:
            state = db.get(IdentityState, 1)
            assert state is None or state.enrollment_hash is None
    finally:
        os.close(writer)


def test_enrollment_refuses_plaintext_file_sink(empty_store, monkeypatch, tmp_path):
    engine, path = empty_store
    target = tmp_path / "rejected-sink"
    with target.open("wb") as stream:
        assert invoke(monkeypatch, path, stream.fileno()) == 1
    assert target.read_bytes() == b""
    with transaction(engine) as db:
        state = db.get(IdentityState, 1)
        assert state is None or state.enrollment_hash is None


@pytest.mark.parametrize("descriptor", [0, 1, 2])
def test_enrollment_refuses_standard_descriptors(empty_store, monkeypatch, descriptor):
    engine, path = empty_store
    assert invoke(monkeypatch, path, descriptor) == 1
    with transaction(engine) as db:
        state = db.get(IdentityState, 1)
        assert state is None or state.enrollment_hash is None


def test_enrollment_refuses_an_alias_of_ordinary_output(empty_store, monkeypatch):
    engine, path = empty_store
    reader, writer = os.pipe()
    original_fstat = os.fstat
    try:
        # Isolated descriptor metadata fixture; no real stdout is replaced or written.
        monkeypatch.setattr(os, "fstat", lambda fd: original_fstat(writer if fd == 1 else fd))
        assert invoke(monkeypatch, path, writer) == 1
        os.set_blocking(reader, False)
        with pytest.raises(BlockingIOError):
            os.read(reader, 128)
        with transaction(engine) as db:
            state = db.get(IdentityState, 1)
            assert state is None or state.enrollment_hash is None
    finally:
        os.close(reader)
        os.close(writer)


def test_enrollment_refuses_existing_real_owner(enrolled_owner, monkeypatch):  # noqa: F811
    from pathlib import Path

    owner = enrolled_owner
    reader, writer = os.pipe()
    try:
        assert invoke(monkeypatch, Path(owner.engine.url.database), writer) == 1
        os.set_blocking(reader, False)
        with pytest.raises(BlockingIOError):
            os.read(reader, 128)
        with transaction(owner.engine) as db:
            state = db.get(IdentityState, 1)
            assert state.owner_id == owner.principal_id
            assert state.enrollment_hash is None
    finally:
        os.close(reader)
        os.close(writer)
