# SPDX-License-Identifier: AGPL-3.0-only
import asyncio
import http.client
import json
import os
import runpy
import signal
import socket
import ssl
import subprocess
import sys
import time
import tomllib
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import select, text

from journeon.database import transaction
from journeon.models import AuthRateEvent
from journeon.runtime import RuntimeConfig, application, read_config, server_config
from journeon.sessions import digest, issue_session

ROOT = Path(__file__).resolve().parents[1]
BUILD = runpy.run_path(str(ROOT / "tools/build_release.py"))


@pytest.fixture
def release(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"packages": [], "platform": "synthetic"}))
    original = tmp_path / "original"
    BUILD["build"](original, inventory, tmp_path)
    relocated = tmp_path / "relocated"
    original.rename(relocated)
    return relocated


def certificate(directory, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certpath, keypath = directory / f"{name}.crt", directory / f"{name}.key"
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keypath.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keypath.chmod(0o600)
    return certpath, keypath


@pytest.fixture
def settings(database, tmp_path):
    cert, key = certificate(tmp_path, "server")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return dict(
        host="127.0.0.1",
        port=port,
        origin=f"https://localhost:{port}",
        rp_id="localhost",
        database=str(database[1]),
        tls_certificate=str(cert),
        tls_private_key=str(key),
        trusted_proxy_peers=[],
        busy_timeout_ms=5000,
        backlog=16,
        limit_concurrency=20,
        timeout_keep_alive=1,
        timeout_graceful_shutdown=2,
    )


def config_file(tmp_path, settings):
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(settings))
    return path


def request(
    settings,
    method="GET",
    path="/openapi.json",
    body=None,
    headers=None,
    context=None,
    host="localhost",
):
    context = context or ssl.create_default_context(cafile=settings["tls_certificate"])
    connection = http.client.HTTPSConnection(host, settings["port"], context=context, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def spawn(release, config, cwd):
    return subprocess.Popen(
        [sys.executable, "-I", str(release / "launch.py"), "--config", str(config)],
        cwd=cwd,
        env={
            "PATH": os.defpath,
            "UVICORN_HOST": "invalid",
            "UVICORN_PORT": "1",
            "FORWARDED_ALLOW_IPS": "*",
            "PYTHONPATH": "/nonexistent",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@contextmanager
def running(release, settings, tmp_path):
    process = spawn(release, config_file(tmp_path, settings), tmp_path)
    try:
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, process.communicate()
            try:
                assert request(settings)[0] == 200
                break
            except OSError:
                assert time.monotonic() < deadline
                time.sleep(0.02)
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        output = process.communicate(timeout=10)
        assert process.returncode == -signal.SIGTERM, output
        assert b'{"status": "STOPPED"}' in output[0], output
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection((settings["host"], settings["port"]), timeout=1)


def test_relocated_imports_version_and_migrations(release, settings, tmp_path):
    script = """
import json, sys
from pathlib import Path
sys.dont_write_bytecode=True
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'src'))
from journeon.runtime import read_config, application
from journeon.migrate import configuration
from alembic.script import ScriptDirectory
app=application(read_config(Path(sys.argv[2])))
modules=[m.__file__ for n,m in sys.modules.items() if n=='journeon' or n.startswith('journeon.')]
assert all(Path(p).is_relative_to(root) for p in modules)
source=Path(sys.argv[3])
assert not any(Path(p).is_relative_to(source) for p in sys.path if p)
revisions=[r.revision for r in ScriptDirectory.from_config(configuration()).walk_revisions()]
print(json.dumps({'version':app.version,'revisions':revisions,'modules':len(modules)}))
app.state.engine.dispose()
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(release),
            str(config_file(tmp_path, settings)),
            str(ROOT),
        ],
        cwd=tmp_path,
        env={"PATH": os.defpath},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert (
        data["version"]
        == tomllib.loads((release / "pyproject.toml").read_text())["project"]["version"]
    )
    assert data["revisions"] == [
        "0014_review_completion",
        "0013_task_dispatch",
        "0012_attempt_execution",
        "0011_task_admission",
        "0010_work_execution",
        "0009_instruction_scope",
        "0008_project_instructions",
        "0007_identity_instructions",
        "0006_work",
        "0005_protected_operations",
        "0004_auth_rate_events",
        "0003_passkeys",
        "0002_browser_sessions",
        "0001_foundation",
    ]
    assert data["modules"] >= 15
    for name in ("core.md", "navigation.md"):
        assert (release / "src" / "journeon" / "assets" / "instructions" / name).read_bytes() == (
            ROOT / "src" / "journeon" / "assets" / "instructions" / name
        ).read_bytes()
    BUILD["verify"](release)


@pytest.mark.parametrize("kind", ["extra", "missing", "changed", "symlink"])
def test_exact_manifest(release, kind):
    if kind == "extra":
        (release / "undeclared").write_text("unexpected")
    elif kind == "missing":
        (release / "pyproject.toml").unlink()
    elif kind == "changed":
        (release / "pyproject.toml").write_text("changed")
    else:
        (release / "link").symlink_to(release / "pyproject.toml")
    with pytest.raises(ValueError):
        BUILD["verify"](release)


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "http://localhost"),
        ("rp_id", "other.test"),
        ("port", True),
        ("trusted_proxy_peers", ["*"]),
        ("trusted_proxy_peers", ["127.0.0.0/8"]),
        ("tls_private_key", "/missing-key"),
        ("host", ""),
        ("timeout_graceful_shutdown", 0),
        ("database", "relative.db"),
        ("unexpected", "secret-sentinel"),
    ],
)
def test_invalid_configuration_fails_without_values(release, settings, tmp_path, field, value):
    settings[field] = value
    process = spawn(release, config_file(tmp_path, settings), tmp_path)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 1
    assert b"secret-sentinel" not in stdout + stderr
    assert b"Runtime configuration or startup failed" in stdout


def test_every_setting_required(settings):
    for field in settings:
        with pytest.raises(ValueError):
            RuntimeConfig.model_validate({k: v for k, v in settings.items() if k != field})


@pytest.mark.parametrize("kind", ["missing", "symlink", "unreadable"])
def test_config_file_failures(settings, tmp_path, kind):
    path = config_file(tmp_path, settings)
    if kind == "missing":
        path.unlink()
    elif kind == "symlink":
        linked = tmp_path / "link.json"
        linked.symlink_to(path)
        path = linked
    else:
        path.chmod(0)
    try:
        with pytest.raises((ValueError, OSError)):
            read_config(path)
    finally:
        if kind == "unreadable":
            path.chmod(0o600)


@pytest.mark.parametrize("kind", ["missing-db", "old-schema", "version", "migrations"])
def test_startup_never_repairs_missing_state(release, settings, tmp_path, database, kind):
    if kind == "missing-db":
        settings["database"] = str(tmp_path / "absent.db")
    elif kind == "old-schema":
        with database[0].begin() as db:
            db.execute(text("UPDATE alembic_version SET version_num='0004_auth_rate_events'"))
    elif kind == "version":
        (release / "pyproject.toml").unlink()
    else:
        (release / "migrations/versions/0005_protected_operations.py").unlink()
    process = spawn(release, config_file(tmp_path, settings), tmp_path)
    stdout, _ = process.communicate(timeout=10)
    assert process.returncode == 1 and b"startup failed" in stdout
    if kind == "missing-db":
        assert not Path(settings["database"]).exists()
    if kind == "old-schema":
        with database[0].connect() as db:
            assert (
                db.scalar(text("SELECT version_num FROM alembic_version"))
                == "0004_auth_rate_events"
            )


def test_lifespan_disposes_engine(settings, monkeypatch):
    app = application(RuntimeConfig.model_validate(settings))
    disposed = []
    monkeypatch.setattr(app.state.engine, "dispose", lambda: disposed.append(True))

    async def lifecycle():
        async with app.router.lifespan_context(app):
            assert not disposed

    asyncio.run(lifecycle())
    assert disposed == [True]


def test_real_tls_auth_restart_and_collision(release, settings, tmp_path, database, command):
    with transaction(database[0]) as db:
        issued = issue_session(
            db,
            "owner-test",
            authentication_method="synthetic",
            client_label="Runtime fixture",
            strong=True,
        )
    headers = {
        "Origin": settings["origin"],
        "Cookie": f"__Host-journeon-session={issued.token}",
        "X-CSRF-Token": issued.csrf_token,
        "Content-Type": "application/json",
    }
    with running(release, settings, tmp_path):
        assert request(settings, path="/api/v1/operations/unknown")[0] == 401
        assert (
            request(
                settings,
                "POST",
                "/api/v1/projects",
                command.model_dump_json(),
                {**headers, "Origin": "https://wrong.test"},
            )[0]
            == 401
        )
        assert (
            request(
                settings,
                "POST",
                "/api/v1/projects",
                command.model_dump_json(),
                {**headers, "X-CSRF-Token": "wrong"},
            )[0]
            == 401
        )
        status, receipt = request(
            settings, "POST", "/api/v1/projects", command.model_dump_json(), headers
        )
        assert status == 200
        wrong_cert, _ = certificate(tmp_path, "wrong")
        with pytest.raises(ssl.SSLCertVerificationError):
            request(settings, context=ssl.create_default_context(cafile=str(wrong_cert)))
        with pytest.raises(ssl.SSLCertVerificationError):
            request(settings, host="127.0.0.1")
        collision = spawn(release, config_file(tmp_path, settings), tmp_path)
        collision.communicate(timeout=10)
        assert collision.returncode != 0
    with running(release, settings, tmp_path):
        status, retained = request(
            settings, path=f"/api/v1/operations/{receipt['operation_id']}", headers=headers
        )
        assert status == 200 and retained == receipt
    with database[0].connect() as db:
        assert db.scalar(text("SELECT count(*) FROM projects")) == 1


@pytest.mark.parametrize("trust", [False, True])
def test_peer_provenance_and_disconnect_reservations(release, settings, tmp_path, database, trust):
    settings["trusted_proxy_peers"] = ["127.0.0.1"] if trust else []
    expected = "198.51.100.9" if trust else "127.0.0.1"
    with running(release, settings, tmp_path):
        status, _ = request(
            settings,
            "POST",
            "/api/v1/auth/passkeys/begin",
            "{",
            {
                "Origin": settings["origin"],
                "Content-Type": "application/json",
                "X-Forwarded-For": "198.51.100.9",
                "X-Forwarded-Proto": "https",
            },
        )
        assert status == 422
        with transaction(database[0]) as db:
            rows = list(db.scalars(select(AuthRateEvent)))
            assert len(rows) == 1
            assert rows[0].bucket == "rejected-source:" + digest(expected)
        context = ssl.create_default_context(cafile=settings["tls_certificate"])
        with socket.create_connection(("127.0.0.1", settings["port"])) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as stream:
                stream.sendall(
                    b"POST /api/v1/auth/passkeys/begin HTTP/1.1\r\n"
                    b"Host: localhost\r\nContent-Length: 100\r\n\r\n{"
                )
                deadline = time.monotonic() + 5
                while True:
                    with transaction(database[0]) as db:
                        rows = list(db.scalars(select(AuthRateEvent)))
                    if len(rows) == 2:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.02)
        with transaction(database[0]) as db:
            rows = list(db.scalars(select(AuthRateEvent)))
            assert len(rows) == 2
            assert all(row.expires_at - row.observed_at == 300 and row.weight == 1 for row in rows)


def test_explicit_server_binding_ignores_environment(settings, monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    monkeypatch.setenv("UVICORN_PORT", "1")
    config = RuntimeConfig.model_validate(settings)
    app = application(config)
    try:
        server = server_config(config, app)
        assert server.port == settings["port"]
        assert server.forwarded_allow_ips == [] and not server.proxy_headers
        assert server.http == "h11" and server.loop == "asyncio" and server.workers == 1
    finally:
        app.state.engine.dispose()


def test_sigterm_cancels_partial_body_and_keeps_finite_reservation(
    release, settings, tmp_path, database
):
    with running(release, settings, tmp_path) as process:
        context = ssl.create_default_context(cafile=settings["tls_certificate"])
        with socket.create_connection(("127.0.0.1", settings["port"])) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as stream:
                stream.sendall(
                    b"POST /api/v1/auth/passkeys/begin HTTP/1.1\r\n"
                    b"Host: localhost\r\nContent-Length: 100\r\n\r\n{"
                )
                deadline = time.monotonic() + 5
                while True:
                    with transaction(database[0]) as db:
                        rows = list(db.scalars(select(AuthRateEvent)))
                    if rows:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.02)
                process.terminate()
                process.wait(timeout=10)
                with transaction(database[0]) as db:
                    rows = list(db.scalars(select(AuthRateEvent)))
                    assert len(rows) == 1
                    assert rows[0].expires_at - rows[0].observed_at == 300


def test_factory_errors_do_not_echo_configuration(tmp_path, monkeypatch):
    from journeon.runtime import factory

    path = tmp_path / "invalid.json"
    path.write_text('{"secret-sentinel": "invalid"}')
    monkeypatch.setenv("JOURNEON_CONFIG", str(path))
    with pytest.raises(RuntimeError, match="Runtime configuration or startup failed") as error:
        factory()
    assert "secret-sentinel" not in str(error.value)
    assert error.value.__suppress_context__


def test_origin_ports_are_validated_by_all_bindings(settings, database):
    from journeon.browser_auth import BrowserAuth
    from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService

    for port in ("invalid", "65536", "0", ""):
        origin = f"https://localhost:{port}"
        with pytest.raises(ValueError):
            BrowserAuth(origin)
        with pytest.raises(ValueError):
            PasskeyService(
                database[0], rp_id="localhost", origin=origin, policy=STANDARD_PASSKEY_POLICY
            )
        with pytest.raises(ValueError):
            RuntimeConfig.model_validate({**settings, "origin": origin})


def test_runtime_owns_execution_reconciliation_and_drain(settings, monkeypatch):
    from fastapi.testclient import TestClient

    from journeon.executions import ExecutionService

    events = []
    monkeypatch.setattr(ExecutionService, "reconcile", lambda self: events.append("reconciled"))
    monkeypatch.setattr(ExecutionService, "shutdown", lambda self: events.append("drained"))
    app = application(RuntimeConfig.model_validate(settings))
    with TestClient(app):
        assert events == ["reconciled"]
        assert isinstance(app.state.execution_service, ExecutionService)
    assert events == ["reconciled", "drained"]
