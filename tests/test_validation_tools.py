import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "counts",
    ['tests="0"', 'tests="2" skipped="1"', 'tests="2" failures="1"', 'tests="2" errors="1"'],
)
def test_preflight_rejects_incomplete_suites(tmp_path, counts):
    report = tmp_path / "results.xml"
    report.write_text(f"<testsuites><testsuite {counts}/></testsuites>")
    with pytest.raises(ValueError):
        load("preflight").test_count(report)


def test_preflight_missing_tools_cannot_pass(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/preflight.py"),
            "--repo",
            str(tmp_path),
            "--python",
            sys.executable,
            "--node-bin",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "PASS:" not in result.stdout


def test_bootstrap_rejects_modified_download(tmp_path):
    target = tmp_path / "download.whl"
    target.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="hash"):
        load("bootstrap_validation").verify(target, "0" * 64)


def test_workflow_uses_readonly_pr_head():
    workflow = (ROOT / ".github/workflows/validation.yml").read_text()
    assert "pull_request:" in workflow
    assert "pull_request_target" not in workflow
    assert "workflow_dispatch" not in workflow
    assert "draft" not in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "ref: ${{ github.event.pull_request.head.sha }}" in workflow
    assert "github.sha" in workflow
    assert "tools/bootstrap_validation.py" in workflow
    assert "tools/preflight.py" in workflow


def test_bootstrap_trust_does_not_union_system_roots(monkeypatch):
    import hashlib
    import re
    import ssl

    module = load("bootstrap_validation")
    roots = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        Path("/etc/ssl/certs/ca-certificates.crt").read_text(),
        re.S,
    )
    monkeypatch.setattr(
        module, "BLOCKED_ROOT", hashlib.sha256(ssl.PEM_cert_to_DER_cert(roots[0])).hexdigest()
    )
    tls = module.context("\n".join(roots[:2]))
    assert tls.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(roots[1])]
    assert tls.check_hostname
    assert tls.verify_mode == ssl.CERT_REQUIRED


def test_bootstrap_rejects_unexpected_origin_before_network():
    import ssl

    with pytest.raises(ValueError, match="origin"):
        load("bootstrap_validation").fetch(
            "http://example.invalid/wheel", ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        )


def test_bootstrap_rejects_redirect_before_following():
    from email.message import Message
    from io import BytesIO
    from urllib.request import Request

    with pytest.raises(ValueError, match="redirect"):
        load("bootstrap_validation").NoRedirect().redirect_request(
            Request("https://pypi.org/"),
            BytesIO(),
            302,
            "Found",
            Message(),
            "http://example.invalid/",
        )


def test_workflow_head_check_executes_and_rejects_merge_head(tmp_path):
    import os

    workflow = (ROOT / ".github/workflows/validation.yml").read_text()
    script = workflow.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
    script = "\n".join(line[10:] for line in script.splitlines())
    binary = tmp_path / "git"
    binary.write_text("#!/bin/sh\nprintf '%s\n' actual-head\n")
    binary.chmod(0o755)
    env = {
        "PATH": str(tmp_path) + ":" + os.defpath,
        "PR_HEAD_SHA": "actual-head",
        "EVENT_SHA": "synthetic-merge",
    }
    result = subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode == 0
    assert "checkout=actual-head" in result.stdout
    assert "event_merge=synthetic-merge" in result.stdout
    env["PR_HEAD_SHA"] = "wrong-head"
    result = subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode != 0


@pytest.mark.parametrize(
    "test_source",
    [
        "",
        'import pytest\ndef test_skipped():\n    pytest.skip("control")\n',
        "def test_kept():\n    assert True\ndef test_omitted():\n    assert False\n",
    ],
)
def test_preflight_runs_real_suite_without_hiding_failures(tmp_path, monkeypatch, test_source):
    module = load("preflight")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_control.py").write_text(test_source)
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\naddopts="-k kept"\n')
    monkeypatch.setattr(module, "validate", lambda *args: None)
    original = module.run

    def run(command, repo, env, capture=False):
        if command[1:3] == ["-m", "pytest"]:
            return original(command, repo, env, capture)
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "preflight",
            "--repo",
            str(tmp_path),
            "--python",
            sys.executable,
            "--node-bin",
            "/usr/bin",
        ],
    )
    assert module.main() == 1
