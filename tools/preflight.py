"""Run the configured checkout's pinned checks without installing dependencies."""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

PROBE = """
import importlib.metadata as m, json, platform
print(json.dumps({'python':platform.python_version(), 'system':platform.system(),
'machine':platform.machine(),
'packages':{d.metadata['Name']:d.version for d in m.distributions()}}))
"""


def run(
    command: list[str], repo: Path, env: dict[str, str], capture: bool = False
) -> subprocess.CompletedProcess[str]:
    print("RUN:", shlex.join(map(str, command)), flush=True)
    return subprocess.run(
        command,
        cwd=repo,
        env=env,
        text=True,
        check=True,
        stdout=subprocess.PIPE if capture else None,
    )


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_count(report: Path) -> int:
    suites = ET.parse(report).getroot().findall(".//testsuite")
    count = sum(int(s.get("tests", "0")) for s in suites)
    if count < 1 or any(
        int(s.get(k, "0")) for s in suites for k in ("failures", "errors", "skipped")
    ):
        raise ValueError("Full Python suite must execute tests with no failures, errors or skips.")
    return count


def validate(repo: Path, python: str, node_bin: Path, env: dict[str, str]) -> None:
    required = [
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "tools/generate_contracts.py",
        "tests/client-runtime.cjs",
        "node_modules/typescript/package.json",
        "node_modules/.bin/tsc",
    ]
    if any(not (repo / p).is_file() for p in required):
        raise ValueError("Required project checks or installed client dependencies are missing.")
    for directory in ("src", "tests", "tools", "migrations"):
        if not any((repo / directory).rglob("*.py")):
            raise ValueError("Required Python source or test directories are empty.")
    top = run(["git", "rev-parse", "--show-toplevel"], repo, env, True).stdout.strip()
    if Path(top).resolve() != repo:
        raise ValueError("Select the Git checkout root.")
    probe = json.loads(run([python, "-I", "-c", PROBE], repo, env, True).stdout)
    if probe["system"] != "Linux" or probe["machine"] not in ("aarch64", "x86_64"):
        raise ValueError("No verified dependency inventory exists for this Python platform.")
    suffix = "-linux-aarch64" if probe["machine"] == "aarch64" else ""
    inventory = json.loads((repo / f"dependency-inventory{suffix}.json").read_text())
    expected = {normalized(p["name"]): p["version"] for p in inventory["packages"]}
    installed = {normalized(k): v for k, v in probe["packages"].items()}
    if not expected or installed != expected or probe["python"] != inventory["python"]:
        raise ValueError("Selected Python environment does not match the pinned inventory.")
    project = tomllib.loads((repo / "pyproject.toml").read_text())
    for tool in ("pytest", "ruff", "mypy"):
        if not project["tool"].get(tool):
            raise ValueError("Required Python check configuration is missing.")
    for requirement in project["project"]["dependencies"]:
        name, separator, version = requirement.partition("==")
        if not separator or expected.get(normalized(name)) != version:
            raise ValueError("Project runtime dependencies disagree with the pinned inventory.")
    locked = {}
    for line in (repo / f"requirements{suffix}.lock").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([\w.-]+)==([^\s]+) --hash=sha256:([a-f0-9]{64})", line)
        if not match or normalized(match[1]) in locked:
            raise ValueError("Python lock contains an unsupported or duplicate requirement.")
        locked[normalized(match[1])] = (match[2], match[3])
    if locked != {
        normalized(p["name"]): (p["version"], p["sha256"]) for p in inventory["packages"]
    }:
        raise ValueError("Python lock and dependency inventory disagree.")
    if not {"pytest", "ruff", "mypy", "pip"} <= expected.keys():
        raise ValueError("Required Python checks are not pinned.")
    package = json.loads((repo / "package.json").read_text())
    lock = json.loads((repo / "package-lock.json").read_text())
    typescript = json.loads((repo / "node_modules/typescript/package.json").read_text())
    version = package["devDependencies"]["typescript"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not (
        version
        == typescript["version"]
        == lock["packages"]["node_modules/typescript"]["version"]
        == lock["packages"][""]["devDependencies"]["typescript"]
    ):
        raise ValueError("Installed TypeScript does not match exact package and lock versions.")
    for check in ("check", "test"):
        if not package["scripts"].get(check, "").strip():
            raise ValueError("Required npm check or test script is unconfigured.")
    for executable in ("node", "npm"):
        if not os.access(node_bin / executable, os.X_OK):
            raise ValueError("Selected Node directory must provide node and npm executables.")
        output = run([str(node_bin / executable), "--version"], repo, env, True).stdout.strip()
        if executable == "node" and output != "v24.22.1":
            raise ValueError("Node does not match the pinned version.")
    print(
        f"VERIFIED: {len(expected)} Python package versions and TypeScript {version}.",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", type=Path, help="Python executable in the pinned environment")
    parser.add_argument("--node-bin", type=Path, help="Directory containing installed node and npm")
    args = parser.parse_args()
    if args.python is None or args.node_bin is None:
        print(
            "NOT_CONFIGURED: select --repo, --python and --node-bin; no checks ran.",
            file=sys.stderr,
        )
        return 2
    repo = args.repo.resolve()
    python = str(args.python.absolute())
    node_bin = args.node_bin.resolve()
    env = {
        "PATH": f"{node_bin}:{Path(python).parent}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONPATH": str(repo / "src"),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "npm_config_ignore_scripts": "true",
        "npm_config_offline": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="validation-") as directory:
            env["npm_config_cache"] = directory
            for scope in ("user", "global"):
                config = Path(directory) / f"{scope}.npmrc"
                config.write_text("")
                env[f"npm_config_{scope}config"] = str(config)
            try:
                validate(repo, python, node_bin, env)
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                subprocess.CalledProcessError,
            ):
                print(
                    "NOT_CONFIGURED: checkout, pinned environment or required tools "
                    "failed validation.",
                    file=sys.stderr,
                )
                return 2
            report = Path(directory) / "pytest.xml"
            run([python, "-m", "pip", "check"], repo, env)
            run(
                [
                    python,
                    "-m",
                    "pytest",
                    "tests",
                    "-o",
                    "addopts=",
                    f"--junitxml={report}",
                ],
                repo,
                env,
            )
            count = test_count(report)
            targets = ["src", "tests", "tools", "migrations"]
            run([python, "-m", "ruff", "check", *targets], repo, env)
            run([python, "-m", "ruff", "format", "--check", *targets], repo, env)
            run([python, "-m", "mypy"], repo, env)
            run([python, "tools/generate_contracts.py", "--check"], repo, env)
            run([str(node_bin / "npm"), "run", "check"], repo, env)
            run([str(node_bin / "npm"), "test"], repo, env)
            run(["git", "diff", "--check"], repo, env)
            run(["git", "diff", "--cached", "--check"], repo, env)
    except (OSError, ValueError, ET.ParseError, subprocess.CalledProcessError):
        print("FAIL: a required check failed; preflight is not cleared.", file=sys.stderr)
        return 1
    print(
        f"PASS: preflight; {count} Python tests. Publication and release approvals remain separate."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
