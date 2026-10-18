# SPDX-License-Identifier: AGPL-3.0-only
"""Record installed dependency versions, declared licenses and downloaded wheel hashes."""

import argparse
import hashlib
import json
import platform
import tomllib
from importlib.metadata import distributions
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel_directory", type=Path)
    parser.add_argument("--lock-file", type=Path, default=ROOT / "requirements.lock")
    parser.add_argument("--inventory-file", type=Path, default=ROOT / "dependency-inventory.json")
    args = parser.parse_args()
    wheel_directory = args.wheel_directory
    target = f"{platform.system()} {platform.machine()}"
    python = ".".join(platform.python_version_tuple()[:2])
    installed = {canonicalize_name(dist.metadata["Name"]): dist for dist in distributions()}
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    pending = [canonicalize_name(Requirement(raw).name) for raw in project["dependencies"]]
    runtime: set[str] = set()
    while pending:
        name = pending.pop()
        if name in runtime:
            continue
        runtime.add(name)
        for raw in installed[name].requires or []:
            requirement = Requirement(raw)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(canonicalize_name(requirement.name))
    wheels = {}
    for wheel in wheel_directory.glob("*.whl"):
        name, version, _, _ = parse_wheel_filename(wheel.name)
        wheels[(name, str(version))] = (wheel.name, hashlib.sha256(wheel.read_bytes()).hexdigest())
    rows = []
    pins = [
        "# Generated from installed distributions and downloaded wheel SHA-256 values.",
        f"# Target: CPython {python}, {target}. Other targets require separately verified wheels.",
    ]
    for name, dist in sorted(installed.items()):
        filename, digest = wheels[(name, dist.version)]
        metadata = dist.metadata
        declared = metadata.get("License-Expression") or metadata.get("License")
        if not declared:
            declared = (
                "; ".join(
                    value.removeprefix("License :: ")
                    for value in metadata.get_all("Classifier", [])
                    if value.startswith("License :: ")
                )
                or "UNDECLARED"
            )
        rows.append(
            {
                "name": name,
                "version": dist.version,
                "use": "runtime" if name in runtime else "development",
                "declared_license": declared,
                "license_files": metadata.get_all("License-File", []),
                "wheel": filename,
                "sha256": digest,
            }
        )
        pins.append(f"{name}=={dist.version} --hash=sha256:{digest}")
    args.lock_file.write_text("\n".join(pins) + "\n")
    inventory = {
        "scope": "Installed Python distributions; metadata inventory, not a full rights review",
        "python": platform.python_version(),
        "platform": target,
        "packages": rows,
    }
    args.inventory_file.write_text(json.dumps(inventory, indent=2) + "\n")


if __name__ == "__main__":
    main()
