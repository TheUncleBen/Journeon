# SPDX-License-Identifier: AGPL-3.0-only
"""Assemble and verify a source-shaped release using the selected target inventory."""

import argparse
import hashlib
import json
import shutil
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TREES = ("src/journeon", "migrations", "generated", "docs")
FILES = ("pyproject.toml", "launch.py", "LICENSE", "README.md")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payload(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Release payload cannot contain symbolic links")
        if path.is_file() and path != root / "manifest.json":
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def verify(root: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((root / "manifest.json").read_text())
    if manifest["format"] != 1 or manifest["files"] != payload(root):
        raise ValueError("Release payload does not match its manifest")
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    if manifest["version"] != version:
        raise ValueError("Release version does not match project metadata")
    return manifest


def build(destination: Path, inventory: Path, wheels: Path) -> dict[str, Any]:
    if destination.resolve().is_relative_to(ROOT):
        raise ValueError("Build the release outside the source checkout")
    for name in FILES + TREES:
        source = ROOT / name
        if source.is_symlink() or any(p.is_symlink() for p in source.rglob("*")):
            raise ValueError("Release source cannot contain symbolic links")
    data = json.loads(inventory.read_text())
    packages = [row for row in data["packages"] if row["use"] == "runtime"]
    for row in packages:
        wheel = wheels / row["wheel"]
        if wheel.name != row["wheel"] or digest(wheel) != row["sha256"]:
            raise ValueError("Runtime wheel does not match the inventory")
    destination.mkdir()
    for name in FILES:
        shutil.copyfile(ROOT / name, destination / name)
    for name in TREES:
        shutil.copytree(
            ROOT / name,
            destination / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    (destination / "wheels").mkdir()
    for row in packages:
        shutil.copyfile(wheels / row["wheel"], destination / "wheels" / row["wheel"])
    (destination / "runtime-inventory.json").write_text(
        json.dumps({**data, "packages": packages}, indent=2) + "\n"
    )
    (destination / "runtime.lock").write_text(
        "\n".join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}" for r in packages)
        + "\n"
    )
    manifest = {
        "format": 1,
        "version": tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"],
        "files": payload(destination),
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return verify(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--wheels", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify(args.destination)
    elif args.inventory is None or args.wheels is None:
        parser.error("Building requires an explicit target inventory and wheel directory")
    else:
        build(args.destination, args.inventory, args.wheels)


if __name__ == "__main__":
    main()
