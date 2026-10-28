"""Acquire hash-pinned validation wheels and install them offline in a new environment."""

import argparse
import hashlib
import json
import os
import platform
import re
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path
from typing import IO

BLOCKED_ROOT = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"


def verify(path: Path, digest: str) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("Downloaded artifact hash does not match the inventory.")


def context(pem: str) -> ssl.SSLContext:
    certificates = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    certificates = [
        certificate
        for certificate in certificates
        if hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest() != BLOCKED_ROOT
    ]
    if not certificates:
        raise ValueError("No trusted certificates remain.")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(cadata="\n".join(certificates))
    return tls


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> None:
        raise ValueError("Unexpected package download redirect.")


def fetch(url: str, tls: ssl.SSLContext) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ("pypi.org", "files.pythonhosted.org"):
        raise ValueError("Unexpected package download origin.")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), NoRedirect()
    )
    with opener.open(url, timeout=60) as response:
        if response.url != url:
            raise ValueError("Unexpected package download redirect.")
        return bytes(response.read())


def download(package: dict[str, str], wheels: Path, tls: ssl.SSLContext) -> Path:
    name, version = package["name"], package["version"]
    metadata = json.loads(fetch(f"https://pypi.org/pypi/{name}/{version}/json", tls))
    matching = [entry for entry in metadata["urls"] if entry["filename"] == package["wheel"]]
    if len(matching) != 1 or matching[0]["digests"]["sha256"] != package["sha256"]:
        raise ValueError("Published artifact does not match the inventory.")
    path = wheels / package["wheel"]
    if path.name != package["wheel"]:
        raise ValueError("Invalid wheel filename.")
    path.write_bytes(fetch(matching[0]["url"], tls))
    verify(path, package["sha256"])
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--node-bin", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    if (platform.system(), platform.machine(), platform.python_version()) != (
        "Linux",
        "aarch64",
        "3.12.15",
    ):
        raise ValueError("Bootstrap requires Linux aarch64 and Python 3.12.15.")
    destination = args.destination.resolve()
    destination.mkdir()
    wheels = destination / "wheels"
    wheels.mkdir()
    packages = json.loads((repo / "dependency-inventory-linux-aarch64.json").read_text())[
        "packages"
    ]
    pinned = {package["name"].lower(): package for package in packages}
    if (
        len(pinned) != 36
        or pinned["pip"]["version"] != "26.2.2"
        or pinned["certifi"]["version"] != "2026.10.19"
    ):
        raise ValueError("Unexpected bootstrap inventory.")
    tls = context(Path("/etc/ssl/certs/ca-certificates.crt").read_text())
    certifi = download(pinned["certifi"], wheels, tls)
    with zipfile.ZipFile(certifi) as archive:
        pem = archive.read("certifi/cacert.pem").decode("ascii")
    tls = context(pem)
    ca = destination / "ca.pem"
    ca.write_text(pem)
    for package in packages:
        if package["name"].lower() != "certifi":
            download(package, wheels, tls)
    empty_ca = destination / "empty-ca"
    empty_ca.mkdir()
    env = {
        "PATH": f"{args.node_bin.resolve()}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PIP_CONFIG_FILE": os.devnull,
        "SSL_CERT_FILE": str(ca),
        "SSL_CERT_DIR": str(empty_ca),
    }
    subprocess.run(
        [sys.executable, "-I", "-m", "venv", "--without-pip", str(destination / "venv")],
        env=env,
        check=True,
    )
    python = str(destination / "venv/bin/python")
    subprocess.run(
        [
            python,
            "-I",
            str(wheels / pinned["pip"]["wheel"]) + "/pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links",
            str(wheels),
            "-r",
            str(repo / "requirements-linux-aarch64.lock"),
        ],
        env=env,
        check=True,
    )
    for scope in ("user", "global"):
        config = destination / f"{scope}.npmrc"
        config.write_text("")
        env[f"npm_config_{scope}config"] = str(config)
    env.update(
        {
            "npm_config_cache": str(destination / "npm-cache"),
            "npm_config_cafile": str(ca),
            "npm_config_strict_ssl": "true",
            "npm_config_registry": "https://registry.npmjs.org/",
            "npm_config_update_notifier": "false",
        }
    )
    node = args.node_bin.resolve()
    if (
        subprocess.check_output([str(node / "node"), "--version"], env=env, text=True).strip()
        != "v24.22.1"
    ):
        raise ValueError("Node does not match the pinned version.")
    subprocess.run(
        [str(node / "npm"), "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=repo,
        env=env,
        check=True,
    )


if __name__ == "__main__":
    main()
