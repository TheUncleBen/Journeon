# SPDX-License-Identifier: AGPL-3.0-only
"""Read the running package's reviewed instruction candidate, without installing it."""

from importlib.resources import files
from typing import Literal

from journeon.contracts import Contract, InstructionTemplate
from journeon.instructions import digest, validate_template


class PackagedInstruction(Contract):
    asset_id: str
    version: str
    purpose: Literal["CORE", "NAVIGATION"]
    content_hash: str
    template: InstructionTemplate


class CandidateManifest(Contract):
    provenance: Literal["DEVELOPMENT_CANDIDATE"] = "DEVELOPMENT_CANDIDATE"
    digest: str
    source_digest: str
    assets: list[PackagedInstruction]


def candidate_manifest() -> CandidateManifest:
    assets = []
    for purpose in ("CORE", "NAVIGATION"):
        name = purpose.lower()
        content = (
            files("journeon")
            .joinpath("assets", "instructions", name + ".md")
            .read_text(encoding="utf-8")
        )
        template = InstructionTemplate(
            template_id="system-" + name + "-v1",
            template=content,
            required_variables=[],
            eval_ids=["instruction-boundaries-v1"],
        )
        validate_template(template)
        from journeon.instruction_evals import execute

        execute(template)
        assets.append(
            PackagedInstruction(
                asset_id="system-" + name,
                version="1.0.0",
                purpose=purpose,
                content_hash=digest(template.model_dump(mode="json")),
                template=template,
            )
        )
    import hashlib
    from pathlib import Path

    package = Path(__file__).resolve().parent
    sources = {
        path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(package.rglob("*"))
        if path.is_file()
        and path.suffix in {".py", ".md", ".json"}
        and "__pycache__" not in path.parts
    }
    source_digest = digest(sources)
    manifest_hash = digest(
        {
            "assets": [asset.model_dump(mode="json") for asset in assets],
            "source_digest": source_digest,
        }
    )
    return CandidateManifest(digest=manifest_hash, source_digest=source_digest, assets=assets)
