# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
from pathlib import Path

import pytest
from sqlalchemy import select, text
from test_task_dispatch import dispatch_worker
from test_workspace_discovery_pages import grant, revoke
from test_workspace_discovery_work import dispatch
from test_workspace_durable_resolution import read_state
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.database import transaction
from journeon.instructions import digest
from journeon.models import Attention, Receipt


def test_search_finds_authorized_real_project(genuine_project_task):
    owner, _, receipt, _, _, _ = genuine_project_task
    project = receipt["project"]
    grant(owner, "project.read", project["project_id"], "search-project-read")
    response = owner.client.get(
        "/api/v1/search",
        params={"q": project["name"], "kinds": "PROJECT", "limit": 10},
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert [item["entity_id"] for item in response.json()["items"]] == [project["project_id"]]
    assert response.json()["supported_coverage"] == [
        "ATTEMPT",
        "INSTRUCTION_NAVIGATION",
        "JOB",
        "PROJECT",
        "TASK",
    ]


def test_attention_global_read_is_explicit_and_canonical(enrolled_owner):
    response = enrolled_owner.client.get("/api/v1/attention", params={"limit": 10})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["items"] == []
    assert response.json()["supported_coverage"] == ["JOB"]


def search(owner, q="a", kinds=("PROJECT", "TASK"), **params):
    return owner.client.get(
        "/api/v1/search", params={"q": q, "kinds": list(kinds), "limit": 100} | params
    )


def attention_page(owner, **params):
    response = owner.client.get("/api/v1/attention", params={"limit": 100} | params)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def failed_work(monkeypatch, request):
    from workspace_durable_helpers import route

    def failing_route():
        original = route()
        return original.model_copy(
            update={"argv": [*original.argv[:-1], "raise SystemExit(7)"], "artifacts": []}
        )

    monkeypatch.setattr("workspace_durable_helpers.route", failing_route)
    fixture = request.getfixturevalue("genuine_durable_work")
    receipt = dispatch(fixture, "attention-real-failure")
    dispatch_worker(fixture[0].engine, fixture[1])
    source = fixture[0].client.get(f"/api/v1/jobs/{receipt['job_id']}")
    assert source.status_code == 200
    assert source.json()["state"] == "FAILED"
    assert source.json()["reason"] == "VERIFICATION_FAILED"
    return fixture, receipt


def dismiss(owner, item, key="own-dismissal", **changes):
    command = {
        "schema_version": 1,
        "idempotency_key": key,
        "attention_id": item["attention_id"],
        "expected_revision": item["presentation_revision"],
        "expected_source_revision": item["source_revision"],
    } | changes
    return command, owner.client.post(
        "/api/v1/notifications/dismiss", headers=owner.headers, json=command
    )


def test_real_failure_dismissal_keeps_canonical_and_both_receipts(failed_work):
    fixture, _ = failed_work
    owner = fixture[0]
    item = attention_page(owner)["items"][0]
    assert item["canonical_disposition"] == "OPEN"
    assert item["presentation_disposition"] == "UNACKNOWLEDGED"
    assert item["source_revision"] == item["source"]["revision"]
    with transaction(owner.engine) as db:
        original = db.get(Attention, item["attention_id"])
        history, occurrences = original.history, original.occurrences
    first_command, first = dismiss(owner, item)
    assert first.status_code == 200, first.text
    after = attention_page(owner, canonical_disposition="OPEN")["items"][0]
    assert after["canonical_disposition"] == "OPEN"
    assert after["presentation_disposition"] == "DISMISSED"
    assert after["presentation_revision"] == 1
    assert after["source"] == item["source"]
    second_command, second = dismiss(owner, after, key="second-explicit-dismissal")
    assert second.status_code == 200, second.text
    assert second.json()["revision"] == 2
    for command, accepted in ((first_command, first), (second_command, second)):
        receipt = accepted.json()
        observed = owner.client.post(
            "/api/v1/operations/resolve",
            headers=owner.headers,
            json={
                "schema_version": 1,
                "command": "notification.dismiss.v1",
                "idempotency_key": command["idempotency_key"],
                "payload_digest": digest(
                    {key: value for key, value in command.items() if key != "idempotency_key"}
                ),
                "scope": {"attention_id": item["attention_id"]},
                "store_incarnation": attention_page(owner)["store_incarnation"],
            },
        )
        assert observed.status_code == 200, observed.text
        assert observed.json()["status"] == "OBSERVED_RECEIPT"
        assert observed.json()["receipt"] == receipt
        replayed = owner.client.post(
            "/api/v1/notifications/dismiss", headers=owner.headers, json=command
        )
        assert replayed.status_code == 200
        assert replayed.json() == receipt
        assert owner.client.get(f"/api/v1/operations/{receipt['operation_id']}").json() == receipt
    with transaction(owner.engine) as db:
        original = db.get(Attention, item["attention_id"])
        assert (original.history, original.occurrences, original.disposition) == (
            history,
            occurrences,
            "OPEN",
        )
        assert (
            len(
                list(
                    db.scalars(select(Receipt).where(Receipt.command == "notification.dismiss.v1"))
                )
            )
            == 2
        )


def test_instruction_metadata_search_does_not_scan_and_keeps_live_read(
    genuine_instruction_scope, monkeypatch
):
    owner, config, project, _, _, _ = genuine_instruction_scope
    before = read_state(owner)

    def forbidden(*args, **kwargs):
        raise AssertionError("Search performed a filesystem scan")

    import journeon.project_instructions as instructions

    bounded = []
    original = instructions.open_directory

    def opening(path):
        bounded.append(path)
        return original(path)

    with monkeypatch.context() as guarded:
        guarded.setattr(instructions, "read_tree", forbidden)
        guarded.setattr("journeon.instruction_config.observe_root", forbidden)
        guarded.setattr(instructions, "open_directory", opening)
        result = search(owner, "rules", ("INSTRUCTION_NAVIGATION",))
        assert result.status_code == 200, result.text
        assert result.json()["items"][0]["provenance"] == "ACCEPTED_INSTRUCTION_REVISION"
        assert result.json()["items"][0]["display_fields"] == ["INDEX.md", "rules.md"]
        assert bounded
    assert read_state(owner) == before
    tree = Path(config.roots[0].path) / "instructions" / "projects" / project
    (tree / "rules.md").write_text("Unaccepted disk change\n")
    assert search(owner, "rules", ("INSTRUCTION_NAVIGATION",)).status_code == 200
    assert owner.client.get(f"/api/v1/projects/{project}/instructions").status_code == 409


@pytest.mark.parametrize("hidden", ["grant", "root", "identity", "git", "config", None])
def test_instruction_authority_precedes_corrupt_accepted_metadata(
    genuine_instruction_scope, hidden
):
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.models import InstructionRoot

    owner, config, project, _, grants, _ = genuine_instruction_scope
    if hidden == "grant":
        revoke(owner, grants["project.instruction.read"]["grant"])
    if hidden in {"identity", "git"}:
        root = Path(config.roots[0].path)
        if hidden == "identity":
            root.rename(root.with_name("retained-root"))
            root.mkdir()
        else:
            (root / ".git").mkdir()
    with transaction(owner.engine) as db:
        db.execute(text("DROP TRIGGER immutable_project_instruction_revisions_update"))
        if hidden == "root":
            db.get(InstructionRoot, "durable-environment").enabled = False
        db.execute(
            text(
                "UPDATE project_instruction_revisions SET snapshot='invalid-json' "
                "WHERE project_id=:id"
            ),
            {"id": project},
        )
    if hidden == "config":
        with TestClient(
            create_app(
                owner.engine,
                browser_auth=owner.client.app.state.browser_auth,
                instructions=config.model_copy(update={"roots": []}),
            ),
            base_url="https://example.test",
            cookies=owner.client.cookies,
        ) as client:
            response = search(replace(owner, client=client), "rules", ("INSTRUCTION_NAVIGATION",))
    else:
        response = search(owner, "rules", ("INSTRUCTION_NAVIGATION",))
    assert response.status_code == (200 if hidden else 503), response.text
    if hidden:
        assert response.json()["items"] == []
        assert response.json()["has_more"] is False
        assert project not in json.dumps(response.json()["items"])


@pytest.mark.parametrize(
    "broken", ["pending", "missing", "tree-hash", "wrong-ref", "unsafe-path", "required"]
)
def test_required_instruction_metadata_fails_explicitly_without_repair(
    genuine_instruction_scope, broken
):
    from journeon.models import ProjectInstructionBinding, ProjectInstructionRevision

    owner, _, project, _, _, _ = genuine_instruction_scope
    with transaction(owner.engine) as db:
        db.execute(text("DROP TRIGGER immutable_project_instruction_revisions_update"))
        db.execute(text("DROP TRIGGER immutable_project_instruction_revisions_delete"))
        binding = db.get(ProjectInstructionBinding, project)
        revision = db.get(ProjectInstructionRevision, (project, binding.revision))
        if broken == "pending":
            binding.active_operation = "unresolved-publication"
        elif broken == "missing":
            db.delete(revision)
        elif broken == "tree-hash":
            revision.tree_hash = "0" * 64
        else:
            data = json.loads(json.dumps(revision.snapshot))
            if broken == "wrong-ref":
                data["document_refs"]["rules.md"]["project_id"] = "different-project"
            elif broken == "unsafe-path":
                data["documents"]["../escape"] = ""
                data["document_refs"]["../escape"] = data["document_refs"]["rules.md"] | {
                    "path": "../escape"
                }
            else:
                data["required_fragments"] = ["missing.md"]
            revision.snapshot = data
    before = read_state(owner)
    response = search(owner, "rules", ("INSTRUCTION_NAVIGATION",))
    assert response.status_code == 503, response.text
    assert read_state(owner) == before


def test_search_unicode_literals_paging_binding_and_hidden_lookahead(genuine_project_task):
    owner, command, _, _, _, _ = genuine_project_task
    created = []
    for index in range(3):
        response = owner.client.post(
            "/api/v1/projects",
            headers=owner.headers,
            json=command.model_dump(mode="json")
            | {"idempotency_key": f"unicode-project-{index}", "name": "Café Straße %_"},
        )
        assert response.status_code == 200
        created.append(response.json()["project"]["project_id"])
    created.sort()
    for index, identity in enumerate(created[:2]):
        grant(owner, "project.read", identity, f"unicode-read-{index}")
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE projects SET provider_snapshot='invalid-json' WHERE id=:id"),
            {"id": created[-1]},
        )
    before = read_state(owner)
    first = search(owner, "CAFE\u0301 STRASSE %_", ("PROJECT",), limit=1)
    assert first.status_code == 200
    page = first.json()
    assert page["items"][0]["entity_id"] == created[0]
    assert page["has_more"]
    cursor = json.loads(base64.urlsafe_b64decode(page["next_cursor"]))
    assert (cursor["after_kind"], cursor["after"]) == ("PROJECT", created[0])
    second = search(owner, "café straße %_", ("PROJECT",), limit=1, cursor=page["next_cursor"])
    assert second.status_code == 200
    assert [item["entity_id"] for item in second.json()["items"]] == [created[1]]
    assert not second.json()["has_more"]
    for replacement in ({"q": "different"}, {"kinds": ["TASK"]}, {"project_id": created[0]}):
        params = {
            "q": "café straße %_",
            "kinds": ["PROJECT"],
            "limit": 1,
            "cursor": page["next_cursor"],
        } | replacement
        assert owner.client.get("/api/v1/search", params=params).status_code == 409
    assert search(owner, "!", ("PROJECT",), cursor="!").status_code == 422
    assert read_state(owner) == before


def test_search_budget_and_requested_unavailable_adapters(genuine_project_task, monkeypatch):
    owner = genuine_project_task[0]
    monkeypatch.setattr("journeon.search.SCAN_LIMIT", 0)
    response = search(owner, "missing", ("PROJECT",))
    assert response.status_code == 503
    assert response.json()["code"] == "DEPENDENCY_UNAVAILABLE"
    assert search(owner, "a", ("UNIMPLEMENTED",)).status_code == 503
    assert search(owner, "a", ("ATTEMPT",)).status_code == 503
    assert search(owner, "a", ("JOB",)).status_code == 503
    for params in (
        {"q": "", "kinds": "PROJECT", "limit": 1},
        {"q": "a" * 201, "kinds": "PROJECT", "limit": 1},
        {"q": "a", "limit": 1},
        {"q": "a", "kinds": "PROJECT"},
    ):
        assert owner.client.get("/api/v1/search", params=params).status_code == 422
