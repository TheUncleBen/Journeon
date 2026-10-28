# Journeon

Journeon is being developed as a service-owned project environment. This source-tree foundation implements internal Project creation, passkey labeling and local Task lifecycle commands with transactional authorization, persistence and receipt reconciliation. It is an early development slice, not an operational installation or release candidate.

The FastAPI authentication dependency denies access unless explicitly configured with a canonical HTTPS origin and a valid durable session. Session primitives validate opaque cookies, CSRF, expiry and revocation; explicitly configured passkey ceremonies can issue sessions after WebAuthn verification. Bootstrap requires a secret prepared through trusted local administration and delivered to an operator-supplied protected pipe descriptor. Owner administration APIs provide exact protected confirmation for explicit grants and initial local-only deployment policy. Complete management interfaces, Shared User onboarding, passkey management, recovery and provider approval editing remain dependencies for a usable application.

## Verify this slice

Use CPython 3.12 on Linux x86_64 or Linux aarch64 and Node.js 24.22.1. The Python locks include runtime and development dependencies, with hashes for the inspected wheels on each platform. Use `requirements.lock` and `dependency-inventory.json` for x86_64, or `requirements-linux-aarch64.lock` and `dependency-inventory-linux-aarch64.json` for aarch64. Other platforms need separately verified wheels; Raspberry Pi qualification has not run.

Obtain the wheels on a machine with updated TLS trust and pip 26.2.2 or later. Follow the [Python Software Foundation bootstrap guidance](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576) to obtain and verify a corrected installer before its first network operation. Updating certifi alone does not remove certificates from pip's system trust store. An online installer must use updated system trust or an explicitly validated CA file and certificate directory that exclude the affected certificates.

With that prepared installer, download the exact wheels for the target platform. The following commands use the x86_64 files; substitute both aarch64 filenames on an aarch64 machine. Transfer the resulting `wheels` directory if installation is on a separate machine of the same target platform.

```sh
python3.12 -m pip download --only-binary=:all: --require-hashes --dest wheels -r requirements.lock
```

Before executing any downloaded wheel, verify every file against the checked-in inventory. Run this from the source-tree root, and continue only if it succeeds:

```sh
python3.12 - dependency-inventory.json wheels <<'PY'
import hashlib
import json
from pathlib import Path
import sys

inventory = json.loads(Path(sys.argv[1]).read_text())
for package in inventory["packages"]:
    wheel = Path(sys.argv[2]) / package["wheel"]
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != package["sha256"]:
        raise SystemExit("Wheel hash mismatch; do not install.")
print("All pinned wheel hashes match.")
PY
```

Create an empty environment and install offline using the verified pip wheel. This avoids using the virtual environment's bundled installer for an initial download.

```sh
python3.12 -m venv --without-pip .venv
.venv/bin/python -I wheels/pip-26.2.2-py3-none-any.whl/pip --isolated --disable-pip-version-check install --no-index --no-deps --no-cache-dir --only-binary=:all: --require-hashes --find-links wheels -r requirements.lock
.venv/bin/python -m pip check
PYTHONPATH="$PWD/src" .venv/bin/pytest
.venv/bin/ruff check src tests tools migrations
.venv/bin/ruff format --check src tests tools migrations
.venv/bin/mypy
PYTHONPATH=src .venv/bin/python tools/generate_contracts.py --check
npm ci --ignore-scripts
npm run check
npm test
```

The tests use temporary file-backed databases and subprocesses. They cover current Owner/grant checks, provider allowance narrowing, conflicting and concurrent retries, revoked receipt access, schema incompatibility, crash rollback and recovery after a committed response is lost. They make no external provider calls. The client transport test uses a synthetic fetch implementation.

On Linux aarch64, substitute `requirements-linux-aarch64.lock` in the install command above. The offline Python installation does not update the host's TLS trust or other Python environments.

The [local runtime guide](docs/runtime.md) describes the explicit TLS launcher and relocatable source-shaped release bundle. The bundle preserves project metadata and migration paths and includes a checked runtime wheel lock. Local subprocess checks cover TLS, authentication, shutdown and restart. A project wheel, production installer, signed updater and complete recovery workflow remain unavailable; these checks do not establish deployment readiness.

## Service boundary

`ProjectService.create` owns Project registration. The command accepts a name, description, idempotency key, expected deployment-policy revision and an inheritance/narrowing choice. It creates no files, Git repository, graph, provider request, implicit verification policy or automatic sharing grant. Environment-owned instruction authority starts with a stable reference. The [local instruction service](docs/project-instructions.md) separately admits roots, binds and versions canonical trees, evaluates candidates and journals publication.

Creation requires a current durable session, a current enabled Owner and two explicit deployment grants: `project.create` and `project.receipt.read`. The receipt grant authorizes the normal creation response without inventing a grant for a Project that does not yet exist. It does not authorize general Project reads. Shared-user Project creation is outside this slice.

An existing receipt requires its original actor, a current durable session, a current matching authorization epoch and a current deployment or exact-Project `project.receipt.read` grant. A retry does not need a fresh creation grant. The stored provider allowance is explicitly a **historical creation snapshot**; neither it nor a receipt permits current provider egress. Future egress must re-evaluate current setup approval and Project narrowing.

The API exposes `POST /api/v1/projects`, `GET /api/v1/operations/{operation_id}`, and passkey ceremony endpoints at `POST /api/v1/auth/passkeys/begin` and `POST /api/v1/auth/passkeys/finish`. The passkey endpoints remain disabled without explicit origin and ceremony policy configuration. OpenAPI, JSON schemas and the TypeScript fetch client are generated from the real API/models in `generated/`. These bindings are INTERNAL. The client supplies compile-time DTO types; the service performs authoritative runtime and cross-field validation. The client provides passkey ceremony transport methods; it does not provide a browser credential UI, retries, offline queues or runtime response validation.

`POST /api/v1/operations/resolve` reads an original command identity under current authority. It requires the original command, key, owner-canonical payload digest, scope and store incarnation. `NOT_OBSERVED` does not prove that no effect occurred or can later commit. A changed incarnation requires reconciliation; no result authorizes automatic mutation retry. Generated `digest<CommandType>` helpers apply command defaults and owner normalization to the same unchanged DTO sent through the generated client. Retain that DTO, key, scope and incarnation before dispatch. Digests reflect JSON transport values, including JavaScript number precision; they cannot recover precision already lost before transmission. The service remains responsible for runtime validation and authorization.

Session policy defaults are seven days absolute, twelve hours inactivity and five minutes recent strong authentication. The earlier session deadline applies. Browser commands with valid origin and CSRF qualify as activity; reads and background polling do not extend inactivity. Rotation invalidates the old cookie and preserves the absolute deadline. Session records store token and CSRF hashes, and revocation survives restart. Session issuance and strong-auth rotation are internal primitives that must be called only after verified authentication; configured passkey endpoints call them after maintained-verifier checks. Authenticated context, session inventory, revocation and self-logout routes are available under `/api/v1/auth`. The Owner can list all browser sessions; Shared Users can list and control their own. Revoking another human's session requires exact official protected confirmation. Context bootstrap rotates only the CSRF token under the current cookie and exact configured Origin; it does not extend the session. These routes have no management UI yet.

See [foundation invariants](docs/foundation.md) and [validation scope](docs/validation.md).

## License and dependencies

Owned code is AGPL-3.0-only; see [LICENSE](LICENSE). The platform-specific Python locks and `package-lock.json` pin the actual Python and TypeScript tooling. [dependency-inventory.json](dependency-inventory.json) and [dependency-inventory-linux-aarch64.json](dependency-inventory-linux-aarch64.json) record installed Python distributions, their declared licenses and wheel SHA-256 values for their respective platforms. This is metadata inventory, not a completed distribution-rights review. TypeScript 6.0.2 declares Apache-2.0 and is a development-only dependency; no third-party source or wheel is vendored here.

## Traceability

Planning, approval and source records are maintained separately. This bounded implementation does not establish completion of the wider milestone.

## Local Work transactions

The authenticated API supports `POST /api/v1/tasks`, `GET /api/v1/tasks/{task_id}`,
and `POST /api/v1/tasks/pause`, `/resume`, and `/cancel`. Task creation records an
objective, optional user success conditions, an inherited Project verification-policy
reference with its Project revision, and explicit human or unassigned responsibility.
A human assignment names the authenticated creator. Creation does not require a Bot
or start execution. New Tasks remain in `BACKLOG`.

Each action requires its own current deployment or exact-Project grant:
`task.create`, `task.pause`, `task.resume`, or `task.cancel`. Mutations also require
`task.read` and `task.receipt.read`; reads require `task.read`. Both Owners and Shared
Users use these same checks. Receipt lookup is restricted to the original actor with
current read and receipt grants. An identical command retry additionally requires the
current action grant and returns the original receipt; changed input under that key
conflicts. Controls require the current Task revision.

Pause prevents future admission and preserves active `RUNNING`/`REVIEW` and existing
`BLOCKED` states; other nonterminal states become `WAITING`. Resume rechecks Project
policy and dependencies and preserves existing blockers. A missing verification policy
blocks continuation. Otherwise unresolved dependencies remain waiting and a locally
registered Task returns to `BACKLOG`, without claiming route or execution admission.
Cancel records `CANCELLED` and denies subsequent continuation controls. Terminal Tasks
cannot be reopened through these commands. Historical receipts remain historical.

Task changes, typed receipts and versioned event payloads commit in one transaction.
Migration `0011_task_admission` retains existing records and adds immutable Task and
verification-policy revisions. Earlier history remains in its original receipts.

`GET /api/v1/projects/{project_id}` returns the current Project revision and
configuration under an explicit `project.read` grant. Refresh this view after a
revision conflict or another writer's change before submitting a revised command.
A replayed creation or policy receipt remains historical; its revision does not
establish the current Project revision. Provider allowance in the view is labelled
as the historical creation snapshot and does not authorize current egress.

`POST /api/v1/projects/verification` configures a versioned proof definition under
`project.verification.configure`, `project.verification.read` and
`project.receipt.read` grants. `GET /api/v1/projects/{project_id}/verification` reads it.
Checks name exact argv, an expected exit code and an owned-workspace-relative directory; saving these
operands grants no command execution permission. Task creation inherits configured
criteria when the user does not supply them. `POST /api/v1/tasks/revise` edits criteria
and workflow under `task.revise`, retaining the Project policy steps, dependencies
and loop bounds. Tasks may add unconditional work or review prerequisites before
retained policy steps; added prerequisites cannot make a required gate conditional.
Invalid proposed policy check bindings or Task workflows return validation errors
without partially changing stored state. Graphs support conditions, parallel branches, joins and explicit
finite loops; recursive dependency edges are rejected. The authenticated
`GET /api/v1/tasks/workflow-templates?project_id=...` returns eight provider-neutral
templates. Their `check` identifier must be bound to the configured proof check.

`POST /api/v1/tasks/assign` requires `task.assign` and records explicit human,
unassigned or Bot responsibility. Bot assignment and contribution require current
Project execution-admission and Bot/Profile-use authority. Contributions leave the
primary assignee unchanged. Handoffs preserve Task identity and retained history;
no Bot-private memory, sessions, credentials or Workspace data are copied. The
current implementation accepts supported deterministic preparation only. Declared
native, resource, Skill, Connection or tool service requirements block Bot assignment
until their owning services are available; Profile eligibility strings confer no
permission.

`POST /api/v1/tasks/admit` requires `task.admit`, current Task read/receipt grants
and the expected Task/policy revisions. The service derives `ADMIT`, `QUEUE`, `DENY`
or `REQUIRE_APPROVAL` from current grants, policy, responsibility, dependencies and
approval gates. An admitted Task becomes `READY`. The result is explicitly scoped
to `TASK_PREPARATION`, with `execution_authorized=false`; it cannot authorize a
process, an Attempt, a model call or a later effect. Consumers must independently
validate actual resources, routes, artifacts and current authority. Policy-reference
strings alone cannot admit work. Stored receipts remain historical observations.
Identical assignment retries recheck the applicable current grants; human and
unassigned responsibility do not acquire Bot execution prerequisites on replay.
Admission retries recheck current eligibility. A historical denial remains a denial;
replaying it cannot grant execution authority.
Task verification dispatch now runs configured deterministic checks through durable
Jobs against immutable Attempt snapshots. See [execution operations](docs/execution.md)
for dispatch, evidence, configuration and grants. [Review and completion](docs/reviews.md)
adds explicit review policy, immutable candidate selection and deterministic-only
completion through current evidence gates. Native/model execution, independent
review execution, workflow loops, semantic approval settlement and an operational
Work UI remain unavailable.

## Identity configuration and instruction provenance

Authenticated configuration routes under `/api/v1/profiles`, `/api/v1/bots` and
`/api/v1/teams` create stable identities and immutable revision history. The current
Owner may administer this configuration. Shared Users need explicit exact resource
and action grants. Owner-only grant administration routes under `/api/v1/permissions` require exact protected confirmation for changes.
Bot creation requires an explicit personal-memory choice and allocates a distinct
namespace identity. It does not create a working memory collection. Team creation
atomically creates its members and selects one of those members as lead.

Profile revision requires a non-mutating `/api/v1/profiles/preview-revision` result.
The commit rechecks the proposed payload, current Profile revision and authorized
Bot impact. The preview reports only authorized Bots. Profile preferences propagate
where a Bot has no override; resetting an override restores inheritance. Visual
references are independent creation-time copies. Effective settings remain
unqualified reference selections, and eligibility references confer no authority.

`/api/v1/instruction-bundles` resolves registered immutable component revisions into
a candidate bundle with deterministic rendering, a digest and byte count. Literal
`{{name}}` variables must exactly match their declarations and are encoded as
separate lower-trust data segments. Rendered variable values are returned transiently,
not retained in the bundle, receipt or event. Identical accepted retries render
the accepted immutable revisions under current constituent disclosure authority;
new operation keys require current revisions. Bundle provenance does not confer
execution permission or establish adoption by a native context. Protected core,
navigation, Project and Skill instruction registration still require their owning
services; an unconfigured installation returns a missing-dependency error. No
protected assets are seeded by this increment.

`/api/v1/legacy-memory/preview` validates supplied mappings against exact authorized
inventory evidence and destination consent; it copies no memory. Migration
`0007_identity_instructions` preserves existing Project, Task, authentication,
receipt and event records. No worker, provider execution, native isolation or
operational configuration interface is introduced.

Local Task Attempt preparation and direct deterministic verification are described
in [Local Attempt preparation and deterministic verification](docs/execution.md).
