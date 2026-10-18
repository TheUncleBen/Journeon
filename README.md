# Journeon

Journeon is being developed as a service-owned project environment. This source-tree foundation implements internal Project creation, passkey labeling and local Task lifecycle commands with transactional authorization, persistence and receipt reconciliation. It is an early development slice, not an operational installation or release candidate.

The FastAPI authentication dependency denies access unless explicitly configured with a canonical HTTPS origin and a valid durable session. Session primitives validate opaque cookies, CSRF, expiry and revocation; explicitly configured passkey ceremonies can issue sessions after WebAuthn verification. Bootstrap requires a secret prepared through trusted local administration. Complete protected-confirmation interfaces, passkey management, recovery, provider approval editing and grant administration remain dependencies for a usable application.

## Verify this slice

Use CPython 3.12 on Linux x86_64 or Linux aarch64 and Node.js 24. The Python locks include runtime and development dependencies, with hashes for the inspected wheels on each platform. Use `requirements.lock` for x86_64 or `requirements-linux-aarch64.lock` for aarch64. Other platforms need separately verified wheels; Raspberry Pi qualification has not run.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
.venv/bin/python -m pip check
.venv/bin/pytest
.venv/bin/ruff check src tests tools migrations
.venv/bin/ruff format --check src tests tools migrations
.venv/bin/mypy
PYTHONPATH=src .venv/bin/python tools/generate_contracts.py --check
npm ci --ignore-scripts
npm run check
npm test
```

The tests use temporary file-backed databases and subprocesses. They cover current Owner/grant checks, provider allowance narrowing, conflicting and concurrent retries, revoked receipt access, schema incompatibility, crash rollback and recovery after a committed response is lost. They make no external provider calls. The client transport test uses a synthetic fetch implementation.

On Linux aarch64, substitute `requirements-linux-aarch64.lock` in the install command above.

The [local runtime guide](docs/runtime.md) describes the explicit TLS launcher and relocatable source-shaped release bundle. The bundle preserves project metadata and migration paths and includes a checked runtime wheel lock. Local subprocess checks cover TLS, authentication, shutdown and restart. A project wheel, production installer, signed updater and complete recovery workflow remain unavailable; these checks do not establish deployment readiness.

## Service boundary

`ProjectService.create` owns Project registration. The command accepts a name, description, idempotency key, expected deployment-policy revision and an inheritance/narrowing choice. It creates no files, Git repository, graph, provider request, implicit verification policy or automatic sharing grant. Environment-owned instruction authority is represented by a stable reference; instruction editing is a later operation.

Creation requires a current durable session, a current enabled Owner and two explicit deployment grants: `project.create` and `project.receipt.read`. The receipt grant authorizes the normal creation response without inventing a grant for a Project that does not yet exist. It does not authorize general Project reads. Shared-user Project creation is outside this slice.

An existing receipt requires its original actor, a current durable session, a current matching authorization epoch and a current deployment or exact-Project `project.receipt.read` grant. A retry does not need a fresh creation grant. The stored provider allowance is explicitly a **historical creation snapshot**; neither it nor a receipt permits current provider egress. Future egress must re-evaluate current setup approval and Project narrowing.

The API exposes `POST /api/v1/projects`, `GET /api/v1/operations/{operation_id}`, and passkey ceremony endpoints at `POST /api/v1/auth/passkeys/begin` and `POST /api/v1/auth/passkeys/finish`. The passkey endpoints remain disabled without explicit origin and ceremony policy configuration. OpenAPI, JSON schemas and the TypeScript fetch client are generated from the real API/models in `generated/`. These bindings are INTERNAL. The client supplies compile-time DTO types; the service performs authoritative runtime and cross-field validation. The client provides passkey ceremony transport methods; it does not provide a browser credential UI, retries, offline queues or runtime response validation.

Session policy defaults are seven days absolute, twelve hours inactivity and five minutes recent strong authentication. The earlier session deadline applies. Browser commands with valid origin and CSRF qualify as activity; reads and background polling do not extend inactivity. Rotation invalidates the old cookie and preserves the absolute deadline. Session records store token and CSRF hashes, and revocation survives restart. Session issuance and strong-auth rotation are internal primitives that must be called only after verified authentication; configured passkey endpoints call them after maintained-verifier checks. Owner session inventory/revocation and a Shared User's own-session controls are internal service functions, with no management UI or public route yet.

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
Migration `0006_work` preserves prior Project/passkey operations and the event sequence
allocation ceiling, including pruned sequence numbers. Event delivery, replay cursors,
restore-incarnation invalidation, execution, Attempts, Jobs, review, completion evidence,
Bot assignment and operational Work UI remain unavailable in this increment.

## Identity configuration and instruction provenance

Authenticated configuration routes under `/api/v1/profiles`, `/api/v1/bots` and
`/api/v1/teams` create stable identities and immutable revision history. The current
Owner may administer this configuration. Shared Users need explicit exact resource
and action grants; this increment supplies no public grant administration route.
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
not retained in the bundle, receipt or event. Bundle provenance does not confer
execution permission or establish adoption by a native context. Protected core,
navigation, Project and Skill instruction registration still require their owning
services; an unconfigured installation returns a missing-dependency error. No
protected assets are seeded by this increment.

`/api/v1/legacy-memory/preview` validates supplied mappings against exact authorized
inventory evidence and destination consent; it copies no memory. Migration
`0007_identity_instructions` preserves existing Project, Task, authentication,
receipt and event records. No worker, provider execution, native isolation or
operational configuration interface is introduced.
