# Journeon

Journeon is being developed as a service-owned project environment. This source-tree foundation implements one internal Project-create command with transactional authorization, persistence and receipt reconciliation. It is an early development slice, not an operational installation or release candidate.

The FastAPI authentication dependency denies access unless explicitly configured with a canonical HTTPS origin and a valid durable session. Session primitives validate opaque cookies, CSRF, expiry and revocation; explicitly configured passkey ceremonies can issue sessions after WebAuthn verification. Bootstrap requires a secret prepared through trusted local administration. Protected confirmations, passkey management, recovery, provider approval editing and grant administration remain dependencies for a usable application.

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

Project wheel building, installation into a package location, an ASGI server and an installer have **not been tested or provided**. Run from this checkout with `PYTHONPATH=src`; migration discovery currently depends on the source-tree layout. Python dependency installation from the hashed lock has been tested in a separate empty virtual environment.

## Service boundary

`ProjectService.create` owns Project registration. The command accepts a name, description, idempotency key, expected deployment-policy revision and an inheritance/narrowing choice. It creates no files, Git repository, graph, provider request, implicit verification policy or automatic sharing grant. Environment-owned instruction authority is represented by a stable reference; instruction editing is a later operation.

Creation requires a current durable session, a current enabled Owner and two explicit deployment grants: `project.create` and `project.receipt.read`. The receipt grant authorizes the normal creation response without inventing a grant for a Project that does not yet exist. It does not authorize general Project reads. Shared-user creation is outside this slice.

An existing receipt requires its original actor, a current durable session, a current matching authorization epoch and a current deployment or exact-Project `project.receipt.read` grant. A retry does not need a fresh creation grant. The stored provider allowance is explicitly a **historical creation snapshot**; neither it nor a receipt permits current provider egress. Future egress must re-evaluate current setup approval and Project narrowing.

The API exposes `POST /api/v1/projects`, `GET /api/v1/operations/{operation_id}`, and passkey ceremony endpoints at `POST /api/v1/auth/passkeys/begin` and `POST /api/v1/auth/passkeys/finish`. The passkey endpoints remain disabled without explicit origin and ceremony policy configuration. OpenAPI, JSON schemas and the TypeScript fetch client are generated from the real API/models in `generated/`. These bindings are INTERNAL. The client supplies compile-time DTO types; the service performs authoritative runtime and cross-field validation. The client provides passkey ceremony transport methods; it does not provide a browser credential UI, retries, offline queues or runtime response validation.

Session policy defaults are seven days absolute, twelve hours inactivity and five minutes recent strong authentication. The earlier session deadline applies. Browser commands with valid origin and CSRF qualify as activity; reads and background polling do not extend inactivity. Rotation invalidates the old cookie and preserves the absolute deadline. Session records store token and CSRF hashes, and revocation survives restart. Session issuance and strong-auth rotation are internal primitives that must be called only after verified authentication; configured passkey endpoints call them after maintained-verifier checks. Owner session inventory/revocation and a Shared User's own-session controls are internal service functions, with no management UI or public route yet.

See [foundation invariants](docs/foundation.md) and [validation scope](docs/validation.md).

## License and dependencies

Owned code is AGPL-3.0-only; see [LICENSE](LICENSE). The platform-specific Python locks and `package-lock.json` pin the actual Python and TypeScript tooling. [dependency-inventory.json](dependency-inventory.json) and [dependency-inventory-linux-aarch64.json](dependency-inventory-linux-aarch64.json) record installed Python distributions, their declared licenses and wheel SHA-256 values for their respective platforms. This is metadata inventory, not a completed distribution-rights review. TypeScript 6.0.2 declares Apache-2.0 and is a development-only dependency; no third-party source or wheel is vendored here.

## Traceability

Planning, approval and source records are maintained separately. This bounded implementation does not establish completion of the wider milestone.
