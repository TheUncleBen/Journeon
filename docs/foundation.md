# Foundation invariants

## Authorization and disclosure

`AuthenticatedContext(principal_id, principal_epoch, authentication_ref)` is a frozen internal value supplied by a trusted authentication resolver. Wire commands contain none of those fields. `authentication_ref` identifies the durable session for audit and current validation; it is never a bearer token or independent proof of authority. The protected HTTP dependency denies requests unless explicitly bound to a canonical HTTPS origin and a valid session cookie. Test dependency overrides exist only in tests; their contexts also require durable session records.

Every command and receipt lookup opens a `BEGIN IMMEDIATE` transaction, checks the exact supported migration head, validates the current Principal and durable session, and evaluates the owning action authority. Project creation remains Owner-only. Work uses explicit deployment or exact-Project grants for Owners and Shared Users. Grant expiry is evaluated at the decision boundary; malformed or timezone-free expiry values deny that grant. Principal epoch changes invalidate old contexts. The DB constraint permits at most one enabled Owner; the schema never creates an Owner.

Principal, grant, session, passkey and ceremony Boolean columns have database CHECK constraints allowing only 0 and 1. This prevents non-Boolean SQLite values from bypassing the enabled-Owner uniqueness predicate or acquiring a different meaning when decoded by the ORM.

Authorization and policy edits through the same database serialize with these decisions. A revocation committed before the command obtains the writer lock takes effect. A revocation ordered after an accepted transaction cannot undo that transaction. The create path rechecks current authority immediately before commit. Receipt authorization is evaluated in its locked read transaction before returning the bounded result; this is not a streaming disclosure design. Current session revocation, identity epoch and deadlines are rechecked at these boundaries. The highest observed session time survives a rejected transaction: business effects roll back to a savepoint while the outer writer lock remains held, then the outer transaction advances only the existing session's observed-time fence before returning the error. A later clock rollback cannot undo an expiry already observed by the service, including after restart. This does not establish a trusted physical clock or detect changes the service never observed.

The original actor is part of the receipt namespace. Receipt authority is distinct from creation authority and does not imply resource sharing. A later Owner cannot read the prior actor's receipt through this API. A changed payload using an existing key produces `IDEMPOTENCY_CONFLICT` only after current receipt authorization succeeds.

After current disclosure authorization, the stored receipt is strictly decoded and its operation ID, typed target identity and command are checked against its owning record. Malformed JSON, missing fields or mismatched identities return a static `DEPENDENCY_UNAVAILABLE` error. The service does not repair or rewrite damaged historical results during a lookup or retry.

## Persistence and recovery

The service uses a local file-backed SQLite database with WAL, foreign keys and synchronous FULL. Every connection uses the same explicit transaction discipline. An absolute filename is required; deployment must place it on a filesystem supporting local SQLite WAL semantics. Filesystem/mount qualification is not implemented here.

Project creation stores the Project, operation receipt and one durable `project.created` outbox fact together. Task commands atomically store the Task revision, typed receipt and versioned event payload. The receipt records actor and authentication reference. It reports `CANONICAL_COMMITTED`, with no external effect implied. Outbox transport delivery, consumer deduplication and retention are not implemented.

Idempotency identity is `(principal_id, command, idempotency_key)`. The hash includes validated command semantics except the key; provider selections and Task dependency IDs are sorted before hashing. Retries reconcile to the stored accepted result. Changing the expected policy revision is a payload change. A process that dies after commit but before response delivery can retrieve the original result using the same identity, subject to current disclosure rights. Keys and receipts have no garbage-collection policy in this slice.

The exact migration head is checked inside each service transaction. Missing or future heads deny commands, replay and disclosure; existing table names alone cannot establish compatibility. Migration is explicit through `journeon.migrate.upgrade(engine)` and does not run on API construction. A destructive downgrade is deliberately unavailable. The health probe reports database availability and known schema head/table presence; it is not a data-integrity audit or application-readiness assertion. Operational authentication is reported as not assessed because a database-only probe cannot establish transport or ceremony configuration.

Identity, grants, deployment policy, Projects and Tasks have R0 registry classification. Receipts/outbox have R1 classification, but **all records in this slice require a coherent whole-database recovery boundary**. Class labels do not authorize dropping receipt history, revocations or audit attribution. Coherent local snapshot creation and offline inspection are implemented; encryption, restore and scoped recovery are not implemented; never treat a copy of an active main DB file alone as a coherent WAL backup.

## Consent and defaults

The caller supplies an expected deployment-policy revision. A stale revision fails before mutation. An unapproved deployment permits no providers even if its stored list contains configured provider identifiers. An approved list is attributed to a current enabled Owner. INHERIT records the approved set, NARROW permits only an explicit subset (including empty), and LOCAL_ONLY records an empty set. No provider execution is implemented. Subsequent consent revocation does not rewrite historical receipts and cannot be bypassed by replaying them.

The complete persisted policy is strictly validated before revision comparison or allowance evaluation. Approved providers must be a list of distinct valid identifiers; objects, scalar values, mixed lists and duplicate entries are rejected. Invalid policy references, revisions and attribution also fail closed with a sanitized dependency error. Invalid stored values are not coerced into consent and no Project, receipt or outbox fact is committed.

New Projects use environment-owned instructions. Verification policy is an explicit nullable reference: null means unconfigured, not verified or approved. Resource references start empty, allowing projects without code repositories. Project creation does not start Runs, bind repositories, infer provider consent or accept caller-supplied protected fields.

## Bounded implementation limits

The HTTP adapter accepts at most 65,536 body bytes, including chunked input, before framework JSON parsing. Names have 200 characters, descriptions 2,000, identifiers 128 and narrowing selections 128 entries. These are defensive limits for this internal operation, not measured product capacity claims. Validation and domain errors return stable codes and static reasons without reflecting submitted values or framework validator details.

The database busy timeout is configurable from 1 to 60,000 ms, with a 5,000 ms engineering default. Transactions serialize even receipt reads in this initial implementation. No Raspberry Pi throughput, concurrency, timeout or resource-budget qualification is claimed. A production transport still needs bounded connection counts, read deadlines and operational authentication. The session defaults are 604800 seconds absolute, 43200 seconds inactivity and 300 seconds recent strong authentication. Authentication throttling uses the separately configured passkey policy. No Work retry, scheduling, recovery or provider-network default is selected here.

## Registry and generated bindings

Every canonical table has one module owner with explicit backup classification, health binding, migration, permission declarations and current settings surface. Each API operation declares its owner. Project creation is registered with typed input/result models, permissions, local-mutation risk, no external effects, idempotency and its actual verification boundary. Metadata is descriptive; the owning service enforces current session, role and grant checks.

`tools/generate_contracts.py` generates OpenAPI, JSON schemas and TypeScript bindings without opening a database. Its check mode detects drift, and it fails for unhandled schema shapes or operation bindings. Cross-field rules remain enforced by Pydantic on the service. Future contract changes require regenerated artifacts and compatibility review.


Passkey bootstrap, login and step-up use separately identified authentication-ceremony routes rather than invented resource grants. Exact-origin checks apply before ceremony work. Step-up additionally resolves the current session and CSRF proof, binds the challenge to that session and revalidates it before rotation. Public login options are discoverable and do not accept an account identifier. Failed cryptographic verification returns a uniform denial. A durable identity clock fence and per-ceremony attempts survive rejected verification while the outer SQLite writer lock remains held. This records observed service time; it does not detect unobserved physical clock changes.

## Identity and instruction configuration

Profile, Bot and Team configuration uses current Owner administration authority or
explicit exact resource/action grants for supported Shared User operations.
Deployment grants do not act as wildcards for these resources. Team views expand
only separately readable Bots; Bot settings require Profile read authority before
returning inherited values. Receipt lookups retain the initiating human boundary.
Profile, Bot and Team creation is Owner-only. Permission metadata describes each
check with its resource scope and condition; its inventory is not an all-required
grant list. Profile previews require Profile read and revise authority. Effective
permission diagnostics use the authenticated caller’s current authority without
a separate diagnostic grant.

Profile revision previews bind the proposed payload, current Profile revision/hash
and sorted authorized Bot revisions and inherited-field changes. Hidden Bots do not
contribute identities, counts or fingerprints. Commit recomputes this binding inside
the write transaction. Preview performs no domain, receipt or event mutation;
existing session security-clock bookkeeping still applies.

Instruction templates are owned by versioned instruction assets. Configuration
snapshots reference those revisions. Profile and Bot histories and bundle snapshots
reject updates/deletions at the database boundary. Team lead membership is a deferred
composite foreign key. Bot namespaces are unique and bound to their stable IDs;
trusted Researcher/Librarian designations cannot enable personal memory and are not
accepted in client commands.

Legacy inventory evidence is bound by an exact `legacy_collection` capability named
`legacy_collection.preview:<version>:<hash>:<provenance-reference>`. The hash must
be a lowercase 64-character SHA-256 hexadecimal digest; provenance references may
contain colons. The fixed hash syntax prevents ambiguous evidence bindings. Such evidence
must be supplied by authorized inventory/grant services; there is no public issuance
route or legacy store discovery in this increment. Mappings require readable and
revisable destination Bots, enabled memory, current destination revisions and
explicit destination consent. Duplicate source mappings are rejected.

Bundle assembly requires registered core, navigation, Profile, optional named-Bot,
Project and Skill layers in that order, with Task/workflow layers for Task Attempts.
The initiating human comes from the authenticated context. One-off Profile origins
contain no Bot or private-memory namespace. These origin records establish candidate
provenance only; Chat admission, runtime lane isolation and native context adoption
remain separate dependencies. All registry data retains the coherent database
recovery boundary; no prompt retention or new grant policy is introduced.

Bundle reads, receipt lookups and retries check current Profile, optional Bot,
Project and optional Task disclosure authority before decoding stored results.
An accepted retry with identical input renders its immutable accepted component
revisions, even if current configuration has advanced. New operation keys still
require current revisions. Neither retry path retains rendered variable values.
