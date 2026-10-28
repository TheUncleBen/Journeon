# Local Attempt preparation and deterministic verification

Attempt preparation and direct verification have separate authorization and evidence.
Preparing a Task does not start a process. Direct verification does not dispatch a
Task, change its completion state, invoke a model, or establish native coding-tool
readiness. Task verification dispatch uses the canonical Job worker described below.

## Preparing an Attempt

`POST /api/v1/attempts/prepare` accepts an `AttemptPrepare` command and returns an
`AttemptReceipt`. `GET /api/v1/attempts/{attempt_id}` reads the current Attempt;
`GET /api/v1/operations/{operation_id}` reconciles its preparation receipt.
The generated client exposes `prepareAttempt` and `getAttempt`.

The command identifies the Task and its expected revisions, verification policy,
assignment, instruction revision and explicitly configured workspace. It cannot
supply an arbitrary host path. Current Task admission, Project and Attempt grants,
the original authenticated session, and the exact admitted Project root must still
permit preparation. An Environment instruction root does not grant workspace
access. Applicable accepted CORE, NAVIGATION, Project, Task and workflow inputs
are retained in the deterministic instruction bundle; no Bot or native Session is
fabricated for this route.

Git preparation creates an Attempt-specific branch and worktree. Its manifest
retains HEAD, index, working files, deletions, untracked files, binary differences,
symlinks and submodule snapshots. Non-Git preparation uses an exclusive writer lock
and a durable fenced lease. Snapshot evidence is stored outside the source and
mutable workspace. Explicit snapshot, file-count, retained-byte and Attempt-count
budgets bound preparation. Retained byte reservations include snapshot documents,
blob payloads and copied working-file payloads; filesystem allocation overhead and
later edits to an Attempt workspace are not a filesystem quota.

A retry with the same identity reconciles the original preparation. An interrupted
workspace is reused only when its bytes and evidence match the retained intent.
Unrecognized partial effects remain unavailable for automatic continuation and are
retained for inspection. Preparation never removes an interrupted workspace or
silently repeats its filesystem effect.

Only the Task origin currently has a preparation producer. Other typed origin
shapes do not create admission authority; their owning services must provide the
corresponding producer and current authorization before they can be used.

## Discovering current work

Start with `GET /api/v1/projects?limit=20`. Each authorized Project summary can
link to its Tasks, each Task to its Attempts, and each Attempt to its Jobs. Follow
returned `links` directly; collection links carry the requested page limit.
Links appear only when the current session can read their target. A Job may also
link to its existing verification evidence after the evidence read checks pass.

The collection routes are:

- `GET /api/v1/projects?limit=20`
- `GET /api/v1/projects/{project_id}/tasks?limit=20`, optionally filtered by `state`
- `GET /api/v1/tasks/{task_id}/attempts?limit=20`
- `GET /api/v1/jobs?limit=20`, optionally filtered by `project_id`, `task_id`, or
  `attempt_id`

Every request requires an explicit limit from 1 to 100. Responses contain `items`,
`next_cursor`, `has_more`, `observed_at`, and `store_incarnation`; each item carries
its current revision. IDs determine page order. Pass `next_cursor` unchanged with
the same route and filters to continue. The generated client provides
`listProjects`, `listTasks`, `listAttempts`, and `listJobs` with query encoding.

Pages reflect current authority and state on each request. They are live views;
a grant change or Task transition can change later pages. A cursor grants no
access and cannot cross Principals, filters, or store incarnations. If its binding
is stale, restart from the first page. Hidden records do not contribute to
`has_more`, and no global total is returned. If bounded scanning cannot establish
a complete authorized page, the service returns unavailable instead of a partial
success. Authorized corrupt state also returns unavailable and requires repair.

Discovery does not renew session inactivity, dispatch work, or change Task
completion. Creation authority does not imply read authority, including for the
Owner. Attempts retain their originating Principal, exact instruction scope and
current workspace checks. Jobs retain their kind-specific authorization and Task
binding checks. Missing required Attempt or Job configuration returns unavailable.

## Task verification dispatch

`POST /api/v1/tasks/dispatch` accepts `TaskDispatch` and returns the durable Job.
`GET /api/v1/jobs/{job_id}/evidence` returns `TaskEvidence` after an authenticated,
drained process completion can be published under current authority. The generated
client exposes `dispatchTask` and `readTaskEvidence`. Job read, cancellation,
Attention and event replay use the existing typed Job interfaces.

Dispatch identifies an existing Task, current Task/criteria/workflow/assignment and
policy revisions, a verification step, configured workspace and configured route.
It prepares one durable Attempt or selects an existing exact Attempt using
`attempt_id`. The same idempotency key reconciles the original operation; changing
its input produces a conflict. Dispatch requires `task.dispatch`, Job read/cancel,
Task read/receipt, Attempt prepare/read/receipt, the applicable execution grants,
and current Project, policy and instruction read grants. Policy-required grants
remain additional checks. Evidence reads require `job.read`, `task.read`,
`attempt.read`, `execution.read`, `project.read`, `project.instruction.read` and
`project.verification.read`. Stored payloads do not confer authority.

Configure `instructions.jobs`, `instructions.attempts` and
`instructions.executions` explicitly. The existing Job claim loop owns both
instruction navigation and Task verification; there is no separate Task worker.
The execution uses the immutable Attempt manifest and its retained workspace under
an exclusive physical lock. Source edits after preparation do not enter the
verification input. Task Git projections expose only objects reachable from the
captured HEAD history and index, recursively including captured submodules.
Alternate stores still require admission; future and unreachable objects are not
exposed to the command. The copied stores and sealed object closure share the
configured snapshot byte and file budgets.

The manifest records whether Git marks the repository shallow and the declared
shallow boundary, including an empty shallow file. Legacy Git snapshots without
this observation remain readable with their original hashes and receipts, but
require a newly prepared Attempt before Task execution. The service does not infer
missing history metadata or fetch objects to fill it in.

A verification prerequisite needs passing service-produced evidence from the same
Attempt manifest. WORK, CONDITION, REVIEW and APPROVAL steps have no execution
producer here. Loop execution is also unavailable. These steps block dependent
verification; they are never treated as passing. Native/model execution, independent
review execution, semantic approval settlement and an operational Work UI remain
unavailable. Successful verification does not itself mark a Task DONE. The separate
[completion command](reviews.md) can consume exact evidence under an explicitly
configured policy that requires deterministic verification only.

Evidence binds the exact criterion text and Task, criteria, workflow, assignment,
policy, Attempt, Job claim, Execution, invocation, drained completion and output.
Only an authenticated `EXITED` completion with the configured `expected_exit_code`
can pass verification, after the process has drained and current authority permits
publication. A different exit code retains failed verification. Cancellation or lost current authority stops new effects and
publication while retaining actual observations. Unknown launch or completion
requires canonical Attention and never causes an automatic process rerun. A known
completed and drained execution can reconcile publication under its original
claim identity and current original authority without starting another process.
A lost response after publication returns the same immutable evidence. Authorized
history remains readable after a Task revision, but old evidence cannot satisfy
new criteria. Evidence and retained completion are separate records.

## Direct verification service

The in-process `ExecutionService` provides `start`, `read`, `stop`, `doctor` and
`reconcile`. Runtime startup reconciles interrupted executions before serving;
shutdown drains the service before disposing its database. This service has no
public process-start HTTP endpoint. A trusted server integration must obtain the
actual enrolled session through the authentication owner, rather than constructing
caller identity or approval flags.

A direct operation binds an exact Project, admitted Project root, enabled
verification-policy revision, check, and configured route revision. It requires
current Project read and policy access plus the applicable `execution.start`,
`execution.read`, `execution.stop`, `execution.drain`, `execution.complete` and
`execution.receipt.read` grants. Policy-required capabilities remain additional
checks. An unresolved required service is unavailable. Admission does not turn a
service label into an executable capability.

Host configuration must explicitly provide the private evidence directory,
snapshot budgets, aggregate concurrency, memory, CPU and storage budgets, protected
core CPU reserve, and each route. A route declares its executable hash, argv,
relative working directory, environment, artifact paths, memory/process/CPU limits,
workspace and temporary-space limits, output and artifact limits, core memory and
recovery-disk reserves, authority lease/poll interval, drain bound and control bound.
Serialized snapshot documents, including nested submodule metadata, are measured
and reserved against the retained storage budget before their files are written.
If the additional reservation cannot fit, preparation stops without writing those
files; its original operation remains available for reconciliation.
There are no shipping capacity values or unrestricted fallback route.

The implemented backend uses Linux unified cgroups through the user's systemd
manager and bubblewrap namespaces. Required binaries, delegated controllers and
namespace support must already be installed and permitted. The service does not
change host settings or install missing components. Admission observes available
memory, inherited cgroup capacity and filesystem capacity before reserving aggregate
resources. The launched unit must report the declared memory, swap, process and CPU
limits before the verification command starts.
The trusted supervisor renews or expires authority during workspace preparation,
including cancellation or controller loss. Its observed unit identity is retained
while the operation remains `STARTING`. A durable `START_REQUESTED` records intent;
`STARTED` and `RUNNING` require the helper's actual process-launch observation.
An interrupted delivery or missing launch observation remains uncertain and requires
reconciliation rather than an automatic retry.

The command receives immutable input and a separate bounded writable workspace,
with bounded temporary storage. It can build and read declared outputs without
editing the admitted source. The route clears inherited environment values, does
not expose the host home or session-bus directory, and uses an isolated network
namespace. It invokes an argv directly, without a shell or provider fallback.

Git verification projects clean metadata and service-owned copies of admitted
object stores. Source configuration and hooks are not copied. HEAD, staged content,
working bytes and submodules remain distinct. Alternate object stores require
admitted roots for the same Project. Object-store symlinks that lack an immutable
projection are unavailable. Capture rejects changing object bytes; hashes of the
original and projected stores are retained. Trusted helper checks compare actual
mounted directory identities before reading input or starting the command.

The original session and current authorization are rechecked while the operation
runs. Stop, revocation, lost controller authority, output overflow and process exit
trigger process-tree draining. Artifact collection accepts only declared bounded
regular files. Unknown or incomplete completion never counts as verification
success. Memory-limit termination retains observed launcher status and partial
output where available; reconciliation does not rerun the command.

The execution manifest binds the source, policy, route, original session, root,
resource observation and native installation hashes. Completion retains actual
exit status, output, artifacts, invocation identity and observed kernel limits.
`doctor` assesses an existing execution under current authority and current
installation bytes. Its scope identifies direct verification or Task verification
from the persisted execution origin. Its result is limited to that operation and
route; it is not independent review approval or qualification of an entire Task
workflow, native tools, other routes or other hosts. The database `doctor` command continues to inspect copied
SQLite bytes and does not launch verification processes.

All evidence and workspaces are retained. Automatic garbage collection, broad
workspace cleanup and completed-output export are not provided by this slice.
