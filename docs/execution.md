# Local Attempt preparation and deterministic verification

Attempt preparation and direct verification have separate authorization and evidence.
Preparing a Task does not start a process. Direct verification does not dispatch a
Task, change its completion state, invoke a model, or establish native coding-tool
readiness. Task execution remains unavailable through this interface.

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
`doctor` assesses an existing direct operation under current authority and current
installation bytes. Its result is limited to that operation and route; it is not
independent review approval or qualification of Task dispatch, native tools, other
routes or other hosts. The database `doctor` command continues to inspect copied
SQLite bytes and does not launch verification processes.

All evidence and workspaces are retained. Automatic garbage collection, broad
workspace cleanup and completed-output export are not provided by this slice.
