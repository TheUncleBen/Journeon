# Review policy and exact-candidate completion

This foundation stores explicit Project review rules and immutable selected Attempt
candidates. It can complete a Task that requires deterministic verification only.
It does not run an independent reviewer or accept uploaded verdicts as gate evidence.

## Explicit policy

`POST /api/v1/projects/review-policy` requires `project.review.configure`,
`project.review.read` and `project.receipt.read`, a current authenticated session,
CSRF protection and the expected Project and policy revisions. Each accepted change
increments the Project revision and creates an immutable policy revision, receipt
and event. `GET /api/v1/projects/{project_id}/review-policy` requires
`project.review.read`. Prior operation receipts retain their original policy.

No review policy is installed implicitly. Configuration supplies whether independent
review is required, minimum independence, preferred diversity, required coverage,
material severity labels, severity labels requiring Owner override, an optional
explicit automatic-round limit, and cycle/unchanged-target stop rules. Severity
labels belong to the configured policy. Required independent review needs fresh
Session independence and explicit coverage. Owner-override labels must be material
under that policy. Duplicate entries and contradictory rules are rejected.

These rules do not qualify an execution route. Review rounds, finding dispositions,
thread continuity and technically enforced reviewer execution remain unavailable.
A missing policy or required producer cannot be treated as permission to skip a gate.

## Select an immutable candidate

`POST /api/v1/tasks/review-targets` selects a prepared Attempt at the current Task
and review-policy revisions. The response binds the complete admitted snapshot,
manifest, criteria, workflow, assignment, verification policy and review policy.
It identifies `ADMITTED_ATTEMPT_SNAPSHOT` as the candidate. Subsequent edits to the
original source directory do not change that selected candidate.

Selection requires `task.review.select`, `task.review.read`, `task.read`,
`task.receipt.read`, `project.review.read`, `project.verification.read`,
`attempt.read`, `project.instruction.read` and current Task admission authority.
Current workspace configuration, policy capabilities and assignee eligibility
remain additional requirements. Selection does not start a process.

`GET /api/v1/review-targets/{identity}` requires the target's read grants and current
Attempt/root scope. Historical targets remain readable after Task or policy changes
while that authority remains valid. Reusing an idempotency key with changed input
is rejected after authorization of the original target.

Capture attribution does not establish who authored the contents. Targets currently
report `authorship_status=UNAVAILABLE`; neither a browser session nor an Attempt
capture is represented as an independent reviewer Session.

## Complete through the Work owner

`POST /api/v1/tasks/complete` requires the current Task revision and exact target ID
and digest. The Task must be READY, RUNNING or REVIEW, with current policies,
criteria, workflow, assignment and dependencies. A paused, cancelled, stale or
unsettled Task cannot complete. Required semantic, approval, review and loop producers
remain unavailable and block completion.

For a policy requiring deterministic verification only, every workflow verification
step and every success criterion needs passing service-produced evidence for the
same selected manifest. Completion checks the actual Job, Execution, process,
invocation, configured expected exit and drained output provenance. A Job success,
caller-supplied passed flag or model assertion is insufficient. Unknown or active
Task execution requires settlement first.

The command requires `task.complete`, Task read/receipt, target read, policy read,
Attempt/root read, Job read, Execution read/receipt and current Task admission grants.
The generated command metadata lists the exact capability names. Completion runs
no process, filesystem scan or inference inside its write transaction.

One transaction stores DONE, a Task revision, the selected snapshot/evidence
binding, an operation receipt and an outbox event. Lost-response and restart retries
return the same receipt under current authorized receipt access. Completion approves
only the selected immutable candidate; it does not approve later source edits.
Historical Task and receipt JSON without a completion binding keeps its original
serialized shape.

Migration `0014_review_completion` adds immutable review-policy and target history.
It retains existing Task, Attempt, execution, Job, receipt and event records.
Backup, restore and Doctor use the same canonical store ownership.
