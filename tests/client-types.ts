// SPDX-License-Identifier: AGPL-3.0-only
import { JourneonClient, type ProjectCreate, type OperationReceipt } from "../generated/client.js";

const command: ProjectCreate = {
  schema_version: 1,
  idempotency_key: "synthetic-command",
  name: "Example project",
  expected_policy_revision: 1,
};
const client = new JourneonClient();
const result: Promise<OperationReceipt> = client.createProject(command);
void result;
// @ts-expect-error Actor identity is never part of a command DTO.
const forged: ProjectCreate = { ...command, principal_id: "synthetic-forged-actor" };
void forged;
// @ts-expect-error Unsupported schema version cannot be emitted by the typed client.
const incompatible: ProjectCreate = { ...command, schema_version: 2 };
void incompatible;

import type { CanonicalReceipt, PasskeyLabelCommand, PasskeyMutationReceipt } from "../generated/client.js";
const label: PasskeyLabelCommand = {
  schema_version: 1, idempotency_key: "label-fixture", passkey_id: "key-fixture",
  expected_revision: 1, label: "Renamed",
};
const factorResult: Promise<PasskeyMutationReceipt> = client.labelPasskey(label);
const receiptResult: Promise<CanonicalReceipt> = client.getOperationReceipt("operation-fixture");
void factorResult;
void receiptResult;
// @ts-expect-error Caller flags cannot establish consent or channel authority.
const forgedLabel: PasskeyLabelCommand = { ...label, approved: true };
void forgedLabel;
// @ts-expect-error A general receipt may describe a passkey instead of a Project.
const projectOnly: Promise<OperationReceipt> = client.getOperationReceipt("operation-fixture");
void projectOnly;

import type { TaskCreate, TaskControl, TaskReceipt, TaskView } from "../generated/client.js";
const task: TaskCreate = {schema_version: 1, idempotency_key: "task-fixture", project_id: "project-fixture",
  expected_project_revision: 1, objective: "Check result", responsibility: "UNASSIGNED"};
const taskResult: Promise<TaskReceipt> = client.createTask(task);
const taskRead: Promise<TaskView> = client.getTask("task-fixture");
const taskControl: TaskControl = {schema_version: 1, idempotency_key: "control-fixture", task_id: "task-fixture",
  expected_revision: 1, reason: "Human requested control"};
const paused: Promise<TaskReceipt> = client.pauseTask(taskControl);
const resumed: Promise<TaskReceipt> = client.resumeTask(taskControl);
const cancelled: Promise<TaskReceipt> = client.cancelTask(taskControl);
void [taskResult, taskRead, paused, resumed, cancelled];
// @ts-expect-error Task creation cannot assert execution or completion.
const fakeSuccess: TaskCreate = {...task, state: "DONE"};
void fakeSuccess;
// @ts-expect-error Responsibility cannot fabricate a Bot identity.
const fakeBot: TaskCreate = {...task, responsibility: "BOT"};
void fakeBot;

import type { InstructionChangeConsent, InstructionReceipt, ProtectedEffectResult, ProtectedPrepare, HistoryRead } from "../generated/client.js";
const consent: InstructionChangeConsent = {kind: "project.instructions.accept.v1", idempotency_key: "instruction-accept", project_id: "project", candidate_id: "candidate", candidate_hash: "a".repeat(64), expected_binding_revision: 1, expected_policy_revision: 1, review_ids: [], eval_ids: []};
const prepared: ProtectedPrepare = {effect: consent};
void client.prepareInstructionEffect(prepared, "csrf");
const confirmed: Promise<ProtectedEffectResult> = client.confirmInstructionEffect({request_id: "request", request_hash: "a".repeat(64), nonce: "n".repeat(43)}, "csrf");
const history: HistoryRead = {project_id: "project", revision: 1};
void client.readInstructionHistory("project", history, "csrf");
void confirmed;
// @ts-expect-error Caller flags cannot approve an instruction change.
const forgedConsent: InstructionChangeConsent = {...consent, approved: true};
void forgedConsent;
// @ts-expect-error The production effect set does not accept arbitrary commands.
const rawEffect: ProtectedPrepare = {effect: {kind: "execute.raw", command: "anything"}};
void rawEffect;

import type { PublicationRecovery, RecoveryTarget } from "../generated/client.js";
const recoveryTarget: RecoveryTarget = {project_id: "project", operation_id: "operation", expected_generation: 1, expected_binding_revision: 1, expected_policy_revision: 2, publication_hash: "a".repeat(64), target_hash: "b".repeat(64), root_revisions: [{root_id: "environment", revision: 3}]};
const recovery: PublicationRecovery = {...recoveryTarget, kind: "project.instructions.recover.v1", idempotency_key: "recovery", disposition: "RESTORE_BASE"};
void client.prepareInstructionEffect({effect: recovery}, "csrf");
void client.inspectInstructionRecovery("project", {project_id: "project"}, "csrf");
// @ts-expect-error Recovery must explicitly select the exact reconciliation effect.
const missingRecoveryChoice: PublicationRecovery = {...recoveryTarget, kind: "project.instructions.recover.v1", idempotency_key: "recovery"};
void missingRecoveryChoice;

// @ts-expect-error Offline restore authorization is not a completed instruction receipt.
const confirmationReceipt: Promise<InstructionReceipt> = confirmed;
void confirmationReceipt;

import type { JobCancel, JobView, ReplayPage, RestorePlan, RestorePreview } from "../generated/client.js";
const cancellation: JobCancel = {expected_revision: 1};
const cancelledJob: Promise<JobView> = client.cancelJob("job", cancellation, "csrf");
const replay: Promise<ReplayPage> = client.replayEvents({limit: 10}, "csrf");
const restorePreview: RestorePreview = {idempotency_key: "restore", snapshot: "snapshot", destination: "target", data_class: "PROJECT_INSTRUCTION_HISTORY", selection: [{project_id: "project", revisions: [1]}]};
const restorePlan: Promise<RestorePlan> = client.previewRestore(restorePreview, "csrf");
void [cancelledJob, replay, restorePlan];
// @ts-expect-error Job cancellation cannot supply worker identity or approval.
const forgedCancellation: JobCancel = {...cancellation, claim_owner: "caller"};
void forgedCancellation;

import type { VerificationPolicyReceipt, JobReceipt, RestoreReceipt, TaskAdmission } from "../generated/client.js";
function canonicalPolicy(receipt: VerificationPolicyReceipt): CanonicalReceipt { return receipt; }
function canonicalJob(receipt: JobReceipt): CanonicalReceipt { return receipt; }
function canonicalRestore(receipt: RestoreReceipt): CanonicalReceipt { return receipt; }
void [canonicalPolicy, canonicalJob, canonicalRestore];
const admission: TaskAdmission = {...taskControl, expected_policy_revision: 1};
void client.admitTask(admission, "csrf");
// @ts-expect-error Admission cannot accept caller approval.
const approvedAdmission: TaskAdmission = {...admission, approved: true};
void approvedAdmission;

import type { ProjectView } from "../generated/client.js";
const currentProject: Promise<ProjectView> = client.getProject("project-fixture");
void currentProject;

import type { ProjectPage, TaskPage, AttemptPage, JobPage } from "../generated/client.js";
const projectsPage: Promise<ProjectPage> = client.listProjects(1);
const tasksPage: Promise<TaskPage> = client.listTasks("project", 2, undefined, "BACKLOG");
const attemptsPage: Promise<AttemptPage> = client.listAttempts("task", 3);
const jobsPage: Promise<JobPage> = client.listJobs(4, {attempt_id: "attempt"});
void [projectsPage, tasksPage, attemptsPage, jobsPage];
// @ts-expect-error Discovery requires an explicit page limit.
void client.listProjects();
// @ts-expect-error State filters use canonical Task states.
void client.listTasks("project", 1, undefined, "FINISHED");
// @ts-expect-error Callers cannot select another Principal through discovery filters.
void client.listJobs(1, {principal_id: "other-human"});
