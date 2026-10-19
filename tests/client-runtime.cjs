// SPDX-License-Identifier: AGPL-3.0-only
const assert = require("node:assert/strict");
const { JourneonClient, JourneonError } = require("../work/client-build/generated/client.js");

async function main() {
  const calls = [];
  const receipt = { operation_id: "synthetic-operation" };
  const transport = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(receipt), { status: 200 });
  };
  const successorCalls = [];
  const successor = new JourneonClient("", async (url, init) => {
    successorCalls.push({url, init});
    return new Response(JSON.stringify(receipt), {status: 200});
  });
  for (const [method, path] of [["admitTask", "/api/v1/tasks/admit"],
    ["assignTask", "/api/v1/tasks/assign"], ["reviseTask", "/api/v1/tasks/revise"],
    ["configureVerification", "/api/v1/projects/verification"]]) {
    assert.deepEqual(await successor[method]({idempotency_key: "fixture"}, "csrf"), receipt);
    const call = successorCalls.at(-1);
    assert.equal(call.url, path);
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.headers["X-CSRF-Token"], "csrf");
    assert.equal(call.init.credentials, "same-origin");
  }
  await successor.getProject("encoded/project");
  assert.equal(successorCalls.at(-1).url, "/api/v1/projects/encoded%2Fproject");
  assert.equal(successorCalls.at(-1).init.method, "GET");
  assert.equal(successorCalls.at(-1).init.credentials, "same-origin");
  await successor.getVerification("encoded/project");
  assert.equal(successorCalls.at(-1).url, "/api/v1/projects/encoded%2Fproject/verification");
  await successor.getWorkflowTemplates("encoded/project");
  assert.equal(successorCalls.at(-1).url, "/api/v1/tasks/workflow-templates?project_id=encoded%2Fproject");
  const client = new JourneonClient("", transport);
  const command = {
    schema_version: 1, idempotency_key: "synthetic-command", name: "Example project",
    expected_policy_revision: 1,
  };
  assert.deepEqual(await client.createProject(command), receipt);
  assert.equal(calls[0].url, "/api/v1/projects");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.credentials, "same-origin");
  assert.deepEqual(JSON.parse(calls[0].init.body), command);
  await client.getOperationReceipt("encoded/operation");
  assert.equal(calls[1].url, "/api/v1/operations/encoded%2Foperation");
  assert.equal(calls[1].init.method, "GET");
  await client.beginPasskey({purpose: "stepup", label: ""}, "synthetic-csrf");
  assert.equal(calls[2].url, "/api/v1/auth/passkeys/begin");
  assert.equal(calls[2].init.headers["X-CSRF-Token"], "synthetic-csrf");
  await client.finishPasskey({purpose: "login", ceremony_id: "synthetic", credential_json: "{}"});
  assert.equal(calls[3].url, "/api/v1/auth/passkeys/finish");
  assert.equal(calls[3].init.credentials, "same-origin");
  await client.createProject(command, "synthetic-csrf");
  assert.equal(calls[4].init.headers["X-CSRF-Token"], "synthetic-csrf");
  const label = {schema_version: 1, idempotency_key: "label-fixture", passkey_id: "key-fixture",
    expected_revision: 1, label: "Renamed"};
  assert.deepEqual(await client.labelPasskey(label, "synthetic-csrf"), receipt);
  assert.equal(calls[5].url, "/api/v1/auth/passkeys/label");
  assert.equal(calls[5].init.headers["X-CSRF-Token"], "synthetic-csrf");
  assert.equal(calls[5].init.credentials, "same-origin");
  assert.deepEqual(JSON.parse(calls[5].init.body), label);
  const task = {schema_version: 1, idempotency_key: "task-fixture", project_id: "project-fixture",
    expected_project_revision: 1, objective: "Check result", responsibility: "UNASSIGNED"};
  assert.deepEqual(await client.createTask(task, "synthetic-csrf"), receipt);
  await client.getTask("encoded/task");
  const control = {schema_version: 1, idempotency_key: "control-fixture", task_id: "task-fixture",
    expected_revision: 1, reason: "Human requested control"};
  for (const action of ["pause", "resume", "cancel"]) {
    assert.deepEqual(await client[`${action}Task`](control, "synthetic-csrf"), receipt);
  }
  assert.deepEqual(calls.slice(6).map(call => call.url), ["/api/v1/tasks", "/api/v1/tasks/encoded%2Ftask",
    "/api/v1/tasks/pause", "/api/v1/tasks/resume", "/api/v1/tasks/cancel"]);
  for (const call of [calls[6], ...calls.slice(8)]) {
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.headers["X-CSRF-Token"], "synthetic-csrf");
  }
  const instruction = {project_id: "encoded/project", revision: 1, path: "rules.md"};
  await client.readInstructionDocument("encoded/project", instruction, "instruction-csrf");
  const documentCall = calls.at(-1);
  assert.equal(documentCall.url, "/api/v1/projects/encoded%2Fproject/instructions/document");
  assert.equal(documentCall.init.headers["X-CSRF-Token"], "instruction-csrf");
  assert.deepEqual(JSON.parse(documentCall.init.body), instruction);
  await client.prepareInstructionEffect({effect: {kind: "instruction.candidate.register.v1", idempotency_key: "candidate", manifest_digest: "a".repeat(64), expected_revision: 0}}, "instruction-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/protected-operations/prepare");
  assert.equal(calls.at(-1).init.credentials, "same-origin");
  await client.projectInstructionProjection("encoded/project", "check", {project_id: "encoded/project"}, "instruction-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/projects/encoded%2Fproject/instructions/projections/check");
  await client.inspectInstructionRecovery("encoded/project", {project_id: "encoded/project"}, "recovery-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/projects/encoded%2Fproject/instructions/recovery");
  assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "recovery-csrf");
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), {project_id: "encoded/project"});
  await client.readJob("encoded/job");
  assert.equal(calls.at(-1).url, "/api/v1/jobs/encoded%2Fjob");
  await client.cancelJob("encoded/job", {expected_revision: 1}, "job-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/jobs/encoded%2Fjob/cancel");
  assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "job-csrf");
  await client.replayEvents({limit: 10}, "replay-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/events/replay");
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), {limit: 10});
  await client.previewRestore({idempotency_key: "restore", snapshot: "saved", destination: "target", data_class: "PROJECT_INSTRUCTION_HISTORY", selection: [{project_id: "project", revisions: [1]}]}, "restore-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/lifecycle/restore-preview");
  assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "restore-csrf");
  await client.prepareAttempt({idempotency_key: "attempt"}, "attempt-csrf");
  assert.equal(calls.at(-1).url, "/api/v1/attempts/prepare");
  assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "attempt-csrf");
  await client.getAttempt("encoded/attempt");
  assert.equal(calls.at(-1).url, "/api/v1/attempts/encoded%2Fattempt");
  const denied = new JourneonClient("", async () => new Response(
    JSON.stringify({code: "PERMISSION_DENIED"}), {status: 403},
  ));
  await assert.rejects(denied.createProject(command), error =>
    error instanceof JourneonError && error.status === 403 &&
    error.body.code === "PERMISSION_DENIED");
  console.log("Generated client transport checks passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
