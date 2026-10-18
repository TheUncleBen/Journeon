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
  const denied = new JourneonClient("", async () => new Response(
    JSON.stringify({code: "PERMISSION_DENIED"}), {status: 403},
  ));
  await assert.rejects(denied.createProject(command), error =>
    error instanceof JourneonError && error.status === 403 &&
    error.body.code === "PERMISSION_DENIED");
  console.log("Generated client transport checks passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
