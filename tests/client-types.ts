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
