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
