// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const {receipt, mode} = input;
let requests = 0;
const elements = new Map();
for (const id of ["status", "confirm", "cancel", "expiry", "deadline", "request_id", "request_hash", "nonce"]) {
  elements.set(id, {value: id === "deadline" ? String(Date.now() / 1000 + (mode === "expired" ? -60 : 60)) : "consumer-fixture",
    textContent: "", disabled: false, focused: false, handlers: {},
    focus() { this.focused = true; },
    addEventListener(name, handler) { this.handlers[name] = handler; }});
}
const source = fs.readFileSync(path.join(__dirname, "../src/journeon/assets/confirmation.js"), "utf8");
vm.runInNewContext(source, {
  document: {getElementById: id => elements.get(id) || null},
  sessionStorage: {getItem: () => ""},
  fetch: async () => { requests++; return {ok: true, json: async () => receipt}; },
  Date, setInterval: () => 1,
});
(async () => {
  if (mode === "expired") {
    await elements.get("confirm").handlers.click();
    if (requests !== 0 || !elements.get("confirm").disabled ||
        !elements.get("expiry").textContent.includes("expired")) {
      throw new Error("Expired confirmation was not blocked");
    }
    process.stdout.write("Expired confirmation blocked.\n");
    return;
  }
  await elements.get(mode === "cancel" ? "cancel" : "confirm").handlers.click();
  const expected = mode === "cancel" ? "Request state: CANCELLED."
    : mode === "restore" ? "Offline restore authorized. Authorization: " + receipt.request_id + ". No database has been restored."
    : "Operation result: " + (mode === "abandoned" ? "ABANDONED" : "CANONICAL_COMMITTED") + ". Receipt: " + receipt.operation_id + ".";
  if (elements.get("status").textContent !== expected || !elements.get("status").focused) {
    process.stderr.write("Confirmation consumer did not present the canonical receipt outcome.\n");
    process.exitCode = 1;
  } else {
    process.stdout.write("Confirmation receipt outcome presented.\n");
  }
})().catch(() => {
  process.stderr.write("Confirmation consumer did not complete.\n");
  process.exitCode = 1;
});
