// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const status = document.getElementById("status");
const tell = (message) => { status.textContent = message; status.focus(); };
const token = () => sessionStorage.getItem("journeon-csrf") || "";
async function post(path, body) {
  const response = await fetch(path, {method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": token()}, body: JSON.stringify(body)});
  if (!response.ok) throw new Error("No confirmed result was received. Check current authorization and request status before retrying.");
  return response.json();
}
function bytes(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}
function encoded(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
for (const purpose of ["login", "stepup"]) {
  document.getElementById(purpose)?.addEventListener("click", async () => {
    tell("Authentication in progress. No instruction operation has been approved.");
    try {
      const challenge = await post("/api/v1/auth/passkeys/begin", {purpose, label: ""});
      const options = JSON.parse(challenge.options_json).publicKey;
      options.challenge = bytes(options.challenge);
      if (options.allowCredentials) options.allowCredentials.forEach(c => { c.id = bytes(c.id); });
      const credential = await navigator.credentials.get({publicKey: options});
      const response = credential.response;
      const result = await post("/api/v1/auth/passkeys/finish", {purpose, ceremony_id: challenge.ceremony_id,
        credential_json: JSON.stringify({id: credential.id, rawId: encoded(credential.rawId), type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment,
          clientExtensionResults: credential.getClientExtensionResults(),
          response: {clientDataJSON: encoded(response.clientDataJSON), authenticatorData: encoded(response.authenticatorData),
            signature: encoded(response.signature), userHandle: response.userHandle ? encoded(response.userHandle) : null}})});
      sessionStorage.setItem("journeon-csrf", result.csrf_token);
      tell("Authentication succeeded. Prepare a new instruction request, then open its confirmation page.");
    } catch { tell("Authentication did not complete. No instruction operation was approved."); }
  });
}
const confirm = document.getElementById("confirm");
const cancel = document.getElementById("cancel");
if (confirm) {
  const value = id => document.getElementById(id).value;
  const expired = () => Date.now() / 1000 >= Number(value("deadline"));
  const update = () => {
    if (expired()) { confirm.disabled = true; document.getElementById("expiry").textContent = "This preview has expired. Prepare a new request before confirming."; }
    else document.getElementById("expiry").textContent = "Preview expires at " + new Date(Number(value("deadline")) * 1000).toLocaleString() + ". Server authorization is checked again on confirmation.";
  };
  update(); setInterval(update, 1000);
  confirm.addEventListener("click", async () => {
    if (expired()) { update(); return; }
    confirm.disabled = true;
    try {
      const result = await post("/api/v1/protected-operations/confirm", {request_id: value("request_id"), request_hash: value("request_hash"), nonce: value("nonce")});
      cancel.disabled = true;
      const outcome = result.outcome === "CANONICAL_COMMITTED" ? result.outcome : result.status;
      tell(result.status === "AUTHORIZED_OFFLINE_ONLY"
        ? "Offline restore authorized. Authorization: " + result.request_id + ". No database has been restored."
        : "Operation result: " + outcome + ". Receipt: " + result.operation_id + ".");
    } catch (error) { tell(error.message); }
  });
  cancel.addEventListener("click", async () => {
    confirm.disabled = true; cancel.disabled = true;
    try { const result = await post("/api/v1/protected-operations/cancel", {request_id: value("request_id")}); tell("Request state: " + result.state + "."); }
    catch (error) { tell(error.message); }
  });
}
