# Local runtime and release bundle

The runtime binds the existing service to a directly configured TLS listener. It does not provision identities, create a database, or migrate a schema. Stop the service and use the separate `journeon.operations` migration command with a new snapshot destination before upgrading an existing database.

Run `python -I launch.py --config /absolute/path/runtime.json` using a Python 3.12 environment installed from the selected target's checked lock. The launch path is independent of the current working directory. Configuration and persistent data belong outside the release. Never place private keys or session credentials in command arguments or the release directory.

The JSON configuration requires every field below and rejects additional fields:

| Field | Meaning |
| --- | --- |
| `host`, `port` | Explicit listener IP address and port from 1 to 65535. |
| `origin`, `rp_id` | Exact HTTPS origin and matching relying-party hostname. |
| `database` | Absolute existing database file with the current schema. |
| `tls_certificate`, `tls_private_key` | Absolute readable certificate-chain and private-key files. Encrypted-key prompting is not supported. |
| `trusted_proxy_peers` | Explicit IP addresses permitted to supply forwarding headers; an empty list disables forwarding trust. Wildcards and networks are rejected. |
| `busy_timeout_ms` | SQLite writer wait, from 1 to 60000 milliseconds. |
| `backlog`, `limit_concurrency` | Positive listener backlog and server concurrency settings. |
| `timeout_keep_alive` | Nonnegative idle time between requests, in seconds. |
| `timeout_graceful_shutdown` | Positive graceful shutdown wait, in seconds. |

All file paths reject symbolic links. TLS is required by this binding; it does not select a production TLS custody or termination strategy. Operational ports, exposure, timers and resource settings require an explicit deployment configuration. Passkey policy uses the existing standard policy. No ambient `UVICORN_*` or forwarding environment variable grants configuration authority. Access logging is disabled to avoid retaining request credentials. The factory entry point additionally supports an explicit `JOURNEON_CONFIG` file path; use the launcher to apply the complete listener binding.

Build with `python tools/build_release.py DESTINATION --inventory TARGET_INVENTORY --wheels WHEEL_DIRECTORY`. The destination must be new. Supply all runtime wheels from the selected architecture inventory. The bundle contains source, migrations, generated client/contracts, project metadata, operating documentation, licenses, exact runtime wheels, inventory and lock. Install the bundled lock into a new target-specific environment with `python -m pip install --no-index --find-links RELEASE/wheels --require-hashes -r RELEASE/runtime.lock`. Bootstrap Python and pip are separate prerequisites; a virtual environment is never copied between hosts.

Verify bytes with `python tools/build_release.py RELEASE --verify` before use. The manifest rejects added, missing or changed payload files and records the sole version from `pyproject.toml`. This is integrity accounting, not signature authentication or approval to promote an artifact. Protect release directories against modification. Runtime bytecode writes are disabled by the launcher.

SIGTERM requests graceful shutdown and disposes the database engine. The runtime emits `{"status": "STOPPED"}` after disposal; Uvicorn then restores the native SIGTERM exit status. The backlog and concurrency settings do not establish a whole-request deadline or a hard bound on accepted connections before headers. Interrupted authentication bodies retain the existing finite reservation semantics. Physical target pressure, recovery, signed updates, rollback, backup overlap and production transport remain separate qualification obligations. Architecture inventories describe wheel availability; they do not establish execution on an untested architecture.

Optional `instructions.jobs` enables the deterministic instruction dispatcher. Supply explicit positive `pending_count`, `pending_bytes`, `lease_seconds`, `poll_seconds`, `retry_seconds` and `max_attempts`, and set `concurrency` to `1`. These limits have no shipping defaults. Without this configuration, automatic Job admission is unavailable. Startup resumes durable eligible work; shutdown stops claims and drains the current local operation before closing the store. Polling does not extend human session inactivity.

The selected-history restore path recovers missing immutable Project instruction revisions into a new database staged from the surviving current store. It preserves newer unselected records, current security state and external files; it rejects conflicting history instead of replacing it. Other restore classes, replacement rollback and fresh-host recovery are unavailable through this command.

Configure `instructions.restore.snapshot_root` and `destination_root` as absolute local directories. Request `/api/v1/lifecycle/restore-preview` with a snapshot directory name, a new destination name, `data_class` equal to `PROJECT_INSTRUCTION_HISTORY`, and exact Project/revision selections. Current Owner authority, `lifecycle.restore`, and exact Project instruction read/restore grants are required. Confirm the returned exact plan through the existing official protected-operation surface. Confirmation returns an offline authorization reference; it does not restore bytes.

Stop all writers, retain the plan and instruction configuration as local JSON files, then run:

```text
python -m journeon.operations restore SOURCE_DATABASE DESTINATION_DIRECTORY --authorization REQUEST_ID --plan PLAN_JSON --instruction-config INSTRUCTION_CONFIG_JSON --json
```

The command consumes the current session-bound authorization once and enforces an exclusive maintenance lock. It preserves the source snapshot, creates a verified snapshot of the surviving store, imports eligible selected history through its owner and records a fresh store incarnation. Pending copied approvals are invalidated and queued Jobs require new authorization. Missing, expired or revoked authority, changed versions or external files, and incomplete staging deny activation.

A successful command reports `RESTORED_INACTIVE` and the staged database path. Explicitly select that path in runtime configuration to activate it. Startup requires matching completed admission records at the source and destination; the old source remains fenced. Retain both stores and their admission metadata. An interruption preserves partial outputs for inspection and never automatically switches the runtime. Replay cursors from the old incarnation require canonical refetch; normal restarts preserve the new incarnation.

Store activation and writable connections verify the recorded database destination. Copying a current database or its admission metadata to another path does not authorize activation; use the protected offline restore operation. Snapshot validation and copied-byte doctor inspection remain available without activating the snapshot. A durable staging fence precedes destination copies and remains until completed source and destination admission records are durable. Failed stages remain unavailable even when staging metadata is missing, because the copied source destination does not match. Moving the application release artifact does not move or rebind the configured database.
