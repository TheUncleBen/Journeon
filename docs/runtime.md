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
