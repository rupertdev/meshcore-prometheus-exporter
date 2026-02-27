# meshcore-prom-exporter

Prometheus exporter for MeshCore nodes, using `meshcore-cli` as the polling backend.

The exporter:
- refreshes `contacts` on a configured interval and, per poll cycle, runs `req_status` then `req_neighbours`,
- stores poll snapshots in SQLite,
- exposes latest values on `/metrics`.

## Requirements

- Python 3.10+
- `meshcore-cli` (`meshcli`) installed and reachable
- Linux host with `systemd` (for the recommended install path)

## Install (Recommended)

Use the provided helper script. This is the primary install path for running the exporter as a systemd service.

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
bash scripts/build_and_install_systemd.sh
```

The script will:
- build the executable with PyInstaller,
- install the binary to `/opt/meshcore-prom-exporter/meshcore-prom-exporter`,
- install the service file to `/etc/systemd/system/meshcore-prom-exporter.service`,
- copy config template to `/etc/meshcore-prom-exporter/meshcore-prom-exporter.env` (if missing),
- run `systemctl daemon-reload`.

Then edit config and start service:

```bash
sudoedit /etc/meshcore-prom-exporter/meshcore-prom-exporter.env
sudo systemctl enable --now meshcore-prom-exporter
sudo systemctl status meshcore-prom-exporter
```

## Install (Local Dev)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Build Executable (PyInstaller)

Build a single-file executable:

```bash
pyinstaller --clean --onefile --name meshcore-prom-exporter --paths src src/meshcore_prom_exporter/__main__.py
```

Output binary:

```text
dist/meshcore-prom-exporter
```

## Run (local)

Example using TCP to a companion node:

```bash
meshcore-prom-exporter \
  --target repeater01 \
  --device-password "<repeater-password>" \
  --meshcore-args "-t 192.168.1.10 -p 5000" \
  --poll-interval-seconds 30 \
  --db-path ./data/telemetry.db \
  --listen-address 0.0.0.0 \
  --listen-port 9108
```

Metrics endpoint:

```text
http://localhost:9108/metrics
```

## Configuration

Most runtime CLI flags have environment variable equivalents (`--once` is CLI-only):

- `--meshcli-bin` / `MESHCORE_CLI_BIN` (default: `meshcli`)
- `--target` / `MESHCORE_TARGET` (required if env not set)
- `--meshcore-args` / `MESHCORE_ARGS` (default: empty)
- `--timeout-seconds` / `MESHCORE_TIMEOUT_SECONDS` (default: `20`)
- `--contacts-timeout-seconds` / `MESHCORE_CONTACTS_TIMEOUT_SECONDS` (default: `60`)
- `--device-password` / `MESHCORE_DEVICE_PASSWORD` (fallback: `MESHCORE_PASSWORD`)
- `--login-target` / `MESHCORE_LOGIN_TARGET` (default: target)
- `--poll-interval-seconds` / `MESHCORE_POLL_INTERVAL_SECONDS` (default: `30`)
- `--contacts-refresh-seconds` / `MESHCORE_CONTACTS_REFRESH_SECONDS` (default: `300`)
- `--request-stagger-seconds` / `MESHCORE_REQUEST_STAGGER_SECONDS` (default: `2`)
- `--status-error-retry-seconds` / `MESHCORE_STATUS_ERROR_RETRY_SECONDS` (default: `1`)
- `--db-path` / `MESHCORE_DB_PATH` (default: `./data/telemetry.db`)
- `--listen-address` / `MESHCORE_LISTEN_ADDRESS` (default: `0.0.0.0`)
- `--listen-port` / `MESHCORE_LISTEN_PORT` (default: `9108`)
- `--log-level` / `MESHCORE_LOG_LEVEL` (default: `INFO`)
- `--debug-meshcli` / `MESHCORE_DEBUG_MESHCLI` (default: `false`)

Polling guidance:
- Avoid aggressive polling. For most deployments, `--poll-interval-seconds 3600` (hourly) is frequent enough and reduces load/timeouts on MeshCore nodes.

## Docker

Build:

```bash
docker build -t meshcore-prom-exporter:latest .
```

Run:

```bash
docker run --rm -p 9108:9108 \
  -e MESHCORE_TARGET="repeater01" \
  -e MESHCORE_ARGS="-t 192.168.1.10 -p 5000" \
  -e MESHCORE_DEVICE_PASSWORD="your-password" \
  -e MESHCORE_DB_PATH="/data/telemetry.db" \
  -v "$(pwd)/data:/data" \
  meshcore-prom-exporter:latest
```

Notes:
- The image includes both this exporter and `meshcore-cli`.
- If you are using BLE/serial access from container, you may need host networking and device passthrough.

## Grafana Dashboard

- Included dashboard JSON: `dashboards/meshcore.json`
- Import in Grafana: Dashboards -> New -> Import -> Upload JSON file
- The dashboard expects a Prometheus datasource UID of `cf5zubsowsg00f`; update that UID in the JSON if your datasource uses a different one.

## systemd

Included files:
- `deploy/systemd/meshcore-prom-exporter.service`
- `deploy/systemd/meshcore-prom-exporter.env.example`
- `scripts/build_and_install_systemd.sh` (build + install helper)

The provided unit does not set `User`/`Group`, so systemd runs it as root by default.

Manual install (if not using the helper script):

```bash
sudo mkdir -p /var/lib/meshcore-prom-exporter
sudo mkdir -p /etc/meshcore-prom-exporter
sudo mkdir -p /opt/meshcore-prom-exporter
sudo cp dist/meshcore-prom-exporter /opt/meshcore-prom-exporter/meshcore-prom-exporter
sudo chmod 0755 /opt/meshcore-prom-exporter/meshcore-prom-exporter
sudo cp deploy/systemd/meshcore-prom-exporter.env.example /etc/meshcore-prom-exporter/meshcore-prom-exporter.env
sudo cp deploy/systemd/meshcore-prom-exporter.service /etc/systemd/system/meshcore-prom-exporter.service
sudo systemctl daemon-reload
sudo systemctl enable --now meshcore-prom-exporter
```

After editing env values:

```bash
sudo systemctl restart meshcore-prom-exporter
sudo systemctl status meshcore-prom-exporter
```

## Metric Sources

| Metric | Labels | Source |
|---|---|---|
| `meshcore_poll_success` | `target` | Exporter internal: 1 on successful poll, 0 on failed poll |
| `meshcore_poll_duration_seconds` | `target` | Exporter internal: end-to-end poll cycle duration |
| `meshcore_poll_timestamp_seconds` | `target` | Exporter internal: timestamp of last successful poll |
| `meshcore_telemetry_snapshots_total` | `target` | SQLite row count in `telemetry_snapshots` for target |
| `meshcore_battery_voltage_volts` | `target` | `req_status.bat` (mV) converted to volts |
| `meshcore_battery_percent` | `target` | Estimated from `meshcore_battery_voltage_volts` using 1S LiPo curve |
| `meshcore_contacts_total` | `target` | Parsed from `contacts` output (cached between refreshes) |
| `meshcore_neighbors_zero_hop_total` | `target` | Derived from `req_neighbours` entries (`hops==0`, or count fallback) |
| `meshcore_neighbor_snr_db` | `target,neighbor_pubkey,neighbor_name` | `req_neighbours[].snr` |
| `meshcore_neighbor_last_seen_seconds` | `target,neighbor_pubkey,neighbor_name` | `req_neighbours[].secs_ago` |
| `meshcore_status_value` | `target,field` | Every numeric field from `req_status` (`bat` exported as `bat_mv`) |

## Exported Metrics (Examples)

These are example Prometheus exposition lines you should see on `/metrics`:

```text
meshcore_poll_success{target="repeater01"} 1
meshcore_poll_duration_seconds{target="repeater01"} 0.842
meshcore_poll_timestamp_seconds{target="repeater01"} 1772246400.123
meshcore_telemetry_snapshots_total{target="repeater01"} 189
meshcore_battery_voltage_volts{target="repeater01"} 3.742
meshcore_battery_percent{target="repeater01"} 23
meshcore_contacts_total{target="repeater01"} 41
meshcore_neighbors_zero_hop_total{target="repeater01"} 5
meshcore_neighbor_snr_db{target="repeater01",neighbor_pubkey="028f91d9",neighbor_name="OakRelay"} -0.75
meshcore_neighbor_last_seen_seconds{target="repeater01",neighbor_pubkey="028f91d9",neighbor_name="OakRelay"} 799
meshcore_status_value{target="repeater01",field="bat_mv"} 3742
meshcore_status_value{target="repeater01",field="uptime"} 259345
meshcore_status_value{target="repeater01",field="last_snr"} 13
```

Neighbor naming:
- `neighbor_name` is resolved by matching neighbour pubkey prefixes to the cached `contacts` list.
- If no match is found, `neighbor_name` falls back to `neighbor_pubkey`.

## Logging and Troubleshooting

- MeshCore CLI log lines (`LEVEL:logger:message`) are forwarded to exporter logs.
- `--debug-meshcli` logs raw stdout/stderr and timings for each command.
- `contacts` timeout warning means the subprocess hit `MESHCORE_CONTACTS_TIMEOUT_SECONDS`.
- If `req_status` returns an error payload (for example `{"error":"Getting data"}`), exporter retries once after `MESHCORE_STATUS_ERROR_RETRY_SECONDS`.
- `status=200/CHDIR` in `systemctl status` means `WorkingDirectory` does not exist for the unit.
- `meshcore-prom-exporter: error: the following arguments are required: --target` means `MESHCORE_TARGET` is missing in `/etc/meshcore-prom-exporter/meshcore-prom-exporter.env`.

## Local SQLite schema

- `telemetry_snapshots`: one row per poll, includes raw status payload JSON
- `telemetry_values`: flattened numeric values per snapshot

## Test

```bash
pytest -q
```

