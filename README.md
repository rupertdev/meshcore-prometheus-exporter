# meshcore-prom-exporter

Prometheus exporter for MeshCore nodes, using `meshcore-cli` as the polling backend.

The exporter:
- refreshes `contacts` on a configured interval and, per poll cycle, runs `req_status` then `req_neighbours`,
- stores poll snapshots in SQLite,
- exposes latest values on `/metrics`.

## Requirements

- Python 3.10+
- `meshcore-cli` (`meshcli`) installed and reachable

## Install (local)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
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

Suggested install:

```bash
sudo useradd --system --home /var/lib/meshcore-prom-exporter --create-home meshcore-exporter
sudo mkdir -p /etc/meshcore-prom-exporter
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

Neighbor naming:
- `neighbor_name` is resolved by matching neighbour pubkey prefixes to the cached `contacts` list.
- If no match is found, `neighbor_name` falls back to `neighbor_pubkey`.

## Logging and Troubleshooting

- MeshCore CLI log lines (`LEVEL:logger:message`) are forwarded to exporter logs.
- `--debug-meshcli` logs raw stdout/stderr and timings for each command.
- `contacts` timeout warning means the subprocess hit `MESHCORE_CONTACTS_TIMEOUT_SECONDS`.
- If `req_status` returns an error payload (for example `{"error":"Getting data"}`), exporter retries once after `MESHCORE_STATUS_ERROR_RETRY_SECONDS`.

## Local SQLite schema

- `telemetry_snapshots`: one row per poll, includes raw status payload JSON
- `telemetry_values`: flattened numeric values per snapshot

## Test

```bash
pytest -q
```

