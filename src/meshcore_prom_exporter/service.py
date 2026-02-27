from __future__ import annotations

import json
import logging
import re
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]+")
_MESHCORE_LOG_LINE = re.compile(r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL):([^:]+):(.*)$")
LOGGER = logging.getLogger("meshcore_prom_exporter.meshcli")
_CONTACT_CACHE: dict[tuple[str, str], tuple[float, dict[str, str], float | None]] = {}
_LIPO_1S_CURVE: tuple[tuple[float, float], ...] = (
    (3.27, 0.0),
    (3.61, 5.0),
    (3.69, 10.0),
    (3.71, 15.0),
    (3.73, 20.0),
    (3.75, 25.0),
    (3.77, 30.0),
    (3.79, 35.0),
    (3.80, 40.0),
    (3.82, 45.0),
    (3.84, 50.0),
    (3.85, 55.0),
    (3.87, 60.0),
    (3.91, 65.0),
    (3.95, 70.0),
    (3.98, 75.0),
    (4.02, 80.0),
    (4.08, 85.0),
    (4.11, 90.0),
    (4.15, 95.0),
    (4.20, 100.0),
)


@dataclass(frozen=True)
class PollConfig:
    meshcli_bin: str
    target: str
    meshcore_args: list[str] = field(default_factory=list)
    timeout_seconds: float = 20.0
    contacts_timeout_seconds: float = 60.0
    device_password: str | None = None
    login_target: str | None = None
    contacts_refresh_seconds: float = 300.0
    request_stagger_seconds: float = 0.0
    debug_meshcli: bool = False
    status_error_retry_seconds: float = 1.0

    def _base_command(self) -> list[str]:
        return [self.meshcli_bin, "-j", *self.meshcore_args]

    def _auth_prefix(self) -> list[str]:
        if not self.device_password:
            return []
        login_target = self.login_target or self.target
        return ["login", login_target, self.device_password]

    def contacts_command(self) -> list[str]:
        # Contacts command has no target argument; when login is present, it
        # runs in the authenticated remote context.
        return [*self._base_command(), *self._auth_prefix(), "contacts"]

    def neighbours_command(self) -> list[str]:
        return [*self._base_command(), *self._auth_prefix(), "req_neighbours", self.target]

    def status_command(self) -> list[str]:
        return [*self._base_command(), *self._auth_prefix(), "req_status", self.target]

    def command(self) -> list[str]:
        return self.status_command()


@dataclass(frozen=True)
class PollResult:
    success: bool
    observed_at: float | None = None
    poll_duration_seconds: float | None = None
    values: dict[str, float] = field(default_factory=dict)
    neighbors: list[dict[str, Any]] | None = None
    error: str | None = None


def parse_cli_json_objects(output: str) -> list[Any]:
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = 0
    while index < len(output):
        while index < len(output) and output[index] not in "{[":
            index += 1
        if index >= len(output):
            break
        try:
            parsed, end_index = decoder.raw_decode(output, index)
        except json.JSONDecodeError:
            index += 1
            continue
        values.append(parsed)
        index = end_index
    return values


def _sanitize_metric_segment(raw: str) -> str:
    return _NON_ALNUM.sub("_", raw.strip().lower()).strip("_")


def flatten_numeric_values(
    payload: Any,
    prefix: str = "",
    output: dict[str, float] | None = None,
) -> dict[str, float]:
    if output is None:
        output = {}

    if isinstance(payload, dict):
        for key, value in payload.items():
            metric_part = _sanitize_metric_segment(str(key))
            if not metric_part:
                continue
            next_prefix = metric_part if not prefix else f"{prefix}_{metric_part}"
            flatten_numeric_values(value, next_prefix, output)
        return output

    if isinstance(payload, list):
        for index, value in enumerate(payload):
            next_prefix = f"{prefix}_{index}" if prefix else str(index)
            flatten_numeric_values(value, next_prefix, output)
        return output

    if isinstance(payload, bool):
        if prefix:
            output[prefix] = 1.0 if payload else 0.0
        return output

    if isinstance(payload, (int, float)) and not isinstance(payload, bool):
        if prefix:
            output[prefix] = float(payload)
        return output

    return output


class TelemetryStore:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS telemetry_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    poll_duration_seconds REAL NOT NULL,
                    raw_payload TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_telemetry_snapshots_target_time
                    ON telemetry_snapshots (target, observed_at DESC);

                CREATE TABLE IF NOT EXISTS telemetry_values (
                    snapshot_id INTEGER NOT NULL,
                    metric_key TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    PRIMARY KEY (snapshot_id, metric_key),
                    FOREIGN KEY (snapshot_id) REFERENCES telemetry_snapshots (id)
                );
                """
            )
            self._conn.commit()

    def record_snapshot(
        self,
        *,
        target: str,
        observed_at: float,
        poll_duration_seconds: float,
        raw_payload: dict[str, Any],
        values: dict[str, float],
    ) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO telemetry_snapshots (target, observed_at, poll_duration_seconds, raw_payload)
                VALUES (?, ?, ?, ?)
                """,
                (target, observed_at, poll_duration_seconds, json.dumps(raw_payload, sort_keys=True)),
            )
            snapshot_id = int(cursor.lastrowid)
            self._conn.executemany(
                """
                INSERT INTO telemetry_values (snapshot_id, metric_key, metric_value)
                VALUES (?, ?, ?)
                """,
                [(snapshot_id, key, value) for key, value in values.items()],
            )
            self._conn.commit()
        return snapshot_id

    def read_latest_values(self, *, target: str) -> dict[str, float]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id
                FROM telemetry_snapshots
                WHERE target = ?
                ORDER BY observed_at DESC, id DESC
                LIMIT 1
                """,
                (target,),
            ).fetchone()
            if row is None:
                return {}
            snapshot_id = int(row[0])
            rows = self._conn.execute(
                """
                SELECT metric_key, metric_value
                FROM telemetry_values
                WHERE snapshot_id = ?
                """,
                (snapshot_id,),
            ).fetchall()
        return {str(metric_key): float(metric_value) for metric_key, metric_value in rows}

    def count_snapshots(self, *, target: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM telemetry_snapshots WHERE target = ?",
                (target,),
            ).fetchone()
        return int(row[0] if row else 0)


def _select_latest_payload(parsed_objects: list[Any]) -> dict[str, Any] | None:
    for candidate in reversed(parsed_objects):
        if not isinstance(candidate, dict):
            continue
        telemetry_value = candidate.get("telemetry")
        if isinstance(telemetry_value, dict):
            return telemetry_value
        if candidate.get("ok") is not None and len(candidate) <= 2:
            continue
        if flatten_numeric_values(candidate):
            return candidate
    return None


def _select_latest_status_payload(parsed_objects: list[Any]) -> dict[str, Any] | None:
    for candidate in reversed(parsed_objects):
        if not isinstance(candidate, dict):
            continue
        if candidate.get("login_success") is not None and len(candidate) <= 2:
            continue
        has_numeric = any(
            isinstance(value, (int, float)) and not isinstance(value, bool) for value in candidate.values()
        )
        if has_numeric:
            return candidate
    return None


def _select_latest_error_message(parsed_objects: list[Any]) -> str | None:
    for candidate in reversed(parsed_objects):
        if not isinstance(candidate, dict):
            continue
        error_value = candidate.get("error")
        if isinstance(error_value, str) and error_value.strip():
            return error_value.strip()
    return None


def _parse_hops(contact: dict[str, Any]) -> int | None:
    for key in ("hops", "hop", "h"):
        if key not in contact:
            continue
        value = contact[key]
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value.strip())
            except ValueError:
                continue
    return None


def _looks_like_contact(contact: Any) -> bool:
    if not isinstance(contact, dict):
        return False
    for key in ("name", "hops", "hop", "path", "type", "public_key"):
        if key in contact:
            return True
    return False


def _extract_contacts_total(parsed_objects: list[Any]) -> tuple[float, bool]:
    for parsed in parsed_objects:
        if isinstance(parsed, dict):
            if isinstance(parsed.get("contacts_total"), (int, float)):
                return float(parsed["contacts_total"]), True
            contacts = parsed.get("contacts")
            if isinstance(contacts, list):
                counted = sum(1 for entry in contacts if _looks_like_contact(entry))
                return float(counted), True
            if isinstance(contacts, dict):
                counted = sum(1 for entry in contacts.values() if _looks_like_contact(entry))
                return float(counted), True
            direct_values = [entry for entry in parsed.values() if _looks_like_contact(entry)]
            if direct_values:
                return float(len(direct_values)), True
        if isinstance(parsed, list):
            counted = sum(1 for entry in parsed if _looks_like_contact(entry))
            return float(counted), True
    return 0.0, False


def _normalize_pubkey(raw: str) -> str:
    return raw.strip().lower()


def _contact_name(entry: dict[str, Any]) -> str | None:
    for key in ("adv_name", "name", "node_name", "display_name", "alias"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_contact_name_index(parsed_objects: list[Any]) -> tuple[dict[str, str], bool]:
    index: dict[str, str] = {}
    found = False

    def add_alias(alias: str, name: str) -> None:
        normalized = _normalize_pubkey(alias)
        if not normalized:
            return
        index[normalized] = name
        if len(normalized) >= 8:
            index.setdefault(normalized[:8], name)
        if len(normalized) >= 12:
            index.setdefault(normalized[:12], name)

    def consume_entry(entry: Any, *, key_hint: str | None = None) -> None:
        if not isinstance(entry, dict):
            return
        if not _looks_like_contact(entry):
            return
        name = _contact_name(entry)
        if not name:
            return
        pubkeys: list[str] = []
        for key in ("public_key", "pubkey", "id", "key"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                pubkeys.append(value.strip())
        if key_hint and key_hint.strip():
            pubkeys.append(key_hint.strip())
        for candidate in pubkeys:
            add_alias(candidate, name)

    for parsed in parsed_objects:
        if isinstance(parsed, dict):
            contacts = parsed.get("contacts")
            if isinstance(contacts, list):
                found = True
                for entry in contacts:
                    consume_entry(entry)
                continue
            if isinstance(contacts, dict):
                found = True
                for key_hint, entry in contacts.items():
                    if isinstance(key_hint, str):
                        consume_entry(entry, key_hint=key_hint)
                continue

            direct_items = [(key, value) for key, value in parsed.items() if isinstance(value, dict)]
            if direct_items:
                direct_found = False
                for key_hint, entry in direct_items:
                    if not _looks_like_contact(entry):
                        continue
                    direct_found = True
                    if isinstance(key_hint, str):
                        consume_entry(entry, key_hint=key_hint)
                    else:
                        consume_entry(entry)
                if direct_found:
                    found = True
        elif isinstance(parsed, list):
            if all(isinstance(entry, dict) for entry in parsed):
                found = True
                for entry in parsed:
                    consume_entry(entry)

    return index, found


def _extract_neighbours_zero_hop_total(parsed_objects: list[Any]) -> tuple[float, bool]:
    for parsed in parsed_objects:
        candidate_entries: list[dict[str, Any]] | None = None
        if isinstance(parsed, dict):
            for key in ("neighbours", "neighbors"):
                value = parsed.get(key)
                if isinstance(value, list):
                    candidate_entries = [entry for entry in value if isinstance(entry, dict)]
                    break
            if candidate_entries is None and isinstance(parsed.get("neighbors_zero_hop_total"), (int, float)):
                return float(parsed["neighbors_zero_hop_total"]), True
        elif isinstance(parsed, list):
            candidate_entries = [entry for entry in parsed if isinstance(entry, dict)]

        if candidate_entries is None:
            continue

        if not candidate_entries:
            return 0.0, True

        hops_present = any(_parse_hops(entry) is not None for entry in candidate_entries)
        if hops_present:
            zero_hop = sum(1 for entry in candidate_entries if _parse_hops(entry) == 0)
            return float(zero_hop), True
        return float(len(candidate_entries)), True

    return 0.0, False


def _as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _extract_neighbour_entries(
    parsed_objects: list[Any],
    *,
    contact_name_index: dict[str, str],
) -> tuple[list[dict[str, Any]], bool]:
    for parsed in parsed_objects:
        entries: list[dict[str, Any]] | None = None
        if isinstance(parsed, dict):
            for key in ("neighbours", "neighbors"):
                value = parsed.get(key)
                if isinstance(value, list):
                    entries = [entry for entry in value if isinstance(entry, dict)]
                    break
        elif isinstance(parsed, list):
            entries = [entry for entry in parsed if isinstance(entry, dict)]

        if entries is None:
            continue

        neighbors: list[dict[str, Any]] = []
        for idx, entry in enumerate(entries):
            raw_pubkey = entry.get("pubkey")
            if not isinstance(raw_pubkey, str) or not raw_pubkey.strip():
                raw_pubkey = entry.get("public_key")
            if not isinstance(raw_pubkey, str) or not raw_pubkey.strip():
                raw_pubkey = entry.get("name")
            if not isinstance(raw_pubkey, str) or not raw_pubkey.strip():
                raw_pubkey = f"neighbor_{idx}"

            pubkey = raw_pubkey.strip()
            normalized_pubkey = _normalize_pubkey(pubkey)
            name = contact_name_index.get(normalized_pubkey)
            if not name:
                for key_prefix, resolved_name in contact_name_index.items():
                    if key_prefix.startswith(normalized_pubkey) or normalized_pubkey.startswith(key_prefix):
                        name = resolved_name
                        break
            if not name and isinstance(entry.get("name"), str) and entry["name"].strip():
                name = entry["name"].strip()
            if not name:
                name = pubkey

            neighbors.append(
                {
                    "pubkey": pubkey,
                    "name": name,
                    "snr": _as_float(entry.get("snr"), 0.0),
                    "secs_ago": _as_float(entry.get("secs_ago"), 0.0),
                    "hops": _parse_hops(entry),
                }
            )
        return neighbors, True
    return [], False


def _extract_battery_metrics(telemetry_values: dict[str, float]) -> dict[str, float]:
    output: dict[str, float] = {}
    battery_voltage = telemetry_values.get("battery_voltage")
    if battery_voltage is None:
        for key, value in telemetry_values.items():
            if "battery" in key and "volt" in key:
                battery_voltage = value
                break
    if battery_voltage is not None:
        output["battery_voltage_volts"] = float(battery_voltage)

    battery_percent = telemetry_values.get("battery_percent")
    if battery_percent is None:
        percent_aliases = {"pct", "percent", "percentage", "soc", "state_of_charge", "charge", "level"}
        for key, value in telemetry_values.items():
            if "battery" not in key:
                continue
            if any(alias in key for alias in percent_aliases):
                battery_percent = value
                break
    if battery_percent is not None:
        output["battery_percent"] = float(battery_percent)
    return output


def _extract_battery_from_lpp(payload: dict[str, Any]) -> dict[str, float]:
    output: dict[str, float] = {}
    lpp_items = payload.get("lpp")
    if not isinstance(lpp_items, list):
        return output

    for item in lpp_items:
        if not isinstance(item, dict):
            continue
        lpp_type = str(item.get("type", "")).strip().lower()
        value = item.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        numeric_value = float(value)
        if lpp_type == "voltage" and "battery_voltage_volts" not in output:
            output["battery_voltage_volts"] = numeric_value
        if lpp_type in {
            "battery",
            "battery_percent",
            "percentage",
            "percent",
            "pct",
            "soc",
            "state_of_charge",
            "charge",
            "battery_level",
            "level",
        } and "battery_percent" not in output:
            output["battery_percent"] = numeric_value
    return output


def _estimate_1s_lipo_percent(voltage: float) -> float:
    if voltage <= _LIPO_1S_CURVE[0][0]:
        return 0.0
    if voltage >= _LIPO_1S_CURVE[-1][0]:
        return 100.0

    for index in range(1, len(_LIPO_1S_CURVE)):
        v0, p0 = _LIPO_1S_CURVE[index - 1]
        v1, p1 = _LIPO_1S_CURVE[index]
        if voltage <= v1:
            if v1 == v0:
                return p1
            ratio = (voltage - v0) / (v1 - v0)
            return round(p0 + ratio * (p1 - p0), 1)
    return 100.0


def _ensure_estimated_battery_percent(values: dict[str, float]) -> None:
    if "battery_percent" in values:
        return
    voltage = values.get("battery_voltage_volts")
    if voltage is None:
        return
    values["battery_percent"] = _estimate_1s_lipo_percent(voltage)


def _extract_status_values(status_payload: dict[str, Any]) -> dict[str, float]:
    values: dict[str, float] = {}
    for raw_key, raw_value in status_payload.items():
        if isinstance(raw_value, bool):
            continue
        if not isinstance(raw_value, (int, float)):
            continue
        metric_key = _sanitize_metric_segment(str(raw_key))
        if not metric_key:
            continue
        if metric_key == "bat":
            metric_key = "bat_mv"
        values[f"status_{metric_key}"] = float(raw_value)
    return values


def _run_meshcli(command: list[str], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        process.kill()
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            cmd=error.cmd,
            timeout=error.timeout,
            output=stdout,
            stderr=stderr,
        ) from error
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        raise

    return subprocess.CompletedProcess(
        args=command,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _compact_output_snippet(output: str, max_chars: int = 220) -> str:
    normalized = " | ".join(line.strip() for line in output.splitlines() if line.strip())
    if len(normalized) <= max_chars:
        return normalized
    if max_chars <= 3:
        return normalized[:max_chars]
    return normalized[: max_chars - 3] + "..."


def _build_process_error(prefix: str, *, command_name: str, process: subprocess.CompletedProcess[str]) -> str:
    parts: list[str] = [f"{prefix} ({command_name} rc={process.returncode}"]
    stderr = _compact_output_snippet(process.stderr)
    stdout = _compact_output_snippet(process.stdout)
    if stderr:
        parts.append(f"stderr={stderr}")
    if stdout:
        parts.append(f"stdout={stdout}")
    if not stderr and not stdout:
        parts.append("no output")
    return "; ".join(parts) + ")"


def _is_interrupt_return_code(return_code: int) -> bool:
    return return_code in (-2, 130)


def _log_meshcore_output(*, command_name: str, stream_name: str, output: str) -> None:
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        matched = _MESHCORE_LOG_LINE.match(line)
        if not matched:
            continue
        level_name, source, message = matched.groups()
        source = source.strip()
        message = message.strip()
        payload = f"{command_name} {stream_name} [{source}] {message}"
        if level_name in {"ERROR", "CRITICAL"}:
            LOGGER.error(payload)
        else:
            LOGGER.debug(payload)


def _log_meshcli_debug_trace(
    *,
    command_name: str,
    elapsed_seconds: float,
    return_code: int | None,
    stdout: str,
    stderr: str,
    timed_out: bool = False,
) -> None:
    if timed_out:
        LOGGER.info("meshcli timing %s: timeout after %.3fs", command_name, elapsed_seconds)
    else:
        LOGGER.info("meshcli timing %s: %.3fs rc=%s", command_name, elapsed_seconds, return_code)
    LOGGER.info("meshcli raw %s stdout:\n%s", command_name, stdout if stdout else "<empty>")
    LOGGER.info("meshcli raw %s stderr:\n%s", command_name, stderr if stderr else "<empty>")


def poll_once(config: PollConfig, store: TelemetryStore) -> PollResult:
    started_at = time.time()
    monotonic_start = time.monotonic()
    cache_key = (config.meshcli_bin, config.target)
    cached = _CONTACT_CACHE.get(cache_key)
    contact_name_index: dict[str, str] = {}
    contacts_total_value: float | None = None
    if cached is not None:
        _, cached_index, cached_total = cached
        contact_name_index = dict(cached_index)
        contacts_total_value = cached_total

    should_refresh_contacts = (
        cached is None or (started_at - cached[0]) >= max(1.0, config.contacts_refresh_seconds)
    )
    if should_refresh_contacts:
        contacts_started = time.monotonic()
        try:
            contacts_process = _run_meshcli(config.contacts_command(), config.contacts_timeout_seconds)
            contacts_elapsed = time.monotonic() - contacts_started
            if config.debug_meshcli:
                _log_meshcli_debug_trace(
                    command_name="contacts",
                    elapsed_seconds=contacts_elapsed,
                    return_code=contacts_process.returncode,
                    stdout=contacts_process.stdout,
                    stderr=contacts_process.stderr,
                )
        except subprocess.TimeoutExpired as error:
            contacts_process = None
            contacts_elapsed = time.monotonic() - contacts_started
            if config.debug_meshcli:
                _log_meshcli_debug_trace(
                    command_name="contacts",
                    elapsed_seconds=contacts_elapsed,
                    return_code=None,
                    stdout=(str(getattr(error, "output", "") or "")),
                    stderr=(str(getattr(error, "stderr", "") or "")),
                    timed_out=True,
                )
            LOGGER.warning("contacts refresh timed out; keeping previous contact name cache")
            _CONTACT_CACHE[cache_key] = (started_at, dict(contact_name_index), contacts_total_value)
        except OSError as error:
            contacts_process = None
            LOGGER.warning("contacts refresh failed: %s", str(error))
            _CONTACT_CACHE[cache_key] = (started_at, dict(contact_name_index), contacts_total_value)

        if contacts_process is not None:
            _log_meshcore_output(
                command_name="contacts",
                stream_name="stdout",
                output=contacts_process.stdout,
            )
            _log_meshcore_output(
                command_name="contacts",
                stream_name="stderr",
                output=contacts_process.stderr,
            )
            if contacts_process.returncode != 0:
                if _is_interrupt_return_code(contacts_process.returncode):
                    raise KeyboardInterrupt
                LOGGER.warning(
                    _build_process_error(
                        "meshcli contacts command failed (non-fatal)",
                        command_name="contacts",
                        process=contacts_process,
                    )
                )
            else:
                contacts_objects = parse_cli_json_objects(contacts_process.stdout)
                fresh_total, contacts_found = _extract_contacts_total(contacts_objects)
                fresh_index, _ = _extract_contact_name_index(contacts_objects)
                if contacts_found:
                    contacts_total_value = fresh_total
                    if fresh_index:
                        contact_name_index = fresh_index
                    _CONTACT_CACHE[cache_key] = (started_at, dict(contact_name_index), contacts_total_value)
                else:
                    LOGGER.warning(
                        _build_process_error(
                            "meshcli contacts payload was not parseable (non-fatal)",
                            command_name="contacts",
                            process=contacts_process,
                        )
                    )
                    _CONTACT_CACHE[cache_key] = (started_at, dict(contact_name_index), contacts_total_value)

    stagger_seconds = max(0.0, config.request_stagger_seconds)
    if should_refresh_contacts and stagger_seconds > 0.0:
        time.sleep(stagger_seconds)

    def _run_status_request() -> subprocess.CompletedProcess[str] | PollResult:
        status_started = time.monotonic()
        try:
            status_process = _run_meshcli(config.status_command(), config.timeout_seconds)
            status_elapsed = time.monotonic() - status_started
            if config.debug_meshcli:
                _log_meshcli_debug_trace(
                    command_name="req_status",
                    elapsed_seconds=status_elapsed,
                    return_code=status_process.returncode,
                    stdout=status_process.stdout,
                    stderr=status_process.stderr,
                )
        except subprocess.TimeoutExpired as error:
            status_elapsed = time.monotonic() - status_started
            if config.debug_meshcli:
                _log_meshcli_debug_trace(
                    command_name="req_status",
                    elapsed_seconds=status_elapsed,
                    return_code=None,
                    stdout=(str(getattr(error, "output", "") or "")),
                    stderr=(str(getattr(error, "stderr", "") or "")),
                    timed_out=True,
                )
            duration = time.monotonic() - monotonic_start
            return PollResult(success=False, poll_duration_seconds=duration, error="meshcli timeout")
        except OSError as error:
            duration = time.monotonic() - monotonic_start
            return PollResult(success=False, poll_duration_seconds=duration, error=str(error))

        _log_meshcore_output(
            command_name="req_status",
            stream_name="stdout",
            output=status_process.stdout,
        )
        _log_meshcore_output(
            command_name="req_status",
            stream_name="stderr",
            output=status_process.stderr,
        )

        duration = time.monotonic() - monotonic_start
        if _is_interrupt_return_code(status_process.returncode):
            raise KeyboardInterrupt
        if status_process.returncode != 0:
            message = _build_process_error(
                "meshcli command failed",
                command_name="req_status",
                process=status_process,
            )
            return PollResult(success=False, poll_duration_seconds=duration, error=message)
        return status_process

    status_result = _run_status_request()
    if isinstance(status_result, PollResult):
        return status_result
    status_process = status_result
    status_objects = parse_cli_json_objects(status_process.stdout)
    status_payload = _select_latest_status_payload(status_objects)
    status_error_message = _select_latest_error_message(status_objects)
    if status_payload is None and status_error_message is not None:
        retry_delay = max(0.0, config.status_error_retry_seconds)
        LOGGER.warning(
            "req_status returned node error; retrying once in %.3fs: %s",
            retry_delay,
            status_error_message,
        )
        if retry_delay > 0.0:
            time.sleep(retry_delay)
        status_result = _run_status_request()
        if isinstance(status_result, PollResult):
            return status_result
        status_process = status_result
        status_objects = parse_cli_json_objects(status_process.stdout)
        status_payload = _select_latest_status_payload(status_objects)
        status_error_message = _select_latest_error_message(status_objects)

    if status_payload is None:
        duration = time.monotonic() - monotonic_start
        if status_error_message:
            return PollResult(
                success=False,
                poll_duration_seconds=duration,
                error=_build_process_error(
                    f"req_status returned node error after retry: {status_error_message}",
                    command_name="req_status",
                    process=status_process,
                ),
            )
        return PollResult(
            success=False,
            poll_duration_seconds=duration,
            error=_build_process_error(
                "meshcli produced no status JSON payload",
                command_name="req_status",
                process=status_process,
            ),
        )

    status_values = _extract_status_values(status_payload)
    if not status_values:
        return PollResult(
            success=False,
            poll_duration_seconds=duration,
            error=_build_process_error(
                "meshcli status payload had no numeric values",
                command_name="req_status",
                process=status_process,
            ),
        )
    values = dict(status_values)
    if "status_bat_mv" in status_values:
        values["battery_voltage_volts"] = round(status_values["status_bat_mv"] / 1000.0, 6)

    if stagger_seconds > 0.0:
        time.sleep(stagger_seconds)

    neighbours_started = time.monotonic()
    try:
        neighbours_process = _run_meshcli(config.neighbours_command(), config.timeout_seconds)
        neighbours_elapsed = time.monotonic() - neighbours_started
        if config.debug_meshcli:
            _log_meshcli_debug_trace(
                command_name="req_neighbours",
                elapsed_seconds=neighbours_elapsed,
                return_code=neighbours_process.returncode,
                stdout=neighbours_process.stdout,
                stderr=neighbours_process.stderr,
            )
    except subprocess.TimeoutExpired as error:
        neighbours_elapsed = time.monotonic() - neighbours_started
        if config.debug_meshcli:
            _log_meshcli_debug_trace(
                command_name="req_neighbours",
                elapsed_seconds=neighbours_elapsed,
                return_code=None,
                stdout=(str(getattr(error, "output", "") or "")),
                stderr=(str(getattr(error, "stderr", "") or "")),
                timed_out=True,
            )
        duration = time.monotonic() - monotonic_start
        return PollResult(success=False, poll_duration_seconds=duration, error="meshcli timeout")
    except OSError as error:
        duration = time.monotonic() - monotonic_start
        return PollResult(success=False, poll_duration_seconds=duration, error=str(error))

    _log_meshcore_output(
        command_name="req_neighbours",
        stream_name="stdout",
        output=neighbours_process.stdout,
    )
    _log_meshcore_output(
        command_name="req_neighbours",
        stream_name="stderr",
        output=neighbours_process.stderr,
    )

    duration = time.monotonic() - monotonic_start
    if _is_interrupt_return_code(neighbours_process.returncode):
        raise KeyboardInterrupt
    if neighbours_process.returncode != 0:
        message = _build_process_error(
            "meshcli command failed",
            command_name="req_neighbours",
            process=neighbours_process,
        )
        return PollResult(success=False, poll_duration_seconds=duration, error=message)

    neighbours_objects = parse_cli_json_objects(neighbours_process.stdout)
    zero_hop_total, neighbours_found = _extract_neighbours_zero_hop_total(neighbours_objects)
    neighbors, neighbors_entries_found = _extract_neighbour_entries(
        neighbours_objects,
        contact_name_index=contact_name_index,
    )
    if not neighbours_found:
        return PollResult(
            success=False,
            poll_duration_seconds=duration,
            error=_build_process_error(
                "meshcli req_neighbours payload was not parseable",
                command_name="req_neighbours",
                process=neighbours_process,
            ),
        )
    if not neighbors_entries_found:
        return PollResult(
            success=False,
            poll_duration_seconds=duration,
            error=_build_process_error(
                "meshcli req_neighbours entries were not parseable",
                command_name="req_neighbours",
                process=neighbours_process,
            ),
        )

    if neighbors:
        hops_values = [entry.get("hops") for entry in neighbors]
        if any(hops is not None for hops in hops_values):
            zero_hop_total = float(sum(1 for hops in hops_values if hops == 0))
        else:
            zero_hop_total = float(len(neighbors))

    if contacts_total_value is not None:
        values["contacts_total"] = contacts_total_value
    values["neighbors_zero_hop_total"] = zero_hop_total

    _ensure_estimated_battery_percent(values)

    store.record_snapshot(
        target=config.target,
        observed_at=started_at,
        poll_duration_seconds=duration,
        raw_payload=status_payload,
        values=values,
    )
    return PollResult(
        success=True,
        observed_at=started_at,
        poll_duration_seconds=duration,
        values=values,
        neighbors=[{k: v for k, v in neighbor.items() if k != "hops"} for neighbor in neighbors],
    )
