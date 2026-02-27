from __future__ import annotations

import argparse
import logging
import os
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from prometheus_client import start_http_server

from meshcore_prom_exporter.exporter import MeshcoreMetricsPublisher
from meshcore_prom_exporter.service import PollConfig, PollResult, TelemetryStore, poll_once


LOGGER = logging.getLogger("meshcore_prom_exporter")


@dataclass(frozen=True)
class AppConfig:
    poll: PollConfig
    db_path: Path
    poll_interval_seconds: float
    listen_address: str
    listen_port: int
    run_once: bool
    log_level: str


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    return float(value)


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prometheus exporter for meshcore telemetry")
    parser.add_argument(
        "--meshcli-bin",
        default=os.getenv("MESHCORE_CLI_BIN", "meshcli"),
        help="meshcore-cli binary path",
    )
    parser.add_argument(
        "--target",
        default=os.getenv("MESHCORE_TARGET"),
        required=os.getenv("MESHCORE_TARGET") is None,
        help="meshcore contact/repeater name to poll",
    )
    parser.add_argument(
        "--meshcore-args",
        default=os.getenv("MESHCORE_ARGS", ""),
        help='extra meshcore-cli args, for example: "-t 192.168.1.10 -p 5000"',
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=_float_env("MESHCORE_TIMEOUT_SECONDS", 20.0),
        help="timeout for each meshcore-cli invocation",
    )
    parser.add_argument(
        "--contacts-timeout-seconds",
        type=float,
        default=_float_env("MESHCORE_CONTACTS_TIMEOUT_SECONDS", 60.0),
        help="timeout for contacts refresh command",
    )
    parser.add_argument(
        "--device-password",
        default=os.getenv("MESHCORE_DEVICE_PASSWORD", os.getenv("MESHCORE_PASSWORD")),
        help="password used to login to repeater before telemetry query",
    )
    parser.add_argument(
        "--login-target",
        default=os.getenv("MESHCORE_LOGIN_TARGET"),
        help="optional repeater name for login command (defaults to --target)",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=_float_env("MESHCORE_POLL_INTERVAL_SECONDS", 30.0),
        help="interval between telemetry polls",
    )
    parser.add_argument(
        "--contacts-refresh-seconds",
        type=float,
        default=_float_env("MESHCORE_CONTACTS_REFRESH_SECONDS", 300.0),
        help="refresh interval for contacts lookup used for neighbour names",
    )
    parser.add_argument(
        "--request-stagger-seconds",
        type=float,
        default=_float_env("MESHCORE_REQUEST_STAGGER_SECONDS", 2.0),
        help="delay between meshcli commands in each poll cycle",
    )
    parser.add_argument(
        "--status-error-retry-seconds",
        type=float,
        default=_float_env("MESHCORE_STATUS_ERROR_RETRY_SECONDS", 1.0),
        help="delay before one retry when req_status returns a node error payload",
    )
    parser.add_argument(
        "--db-path",
        default=os.getenv("MESHCORE_DB_PATH", "./data/telemetry.db"),
        help="sqlite database path for telemetry history",
    )
    parser.add_argument(
        "--listen-address",
        default=os.getenv("MESHCORE_LISTEN_ADDRESS", "0.0.0.0"),
        help="http bind address for /metrics endpoint",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=_int_env("MESHCORE_LISTEN_PORT", 9108),
        help="http bind port for /metrics endpoint",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single poll and exit",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("MESHCORE_LOG_LEVEL", "INFO"),
        help="python logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    parser.add_argument(
        "--debug-meshcli",
        action=argparse.BooleanOptionalAction,
        default=_bool_env("MESHCORE_DEBUG_MESHCLI", False),
        help="log raw meshcli stdout/stderr and per-command timings",
    )
    return parser


def load_config() -> AppConfig:
    parser = build_arg_parser()
    args = parser.parse_args()
    poll_config = PollConfig(
        meshcli_bin=args.meshcli_bin,
        target=args.target,
        meshcore_args=shlex.split(args.meshcore_args),
        timeout_seconds=args.timeout_seconds,
        contacts_timeout_seconds=args.contacts_timeout_seconds,
        device_password=args.device_password,
        login_target=args.login_target,
        contacts_refresh_seconds=args.contacts_refresh_seconds,
        request_stagger_seconds=args.request_stagger_seconds,
        debug_meshcli=bool(args.debug_meshcli),
        status_error_retry_seconds=args.status_error_retry_seconds,
    )
    return AppConfig(
        poll=poll_config,
        db_path=Path(args.db_path),
        poll_interval_seconds=args.poll_interval_seconds,
        listen_address=args.listen_address,
        listen_port=args.listen_port,
        run_once=bool(args.once),
        log_level=args.log_level,
    )


def _run_poll_cycle(
    *,
    poll_config: PollConfig,
    store: TelemetryStore,
    metrics: MeshcoreMetricsPublisher,
) -> PollResult:
    result = poll_once(poll_config, store)
    snapshots_total = store.count_snapshots(target=poll_config.target)
    metrics.apply_poll_result(target=poll_config.target, result=result, snapshots_total=snapshots_total)
    if result.success:
        LOGGER.info("telemetry poll successful: %d values", len(result.values))
    else:
        LOGGER.warning("telemetry poll failed: %s", result.error)
    return result


def main() -> None:
    config = load_config()
    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    store = TelemetryStore(config.db_path)
    metrics = MeshcoreMetricsPublisher()
    start_http_server(
        port=config.listen_port,
        addr=config.listen_address,
        registry=metrics.registry,
    )
    LOGGER.info("metrics server listening on http://%s:%d/metrics", config.listen_address, config.listen_port)

    try:
        if config.run_once:
            _run_poll_cycle(poll_config=config.poll, store=store, metrics=metrics)
            return

        LOGGER.info("running initial poll on startup")
        _run_poll_cycle(poll_config=config.poll, store=store, metrics=metrics)
        next_poll_at = time.monotonic() + config.poll_interval_seconds

        while True:
            sleep_for = max(0.0, next_poll_at - time.monotonic())
            time.sleep(sleep_for)
            _run_poll_cycle(poll_config=config.poll, store=store, metrics=metrics)
            next_poll_at += config.poll_interval_seconds
    except KeyboardInterrupt:
        LOGGER.info("shutdown requested, exiting")


if __name__ == "__main__":
    main()

