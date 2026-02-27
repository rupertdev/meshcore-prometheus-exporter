import stat
import textwrap
from pathlib import Path
import logging
import pytest

from meshcore_prom_exporter.service import (
    PollConfig,
    TelemetryStore,
    flatten_numeric_values,
    parse_cli_json_objects,
    poll_once,
)


def test_parse_cli_json_objects_ignores_log_lines() -> None:
    output = textwrap.dedent(
        """
        INFO:meshcore:BLE Connection started
        {"foo": 1}
        {"bar": 2}
        """
    ).strip()
    parsed = parse_cli_json_objects(output)
    assert parsed == [{"foo": 1}, {"bar": 2}]


def test_flatten_numeric_values_handles_nested_values() -> None:
    payload = {
        "battery": {"voltage": 4.18, "charging": True},
        "radio": {"snr": -7.5, "status": "ok"},
    }
    flattened = flatten_numeric_values(payload)
    assert flattened["battery_voltage"] == 4.18
    assert flattened["battery_charging"] == 1.0
    assert flattened["radio_snr"] == -7.5
    assert "radio_status" not in flattened


def test_contacts_command_has_no_target_argument() -> None:
    config = PollConfig(meshcli_bin="meshcli", target="repeater01")
    assert config.contacts_command() == ["meshcli", "-j", "contacts"]


def test_poll_once_executes_cli_and_persists_values(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            echo "INFO:meshcore:BLE Connection started"
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":4110,"last_snr":-3.25}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[{"name":"n1","hops":0},{"name":"n2","hops":2}]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '[{"name":"n1","hops":0},{"name":"n3","hops":0}]'
              exit 0
            fi
            echo '{"error":"unexpected command"}'
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True

    latest = store.read_latest_values(target="repeater01")
    assert latest["battery_voltage_volts"] == 4.11
    assert latest["contacts_total"] == 2.0
    assert latest["neighbors_zero_hop_total"] == 2.0
    assert len(result.neighbors) == 2
    assert result.neighbors[0]["pubkey"] == "n1"
    assert result.neighbors[0]["name"] == "n1"
    assert result.neighbors[0]["snr"] == 0.0
    assert result.neighbors[0]["secs_ago"] == 0.0


def test_poll_once_requires_status_payload_not_login_ack(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            echo '{"ok":"Login success"}'
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is False
    assert result.error is not None
    assert "status" in result.error
    assert "Login success" in result.error
    assert store.count_snapshots(target="repeater01") == 0


def test_poll_once_uses_password_and_collects_contacts_metrics(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if ! echo "$args" | /usr/bin/grep -q "login repeater01 s3cr3t"; then
              echo '{"error":"missing login"}'
              exit 2
            fi

            if echo "$args" | /usr/bin/grep -q "req_status repeater01"; then
              echo '{"bat":4050,"last_snr":-2.0}'
              exit 0
            fi

            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[{"name":"n1","hops":0},{"name":"n2","hops":2},{"name":"n3","hops":0}]'
              exit 0
            fi

            if echo "$args" | /usr/bin/grep -q "req_neighbours repeater01"; then
              echo '[{"name":"n1","hops":0},{"name":"n3","hops":0}]'
              exit 0
            fi

            echo '{"error":"unexpected command"}'
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(
        meshcli_bin=str(fake_cli),
        target="repeater01",
        device_password="s3cr3t",
    )

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["battery_voltage_volts"] == 4.05
    assert result.values["contacts_total"] == 3.0
    assert result.values["neighbors_zero_hop_total"] == 2.0
    assert len(result.neighbors) == 2
    assert result.neighbors[0]["pubkey"] == "n1"
    assert result.neighbors[0]["name"] == "n1"
    assert result.neighbors[0]["snr"] == 0.0


def test_poll_once_logs_meshcore_error_lines(tmp_path: Path, caplog) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            echo "ERROR:meshcore:auth failed for repeater01" 1>&2
            exit 2
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    with caplog.at_level(logging.ERROR):
        result = poll_once(config, store)

    assert result.success is False
    assert "auth failed for repeater01" in caplog.text


def test_poll_once_logs_raw_meshcli_output_and_timings_when_debug_enabled(tmp_path: Path, caplog) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[{"public_key":"028f91d9","name":"Oak","hops":0}]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":3742}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{"neighbours":[{"pubkey":"028f91d9","secs_ago":12,"snr":1.25}]}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(
        meshcli_bin=str(fake_cli),
        target="repeater01",
        debug_meshcli=True,
    )

    with caplog.at_level(logging.INFO, logger="meshcore_prom_exporter.meshcli"):
        result = poll_once(config, store)

    assert result.success is True
    assert "meshcli timing contacts:" in caplog.text
    assert "meshcli timing req_status:" in caplog.text
    assert "meshcli timing req_neighbours:" in caplog.text
    assert "meshcli raw contacts stdout:" in caplog.text
    assert "meshcli raw req_status stdout:" in caplog.text
    assert "meshcli raw req_neighbours stdout:" in caplog.text


def test_poll_once_retries_status_once_on_node_error_and_succeeds(tmp_path: Path) -> None:
    status_counter_file = tmp_path / "status_counter.txt"
    fake_cli = tmp_path / "fake-meshcli"
    script = textwrap.dedent(
        """
        #!/bin/sh
        args="$*"
        if echo "$args" | /usr/bin/grep -q "contacts"; then
          echo '[]'
          exit 0
        fi
        if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
          echo '[]'
          exit 0
        fi
        if echo "$args" | /usr/bin/grep -q "req_status"; then
          counter=$(cat "__COUNTER_FILE__" 2>/dev/null || echo "0")
          counter=$((counter + 1))
          echo "$counter" > "__COUNTER_FILE__"
          if [ "$counter" -eq 1 ]; then
            echo '{"login_success":true}'
            echo '{"error":"Getting data"}'
            exit 0
          fi
          echo '{"bat":3742}'
          exit 0
        fi
        exit 3
        """
    ).strip()
    fake_cli.write_text(
        script.replace("__COUNTER_FILE__", str(status_counter_file)),
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(
        meshcli_bin=str(fake_cli),
        target="repeater01",
        status_error_retry_seconds=0.0,
    )

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["battery_voltage_volts"] == 3.742
    assert status_counter_file.read_text(encoding="utf-8").strip() == "2"


def test_poll_once_returns_explicit_status_node_error_after_retry(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"login_success":true}'
              echo '{"error":"Getting data"}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(
        meshcli_bin=str(fake_cli),
        target="repeater01",
        status_error_retry_seconds=0.0,
    )

    result = poll_once(config, store)
    assert result.success is False
    assert result.error is not None
    assert "req_status returned node error" in result.error
    assert "Getting data" in result.error


def test_poll_once_fails_when_neighbours_payload_missing(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":4010}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{"ok":"none"}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is False
    assert result.error is not None
    assert "req_neighbours" in result.error


def test_poll_once_supports_status_voltage_payload(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"login_success":true}'
              echo '{"bat":3730}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '[]'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["battery_voltage_volts"] == 3.73
    assert result.values["battery_percent"] == 20.0


def test_poll_once_supports_contacts_keyed_map_payload(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":3990}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '{"login_success":true}'
              echo '{"pk1":{"public_key":"pk1","type":2,"hops":0},"pk2":{"public_key":"pk2","type":1,"hops":1}}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '[]'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["contacts_total"] == 2.0


def test_poll_once_estimates_battery_percent_from_status_bat_field(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":3950}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '[]'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["battery_percent"] == 70.0


def test_poll_once_extracts_all_numeric_req_status_fields(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{"neighbours":[{"pubkey":"028f91d9","secs_ago":799,"snr":-0.75}]}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"login_success":true}'
              echo '{"pubkey_pre":"915179be5a0e","bat":3742,"tx_queue_len":0,"noise_floor":-115,"last_rssi":-94,"nb_recv":3160,"nb_sent":1586,"airtime":400,"uptime":259345,"sent_flood":1411,"sent_direct":175,"recv_flood":2426,"recv_direct":732,"full_evts":0,"last_snr":13.0,"direct_dups":0,"flood_dups":1167,"rx_airtime":780}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["status_bat_mv"] == 3742.0
    assert result.values["status_tx_queue_len"] == 0.0
    assert result.values["status_last_snr"] == 13.0
    assert result.values["status_rx_airtime"] == 780.0
    assert result.values["battery_voltage_volts"] == 3.742


def test_poll_once_extracts_neighbor_snr_and_age_from_neighbours_payload(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":3950}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '[]'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{"neighbours":[{"pubkey":"028f91d9","secs_ago":799,"snr":-0.75},{"pubkey":"eafe035a","secs_ago":4253,"snr":-2.0}]}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.values["neighbors_zero_hop_total"] == 2.0
    assert result.neighbors == [
        {"pubkey": "028f91d9", "name": "028f91d9", "snr": -0.75, "secs_ago": 799.0},
        {"pubkey": "eafe035a", "name": "eafe035a", "snr": -2.0, "secs_ago": 4253.0},
    ]


def test_poll_once_resolves_neighbor_name_from_contacts(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":3950}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '{"4ed020a97eb2e96f5c0df08b8cae5cd6567f2cfd8a6d225ed1e5283abd7fd321":{"public_key":"4ed020a97eb2e96f5c0df08b8cae5cd6567f2cfd8a6d225ed1e5283abd7fd321","name":"PineRelay"}}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{"neighbours":[{"pubkey":"4ed020a9","secs_ago":10,"snr":2.5}]}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.neighbors == [
        {"pubkey": "4ed020a9", "name": "PineRelay", "snr": 2.5, "secs_ago": 10.0},
    ]


def test_poll_once_resolves_neighbor_adv_name_from_contacts(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{"bat":3950}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo '{"4ed020a97eb2e96f5c0df08b8cae5cd6567f2cfd8a6d225ed1e5283abd7fd321":{"public_key":"4ed020a97eb2e96f5c0df08b8cae5cd6567f2cfd8a6d225ed1e5283abd7fd321","adv_name":"Longleaf Remote","type":2}}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{"neighbours":[{"pubkey":"4ed020a9","secs_ago":42,"snr":1.0}]}'
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    result = poll_once(config, store)
    assert result.success is True
    assert result.neighbors == [
        {"pubkey": "4ed020a9", "name": "Longleaf Remote", "snr": 1.0, "secs_ago": 42.0},
    ]


def test_poll_once_raises_keyboard_interrupt_on_sigint_return_code(tmp_path: Path) -> None:
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            exit 130
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(meshcli_bin=str(fake_cli), target="repeater01")

    with pytest.raises(KeyboardInterrupt):
        poll_once(config, store)


def test_poll_once_backs_off_contacts_refresh_after_timeout(tmp_path: Path) -> None:
    counter_file = tmp_path / "contacts_counter.txt"
    fake_cli = tmp_path / "fake-meshcli"
    fake_cli.write_text(
        textwrap.dedent(
            f"""
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo '{{"neighbours":[{{"pubkey":"028f91d9","secs_ago":10,"snr":1.0}}]}}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo '{{"bat":3742}}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo "1" >> "{counter_file}"
              sleep 2
              exit 0
            fi
            exit 3
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(
        meshcli_bin=str(fake_cli),
        target="repeater01",
        timeout_seconds=0.5,
        contacts_timeout_seconds=0.5,
        contacts_refresh_seconds=60.0,
    )

    result_first = poll_once(config, store)
    result_second = poll_once(config, store)

    assert result_first.success is True
    assert result_second.success is True
    assert counter_file.exists() is True
    assert len(counter_file.read_text(encoding="utf-8").splitlines()) == 1


def test_poll_once_staggers_requests_and_runs_contacts_first(tmp_path: Path) -> None:
    order_file = tmp_path / "request_order.txt"
    fake_cli = tmp_path / "fake-meshcli"
    script = textwrap.dedent(
        """
            #!/bin/sh
            args="$*"
            if echo "$args" | /usr/bin/grep -q "contacts"; then
              echo "contacts" >> "__ORDER_FILE__"
              echo '{"028f91d9":{"public_key":"028f91d9","name":"Oak"}}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_status"; then
              echo "req_status" >> "__ORDER_FILE__"
              echo '{"bat":3742}'
              exit 0
            fi
            if echo "$args" | /usr/bin/grep -q "req_neighbours"; then
              echo "req_neighbours" >> "__ORDER_FILE__"
              echo '{"neighbours":[{"pubkey":"028f91d9","secs_ago":10,"snr":1.0}]}'
              exit 0
            fi
            exit 3
            """
    ).strip()
    fake_cli.write_text(
        script.replace("__ORDER_FILE__", str(order_file)),
        encoding="utf-8",
    )
    fake_cli.chmod(fake_cli.stat().st_mode | stat.S_IEXEC)

    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    config = PollConfig(
        meshcli_bin=str(fake_cli),
        target="repeater01",
        request_stagger_seconds=0.2,
    )

    result = poll_once(config, store)
    assert result.success is True
    assert result.poll_duration_seconds is not None
    assert result.poll_duration_seconds >= 0.35
    assert order_file.read_text(encoding="utf-8").splitlines() == [
        "contacts",
        "req_status",
        "req_neighbours",
    ]

