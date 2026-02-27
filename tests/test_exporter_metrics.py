from prometheus_client import CollectorRegistry, generate_latest

from meshcore_prom_exporter.exporter import MeshcoreMetricsPublisher
from meshcore_prom_exporter.service import PollResult


def test_metrics_publisher_updates_and_removes_stale_keys() -> None:
    registry = CollectorRegistry()
    publisher = MeshcoreMetricsPublisher(registry=registry)

    publisher.apply_poll_result(
        target="rpt01",
        result=PollResult(
            success=True,
            observed_at=1700000000.0,
            poll_duration_seconds=0.7,
            values={
                    "battery_voltage_volts": 4.2,
                "contacts_total": 3.0,
                "neighbors_zero_hop_total": 1.0,
                "status_bat_mv": 4200.0,
                "status_last_snr": 8.0,
            },
            neighbors=[
                {"pubkey": "028f91d9", "name": "PineRelay", "snr": -0.75, "secs_ago": 799.0},
                {"pubkey": "eafe035a", "name": "OakNode", "snr": -2.0, "secs_ago": 4253.0},
            ],
        ),
        snapshots_total=1,
    )
    publisher.apply_poll_result(
        target="rpt01",
        result=PollResult(
            success=True,
            observed_at=1700000030.0,
            poll_duration_seconds=0.6,
                values={"battery_voltage_volts": 4.1},
        ),
        snapshots_total=2,
    )

    rendered = generate_latest(registry).decode("utf-8")
    assert 'meshcore_poll_success{target="rpt01"} 1.0' in rendered
    assert 'meshcore_telemetry_value' not in rendered
    assert 'meshcore_contacts_total{target="rpt01"} 3.0' in rendered
    assert 'meshcore_neighbors_zero_hop_total{target="rpt01"} 1.0' in rendered
    assert 'meshcore_battery_voltage_volts{target="rpt01"} 4.1' in rendered
    assert 'meshcore_status_value{field="bat_mv",target="rpt01"} 4200.0' in rendered
    assert 'meshcore_status_value{field="last_snr",target="rpt01"} 8.0' in rendered
    assert 'meshcore_neighbor_snr_db{neighbor_name="PineRelay",neighbor_pubkey="028f91d9",target="rpt01"} -0.75' in rendered
    assert 'meshcore_neighbor_last_seen_seconds{neighbor_name="OakNode",neighbor_pubkey="eafe035a",target="rpt01"} 4253.0' in rendered


def test_metrics_publisher_keeps_last_values_on_failed_poll() -> None:
    registry = CollectorRegistry()
    publisher = MeshcoreMetricsPublisher(registry=registry)

    publisher.apply_poll_result(
        target="rpt01",
        result=PollResult(
            success=True,
            observed_at=1700000000.0,
            poll_duration_seconds=0.7,
            values={
                "battery_voltage_volts": 4.2,
                "battery_percent": 61.0,
                "contacts_total": 3.0,
                "neighbors_zero_hop_total": 2.0,
            },
            neighbors=[
                {"pubkey": "028f91d9", "name": "PineRelay", "snr": -0.75, "secs_ago": 799.0},
            ],
        ),
        snapshots_total=1,
    )
    publisher.apply_poll_result(
        target="rpt01",
        result=PollResult(
            success=False,
            poll_duration_seconds=0.9,
            error="meshcli produced no telemetry JSON payload",
        ),
        snapshots_total=1,
    )

    rendered = generate_latest(registry).decode("utf-8")
    assert 'meshcore_poll_success{target="rpt01"} 0.0' in rendered
    assert 'meshcore_battery_voltage_volts{target="rpt01"} 4.2' in rendered
    assert 'meshcore_battery_percent{target="rpt01"} 61.0' in rendered
    assert 'meshcore_contacts_total{target="rpt01"} 3.0' in rendered
    assert 'meshcore_neighbors_zero_hop_total{target="rpt01"} 2.0' in rendered
    assert 'meshcore_neighbor_snr_db{neighbor_name="PineRelay",neighbor_pubkey="028f91d9",target="rpt01"} -0.75' in rendered

