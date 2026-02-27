from __future__ import annotations

from collections import defaultdict

from prometheus_client import CollectorRegistry, Gauge

from meshcore_prom_exporter.service import PollResult


class MeshcoreMetricsPublisher:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        if registry is None:
            registry = CollectorRegistry()
        self.registry = registry
        self._known_neighbors: dict[str, set[tuple[str, str]]] = defaultdict(set)

        self.poll_success = Gauge(
            "meshcore_poll_success",
            "Latest poll status (1=success, 0=failure)",
            ["target"],
            registry=self.registry,
        )
        self.poll_duration_seconds = Gauge(
            "meshcore_poll_duration_seconds",
            "Duration of the last meshcore telemetry poll in seconds",
            ["target"],
            registry=self.registry,
        )
        self.poll_timestamp_seconds = Gauge(
            "meshcore_poll_timestamp_seconds",
            "Unix timestamp of the last successful telemetry poll",
            ["target"],
            registry=self.registry,
        )
        self.snapshots_total = Gauge(
            "meshcore_telemetry_snapshots_total",
            "Total telemetry snapshots stored in sqlite for target",
            ["target"],
            registry=self.registry,
        )
        self.contacts_total = Gauge(
            "meshcore_contacts_total",
            "Total contacts reported by meshcore contacts command",
            ["target"],
            registry=self.registry,
        )
        self.neighbors_zero_hop_total = Gauge(
            "meshcore_neighbors_zero_hop_total",
            "Total zero-hop neighbors based on contacts hop count",
            ["target"],
            registry=self.registry,
        )
        self.battery_voltage_volts = Gauge(
            "meshcore_battery_voltage_volts",
            "Latest battery voltage derived from req_status payload",
            ["target"],
            registry=self.registry,
        )
        self.battery_percent = Gauge(
            "meshcore_battery_percent",
            "Latest battery percentage derived from req_status voltage",
            ["target"],
            registry=self.registry,
        )
        self.status_value = Gauge(
            "meshcore_status_value",
            "Latest numeric req_status field value from meshcore",
            ["target", "field"],
            registry=self.registry,
        )
        self.neighbor_snr_db = Gauge(
            "meshcore_neighbor_snr_db",
            "Neighbor SNR in dB from req_neighbours",
            ["target", "neighbor_pubkey", "neighbor_name"],
            registry=self.registry,
        )
        self.neighbor_last_seen_seconds = Gauge(
            "meshcore_neighbor_last_seen_seconds",
            "Seconds since this neighbor was observed",
            ["target", "neighbor_pubkey", "neighbor_name"],
            registry=self.registry,
        )

    def apply_poll_result(self, *, target: str, result: PollResult, snapshots_total: int) -> None:
        self.poll_success.labels(target=target).set(1.0 if result.success else 0.0)
        self.snapshots_total.labels(target=target).set(float(snapshots_total))
        if result.poll_duration_seconds is not None:
            self.poll_duration_seconds.labels(target=target).set(result.poll_duration_seconds)
        if result.success and result.observed_at is not None:
            self.poll_timestamp_seconds.labels(target=target).set(result.observed_at)
        if result.success:
            if "contacts_total" in result.values:
                self.contacts_total.labels(target=target).set(result.values["contacts_total"])
            if "neighbors_zero_hop_total" in result.values:
                self.neighbors_zero_hop_total.labels(target=target).set(result.values["neighbors_zero_hop_total"])

            battery_voltage = result.values.get("battery_voltage_volts", result.values.get("battery_voltage"))
            if battery_voltage is not None:
                self.battery_voltage_volts.labels(target=target).set(battery_voltage)

            if "battery_percent" in result.values:
                self.battery_percent.labels(target=target).set(result.values["battery_percent"])

            for metric_key, metric_value in result.values.items():
                if metric_key.startswith("status_"):
                    self.status_value.labels(
                        target=target,
                        field=metric_key[len("status_") :],
                    ).set(metric_value)

            if result.neighbors is not None:
                current_neighbors: set[tuple[str, str]] = set()
                for neighbor in result.neighbors:
                    pubkey = str(neighbor.get("pubkey", "")).strip()
                    name = str(neighbor.get("name", "")).strip() or pubkey
                    if not pubkey:
                        continue
                    snr = float(neighbor.get("snr", 0.0))
                    secs_ago = float(neighbor.get("secs_ago", 0.0))
                    self.neighbor_snr_db.labels(
                        target=target,
                        neighbor_pubkey=pubkey,
                        neighbor_name=name,
                    ).set(snr)
                    self.neighbor_last_seen_seconds.labels(
                        target=target,
                        neighbor_pubkey=pubkey,
                        neighbor_name=name,
                    ).set(secs_ago)
                    current_neighbors.add((pubkey, name))

                stale_neighbors = self._known_neighbors[target] - current_neighbors
                for stale_pubkey, stale_name in stale_neighbors:
                    self.neighbor_snr_db.remove(target, stale_pubkey, stale_name)
                    self.neighbor_last_seen_seconds.remove(target, stale_pubkey, stale_name)
                self._known_neighbors[target] = current_neighbors

