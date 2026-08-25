import os
import queue
import time
from typing import Optional

from alerting.suppression import AlertDeduplicator
from detection.engine import DetectionEngine
from output.logger import DATA_DIR, log_alert
from output.stats import NetworkStats


def process_packet_worker(
    packet_queue: queue.Queue,
    alert_queue: queue.Queue,
    stats: NetworkStats,
    engine: DetectionEngine,
    deduplicator: AlertDeduplicator,
) -> None:
    while True:
        try:
            packet = packet_queue.get(block=True, timeout=0.1)

            stats.record_packet(packet)
            stats.record_port(packet)

            alerts = engine.evaluate(packet)
            for alert in alerts:
                if deduplicator.check_alert(alert):
                    stats.record_alert(alert)
                    try:
                        alert_queue.put_nowait(alert)
                    except queue.Full:
                        pass

            packet_queue.task_done()

        except queue.Empty:
            pass


def process_logging_worker(
    alert_queue: queue.Queue,
    filepath: Optional[str] = None,
) -> None:
    target_path = filepath if filepath is not None else os.path.join(DATA_DIR, "alerts.jsonl")
    with open(target_path, "a", encoding="utf-8") as f:
        while True:
            try:
                alert = alert_queue.get(block=True, timeout=0.1)
                log_alert(alert, f)
                alert_queue.task_done()
            except queue.Empty:
                pass


def process_deduplication_cleanup_worker(
    deduplicator: AlertDeduplicator,
    interval_seconds: int = 600,
) -> None:
    while True:
        time.sleep(interval_seconds)
        deduplicator.prune_stale_states()