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
    """
    A worker method to allow concurrency in the processing of packets and alerts,
    preventing slowdown or dropped packets during high thoroughput.

    :param packet_queue: Queue of packets to be processed.
    :param alert_queue: Queue of alerts to be processed
    :param stats: The data processing module that allows the gleaming of insights from packet data.
    :param engine: The alert generation engine that checks for suspicious activity.
    :param deduplicator: The alert deduplicator that prevents a spam of identical alerts for attacks such as port scans.
    """
    while True:
        try:
            packet = packet_queue.get(block=True, timeout=0.1)

            stats.record_packet(packet)
            stats.record_port(packet)

            alerts = engine.evaluate(packet)
            for alert in alerts:
                should_log, count = deduplicator.check_alert(alert)

                stats.update_or_record_alert(alert)

                if should_log:
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
    """
    Worker method to allow the concurrent logging of alerts into an appropriate .json file.

    :param alert_queue: Queue of alerts to be processed.
    :param filepath: Points to the .json file.
    """
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
    """
    Prunes unnecessary entries for alert deduplication at a specified interval to prevent memory overload and cleanup unused
    resources.

    :param deduplicator: Alert deduplication engine.
    :param interval_seconds: The interval at which stale deduplication entries are pruned.
    :return:
    """
    while True:
        time.sleep(interval_seconds)
        deduplicator.prune_stale_states()