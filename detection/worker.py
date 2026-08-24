import queue
from detection.engine import DetectionEngine
from output.logger import log_alert
from output.stats import NetworkStats

def process_packet_worker(packet_queue: queue.Queue, stats: NetworkStats, engine: DetectionEngine):
    while True:
        try:
            packet = packet_queue.get(block=True, timeout=0.1)

            stats.record_packet(packet)
            stats.record_port(packet)

            alerts = engine.evaluate(packet)
            for alert in alerts:
                stats.record_alert(alert)
                log_alert(alert)

            packet_queue.task_done()

        except queue.Empty as e:
            pass
