from datetime import datetime, timedelta
from typing import Optional
from alerting.models import Alert
from alerting.registry import TCP_RULES
from ingestion.parser import ParsedPacket


class PortScanDetector:

    def __init__(self, threshold: int = 15, window_seconds: float = 5.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.history: dict[str, list[tuple[datetime, int, ParsedPacket]]] = {}

    def process_packet(self, packet: ParsedPacket) -> Optional[Alert]:
        if packet.protocol == "TCP":
            is_syn_initiation = (
                    packet.flags is not None
                    and "S" in packet.flags
                    and "A" not in packet.flags
            )
            if is_syn_initiation:
                if packet.timestamp is not None and isinstance(packet.dst_port, int):
                    self.history.setdefault(packet.src_ip, []).append(
                        (packet.timestamp, packet.dst_port, packet)
                    )

                    cutoff_time = packet.timestamp - timedelta(seconds=self.window_seconds)
                    self.history[packet.src_ip] = [
                        item for item in self.history[packet.src_ip] if item[0] >= cutoff_time
                    ]

                    unique_ports = {port for _, port, _ in self.history[packet.src_ip]}
                    if len(unique_ports) >= self.threshold:
                        probed = sorted(unique_ports)
                        trigger_packets = [pkt for _, _, pkt in self.history[packet.src_ip]]
                        self.history[packet.src_ip] = []

                        return Alert(
                            rule=TCP_RULES["PORT_SCAN"],
                            packets=trigger_packets,
                            scanned_ports=probed
                        )

        return None
