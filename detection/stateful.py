from datetime import datetime, timedelta
from typing import Optional
from data.models import Alert, ParsedPacket
from alerting.registry import TCP_RULES


class PortScanDetector:
    """
    A class to evaluate a series of packets for port scans.

    :arg threshold: The number of packets that will trigger a port scan alert.
    :arg window_seconds: The time over which these packets must arrive within to be counted as part of an attack.
    """
    def __init__(self, threshold: int = 15, window_seconds: float = 5.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.history: dict[str, list[tuple[datetime, int, ParsedPacket]]] = {}

    def process_packet(self, packet: ParsedPacket) -> Optional[Alert]:
        """
        Examines the supplied packet, adding it to, and checking, the history of packets to determine if a port scan alert
        should be triggered. Also handles the removal of stale packets from history.

        :param packet: The packet to be added to history and examined for a port scan alert
        :return: An appropriate port scan alert
        """

        # Determine if packet is a valid part of a port scan attack
        if "TCP" in packet.protocols:
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

                    # Removing stale packets
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
