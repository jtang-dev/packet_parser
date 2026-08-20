from collections import deque
from datetime import datetime, timedelta, timezone

from ingestion.parser import ParsedPacket


class NetworkStats:

    def __init__(self, max_display_packets: int=20, max_display_alerts: int=10, window_minutes: int = 5):
        self.recent_packets = deque(maxlen=max_display_packets)
        self.recent_alerts = deque(maxlen=max_display_alerts)
        self.ip_history: dict[str, list[datetime]] = {}
        self.window_duration = timedelta(minutes=window_minutes)
        self.top_ips: list[tuple[str, int]] = []

    def record_packet(self, packet: ParsedPacket):
        ip_address = packet.src_ip if packet.src_ip != "192.168.86.60" else packet.dst_ip
        self.ip_history.setdefault(ip_address, []).append(packet.timestamp)
        self.recent_packets.append(packet)


    def prune_and_rank(self, limit: int = 5):
        cutoff = datetime.now(timezone.utc) - self.window_duration

        for ip, timestamps in list(self.ip_history.items()):
            idx = 0
            while idx < len(timestamps) and timestamps[idx] < cutoff:
                idx += 1

            if idx > 0:
                self.ip_history[ip] = timestamps[idx:]

            if not self.ip_history[ip]:
                del self.ip_history[ip]

        sorted_ips = sorted(
            self.ip_history.items(),
            key=lambda item: len(item[1]),
            reverse=True
        )

        self.top_ips = [(ip, len(timestamps)) for ip, timestamps in sorted_ips[:limit]]