from collections import deque
from datetime import datetime, timedelta, timezone
import socket
from typing import Any

from ingestion.parser import ParsedPacket


class NetworkStats:

    def __init__(self, max_display_packets: int=35, max_display_alerts: int=10,max_display_ports: int=10,
                 window_minutes: int = 5):
        self.recent_packets = deque(maxlen=max_display_packets)
        self.recent_alerts = deque(maxlen=max_display_alerts)
        self.recent_ports = deque(maxlen=max_display_ports)

        self.ip_history: dict[str, list[datetime]] = {}
        self.port_history: dict[int, list[datetime]] = {}
        self.ip_to_port: dict[str, dict[int, list[datetime]]] = {}

        self.window_duration = timedelta(minutes=window_minutes)
        self.top_ips: list[tuple[str, int]] = []
        self.top_ports: list[tuple[int, int]] = []
        self.top_ip_to_ports: dict[str, list[tuple[int, int]]] = {}

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.host_address =  str(s.getsockname()[0])
        s.close()

    def get_ports_for_ip(self, ip: str) -> list[tuple[int, int]]:
        return self.top_ip_to_ports.get(ip, [])

    def record_packet(self, packet: ParsedPacket):
        pkt_time = packet.timestamp if packet.timestamp is not None else datetime.now(timezone.utc)

        ip_address = packet.src_ip if packet.src_ip != self.host_address else packet.dst_ip
        if ip_address and ip_address != "N/A":
            self.ip_history.setdefault(ip_address, []).append(pkt_time)

            if isinstance(packet.dst_port, int):
                self.ip_to_port.setdefault(ip_address, {}).setdefault(packet.dst_port, []).append(pkt_time)

        self.recent_packets.append(packet)

    def record_port(self, packet: ParsedPacket):
        if isinstance(packet.dst_port, int):
            pkt_time = packet.timestamp if packet.timestamp is not None else datetime.now(timezone.utc)
            self.port_history.setdefault(packet.dst_port, []).append(pkt_time)
            self.recent_ports.append(packet.dst_port)

    def record_alert(self, alert):
        self.recent_alerts.append(alert)

    @staticmethod
    def _prune_and_rank_dict(history: dict, cutoff: datetime, limit: int) -> list[tuple[Any, int]]:
        for key, timestamps in list(history.items()):
            idx = 0
            while idx < len(timestamps) and timestamps[idx] < cutoff:
                idx += 1

            if idx > 0:
                history[key] = timestamps[idx:]

            if not history[key]:
                del history[key]

        sorted_items = sorted(
            history.items(),
            key=lambda item: len(item[1]),
            reverse=True
        )
        return [(k, len(ts)) for k, ts in sorted_items[:limit]]

    def _prune_nested_dict(self, history: dict, cutoff: datetime, limit: int) -> dict[str, list[tuple[int, int]]]:
        top_ip_ports: dict[str, list[tuple[int, int]]] = {}

        for ip, ports in list(history.items()):
            ranked_ports = self._prune_and_rank_dict(ports, cutoff, limit)
            if ranked_ports:
                top_ip_ports[ip] = ranked_ports
            else:
                del history[ip]

        return top_ip_ports

    def prune_and_rank(self, limit: int = 5):
        cutoff = datetime.now(timezone.utc) - self.window_duration
        self.top_ips = self._prune_and_rank_dict(self.ip_history, cutoff, limit)
        self.top_ports = self._prune_and_rank_dict(self.port_history, cutoff, limit)
        self.top_ip_to_ports = self._prune_nested_dict(self.ip_to_port, cutoff, limit)