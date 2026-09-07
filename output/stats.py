import threading
from collections import deque
from datetime import datetime, timedelta, timezone
import socket
from typing import Any

from alerting.models import Alert
from ingestion.parser import ParsedPacket


class NetworkStats:
    """
    A data analysis class that gathers the top IPs, top ports, and top ports for each IP for analysis and triage.

    :arg max_display_packets: The number of packets to display at once.
    :arg max_display_alerts: The number of alerts to display at once.
    :arg max_display_ports: The number of top ports to display at once
    :arg window_minutes: The time frame over which top ports and ips are tracked for.
    """

    def __init__(self, max_display_packets: int=45, max_display_alerts: int=10,max_display_ports: int=10,
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

        self._lock = threading.Lock()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.host_address =  str(s.getsockname()[0])
        s.close()

    def get_ports_for_ip(self, ip: str) -> list[tuple[int, int]]:
        """
        Looks up the top ports for a specific IP address.

        :param ip: The IP to look up
        :return: A list of tuples, mapping a port number, to the number of occurrences.
        """
        return self.top_ip_to_ports.get(ip, [])

    def record_packet(self, packet: ParsedPacket) -> None:
        """
        Ingests a packet and updates temporal tracking for IP addresses, destination ports,
        and associated endpoint mappings under a single lock acquisition.

        :param packet: The parsed packet to be ingested.
        """
        with self._lock:
            pkt_time = packet.timestamp if packet.timestamp is not None else datetime.now(timezone.utc)

            # Track IP communications
            ip_address = packet.src_ip if packet.src_ip != self.host_address else packet.dst_ip
            if ip_address and ip_address != "N/A":
                self.ip_history.setdefault(ip_address, []).append(pkt_time)

                if isinstance(packet.dst_port, int):
                    self.ip_to_port.setdefault(ip_address, {}).setdefault(packet.dst_port, []).append(pkt_time)

            # Track global destination port metrics
            if isinstance(packet.dst_port, int):
                self.port_history.setdefault(packet.dst_port, []).append(pkt_time)
                self.recent_ports.append(packet.dst_port)

            self.recent_packets.append(packet)

    def record_alert(self, alert):
        """
        Record incoming alerts for data analysis.

        :param alert: The alert to be recorded
        """
        self.recent_alerts.append(alert)

    @staticmethod
    def _prune_and_rank_dict(history: dict, cutoff: datetime, limit: int) -> list[tuple[Any, int]]:
        """
        An internal function used to prune old values from history and return the most common occurrences.

        :param history: The history to be pruned and ranked.
        :param cutoff: The time at which a packet should be pruned after.
        :param limit: The number of topmost values to acquire.
        :return: A list of tuples mapping a value (IP, port number) to number of occurrences.
        """
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
        """
        An internal function used to prune and rank the top ports for each IP address, necessary due to the nested nature
        of this dictionary used.

        :param history: The history to be pruned and ranked.
        :param cutoff: The time at which a packet should be pruned after.
        :param limit: The number of topmost values to acquire.
        :return: A dictionary of strings (IPs) mapped to a list of tuples mapping a value (IP, port number)
        to number of occurrences.
        """
        top_ip_ports: dict[str, list[tuple[int, int]]] = {}

        for ip, ports in list(history.items()):
            ranked_ports = self._prune_and_rank_dict(ports, cutoff, limit)
            if ranked_ports:
                top_ip_ports[ip] = ranked_ports
            else:
                del history[ip]

        return top_ip_ports

    def prune_and_rank(self, limit: int = 5):
        """
        Function used to run the helper functions to prune and rank the various data dictionaries used to store ports, ips,
        etc.

        :param limit: The number of topmost values to acquire.
        """
        with self._lock:
            cutoff = datetime.now(timezone.utc) - self.window_duration
            self.top_ips = self._prune_and_rank_dict(self.ip_history, cutoff, limit)
            self.top_ports = self._prune_and_rank_dict(self.port_history, cutoff, limit)
            self.top_ip_to_ports = self._prune_nested_dict(self.ip_to_port, cutoff, limit)

    def update_or_record_alert(self, alert: Alert) -> None:
        """
        Used to record a new alert, or record an additional occurrence of an existing alert.

        :param alert: The alert to be analysed.
        """
        with self._lock:
            for existing in self.recent_alerts:
                if existing.rule_name == alert.rule_name and existing.src_ip == alert.src_ip:
                    existing.occurrence_count = alert.occurrence_count
                    existing.timestamp = alert.timestamp
                    return

            self.recent_alerts.appendleft(alert)