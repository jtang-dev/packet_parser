from datetime import datetime, timezone
from typing import Optional
import scapy.all as scapy
from dataclasses import dataclass

@dataclass
class ParsedPacket:
    """
    A custom packet dataclass built off of scapy's internal 'packet' class that allows for easier data access and modification.

    :ivar frame_id: A unique identifier to differentiate between packets for triage purposes.
    :ivar src_ip: The source ip of the packet.
    :ivar dst_ip: The destination ip of the packet.
    :ivar src_port: The source port of the packet.
    :ivar dst_port: The destination port of the packet.
    :ivar protocol: The specific protocol used by the packet (e.g. TCP, UDP, etc.).
    :ivar flags: The TCP flags utilised by the packet.
    :ivar timestamp: The time at which the packet was ingested.

    """
    frame_id: int
    src_ip: str
    dst_ip: str
    src_port: Optional[int | str]
    dst_port: Optional[int | str]
    protocol: str
    flags: Optional[list[str]] = None
    timestamp: Optional[datetime] = None

    def __str__(self) -> str:
        formatted_time = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if self.timestamp else "N/A"
        return f"[{formatted_time}] {self.protocol} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"

def packet_parser(packet: scapy.Packet, frame_id: int) -> ParsedPacket:
    """
    Converts scapy's 'packet' class into a custom packet dataclass.

    :param packet: The packet to be converted.
    :param frame_id: The unique identifier for the packet.
    :return: The parsed packet.
    """
    src_ip, dst_ip = "N/A", "N/A"
    src_port, dst_port = "N/A", "N/A"
    protocol = "OTHER"
    flags = None
    pkt_time = datetime.fromtimestamp(float(packet.time), tz=timezone.utc) if hasattr(packet, "time") else None

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
    elif packet.haslayer("IPv6"):
        src_ip = packet["IPv6"].src
        dst_ip = packet["IPv6"].dst
    elif packet.haslayer("ARP"):
        src_ip = packet["ARP"].psrc
        dst_ip = packet["ARP"].pdst
        protocol = "ARP"

    if packet.haslayer("TCP"):
        protocol = "TCP"
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport
        flags = list(str(packet["TCP"].flags))
    elif packet.haslayer("UDP"):
        protocol = "UDP"
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport

    return ParsedPacket(frame_id, src_ip, dst_ip, src_port, dst_port, protocol, flags, pkt_time)