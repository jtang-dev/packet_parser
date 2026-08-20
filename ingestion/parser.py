from datetime import datetime, timezone
from typing import Optional
import scapy.all as scapy
from dataclasses import dataclass

@dataclass
class ParsedPacket:
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


def packet_parser(packet: scapy.Packet) -> ParsedPacket:
    src_ip, dst_ip = "N/A", "N/A"
    src_port, dst_port = "N/A", "N/A"
    protocol = "OTHER"
    flags = None
    pkt_time = datetime.fromtimestamp(float(packet.time), tz=timezone.utc) if hasattr(packet, "time") else None

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

    if packet.haslayer("TCP"):
        protocol = "TCP"
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport
        flags = list(str(packet["TCP"].flags))
    elif packet.haslayer("UDP"):
        protocol = "UDP"
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport

    return ParsedPacket(src_ip, dst_ip, src_port, dst_port, protocol, flags, pkt_time)