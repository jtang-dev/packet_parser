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

def packet_parser(packet):
    src_ip, dst_ip = "N/A", "N/A"
    src_port, dst_port = "N/A", "N/A"
    protocol = "OTHER"
    flags = None

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

    return ParsedPacket(src_ip, dst_ip, src_port, dst_port, protocol, flags)

if __name__ == "__main__":
    packets = scapy.sniff(count=100)
    for packet in packets:
        parsed = packet_parser(packet)
        print(parsed)

