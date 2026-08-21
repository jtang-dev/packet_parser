import scapy.all as scapy

from detection.engine import DetectionEngine
from ingestion.parser import packet_parser

engine = DetectionEngine()


def _handle_packet(raw_pkt, stats, engine):
    parsed = packet_parser(raw_pkt)
    stats.record_packet(parsed)
    stats.record_port(parsed)

    alerts = engine.evaluate(parsed)
    for alert in alerts:
        stats.record_alert(alert)


def start_sniffing(interface: str = None, pcap_file: str = None, count: int = 0, stats=None):
    callback = lambda pkt: _handle_packet(pkt, stats, engine)

    if pcap_file:
        scapy.sniff(offline=pcap_file, prn=callback, store=False, count=count)
    else:
        scapy.sniff(iface=interface, prn=callback, store=False, count=count)