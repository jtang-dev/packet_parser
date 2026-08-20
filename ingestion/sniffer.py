import scapy.all as scapy

from detection.engine import DetectionEngine
from ingestion.parser import packet_parser
from output.logger import log_alert

engine = DetectionEngine()

def _handle_packet(raw_packet):
    parsed = packet_parser(raw_packet)
    alerts = engine.evaluate(parsed)
    for alert in alerts:
        log_alert(alert)
    print(parsed)

def start_sniffing(interface: str = None, pcap_file: str = None, count: int = 0):
    if pcap_file:
        scapy.sniff(offline=pcap_file, prn=_handle_packet, store=False, count=count)
    else:
        scapy.sniff(iface=interface, prn=_handle_packet, store=False, count=count)
