import scapy.all as scapy
import queue

from ingestion.parser import packet_parser

def _handle_packet(raw_pkt, packet_queue: queue.Queue):
    parsed = packet_parser(raw_pkt)
    if parsed is not None:
        try:
            packet_queue.put_nowait(parsed)
        except queue.Full:
            pass

def start_sniffing(interface: str = None, pcap_file: str = None, count: int = 0, packet_queue: queue.Queue = None):
    callback = lambda pkt: _handle_packet(pkt, packet_queue)

    if pcap_file:
        scapy.sniff(offline=pcap_file, prn=callback, store=False, count=count)
    else:
        scapy.sniff(iface=interface, prn=callback, store=False, count=count)