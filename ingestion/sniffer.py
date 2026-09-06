import itertools
import os
import queue
import scapy.all as scapy

from ingestion.parser import packet_parser

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

def _handle_packet(raw_pkt, packet_queue: queue.Queue, counter, writer=None):
    """
    Parses the incoming packet and adds it to the global packet queue to allow for data processing and triage.

    :param raw_pkt: The raw packet to be processed.
    :param packet_queue: The global packet queue.
    :param counter: Ticks up to allow for a unique identifier to be assigned to each packet.
    :param writer: Allows packets to be written to an external pcap file if live ingestion is selected.
    """
    frame_id = next(counter)

    if writer is not None:
        writer.write(raw_pkt)

    parsed = packet_parser(raw_pkt, frame_id)
    if parsed is not None:
        try:
            packet_queue.put_nowait(parsed)
        except queue.Full:
            pass

def start_sniffing(
    interface: str = None,
    pcap_file: str = None,
    count: int = 0,
    packet_queue: queue.Queue = None,
    output_pcap: str = os.path.join(DATA_DIR, "capture.pcap")
):
    """
    Begins the packet ingestion process or handles the processing of the pcap file if this method is chosen.

    :param interface: The network interface to be monitored.
    :param pcap_file: The pcap file to be ingested.
    :param count: The number of packets to be ingested (0=infinite).
    :param packet_queue: The global packet queue that various tools pull packets from.
    :param output_pcap: Path of the output pcap file if interface monitoring is selected.
    """
    counter = itertools.count(start=1)
    writer = scapy.PcapWriter(filename=output_pcap, append=True, sync=True) if not pcap_file else None

    callback = lambda pkt: _handle_packet(pkt, packet_queue, counter, writer)

    try:
        if pcap_file:
            scapy.sniff(offline=pcap_file, prn=callback, store=False, count=count)
        else:
            scapy.sniff(iface=interface, prn=callback, store=False, count=count)
    finally:
        if writer is not None:
            writer.close()