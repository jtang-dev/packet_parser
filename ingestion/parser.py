from datetime import datetime, timezone
import scapy.all as scapy

from data.models import ParsedPacket, DNSMetaData


def packet_parser(packet: scapy.Packet, frame_id: int) -> ParsedPacket:
    """
    Converts scapy's 'packet' class into a custom packet dataclass.

    :param packet: The packet to be converted.
    :param frame_id: The unique identifier for the packet.
    :return: The parsed packet.
    """
    src_ip, dst_ip = "N/A", "N/A"
    src_port, dst_port = "N/A", "N/A"
    protocols = []
    flags = None
    pkt_metadata = None
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
        protocols.append("ARP")

    if packet.haslayer("TCP"):
        protocols.append("TCP")
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport
        flags = list(str(packet["TCP"].flags))
    elif packet.haslayer("UDP"):
        protocols.append("UDP")
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport

    if packet.haslayer("DNS"):
        protocols.insert(0, "DNS")
        is_response = packet["DNS"].qr == 1
        rcode = packet["DNS"].rcode if is_response else None
        tx_id = packet["DNS"].id

        query = "N/A"
        qtype = "UNKNOWN"

        if packet.haslayer("DNSQR"):
            dns_qr = packet["DNSQR"]
            raw_qname = dns_qr.qname
            raw_qtype = dns_qr.qtype

            if isinstance(raw_qname, bytes):
                query = raw_qname.decode("utf-8", errors="replace").rstrip(".")
            else:
                query = str(raw_qname).rstrip(".")

            qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 255: "ANY"}
            qtype = qtype_map.get(raw_qtype, str(raw_qtype))

        answers = []
        if is_response and packet.haslayer("DNSRR"):
            current_rr = packet["DNS"].an
            while current_rr and current_rr.haslayer("DNSRR"):
                rdata = current_rr.rdata

                if isinstance(rdata, bytes):
                    clean_rdata = rdata.decode("utf-8", errors="replace").rstrip(".")
                elif isinstance(rdata, list):
                    clean_rdata = "".join(
                        chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)
                        for chunk in rdata
                    )
                else:
                    clean_rdata = str(rdata)

                answers.append(clean_rdata)
                current_rr = current_rr.payload if hasattr(current_rr, "payload") else None

        pkt_metadata = DNSMetaData(
            query=query,
            qtype=qtype,
            is_response=is_response,
            rcode=rcode,
            answers=answers,
            tx_id=tx_id,
        )

    if not protocols: protocols.append("OTHER")
    return ParsedPacket(frame_id, src_ip, dst_ip, src_port, dst_port, protocols, flags, pkt_metadata, pkt_time)