from datetime import datetime, timezone
import scapy.all as scapy

from data.models import ParsedPacket, DNSMetaData, TLSMetaData, HTTPMetaData

RECORD_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "Application Data",
}

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

        if packet.haslayer("Raw"):
            payload = bytes(packet["TCP"].payload)
            payload_len = len(payload)

            is_tls = (
                    payload_len >= 5
                    and payload[0] in RECORD_TYPES
                    and payload[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03")
            )

            http_request = (
                b"GET "
                b"POST "
                b"PUT "
                b"DELETE "
                b"HEAD "
                b"OPTIONS "
            )

            http_response = (
                b"HTTP/1.0 "
                b"HTTP/1.1 "
            )

            if is_tls:
                protocols.insert(0, "TLS")
                content_type_str = RECORD_TYPES.get(payload[0], "Unknown")

                sni = None
                version = None
                cipher_suites = []

                if payload[0] == 0x16 and payload_len >= 43 and payload[5] == 0x01:
                    version_val = int.from_bytes(payload[9:11], "big")
                    match version_val:
                        case 0x0301:
                            version = "TLS 1.0"
                        case 0x0302:
                            version = "TLS 1.1"
                        case 0x0303:
                            version = "TLS 1.2"
                        case 0x0304:
                            version = "TLS 1.3"
                        case _:
                            version = f"TLS (0x{version_val:04x})"

                    idx = 43
                    try:
                        session_id_len = payload[idx]
                        idx += 1 + session_id_len

                        ciphers_len = int.from_bytes(payload[idx:idx + 2], "big")
                        idx += 2
                        cipher_bytes = payload[idx:idx + ciphers_len]
                        cipher_suites = [
                            int.from_bytes(cipher_bytes[i:i + 2], "big")
                            for i in range(0, len(cipher_bytes), 2)
                        ]
                        idx += ciphers_len

                        comp_len = payload[idx]
                        idx += 1 + comp_len

                        ext_total_len = int.from_bytes(payload[idx:idx + 2], "big")
                        idx += 2
                        ext_end = idx + ext_total_len

                        while idx + 4 <= ext_end:
                            ext_type = int.from_bytes(payload[idx:idx + 2], "big")
                            ext_len = int.from_bytes(payload[idx + 2:idx + 4], "big")
                            idx += 4

                            if ext_type == 0x0000:
                                if payload[idx + 2] == 0x00:
                                    name_len = int.from_bytes(payload[idx + 3:idx + 5], "big")
                                    sni = payload[idx + 5:idx + 5 + name_len].decode("utf-8", errors="replace")
                                    break
                            idx += ext_len

                    except (IndexError, ValueError):
                        pass

                pkt_metadata = TLSMetaData(
                    content_type=content_type_str,
                    sni=sni,
                    version=version,
                    cipher_suites=cipher_suites,
                    ja3_hash=None,
                )
            elif payload.split()[0] in http_request or payload.split()[0] in http_response:
                protocols.insert(0, "HTTP")

                idx = payload.find(b"\r\n\r\n")
                header_bytes = payload[:idx] if idx != -1 else payload[:2048]
                header_text = header_bytes.decode("latin-1", errors="replace")
                lines = header_text.split("\r\n")

                method = None
                uri = None
                status_code = None
                is_response = False

                if lines and lines[0].startswith("HTTP/1."):
                    is_response = True
                    parts = lines[0].split(" ")
                    if len(parts) > 1 and parts[1].isdigit():
                        status_code = int(parts[1])
                elif lines:
                    parts = lines[0].split(" ")
                    if len(parts) >= 2:
                        method = parts[0]
                        uri = parts[1]

                host = None
                user_agent = None
                content_type = None

                for line in lines[1:]:
                    if not line:
                        break
                    if ":" not in line:
                        continue

                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()

                    match key:
                        case "host":
                            host = val
                        case "user-agent":
                            user_agent = val
                        case "content-type":
                            content_type = val.split(";")[0].strip()

                    if host and user_agent and content_type:
                        break

                pkt_metadata = HTTPMetaData(
                    method=method,
                    uri=uri,
                    host=host,
                    status_code=status_code,
                    user_agent=user_agent,
                    content_type=content_type,
                    is_response=is_response,
                )

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