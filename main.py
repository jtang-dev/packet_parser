import argparse
import sys
from ingestion.sniffer import start_sniffing

def parse_args():
    parser = argparse.ArgumentParser(description="Lightweight Network IDS")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0)."
    )
    parser.add_argument(
        "-r", "--pcap",
        type=str,
        default=None,
        help="Path to offline packet capture to ingest."
    )
    parser.add_argument(
        "-c", "--count",
        type=str,
        default=0,
        help="The number of packets to read before exiting (0 = infinite)."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    print("[*] Starting Network Intrusion Detection System...")

    try:
        start_sniffing(
            interface=args.interface,
            pcap_file=args.pcap,
            count=args.count
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping capture and exiting cleanly...")
        sys.exit(0)

if __name__ == "__main__":
    main()