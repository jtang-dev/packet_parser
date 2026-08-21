import argparse
import sys
import threading
import time
from rich.live import Live

from ingestion.sniffer import start_sniffing
from output.stats import NetworkStats
from output.dashboard import make_layout, update_layout

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

    stats = NetworkStats()

    try:
        sniff_thread = threading.Thread(
            target=start_sniffing,
            kwargs={
                "interface": args.interface,
                "pcap_file": args.pcap,
                "count": args.count,
                "stats": stats
            },
            daemon=True
        )
        sniff_thread.start()

        layout = make_layout()

        with Live(layout, refresh_per_second=4, screen=True) as live:
            while True:
                stats.prune_and_rank(limit=10)
                update_layout(layout, stats)
                time.sleep(0.25)

    except KeyboardInterrupt:
        print("\n[*] Stopping capture and exiting cleanly...")
        sys.exit(0)

if __name__ == "__main__":
    main()