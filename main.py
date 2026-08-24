import argparse
import queue
import sys
import threading
import time
from rich.live import Live

from detection.engine import DetectionEngine
from detection.worker import process_packet_worker
from ingestion.sniffer import start_sniffing
from output.logger import export_session_summary
from output.stats import NetworkStats
from output.dashboard import make_layout, update_layout, handle_input

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
    is_paused = False
    frozen_packets = []
    selected_idx = -1
    packet_queue = queue.Queue()
    engine = DetectionEngine()

    try:
        sniff_thread = threading.Thread(
            target=start_sniffing,
            kwargs={
                "interface": args.interface,
                "pcap_file": args.pcap,
                "count": args.count,
                "packet_queue": packet_queue
            },
            daemon=True
        )

        worker_thread = threading.Thread(
            target=process_packet_worker,
            kwargs={
                "packet_queue": packet_queue,
                "stats": stats,
                "engine": engine
            },
            daemon=True
        )

        sniff_thread.start()
        worker_thread.start()

        layout = make_layout()

        with Live(layout, refresh_per_second=12, screen=True) as live:
            while True:
                stats.prune_and_rank(limit=10)
                item_count = len(stats.top_ips)

                new_pause_state, selected_idx = handle_input(is_paused, selected_idx, item_count)
                if new_pause_state and not is_paused:
                    frozen_packets = list(stats.recent_packets)
                is_paused = new_pause_state

                display_packets = frozen_packets if is_paused else list(stats.recent_packets)

                if stats.top_ips and 0 <= selected_idx < len(stats.top_ips):
                    selected_ip = stats.top_ips[selected_idx][0]
                else:
                    selected_ip = None

                live.update(update_layout(
                    layout,
                    stats,
                    selected_idx=selected_idx,
                    selected_ip=selected_ip,
                    display_packets=display_packets,
                    is_paused=is_paused
                ))
                time.sleep(0.03)

    except KeyboardInterrupt:
        print("\n[*] Stopping capture and exiting cleanly...")
        export_session_summary(stats)
        print("[*] Saved session_summary.json. Exiting cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()