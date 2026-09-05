Markdown
# Lightweight Network Intrusion Detection System (NIDS):

A high-performance, multi-threaded Network Intrusion Detection System built from the ground up in Python. The engine parses live network traffic and offline PCAP files, executes stateful detection rules, deduplicates high-velocity alert streams, and renders an interactive, real-time Terminal User Interface (TUI) alongside structured forensic JSONL logging.

## Key Features:

* **Multi-Threaded Producer-Consumer Architecture:** Fully decoupled ingestion, packet parsing, rule evaluation, suppression caching, and disk logging using concurrent threads and thread-safe queues.
* **Stateful Alert Deduplication & Suppression Engine:** Prevents alert fatigue and SIEM ingestion flooding by tracking attack velocity per `(rule_name, src_ip)` tuple with sliding cooldown windows and inactivity timeouts.
* **Live In-Memory Aggregation & Telemetry:** Dynamic hit-counter increments in the live dashboard during ongoing attack streams without generating redundant disk I/O.
* **Thread-Safe Memory Management:** Background memory pruning thread reclaims stale host states safely using mutex locks (`threading.Lock`).
* **Interactive Terminal User Interface:** Built with `Rich.Live`, featuring live traffic rates, top communicating hosts, top destination ports, frozen buffer packet inspection, and real-time alert feeds.
* **Dual Ingestion Modes:** Supports real-time network interface sniffing and deterministic offline `.pcap` capture file analysis.
* **Structured Forensic Logging:** Emits machine-readable `alerts.jsonl` entries with full metadata (packet frame IDs, targeted ports, timestamps, hit counts) and clean session summaries on exit.

## Architecture Overview:

```text
               +-----------------------+
               |    Network Source     |
               | (Interface / PCAP)    |
               +-----------+-----------+
                           |
                           v
               +-----------------------+
               |     Sniff Thread      |
               +-----------+-----------+
                           | (packet_queue)
                           v
               +-----------------------+
               |  Packet Worker Thread |
               |  - Parser             |
               |  - Detection Engine   |
               |  - NetworkStats (TUI) |
               +-----------+-----------+
                           | (evaluates alert)
                           v
            +-----------------------------+
            |      AlertDeduplicator      |<----+ Clean-up Daemon Thread
            |  - Sliding Cooldown Windows |     | (Prunes stale states)
            |  - Thread-Safe Lock         |     |
            +-------------+---------------+     |
                          |                     |
            +-------------+-------------+       |
            | (Pass / Cooldown Expired) | (Suppressed / Active Window)
            v                           v
  +-------------------+       +-------------------+
  |   Alert Queue     |       | NetworkStats Only |
  +---------+---------+       | (Increments Hits) |
            |                 +-------------------+
            v
  +-------------------+
  |  Logging Worker   |
  |  (alerts.jsonl)   |
  +-------------------+
```
# Project Structure:

```text
  ├── alerting/
  │   ├── models.py          # Alert, RuleMetadata, and SuppressionState data models
  │   └── suppression.py     # Thread-safe AlertDeduplicator and background pruner
  ├── detection/
  │   ├── engine.py          # Detection engine and rule execution logic
  │   └── worker.py          # Packet processing, logging, and cleanup worker routines
  ├── ingestion/
  │   ├── parser.py          # Protocol parsing and ParsedPacket abstraction
  │   └── sniffer.py         # Socket/Scapy packet capture ingestion
  ├── output/
  │   ├── dashboard.py       # Rich TUI layout, table rendering, and keyboard handler
  │   ├── logger.py          # Structured JSONL logging and session export
  │   └── stats.py           # Thread-safe telemetry, recent packet buffers, top IPs/ports
  ├── main.py                # CLI argument parsing, thread orchestration, and main UI loop
└── README.md
```

# Getting Started:

## Prerequisites:

Python 3.10+
Root/Administrator privileges (required for raw packet capture on live interfaces)

## Installation:

Clone the repository:
```bash
git clone [https://github.com/your-username/network-ids.git](https://github.com/your-username/network-ids.git)
cd network-ids
```

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

Install required dependencies:

```bash
pip install -r requirements.txt
```

# Usage:

## Live Network Monitoring:

Run the engine on a specific network interface (e.g., `eth0`, `wlan0`, `en0`):

```bash
sudo python main.py -i eth0
```

## Offline PCAP Analysis:

Ingest and analyse a pre-recorded packet capture file:

```bash
python main.py -r samples/capture.pcap
```

## Limit Packet Count:

Process an exact number of packets before shutting down:

```bash#
python main.py -i eth0 -c 5000
```

## Interactive Dashboard Controls:

While the live dashboard is running:

- `Space`: Pause / unpause the live packet stream buffer for inspection.
- `Up` / `Down` Arrow Keys: Navigate through the Top Hosts table.
- `Enter`: Select and filter traffic for a specific host.
- `Ctrl + C`: Trigger a graceful shutdown, flush queues to disk, and export `session_summary.json`.

## Alert Deduplication Logic:

To prevent log flooding during high-volume scans or brute-force attempts, the `AlertDeduplicator` enforces stateful windowing based on `(rule_name, src_ip)`:

- New / Idle Session: If no alert has fired for a host within the i`dle_timeout` (default: 300s), the alert is emitted immediately with `occurrence_count = 1`.
- Active Cooldown: If an alert matches an active session within `cooldown_duration` (default: 60s), the alert is suppressed from disk logs, the in-memory hit counter increments, and the TUI updates live.
- Window Expiration: If an attack continues past the cooldown window, an aggregated alert is flushed to `alerts.jsonl` carrying the total accumulated burst count.
