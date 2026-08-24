import json
import os
from datetime import datetime, timezone

from alerting.models import Alert
from output.stats import NetworkStats

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)


def log_alert(alert: Alert, filepath: str = os.path.join(DATA_DIR, "alerts.jsonl")) -> None:
    line = json.dumps(alert.to_dict())
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def export_session_summary(stats: NetworkStats, filepath: str = os.path.join(DATA_DIR, "session_summary.json")) -> None:
    with stats._lock:
        cutoff = datetime.now(timezone.utc) - stats.window_duration
        stats.top_ips = stats._prune_and_rank_dict(stats.ip_history, cutoff, limit=10)
        stats.top_ports = stats._prune_and_rank_dict(stats.port_history, cutoff, limit=10)
        stats.top_ip_to_ports = stats._prune_nested_dict(stats.ip_to_port, cutoff, limit=10)

        summary_payload = {
            "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "top_ips": [{"ip": ip, "count": count} for ip, count in stats.top_ips],
            "top_ports": [{"port": port, "count": count} for port, count in stats.top_ports],
            "ip_to_ports": stats.top_ip_to_ports,
            "total_alerts_recorded": len(stats.recent_alerts),
        }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=4)