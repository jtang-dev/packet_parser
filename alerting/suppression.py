from datetime import datetime, timedelta, timezone
import threading
from typing import Dict, Optional, Tuple

from alerting.models import Alert, SuppressionState


class AlertDeduplicator:
    def __init__(self, cooldown_seconds: int = 60, idle_timeout_seconds: int = 300):
        self.cooldown_duration = timedelta(seconds=cooldown_seconds)
        self.idle_timeout = timedelta(seconds=idle_timeout_seconds)
        self.states: Dict[Tuple[str, str], SuppressionState] = {}
        self._lock = threading.Lock()

    def check_alert(self, alert: Alert, current_time: Optional[datetime] = None) -> bool:
        now = current_time or alert.timestamp or datetime.now(timezone.utc)
        key = (alert.rule_name, alert.src_ip)

        with self._lock:
            if key not in self.states:
                self.states[key] = SuppressionState(last_emitted=now, last_seen=now, occurrence_count=1)
                alert.set_count(1)
                return True

            state = self.states[key]

            if (now - state.last_seen) > self.idle_timeout:
                self.states[key] = SuppressionState(last_emitted=now, last_seen=now, occurrence_count=1)
                alert.set_count(1)
                return True

            if (now - state.last_emitted) < self.cooldown_duration:
                state.occurrence_count += 1
                state.last_seen = now
                return False

            aggregated_count = state.occurrence_count + 1
            state.occurrence_count = 1
            state.last_emitted = now
            state.last_seen = now
            alert.set_count(aggregated_count)
            return True

    def prune_stale_states(self, current_time: Optional[datetime] = None) -> int:
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            expired_keys = [
                key for key, state in self.states.items()
                if (now - state.last_seen) > self.idle_timeout
            ]
            for key in expired_keys:
                del self.states[key]
            return len(expired_keys)