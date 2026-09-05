from datetime import datetime, timedelta, timezone
import threading
from typing import Dict, Optional, Tuple

from alerting.models import Alert, SuppressionState


class AlertDeduplicator:
    """
    A way to conglomerate multiple alerts of the same type into a single alert to prevent alert fatigue, as well as the
    entire alert feed filling up with the exact same thing. With default values, an attack will generate an alert the second
    it occurs, then an additional one every minute if the attack is ongoing. After five minutes with no activity, an additional
    alert is treated as a separate incidence.

    :arg cooldown_seconds: The amount of time to prevent an additional occurrence of an identical alert for the same attack.
    :arg idle_timeout_seconds: The amount of time after which the same attack is treated as a separate occurrence.

    """
    def __init__(self, cooldown_seconds: int = 60, idle_timeout_seconds: int = 300):
        self.cooldown_duration = timedelta(seconds=cooldown_seconds)
        self.idle_timeout = timedelta(seconds=idle_timeout_seconds)
        # Stores the suspressing states preventing identical alerts from reappearing
        self.states: Dict[Tuple[str, str], SuppressionState] = {}
        self._lock = threading.Lock()

    def check_alert(self, alert: Alert, current_time: Optional[datetime] = None) -> Tuple[bool, int]:
        """
        Checks if an existing rule has been triggered from the same source IP. If it hasn't, or the timeout has passed,
        generate a new suppression and add to the states dictionary.

        :param alert: The alert to be checked for deduplication.
        :return: Whether an additional alert should be generated, and what the number of occurrences is.
        """
        now = current_time or alert.timestamp or datetime.now(timezone.utc)
        key = (alert.rule_name, alert.src_ip)

        with self._lock:
            if key not in self.states:
                self.states[key] = SuppressionState(last_emitted=now, last_seen=now, occurrence_count=1)
                alert.set_count(1)
                return True, 1

            state = self.states[key]

            if (now - state.last_seen) > self.idle_timeout:
                self.states[key] = SuppressionState(last_emitted=now, last_seen=now, occurrence_count=1)
                alert.set_count(1)
                return True, 1

            # Cooldown has not passed so no new alert, just increase the occurrence of the previous one.
            if (now - state.last_emitted) < self.cooldown_duration:
                state.occurrence_count += 1
                state.last_seen = now
                alert.set_count(state.occurrence_count)
                return False, state.occurrence_count

            # Cooldown has passed, so generate a new alert but pass on the occurrences as the attack is still ongoing.
            aggregated_count = state.occurrence_count + 1
            state.occurrence_count = 1
            state.last_emitted = now
            state.last_seen = now
            alert.set_count(aggregated_count)
            return True, aggregated_count

    def prune_stale_states(self, current_time: Optional[datetime] = None) -> int:
        """
        Removes stale suppression states from the states dictionary, utilised by the concurrent worker thread.
        
        :return: The number of keys that have been pruned.
        """
        now = current_time or datetime.now(timezone.utc)

        with self._lock:
            expired_keys = [
                key for key, state in self.states.items()
                if (now - state.last_seen) > self.idle_timeout
            ]
            for key in expired_keys:
                del self.states[key]
            return len(expired_keys)