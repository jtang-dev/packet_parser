from collections import deque
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Sequence, Optional, Any

from ingestion.parser import ParsedPacket

@dataclass(frozen=True)
class RuleMetadata:
    name: str
    severity: str
    description: str

@dataclass
class Alert:
    rule: RuleMetadata
    packets: Sequence[ParsedPacket]
    timestamp: Optional[datetime] = None
    scanned_ports: Optional[list[int]] = None
    _bounded_packets: deque[ParsedPacket] = field(init=False, repr=False)
    occurrence_count: int = 1

    def set_count(self, count: int) -> None:
        self.occurrence_count = count

    def __post_init__(self):
        self._bounded_packets = deque(self.packets, maxlen=50)

        if self.timestamp is None:
            if self._bounded_packets and self._bounded_packets[-1].timestamp is not None:
                self.timestamp = self._bounded_packets[-1].timestamp
            else:
                self.timestamp = datetime.now(timezone.utc)

    @property
    def rule_name(self) -> str:
        return self.rule.name

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def description(self) -> str:
        return self.rule.description

    @property
    def src_ip(self) -> str:
        return self.packets[0].src_ip if self.packets else "N/A"

    @property
    def dst_ip(self) -> str:
        return self.packets[0].dst_ip if self.packets else "N/A"

    @property
    def frame_ids(self) -> list[int]:
        return [p.frame_id for p in self._bounded_packets]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if self.timestamp else "N/A",
            "rule": self.rule.name,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "packet_ids": self.frame_ids,
            "ports": self.scanned_ports if self.scanned_ports is not None else "N/A",
            "occurrence_count": self.occurrence_count,
        }

@dataclass
class SuppressionState:
    last_emitted: datetime
    last_seen: datetime
    occurrence_count: int = 1