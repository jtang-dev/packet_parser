from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Sequence, Optional, Any

@dataclass
class DNSMetaData:
    query: str
    qtype: str
    is_response: bool = False
    rcode: Optional[int] = None
    answers: list[str] = field(default_factory=list)
    tx_id: Optional[int] = None

@dataclass
class TLSMetaData:
    content_type: str
    sni: Optional[str] = None
    version: Optional[str] = None
    cipher_suites: list[int] = field(default_factory=list)
    ja3_hash: Optional[str] = None


@dataclass
class ParsedPacket:
    """
    A custom packet dataclass built off of scapy's internal 'packet' class that allows for easier data access and modification.

    :ivar frame_id: A unique identifier to differentiate between packets for triage purposes.
    :ivar src_ip: The source ip of the packet.
    :ivar dst_ip: The destination ip of the packet.
    :ivar src_port: The source port of the packet.
    :ivar dst_port: The destination port of the packet.
    :ivar protocols: The specific protocols used by the packet (e.g. TCP, UDP, etc.).
    :ivar flags: The TCP flags utilised by the packet.
    :ivar timestamp: The time at which the packet was ingested.
    """
    frame_id: int
    src_ip: str
    dst_ip: str
    src_port: Optional[int | str]
    dst_port: Optional[int | str]
    protocols: list[str]
    flags: Optional[list[str]] = None
    app_data: DNSMetaData | TLSMetaData | None = None
    timestamp: Optional[datetime] = None

    def __str__(self) -> str:
        formatted_time = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if self.timestamp else "N/A"
        return f"[{formatted_time}] {'/'.join(self.protocols)} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


@dataclass(frozen=True)
class RuleMetadata:
    name: str
    severity: str
    description: str


@dataclass
class Alert:
    """Represents a security alert triggered by rule violations.

    Attributes:
        rule: Metadata defining the violated rule (name, severity, description).
        packets: Sequence of packets associated with the alert, capped at 50 to bound memory.
        timestamp: Time of detection (defaults to the timestamp of the latest packet or UTC now).
        scanned_ports: List of destination ports probed (populated by port scan rules).
        occurrence_count: Number of times this signature occurred within a suppression window.
    """
    rule: RuleMetadata
    packets: Sequence[ParsedPacket]
    timestamp: Optional[datetime] = None
    scanned_ports: Optional[list[int]] = None
    occurrence_count: int = 1

    def set_count(self, count: int) -> None:
        self.occurrence_count = count

    def __post_init__(self):
        # Bound to the last 50 packets to free excess packet references for GC
        if len(self.packets) > 50:
            self.packets = list(self.packets[-50:])
        elif not isinstance(self.packets, list):
            self.packets = list(self.packets)

        if self.timestamp is None:
            if self.packets and self.packets[-1].timestamp is not None:
                self.timestamp = self.packets[-1].timestamp
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
        return [p.frame_id for p in self.packets]

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


