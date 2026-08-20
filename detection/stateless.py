from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ingestion.parser import ParsedPacket

@dataclass(frozen=True)
class RuleMetadata:
    name: str
    severity: str
    description: str

# Central rule registry
TCP_RULES = {
    "NULL": RuleMetadata(
        name="SCAN_TCP_NULL",
        severity="HIGH",
        description="Illegal packet state with no TCP flags set, commonly used to map open/closed ports."
    ),
    "XMAS": RuleMetadata(
        name="SCAN_TCP_XMAS",
        severity="HIGH",
        description="TCP XMAS scan (FIN, PSH, URG flags set) used to probe closed ports."
    ),
    "SYN_FIN": RuleMetadata(
        name="SUSPICIOUS_TCP_SYN_FIN",
        severity="MEDIUM",
        description="Simultaneous SYN and FIN flags used for stack fingerprinting and evasion."
    ),
    "PORT_SCAN": RuleMetadata(
        name="SUSPICIOUS_NO_OF_TCP_SYN",
        severity="HIGH",
        description="High number of SYN packets to various ports, used for port scans."
    ),
}

@dataclass
class Alert:
    rule: RuleMetadata
    packet: ParsedPacket
    timestamp: Optional[datetime] = None
    scanned_ports: Optional[list[int]] = None

    @property
    def rule_name(self) -> str:
        return self.rule.name

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def description(self) -> str:
        return self.rule.description

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = self.packet.timestamp if self.packet.timestamp is not None else datetime.now(timezone.utc)

    def __str__(self):
        formatted_time = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        details = (
            f"Timestamp: {formatted_time}\n"
            f"Severity: {self.severity}\n"
            f"Rule Name: {self.rule_name}\n"
            f"Source: {self.packet.src_ip}:{self.packet.src_port}\n"
            f"Destination: {self.packet.dst_ip}:{self.packet.dst_port}\n"
        )

        if self.scanned_ports:
            details += f"Scanned Ports: {', '.join(str(i) for i in self.scanned_ports)}"

        return details


def detect_suspicious_flags(parsed_packet: ParsedPacket) -> Optional[Alert]:
    if parsed_packet.protocol == "TCP" and parsed_packet.flags is not None:
        flag_set = set(parsed_packet.flags)

        if len(flag_set) == 0:
            return Alert(rule=TCP_RULES["NULL"], packet=parsed_packet)
        if {"F", "P", "U"}.issubset(flag_set):
            return Alert(rule=TCP_RULES["XMAS"], packet=parsed_packet)
        if {"S", "F"}.issubset(flag_set):
            return Alert(rule=TCP_RULES["SYN_FIN"], packet=parsed_packet)

    return None