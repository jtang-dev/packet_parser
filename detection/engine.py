from detection.stateful import PortScanDetector
from typing import Callable, Optional
from detection.stateless import Alert, detect_suspicious_flags
from ingestion.parser import ParsedPacket


class DetectionEngine:

    def __init__(self):
        self.stateful_detectors = [
            PortScanDetector()
        ]

        self.stateless_rules: list[Callable[[ParsedPacket], Optional[Alert]]] = [
            detect_suspicious_flags
        ]

    def evaluate(self, packet: ParsedPacket) -> list[Alert]:
        alerts: list[Alert] = []

        for rule in self.stateless_rules:
            if alert := rule(packet):
                alerts.append(alert)

        for detector in self.stateful_detectors:
            if alert := detector.process_packet(packet):
                alerts.append(alert)

        return alerts