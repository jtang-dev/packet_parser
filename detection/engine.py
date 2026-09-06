from detection.stateful import PortScanDetector
from typing import Callable, Optional
from detection.stateless import Alert, detect_suspicious_flags
from ingestion.parser import ParsedPacket


class DetectionEngine:
    """
    A conglomeration of the various stateful and stateless detectors into a single class for ease of use in the detection
    pipeline.
    """
    def __init__(self):
        self.stateful_detectors = [
            PortScanDetector()
        ]

        self.stateless_rules: list[Callable[[ParsedPacket], Optional[Alert]]] = [
            detect_suspicious_flags
        ]

    def evaluate(self, packet: ParsedPacket) -> list[Alert]:
        """
        Evaluates the supplied packet against stateful and stateless detectors.

        :param packet: The packet to be reviewed by stateful and stateless detectors for suspicious behaviour.
        :return: A list of alerts triggered by the reviewed packet.
        """
        alerts: list[Alert] = []

        for rule in self.stateless_rules:
            if alert := rule(packet):
                alerts.append(alert)

        for detector in self.stateful_detectors:
            if alert := detector.process_packet(packet):
                alerts.append(alert)

        return alerts