from typing import Optional

from alerting.models import Alert
from alerting.registry import TCP_RULES
from ingestion.parser import ParsedPacket

def detect_suspicious_flags(parsed_packet: ParsedPacket) -> Optional[Alert]:
    if parsed_packet.protocol == "TCP" and parsed_packet.flags is not None:
        flag_set = set(parsed_packet.flags)

        if len(flag_set) == 0:
            return Alert(rule=TCP_RULES["NULL"], packets=[parsed_packet])
        if {"F", "P", "U"}.issubset(flag_set):
            return Alert(rule=TCP_RULES["XMAS"], packets=[parsed_packet])
        if {"S", "F"}.issubset(flag_set):
            return Alert(rule=TCP_RULES["SYN_FIN"], packets=[parsed_packet])

    return None