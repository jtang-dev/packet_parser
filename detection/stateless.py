from typing import Optional

from data.models import Alert, ParsedPacket
from alerting.registry import TCP_RULES


def detect_suspicious_flags(parsed_packet: ParsedPacket) -> Optional[Alert]:
    """
    Checks incoming packets for malformed TCP flags that may indicate suspicious activity such as 'NULL' scans or 'XMAS'
    scans.

    :param parsed_packet: A packet that has been parsed to allow for easier data handling.
    :return: An alert, if it is deemed that one is necessary.
    """
    if "TCP" in parsed_packet.protocols and parsed_packet.flags is not None:
        flag_set = set(parsed_packet.flags)

        if len(flag_set) == 0:
            return Alert(rule=TCP_RULES["NULL"], packets=[parsed_packet])
        if {"F", "P", "U"}.issubset(flag_set):
            return Alert(rule=TCP_RULES["XMAS"], packets=[parsed_packet])
        if {"S", "F"}.issubset(flag_set):
            return Alert(rule=TCP_RULES["SYN_FIN"], packets=[parsed_packet])

    return None