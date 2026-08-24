from alerting.models import RuleMetadata

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