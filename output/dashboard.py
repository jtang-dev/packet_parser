from rich.layout import Layout
from rich.table import Table
import msvcrt

from data.models import DNSMetaData, TLSMetaData, HTTPMetaData
from output.stats import NetworkStats


def make_layout() -> Layout:
    """
    Handles the rendering of the layout using the Rich library. Defining the exact size of the screen each table will
    take up.

    :return: The layout to be rendered.
    """
    layout = Layout()

    layout.split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )

    layout["right"].split_column(
        Layout(name="alerts", ratio=1),
        Layout(name="stats", size=15)
    )

    layout["stats"].split_row(
        Layout(name="top_ips", ratio=1),
        Layout(name="top_ports", ratio=1)
    )

    return layout


def apply_packet_filter(packets: list, query: str) -> list:
    if not query:
        return packets

    terms = query.lower().split()
    filtered = []

    for pkt in packets:
        matches_all_terms = True

        for term in terms:
            term_matched = False

            if any(term in proto.lower() for proto in pkt.protocols):
                term_matched = True
            elif term in pkt.src_ip.lower() or term in pkt.dst_ip.lower():
                term_matched = True
            elif pkt.src_port and term == str(pkt.src_port):
                term_matched = True
            elif pkt.dst_port and term == str(pkt.dst_port):
                term_matched = True
            elif pkt.app_data:
                if hasattr(pkt.app_data, "query") and pkt.app_data.query and term in pkt.app_data.query.lower():
                    term_matched = True
                elif hasattr(pkt.app_data, "sni") and pkt.app_data.sni and term in pkt.app_data.sni.lower():
                    term_matched = True
                elif hasattr(pkt.app_data, "host") and pkt.app_data.host and term in pkt.app_data.host.lower():
                    term_matched = True
                elif hasattr(pkt.app_data, "uri") and pkt.app_data.uri and term in pkt.app_data.uri.lower():
                    term_matched = True

            if not term_matched:
                matches_all_terms = False
                break

        if matches_all_terms:
            filtered.append(pkt)

    return filtered


def render_packets(packets_to_display: list, is_paused: bool = False, is_filtering: bool = False,
                   filter_buffer: str = "", active_filter: str = "") -> Table:
    """
    Constructs the table displaying the incoming packets, showing time ingested, protocol used,
    source and destination port/IP, and application-layer metadata (DNS/TLS/HTTP).

    :param packets_to_display: List of incoming packets, received from the NetworkStats class.
    :param is_paused: Indicates if table feed is paused for closer inspection.
    :return: The packet table to be constructed.
    """
    status_tags = []
    if is_paused:
        status_tags.append("PAUSED")
    if is_filtering:
        status_tags.append(f"SEARCH: {filter_buffer}█")
    elif active_filter:
        status_tags.append(f"FILTER: '{active_filter}' [c to clear]")

    status_str = f" [{' | '.join(status_tags)}]" if status_tags else " [Press 'f' to Filter, 'p' to Pause]"
    title = f"Ingested Packets{status_str}"

    table = Table(title=title, expand=True, pad_edge=False, padding=(0, 1))

    table.add_column("Time", width=10, justify="left", style="green", no_wrap=True)
    table.add_column("Source", ratio=2, style="green", overflow="ellipsis", no_wrap=True)
    table.add_column("Destination", ratio=2, style="green", overflow="ellipsis", no_wrap=True)
    table.add_column("Protocol", width=12, justify="left", style="green", no_wrap=True)
    table.add_column("Info", ratio=4, style="cyan", overflow="ellipsis", no_wrap=True)

    for pkt in packets_to_display[-44:]:
        time_str = pkt.timestamp.strftime("%H:%M:%S") if pkt.timestamp else "N/A"
        src_str = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port is not None else str(pkt.src_ip)
        dst_str = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port is not None else str(pkt.dst_ip)
        proto_str = "/".join(pkt.protocols) if pkt.protocols else "OTHER"

        info_str = "-"
        if isinstance(pkt.app_data, DNSMetaData):
            direction = "RESP" if pkt.app_data.is_response else "QUERY"
            info_str = f"DNS {direction} {pkt.app_data.query} ({pkt.app_data.qtype})"
        elif isinstance(pkt.app_data, TLSMetaData):
            if pkt.app_data.sni:
                ver = pkt.app_data.version or "TLS"
                info_str = f"TLS SNI: {pkt.app_data.sni} [{ver}]"
            else:
                info_str = f"TLS {pkt.app_data.content_type}"
        elif isinstance(pkt.app_data, HTTPMetaData):
            if pkt.app_data.is_response:
                code = pkt.app_data.status_code or "RESP"
                mime = f" ({pkt.app_data.content_type})" if pkt.app_data.content_type else ""
                info_str = f"HTTP {code}{mime}"
            else:
                method = pkt.app_data.method or "REQ"
                host = f"{pkt.app_data.host}" if pkt.app_data.host else ""
                uri = pkt.app_data.uri or "/"
                info_str = f"HTTP {method} {host}{uri}"
        elif pkt.flags:
            info_str = f"[{', '.join(pkt.flags)}]"

        table.add_row(time_str, src_str, dst_str, proto_str, info_str)

    return table


def render_alerts(stats: NetworkStats) -> Table:
    """
    Constructs the table displaying incoming alerts, showing time received, severity, rule triggered, number of occurrences,
    source IP, and ports received on.

    :param stats: The incoming alerts are received from the NetworkStats class which dequeues alerts from the global
    alerts queue.
    :return: The alert table to be constructed.
    """
    table = Table(title="Recent Alerts:", expand=True)

    table.add_column("Time", justify="left", style="magenta")
    table.add_column("Severity", justify="left", style="magenta")
    table.add_column("Rule", style="magenta")
    table.add_column("Hits", justify="right", style="yellow")
    table.add_column("Source", style="magenta")
    table.add_column("Ports", justify="right", style="magenta")

    for alert in stats.recent_alerts:
        time_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.timestamp else "N/A"
        sev_str = alert.severity
        rule_str = alert.rule_name

        count = alert.occurrence_count
        # Repeat alerts are given more significance
        count_str = f"[bold yellow]{count}[/]" if count > 1 else "[dim]1[/]"

        src_str = f"{alert.src_ip}"
        ports_str = f"{', '.join(str(i) for i in alert.scanned_ports)}" if alert.scanned_ports is not None else "N/A"

        table.add_row(time_str, sev_str, rule_str, count_str, src_str, ports_str)

    return table


def render_top_ips(stats: NetworkStats, selected_idx: int) -> Table:
    """
    Constructs the table that renders the most common IPs communicated with, and the number of communications. Also
    serves as a selection box for allowing the user to see the top ports used by each IP.

    :param stats: Top IPs are taken from the Network Stats class.
    :param selected_idx: The selected index, which will display the top ports used by the IP associated with it.
    :return: The top IPs table to be constructed.
    """

    table = Table(title="Most Common IP Communications:", expand=True)

    table.add_column("IP Address", justify="left", style="cyan")
    table.add_column("Hits", justify="right", style="cyan")

    for idx, (ip, hits) in enumerate(stats.top_ips[:10]):
        if idx == selected_idx:
            table.add_row(f"> [bold yellow]{ip}[/]", f"[bold yellow]{hits}[/]")
        else:
            table.add_row(f"  {ip}", str(hits))

    # Populating table with empty rows to align UI if there aren't enough IPs
    for _ in range(10 - len(stats.top_ips[:10])):
        table.add_row("", "")

    return table


def render_top_ports(ports: list[tuple[int, int]], table_title: str) -> Table:
    """
    Constructs the table that renders the most common ports used on the host device. Will also display the top ports used
    by each IP when the user selects this option.

    :param ports: As this can be the top ports globally, or per IP, it is not supplied by NetworkStats, it handled by the
    input handler.
    :param table_title: As this table can display multiple things, the title needs to be able to update dynamically.
    :return: The top ports table to be rendered.
    """
    table = Table(title=table_title, expand=True)

    table.add_column("Port", justify="left", style="cyan")
    table.add_column("Hits", justify="right", style="cyan")

    for port, hits in ports[:10]:
        table.add_row(str(port), str(hits))

    # Populating table with empty rows to align UI if there aren't enough ports
    for _ in range(10 - len(ports[:10])):
        table.add_row("", "")

    return table


def handle_input(is_paused: bool, selected_idx: int, item_count: int, is_filtering: bool = False,
                 filter_buffer: str = "", active_filter: str = ""):
    """
    Detects when a user presses a key the corresponds to an appropriate action to be taken to alter the rendering of the
    tables.

    :param is_paused: Whether the incoming packets table is paused or displays a live ingestion feed.
    :param selected_idx: The chosen IP address to display the top ports for, -1 when nothing is chosen.
    :param item_count: The number of top IPs.
    """
    while msvcrt.kbhit():
        key = msvcrt.getch()

        if key in (b'\x00', b'\xe0'):
            key2 = msvcrt.getch()
            if not is_filtering:
                if key2 == b'H':  # 'Up' key to select IP address
                    selected_idx = max(-1, selected_idx - 1)
                elif key2 == b'P':  # 'Down' key to select IP address
                    selected_idx = min(item_count - 1, selected_idx + 1)
            continue

        if not is_filtering:
            if key in (b'p', b'P', b' '):  # 'p' or 'space' to pause
                is_paused = not is_paused
            elif key == b'\x1b':  # 'escape' to unselect an IP address
                selected_idx = -1
                active_filter = ""
            elif key in (b'f', b'F', b'/'):
                is_filtering = True
                filter_buffer = ""
            elif key in (b'c', b'C'):
                active_filter = ""

        else:
            if key == b'\r':
                active_filter = filter_buffer.strip()
                is_filtering = False
            elif key == b'\x1b':
                filter_buffer = ""
                is_filtering = False
            elif key == b'\x08':
                filter_buffer = filter_buffer[:-1]
            else:
                try:
                    char = key.decode("utf-8")
                    if char.isprintable():
                        filter_buffer += char
                except UnicodeDecodeError:
                    pass

    return is_paused, selected_idx, is_filtering, filter_buffer, active_filter


def update_layout(
        layout: Layout,
        stats: NetworkStats,
        selected_idx: int,
        selected_ip: str | None,
        display_packets: list | None = None,
        is_paused: bool = False,
        is_filtering: bool = False,
        filter_buffer: str = "",
        active_filter: str = "") -> Layout:
    """
    Updates tables when an IP is selected for top port display, or the incoming packet feed is paused.

    :param layout: Rich table layout.
    :param stats: NetworkStats to obtain data to display.
    :param selected_idx: Selected index for IP port display.
    :param selected_ip: Selected IP for port display.
    :param display_packets: A freeze-frame of packets to display when ingestion feed is paused.
    :param is_paused: Whether the packet ingestion feed is paused
    :return: The layout to be displayed.
    """
    packets = display_packets if display_packets is not None else stats.recent_packets

    layout["left"].update(render_packets(packets, is_paused, is_filtering, filter_buffer, active_filter))
    layout["alerts"].update(render_alerts(stats))
    layout["top_ips"].update(render_top_ips(stats, selected_idx))

    if selected_ip and (ports := stats.get_ports_for_ip(selected_ip)):
        layout["top_ports"].update(render_top_ports(ports, f"Most Common Port Destinations for {selected_ip}:"))
    else:
        layout["top_ports"].update(render_top_ports(stats.top_ports, "Most Common Port Destinations:"))

    return layout