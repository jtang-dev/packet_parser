from rich.layout import Layout
from rich.table import Table
import msvcrt

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

def render_packets(packets_to_display: list, is_paused: bool = False) -> Table:
    """
    Constructs the table displaying the incoming packets, showing time ingested, protocol used, and source and destination
    port and IP for each.

    :param packets_to_display: List of incoming packets, recieved from the NetworkStats class which dequeues packets
    from the globalqueue.
    :param is_paused: Table has an option to be paused, allowing a prospective security expert a closer look at any suspicous
    packets in the ingestion feed.
    :return: The packet table to be constructed.
    """

    title = "Incoming and Outgoing Packets [PAUSED - Press 'p' to Resume]" if is_paused else "Incoming and Outgoing Packets [Live - Press 'p' to Pause]"

    table = Table(title=title, expand=True)

    table.add_column("Time", width=12, justify="left", style="green", no_wrap=True)
    table.add_column("Source", ratio=3, style="green", overflow="ellipsis", no_wrap=True)
    table.add_column("Destination", ratio=3, style="green", overflow="ellipsis", no_wrap=True)
    table.add_column("Protocol", width=10, justify="right", style="green", no_wrap=True)

    for pkt in packets_to_display:
        time_str = pkt.timestamp.strftime("%H:%M:%S") if pkt.timestamp else "N/A"
        src_str = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port is not None else str(pkt.src_ip)
        dst_str = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port is not None else str(pkt.dst_ip)

        table.add_row(time_str, src_str, dst_str, str(pkt.protocol))

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

def handle_input(is_paused: bool, selected_idx: int, item_count: int):
    """
    Detects when a user presses a key the corresponds to an appropriate action to be taken to alter the rendering of the
    tables.

    :param is_paused: Whether the incoming packets table is paused or displays a live ingestion feed.
    :param selected_idx: The chosen IP address to display the top ports for, -1 when nothing is chosen.
    :param item_count: The number of top IPs.
    """
    if msvcrt.kbhit():
        key = msvcrt.getch()
        if key in (b'p', b'P', b' '): # 'p' or 'space' to pause
            return not is_paused, selected_idx
        if key in (b'\x1b', b'c'): # 'escape' to unselect an IP address
            return is_paused, -1
        if key in (b'\x00', b'\xe0'):
            key = msvcrt.getch()
            if key == b'H': # 'Up' key to select IP address
                selected_idx = max(-1, selected_idx - 1)
            if key == b'P': # 'Down' key to select IP address
                selected_idx = min(item_count - 1, selected_idx + 1)
    return is_paused, selected_idx


def update_layout(
        layout: Layout,
        stats: NetworkStats,
        selected_idx: int,
        selected_ip: str | None,
        display_packets: list | None = None,
        is_paused: bool = False) -> Layout:
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

    layout["left"].update(render_packets(packets, is_paused=is_paused))
    layout["alerts"].update(render_alerts(stats))
    layout["top_ips"].update(render_top_ips(stats, selected_idx))

    if selected_ip and (ports := stats.get_ports_for_ip(selected_ip)):
        layout["top_ports"].update(render_top_ports(ports, f"Most Common Port Destinations for {selected_ip}:"))
    else:
        layout["top_ports"].update(render_top_ports(stats.top_ports, "Most Common Port Destinations:"))

    return layout