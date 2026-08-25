from rich.layout import Layout
from rich.table import Table
import msvcrt

from output.stats import NetworkStats


def make_layout() -> Layout:
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
    table = Table(title="Recent Alerts:", expand=True)

    table.add_column("Time", justify="left", style="magenta")
    table.add_column("Severity", justify="left", style="magenta")
    table.add_column("Rule", style="magenta")
    table.add_column("Hits", justify="right", style="yellow")
    table.add_column("Source", style="magenta")
    table.add_column("Ports", justify="right", style="magenta")

    for alert in stats.recent_alerts:
        time_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.timestamp else "N/A"
        sev_str = str(alert.rule.severity.value) if hasattr(alert.rule.severity, "value") else str(alert.rule.severity)
        rule_str = f"{alert.rule.name}" if hasattr(alert.rule, "name") else str(getattr(alert, "rule_name", "N/A"))

        count = getattr(alert, "occurrence_count", 1)
        count_str = f"[bold yellow]{count}[/]" if count > 1 else "[dim]1[/]"

        src_str = f"{alert.src_ip}"
        ports_str = f"{', '.join(str(i) for i in alert.scanned_ports)}" if alert.scanned_ports is not None else "N/A"

        table.add_row(time_str, sev_str, rule_str, count_str, src_str, ports_str)

    return table

def render_top_ips(stats: NetworkStats, selected_idx: int) -> Table:
    table = Table(title="Most Common IP Communications:", expand=True)

    table.add_column("IP Address", justify="left", style="cyan")
    table.add_column("Hits", justify="right", style="cyan")

    for idx, (ip, hits) in enumerate(stats.top_ips[:10]):
        if idx == selected_idx:
            table.add_row(f"> [bold yellow]{ip}[/]", f"[bold yellow]{hits}[/]")
        else:
            table.add_row(f"  {ip}", str(hits))

    for _ in range(10 - len(stats.top_ips[:10])):
        table.add_row("", "")

    return table

def render_top_ports(ports: list[tuple[int, int]], table_title: str) -> Table:
    table = Table(title=table_title, expand=True)

    table.add_column("Port", justify="left", style="cyan")
    table.add_column("Hits", justify="right", style="cyan")

    for port, hits in ports[:10]:
        table.add_row(str(port), str(hits))

    for _ in range(10 - len(ports[:10])):
        table.add_row("", "")

    return table

def handle_input(is_paused: bool, selected_idx: int, item_count: int):
    if msvcrt.kbhit():
        key = msvcrt.getch()
        if key in (b'p', b'P', b' '):
            return not is_paused, selected_idx
        if key in (b'\x1b', b'c'):
            return is_paused, -1
        if key in (b'\x00', b'\xe0'):
            key = msvcrt.getch()
            if key == b'H':
                selected_idx = max(-1, selected_idx - 1)
            if key == b'P':
                selected_idx = min(item_count - 1, selected_idx + 1)
    return is_paused, selected_idx


def update_layout(
        layout: Layout,
        stats: NetworkStats,
        selected_idx: int,
        selected_ip: str | None,
        display_packets: list | None = None,
        is_paused: bool = False) -> Layout:
    packets = display_packets if display_packets is not None else stats.recent_packets

    layout["left"].update(render_packets(packets, is_paused=is_paused))
    layout["alerts"].update(render_alerts(stats))
    layout["top_ips"].update(render_top_ips(stats, selected_idx))

    ports = stats.get_ports_for_ip(selected_ip)
    if selected_ip and (ports := stats.get_ports_for_ip(selected_ip)):
        layout["top_ports"].update(render_top_ports(ports, f"Most Common Port Destinations for {selected_ip}:"))
    else:
        layout["top_ports"].update(render_top_ports(stats.top_ports, "Most Common Port Destinations:"))

    return layout