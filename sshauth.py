"""Summarise SSH login activity from a Linux auth.log file.

Counts failed, accepted and invalid-user login attempts per IP, flags
brute-force bursts, and writes a JSON report plus a bar chart of the
worst offenders.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from charset_normalizer import from_path
from rich.console import Console
from rich.table import Table

app = typer.Typer(add_completion=False)
console = Console()

DEFAULT_LOGFILE = Path("sample_auth_small.log")
DEFAULT_REPORT = Path("detailed_report.json")
DEFAULT_CHART = Path("top_attackers.png")

# "from <ip>" - the IP may be followed by a colon or space, e.g.
# "Received disconnect from 1.2.3.4: 11: Bye Bye"
FROM_IP_RE = re.compile(r"\bfrom\s+([0-9A-Fa-f:.]+?)(?=:?\s|:?$)")
USER_RE = re.compile(r"(?:Failed \S+ for (?:invalid user )?|Accepted \S+ for |Invalid user )(\S+)")
REPEATED_RE = re.compile(r"message repeated (\d+) times")


@dataclass
class LogEvent:
    timestamp: Optional[datetime]
    ip: Optional[str]
    event: str  # "failed", "accepted", "invalid_user" or "other"
    user: Optional[str] = None
    count: int = 1  # >1 when syslog collapsed repeats ("message repeated N times")


def detect_encoding(path: Path) -> str:
    """Return the most likely text encoding of a file, defaulting to UTF-8."""
    result = from_path(path).best()
    return result.encoding if result else "utf-8"


def parse_timestamp(line: str, year: int) -> Optional[datetime]:
    """Parse either classic syslog ("Mar 10 13:45:01") or ISO 8601 timestamps."""
    parts = line.split(maxsplit=3)
    if not parts:
        return None
    # Newer rsyslog / journald format: 2025-03-10T13:45:01.123456+00:00
    if parts[0][:4].isdigit() and "T" in parts[0]:
        try:
            return datetime.fromisoformat(parts[0]).replace(tzinfo=None)
        except ValueError:
            return None
    if len(parts) < 3:
        return None
    try:
        return datetime.strptime(f"{parts[0]} {parts[1]} {parts[2]} {year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def extract_ip(line: str) -> Optional[str]:
    """Return the IP after 'from', or None if it isn't a valid IPv4/IPv6 address."""
    match = FROM_IP_RE.search(line)
    if not match:
        return None
    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def parse_auth_line(line: str, year: Optional[int] = None) -> LogEvent:
    """Parse one auth.log line into a LogEvent."""
    if year is None:
        year = datetime.now().year
    ts = parse_timestamp(line, year)

    if "Failed password" in line or "Failed publickey" in line:
        event = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event = "accepted"
    elif "Invalid user" in line:
        event = "invalid_user"
    else:
        event = "other"

    user_match = USER_RE.search(line)
    repeat_match = REPEATED_RE.search(line)
    return LogEvent(
        timestamp=ts,
        ip=extract_ip(line),
        event=event,
        user=user_match.group(1) if user_match else None,
        count=int(repeat_match.group(1)) if repeat_match else 1,
    )


def detect_bruteforce(timestamps_by_ip, window_minutes: float = 10, threshold: int = 5):
    """Find bursts of at least `threshold` failures from one IP within `window_minutes`.

    Every separate burst is reported, so an IP that attacks several times
    produces several incidents. Each burst is grown to include all
    failures that stay within the window of its first attempt.
    """
    incidents = []
    window_seconds = window_minutes * 60
    for ip, timestamps in timestamps_by_ip.items():
        if len(timestamps) < threshold:
            continue
        timestamps = sorted(timestamps)
        start = 0
        while start < len(timestamps):
            end = start
            while (
                end + 1 < len(timestamps)
                and (timestamps[end + 1] - timestamps[start]).total_seconds() <= window_seconds
            ):
                end += 1
            size = end - start + 1
            if size >= threshold:
                incidents.append({
                    "ip": ip,
                    "count": size,
                    "start_time": timestamps[start].isoformat(),
                    "end_time": timestamps[end].isoformat(),
                    "duration_minutes": round(
                        (timestamps[end] - timestamps[start]).total_seconds() / 60.0, 2
                    ),
                })
                start = end + 1  # don't report overlapping windows twice
            else:
                start += 1
    incidents.sort(key=lambda i: i["start_time"])
    return incidents


def analyse(lines, year: Optional[int] = None, window_minutes: float = 10, threshold: int = 5) -> dict:
    """Build the full report dictionary from an iterable of log lines."""
    if year is None:
        year = datetime.now().year
    start_year = year

    totals = Counter()
    failed_by_ip = Counter()
    accepted_by_ip = Counter()
    invalid_by_ip = Counter()
    targeted_users = Counter()
    timestamps_by_ip = defaultdict(list)
    by_day = Counter()
    unique_ips = set()
    prev_month = None

    for line in lines:
        if not line.strip():
            continue
        totals["lines"] += 1
        ev = parse_auth_line(line, year)

        # Syslog lines have no year: roll over when the log crosses Dec -> Jan.
        if ev.timestamp is not None:
            if prev_month is not None and ev.timestamp.month < prev_month and prev_month - ev.timestamp.month > 6:
                year += 1
                ev.timestamp = ev.timestamp.replace(year=year)
            prev_month = ev.timestamp.month
            by_day[ev.timestamp.date().isoformat()] += 1

        if ev.ip:
            unique_ips.add(ev.ip)

        if ev.event == "failed":
            totals["failed"] += ev.count
            if ev.user:
                targeted_users[ev.user] += ev.count
            if ev.ip:
                failed_by_ip[ev.ip] += ev.count
                if ev.timestamp:
                    timestamps_by_ip[ev.ip].extend([ev.timestamp] * ev.count)
        elif ev.event == "accepted":
            totals["accepted"] += ev.count
            if ev.ip:
                accepted_by_ip[ev.ip] += ev.count
        elif ev.event == "invalid_user":
            totals["invalid_user"] += ev.count
            if ev.ip:
                invalid_by_ip[ev.ip] += ev.count

    offenders = set(failed_by_ip) | set(invalid_by_ip)
    return {
        "summary": {
            "total_lines": totals["lines"],
            "total_failed": totals["failed"],
            "total_accepted": totals["accepted"],
            "total_invalid_user": totals["invalid_user"],
            "unique_ips": len(unique_ips),
            "unique_offender_ips": len(offenders),
            "by_day": dict(sorted(by_day.items())),
        },
        "failed_by_ip": failed_by_ip.most_common(),
        "accepted_by_ip": accepted_by_ip.most_common(),
        "invalid_user_by_ip": invalid_by_ip.most_common(),
        "targeted_users": targeted_users.most_common(),
        "suspicious_logins": sorted(set(accepted_by_ip) & offenders),
        "brute_force_incidents": detect_bruteforce(timestamps_by_ip, window_minutes, threshold),
        "settings": {"year": start_year, "window_minutes": window_minutes, "threshold": threshold},
    }


def plot_top_attackers(failed_by_ip: list, top_n: int = 10, out_file: Path = DEFAULT_CHART) -> None:
    """Save a bar chart of the IPs with the most failed attempts."""
    import matplotlib

    matplotlib.use("Agg")  # no window needed; works over SSH / in CI
    import matplotlib.pyplot as plt

    top = failed_by_ip[:top_n]
    if not top:
        console.print("No failed attempts to plot.", style="yellow")
        return
    ips, counts = zip(*top)
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(range(len(ips)), counts, color="crimson")
    ax.set_xticks(range(len(ips)), labels=list(ips), rotation=45, ha="right")
    ax.set_ylabel("Failed attempts")
    ax.set_title(f"Top {len(ips)} IPs by failed attempts")
    for i, c in enumerate(counts):
        ax.annotate(str(c), (i, c), ha="center", va="bottom", xytext=(0, 3), textcoords="offset points")
    fig.tight_layout()
    fig.savefig(out_file)
    plt.close(fig)
    console.print(f"Saved chart to [bold]{out_file}[/bold]")


def print_tables(report: dict, top_n: int) -> None:
    s = report["summary"]
    console.print(
        f"Lines: {s['total_lines']}  Failed: {s['total_failed']}  "
        f"Accepted: {s['total_accepted']}  Invalid user: {s['total_invalid_user']}  "
        f"Unique IPs: {s['unique_ips']}"
    )

    table = Table(title="Top Offending IPs")
    table.add_column("IP")
    table.add_column("Failed Attempts", justify="right")
    for ip, count in report["failed_by_ip"][:top_n]:
        table.add_row(ip, str(count))
    console.print(table)

    incidents = report["brute_force_incidents"]
    if incidents:
        bf = Table(title="Brute-force Incidents")
        bf.add_column("IP")
        bf.add_column("Attempts", justify="right")
        bf.add_column("Start")
        bf.add_column("Minutes", justify="right")
        for inc in incidents:
            bf.add_row(inc["ip"], str(inc["count"]), inc["start_time"], f"{inc['duration_minutes']:.1f}")
        console.print(bf)

    if report["suspicious_logins"]:
        console.print(
            "[bold red]Warning:[/bold red] successful logins from IPs that also failed: "
            + ", ".join(report["suspicious_logins"])
        )


@app.command()
def summarize(
    logfile: Path = typer.Option(DEFAULT_LOGFILE, help="Path to the auth log."),
    report_json: Path = typer.Option(DEFAULT_REPORT, help="Where to write the JSON report."),
    chart: Path = typer.Option(DEFAULT_CHART, help="Where to save the bar chart."),
    no_chart: bool = typer.Option(False, "--no-chart", help="Skip creating the chart."),
    top_n: int = typer.Option(10, min=1, help="How many top IPs to show and plot."),
    year: Optional[int] = typer.Option(None, help="Year of the log entries (syslog lines omit it). Defaults to this year."),
    window: float = typer.Option(10, min=0.1, help="Brute-force time window in minutes."),
    threshold: int = typer.Option(5, min=2, help="Failures within the window that count as brute force."),
):
    """Summarise failed SSH login attempts from an auth.log file."""
    if not logfile.is_file():
        console.print(f"Log file not found: {logfile}", style="red")
        raise typer.Exit(code=2)

    enc = detect_encoding(logfile)
    console.print(f"Detected encoding: {enc}", style="green")

    with logfile.open("r", encoding=enc, errors="replace") as fh:
        report = analyse(fh, year=year, window_minutes=window, threshold=threshold)

    report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    console.print(f"Wrote structured report to [bold]{report_json}[/bold]", style="green")

    print_tables(report, top_n)

    if not no_chart:
        plot_top_attackers(report["failed_by_ip"], top_n=top_n, out_file=chart)


if __name__ == "__main__":
    app()
