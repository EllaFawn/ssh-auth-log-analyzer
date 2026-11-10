from pathlib import Path
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import typer
from rich.console import Console
from rich.table import Table
import matplotlib.pyplot as plt
from charset_normalizer import from_path

app = typer.Typer()
console = Console()

LOGFILE = "sample_auth_small.log"
REPORT_JSON = "detailed_report.json"

# Detect the best text encoding for the given file path
def detect_encoding(path: Path) -> str:
    result = from_path(path).best()
    return result.encoding if result else "utf-8"

# Parse a single auth log line and return (timestamp, ip, event_type)
def parse_auth_line(line: str, year=None):
    parts = line.split()
    if len(parts) < 3:
        return None, None, "other"
    if year is None:
        year = datetime.now().year
    ts_str = " ".join(parts[0:3]) + f" {year}"
    try:
        ts = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
    except Exception:
        ts = None
    event = "other"
    if "Failed password" in line:
        event = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event = "accepted"
    ip = None
    if " from " in line:
        toks = line.split()
        try:
            idx = toks.index("from")
            ip = toks[idx + 1]
        except Exception:
            ip = None
    return ts, ip, event

# Detect brute-force style activity given timestamps grouped by IP
def detect_bruteforce(timestamps_by_ip, max_minutes=10, threshold=5):
    incidents = []
    window_seconds = max_minutes * 60
    for ip, timestamps in timestamps_by_ip.items():
        if len(timestamps) < threshold:
            continue
        timestamps = sorted(timestamps)
        left = 0
        for right in range(len(timestamps)):
            while left <= right and (timestamps[right] - timestamps[left]).total_seconds() > window_seconds:
                left += 1
            window_size = right - left + 1
            if window_size >= threshold:
                incidents.append({
                    "ip": ip,
                    "count": window_size,
                    "start_time": timestamps[left].isoformat(),
                    "end_time": timestamps[right].isoformat(),
                    "duration_minutes": (timestamps[right] - timestamps[left]).total_seconds() / 60.0
                })
                break
    return incidents

# Create and save a bar chart of the top offending IPs
def plot_top_attackers(failed_by_ip: Counter, top_n=10, out_file="top_attackers.png"):
    top = failed_by_ip.most_common(top_n)
    if not top:
        console.print("No failed attempts to plot.", style="yellow")
        return
    ips, counts = zip(*top)
    plt.figure(figsize=(10,6))
    bars = plt.bar(range(len(ips)), counts, tick_label=list(ips), color="crimson")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Failed attempts")
    plt.title(f"Top {top_n} IPs by failed attempts")
    for i, c in enumerate(counts):
        plt.text(i, c + 0.5, str(c), ha="center")
    plt.tight_layout()
    plt.savefig(out_file)
    console.print(f"Saved chart to [bold]{out_file}[/bold]")

# Main CLI command to summarize the auth log and produce a JSON report
@app.command()
def summarize(
    logfile: Path = typer.Option(Path(LOGFILE), help="Path to auth log"),
    report_json: Path = typer.Option(Path(REPORT_JSON), help="Structured JSON report path"),
    top_n: int = typer.Option(10, help="Top N IPs to include/plot")
):
    if not logfile.exists():
        console.print(f"Log file not found: {logfile}", style="red")
        raise typer.Exit(code=2)

    enc = detect_encoding(logfile)
    console.print(f"Detected encoding: {enc}", style="green")

    totals = Counter()
    failed_by_ip = Counter()
    accepted_by_ip = Counter()
    timestamps_by_ip = defaultdict(list)
    by_day = Counter()
    unique_ips = set()

    with logfile.open("r", encoding=enc, errors="replace") as fh:
        for line in fh:
            totals["lines"] += 1
            ts, ip, event = parse_auth_line(line)
            if ts:
                by_day[str(ts.date())] += 1
            if ip:
                unique_ips.add(ip)
            if event == "failed":
                totals["failed"] += 1
                if ip:
                    failed_by_ip[ip] += 1
                    if ts:
                        timestamps_by_ip[ip].append(ts)
            elif event == "accepted":
                totals["accepted"] += 1
                if ip:
                    accepted_by_ip[ip] += 1

    brute_incidents = detect_bruteforce(timestamps_by_ip, max_minutes=10, threshold=5)

    report = {
        "summary": {
            "total_lines": int(totals["lines"]),
            "total_failed": int(totals.get("failed", 0)),
            "total_accepted": int(totals.get("accepted", 0)),
            "unique_ips": len(unique_ips),
            "unique_offender_ips": len(failed_by_ip),
            "by_day": dict(sorted(by_day.items()))
        },
        "failed_by_ip": failed_by_ip.most_common(),
        "accepted_by_ip": accepted_by_ip.most_common(),
        "brute_force_incidents": brute_incidents
    }

    report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    console.print(f"Wrote structured report to [bold]{report_json}[/bold]", style="green")

    table = Table(title="Top Offending IPs")
    table.add_column("IP", justify="left")
    table.add_column("Failed Attempts", justify="right")
    for ip, count in failed_by_ip.most_common(top_n):
        table.add_row(ip, str(count))
    console.print(table)

    plot_top_attackers(failed_by_ip, top_n=top_n)

if __name__ == "__main__":
    app()