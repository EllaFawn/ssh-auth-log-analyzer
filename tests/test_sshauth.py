from datetime import datetime, timedelta
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typer.testing import CliRunner

import sshauth

SAMPLE = Path(__file__).resolve().parent.parent / "sample_auth_small.log"


def test_ip_with_trailing_colon_is_cleaned():
    ev = sshauth.parse_auth_line(
        "Mar 10 13:57:20 host1 sshd[1090]: Received disconnect from 203.0.113.46: 11: Bye Bye [preauth]", 2025
    )
    assert ev.ip == "203.0.113.46"
    assert ev.event == "other"


def test_failed_line_parsed():
    ev = sshauth.parse_auth_line(
        "Mar 10 13:45:01 host1 sshd[1001]: Failed password for invalid user admin from 203.0.113.45 port 52300 ssh2",
        2025,
    )
    assert ev.event == "failed"
    assert ev.ip == "203.0.113.45"
    assert ev.user == "admin"
    assert ev.timestamp == datetime(2025, 3, 10, 13, 45, 1)


def test_invalid_user_line_parsed():
    ev = sshauth.parse_auth_line("Mar 10 13:46:30 host1 sshd[1010]: Invalid user test from 192.0.2.13 port 59800", 2025)
    assert ev.event == "invalid_user"
    assert ev.user == "test"
    assert ev.ip == "192.0.2.13"


def test_ipv6_and_iso_timestamp():
    ev = sshauth.parse_auth_line(
        "2025-03-10T13:45:01.123456+00:00 host1 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
    )
    assert ev.ip == "2001:db8::1"
    assert ev.timestamp == datetime(2025, 3, 10, 13, 45, 1, 123456)


def test_repeated_message_counted():
    line = "Mar 10 13:45:01 host1 sshd[1]: message repeated 4 times: [ Failed password for root from 10.0.0.1 port 22 ssh2]"
    report = sshauth.analyse([line], year=2025)
    assert report["summary"]["total_failed"] == 4


def test_bruteforce_reports_every_burst():
    base = datetime(2025, 1, 1, 12, 0)
    burst1 = [base + timedelta(seconds=10 * i) for i in range(5)]
    burst2 = [base + timedelta(hours=1, seconds=10 * i) for i in range(6)]
    incidents = sshauth.detect_bruteforce({"1.2.3.4": burst1 + burst2})
    assert [i["count"] for i in incidents] == [5, 6]


def test_bruteforce_below_threshold():
    base = datetime(2025, 1, 1)
    spread = [base + timedelta(minutes=11 * i) for i in range(10)]
    assert sshauth.detect_bruteforce({"1.2.3.4": spread}) == []


def test_year_rollover():
    lines = [
        "Dec 31 23:59:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Jan  1 00:01:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    ]
    report = sshauth.analyse(lines, year=2024)
    assert list(report["summary"]["by_day"]) == ["2024-12-31", "2025-01-01"]


def test_sample_log_summary():
    with SAMPLE.open() as fh:
        report = sshauth.analyse(fh, year=2025)
    s = report["summary"]
    assert s["total_failed"] == 56
    assert s["total_accepted"] == 7
    # Every IP that appears in the sample, with no ":"-suffixed duplicates
    assert all(":" not in ip for ip, _ in report["failed_by_ip"])
    assert s["unique_ips"] == 15  # the old version reported 19
    # 203.0.113.45 attacks in three separate bursts
    assert sum(1 for i in report["brute_force_incidents"] if i["ip"] == "203.0.113.45") == 3


def test_cli_end_to_end(tmp_path):
    out = tmp_path / "report.json"
    chart = tmp_path / "chart.png"
    result = CliRunner().invoke(
        sshauth.app,
        ["--logfile", str(SAMPLE), "--report-json", str(out), "--chart", str(chart), "--year", "2025"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["summary"]["total_lines"] == 82
    assert chart.exists()


def test_cli_missing_file(tmp_path):
    result = CliRunner().invoke(sshauth.app, ["--logfile", str(tmp_path / "nope.log"), "--no-chart"])
    assert result.exit_code == 2
