"""Tests for the LAN scanner's pure helpers (parsing + identify output). No network is touched."""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import lan_scanner  # noqa: E402


def test_ip_sort_key_orders_numerically_and_puts_missing_last():
    keys = [lan_scanner._ip_sort_key(ip) for ip in ["192.168.1.10", "192.168.1.2", None, "10.0.0.5"]]
    order = [ip for _, ip in sorted(zip(keys, ["192.168.1.10", "192.168.1.2", None, "10.0.0.5"]))]
    assert order == ["10.0.0.5", "192.168.1.2", "192.168.1.10", None]


def test_print_devices_runs_and_flags_randomized(capsys):
    seen = {
        "02:11:22:33:44:55": {"ip": "192.168.1.20", "hostname": "phone"},   # locally administered
        "a4:b1:c2:d3:e4:f5": {"ip": "192.168.1.1", "hostname": "router"},    # universally administered
    }
    lan_scanner.print_devices(seen)
    out = capsys.readouterr().out
    assert "02:11:22:33:44:55" in out and "private/randomized" in out
    assert "192.168.1.1" in out and "router" in out


def test_print_devices_handles_empty(capsys):
    lan_scanner.print_devices({})
    assert "No devices found" in capsys.readouterr().out
