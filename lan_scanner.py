#!/usr/bin/env python3
"""Self-contained LAN presence scanner.

Every cycle it (optionally) pings the local /24 so sleeping devices answer, reads the operating
system's neighbour table (`arp -a` on Windows, `ip -4 neigh` / `arp -an` elsewhere), normalises the
hardware addresses it finds, and records them in a local SQLite database that the AC offline guard
reads. Standard library only.

    python lan_scanner.py --db presence.sqlite3 [--interval 120] [--subnet 192.168.1.0/24] [--no-sweep] [--once]

The database has two tables (see presence.py): `sightings` (per-address last-seen) and `scans` (one
coverage heartbeat per cycle). Run this continuously on a machine that stays on the home network
(e.g. the always-on display/kiosk). The guard is a separate process that only reads this database.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional

import presence

DEFAULT_DB = "presence.sqlite3"
DEFAULT_INTERVAL_SECONDS = 120
# Heartbeats older than this are pruned. Must exceed the guard's threshold + coverage gap.
HEARTBEAT_RETENTION_SECONDS = 6 * 3600
SWEEP_WORKERS = 64
SWEEP_TIMEOUT_MS = 300

_IS_WINDOWS = platform.system() == "Windows"
_MAC_TOKEN = re.compile(r"\b([0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(\2[0-9a-fA-F]{2}){4})\b")
_IPV4_TOKEN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
# Neighbour-table lines that name no live device.
_DEAD_MARKERS = ("incomplete", "failed", "permanent", "<incomplete>")


def log(message: str) -> None:
    print(f"{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return result.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def local_ipv4() -> Optional[str]:
    """The primary IPv4 of this machine (the source address to a public target; no packet is sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_subnet() -> Optional[ipaddress.IPv4Network]:
    ip = local_ipv4()
    if ip is None:
        return None
    try:
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return None


def _ping(host: str) -> None:
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(SWEEP_TIMEOUT_MS), host]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
    try:
        subprocess.run(cmd, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def ping_sweep(subnet: ipaddress.IPv4Network) -> None:
    hosts = [str(h) for h in subnet.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=SWEEP_WORKERS) as pool:
        list(pool.map(_ping, hosts))


def read_neighbours() -> dict[str, dict[str, Optional[str]]]:
    """Parse the OS neighbour table into {mac: {"ip": ip, "hostname": None}}."""
    if _IS_WINDOWS:
        text = _run(["arp", "-a"])
    else:
        text = _run(["ip", "-4", "neigh"]) or _run(["arp", "-an"])
    seen: dict[str, dict[str, Optional[str]]] = {}
    for line in text.splitlines():
        low = line.lower()
        if any(marker in low for marker in _DEAD_MARKERS):
            continue
        mac_match = _MAC_TOKEN.search(line)
        if mac_match is None:
            continue
        mac = presence.normalize_mac(mac_match.group(1))
        if mac is None:
            continue
        ip_match = _IPV4_TOKEN.search(line)
        seen.setdefault(mac, {"ip": ip_match.group(1) if ip_match else None, "hostname": None})
    return seen


def resolve_hostnames(seen: dict[str, dict[str, Optional[str]]]) -> None:
    for info in seen.values():
        ip = info.get("ip")
        if not ip:
            continue
        try:
            info["hostname"] = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            pass


def scan_once(subnet: Optional[ipaddress.IPv4Network], *, sweep: bool, resolve: bool) -> dict[str, dict[str, Optional[str]]]:
    if sweep and subnet is not None:
        ping_sweep(subnet)
    seen = read_neighbours()
    if resolve:
        resolve_hostnames(seen)
    return seen


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="LAN presence scanner -> local SQLite for the AC offline guard.")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"SQLite database path (default {DEFAULT_DB})")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS, help="seconds between scans")
    parser.add_argument("--subnet", help="the LAN to sweep, e.g. 192.168.1.0/24 (default: the local /24)")
    parser.add_argument("--no-sweep", action="store_true", help="do not ping the subnet first (rely on the neighbour table as is)")
    parser.add_argument("--no-resolve", action="store_true", help="do not look up hostnames")
    parser.add_argument("--once", action="store_true", help="one scan, then exit")
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    subnet: Optional[ipaddress.IPv4Network] = None
    if not args.no_sweep:
        if args.subnet:
            try:
                subnet = ipaddress.ip_network(args.subnet, strict=False)
            except ValueError:
                log(f"invalid --subnet {args.subnet!r}; falling back to the local /24")
                subnet = default_subnet()
        else:
            subnet = default_subnet()

    conn = presence.connect(args.db)
    presence.init_db(conn)
    log(f"scanner writing {args.db} every {args.interval}s (sweep={'off' if args.no_sweep else (subnet or 'n/a')})")
    try:
        while True:
            now = time.time()
            try:
                seen = scan_once(subnet, sweep=not args.no_sweep, resolve=not args.no_resolve)
                presence.record_scan(conn, seen, now, retention_seconds=HEARTBEAT_RETENTION_SECONDS)
                log(f"scan recorded {len(seen)} device(s)")
            except Exception as error:  # noqa: BLE001 - keep the loop alive across transient faults
                log(f"scan failed: {error}")
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log("interrupted")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
