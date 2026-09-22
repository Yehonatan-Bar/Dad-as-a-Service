"""Shared presence primitives: MAC normalisation, the local SQLite schema, and the coverage math.

The scanner (``lan_scanner.py``) writes the SQLite database; the guard (``ac_offline_guard.py``)
reads it. Two tables:

* ``sightings(mac, last_seen, hostname, ip)`` - the latest time each hardware address was seen on
  the LAN. A phone seen within the coverage gap is "home"; otherwise it has been offline since its
  last sighting.
* ``scans(observed_at)`` - one row per completed scan cycle: the *coverage heartbeat*. A gap in
  these proves the scanner stopped, so the guard can never read a stalled monitor as a long absence.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Optional, Sequence

# Six hex pairs separated by ":" or "-", Cisco's dotted triples, or twelve bare hex digits.
_MAC_PAIRS = re.compile(r"^([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})$")
_MAC_DOTTED = re.compile(r"^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$")
_MAC_BARE = re.compile(r"^[0-9a-f]{12}$")
_NEVER_A_DEVICE = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def normalize_mac(value: Any) -> Optional[str]:
    """``aa:bb:cc:dd:ee:ff`` (lower-case, colon-separated) for any common spelling of a hardware
    address, or ``None`` when the value is not one. The null/broadcast addresses and multicast
    (group) addresses are refused: they never name a station. Locally administered addresses (a
    phone's per-network "private address") ARE accepted - they are stable for the home network."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text or len(text) > 32:
        return None
    digits: Optional[str] = None
    if _MAC_PAIRS.match(text):
        digits = text.replace(":", "").replace("-", "")
    elif _MAC_DOTTED.match(text):
        digits = text.replace(".", "")
    elif _MAC_BARE.match(text):
        digits = text
    if digits is None:
        return None
    mac = ":".join(digits[i:i + 2] for i in range(0, 12, 2))
    if mac in _NEVER_A_DEVICE:
        return None
    if int(digits[0:2], 16) & 0x01:  # the I/G bit: a group (multicast) address, not a station
        return None
    return mac


def is_locally_administered(mac: str) -> bool:
    """True for a locally administered address - what a phone's randomised per-network address looks
    like. Informational only; such an address is still stable for the home network."""
    return bool(int(mac[0:2], 16) & 0x02)


# --------------------------------------------------------------------------- database
def connect(path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    resolved = Path(path)
    if read_only:
        if not resolved.exists():
            raise FileNotFoundError(f"presence database not found: {resolved}")
        uri = f"{resolved.resolve().as_uri()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        except sqlite3.OperationalError:
            conn = sqlite3.connect(str(resolved), check_same_thread=False)
    else:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(resolved), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")  # so the guard can read while the scanner writes
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sightings (
            mac TEXT PRIMARY KEY,
            last_seen REAL NOT NULL,
            hostname TEXT,
            ip TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            observed_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_observed ON scans(observed_at);
        """
    )
    conn.commit()


def record_scan(conn: sqlite3.Connection, seen: dict[str, dict[str, Any]], now: float, *, retention_seconds: float) -> None:
    """One scan cycle: refresh each seen address's ``last_seen``, append a coverage heartbeat, and
    prune heartbeats older than ``retention_seconds`` so the table never grows."""
    for mac, info in seen.items():
        conn.execute(
            "INSERT INTO sightings (mac, last_seen, hostname, ip) VALUES (?,?,?,?) "
            "ON CONFLICT(mac) DO UPDATE SET last_seen=excluded.last_seen, "
            "hostname=COALESCE(excluded.hostname, sightings.hostname), ip=COALESCE(excluded.ip, sightings.ip)",
            (mac, now, info.get("hostname"), info.get("ip")),
        )
    conn.execute("INSERT INTO scans (observed_at) VALUES (?)", (now,))
    conn.execute("DELETE FROM scans WHERE observed_at < ?", (now - retention_seconds,))
    conn.commit()


# --------------------------------------------------------------------------- coverage math (pure)
def continuous_coverage_start(sample_times: Sequence[float], now: float, max_gap: float) -> Optional[float]:
    """Start of the unbroken run of coverage samples ending at ``now``. The run "reaches now" only if
    the most recent sample is within ``max_gap`` of ``now`` and every consecutive gap inside the run
    is also within ``max_gap``. Returns ``None`` when there is no fresh, continuous coverage (e.g.
    the scanner stopped)."""
    times = sorted(float(t) for t in sample_times if t is not None and t <= now)
    if not times:
        return None
    if now - times[-1] > max_gap:
        return None
    run_start = times[-1]
    for earlier in reversed(times[:-1]):
        if run_start - earlier <= max_gap:
            run_start = earlier
        else:
            break
    return run_start


def effective_offline_since(offline_since: float, sample_times: Sequence[float], now: float, max_gap: float) -> tuple[float, bool]:
    """``(effective_offline_since, coverage_ok)``. When a monitoring gap occurred after the phone went
    offline, the clock effectively restarts at the end of the gap, because absence could not be
    observed during it. The effective start is therefore ``max(offline_since, run_start)``."""
    run_start = continuous_coverage_start(sample_times, now, max_gap)
    if run_start is None:
        return offline_since, False
    return max(offline_since, run_start), True
