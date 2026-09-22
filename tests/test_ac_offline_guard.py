"""Offline tests: no real cloud or router is contacted. Presence and coverage are seeded straight
into the SQLite schema the scanner writes, and the Tornado client is a fake that records calls."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import presence  # noqa: E402
from ac_offline_guard import (  # noqa: E402
    GuardConfig,
    OfflineGuard,
    PresenceReader,
    StateStore,
)
from presence import continuous_coverage_start, effective_offline_since, normalize_mac  # noqa: E402

# A fabricated, locally-administered example address (not a real device).
MAC = "02:11:22:33:44:55"
NORMALIZED = normalize_mac(MAC)
STEP = 120.0


def _db(tmp_path):
    conn = presence.connect(tmp_path / "presence.sqlite3")
    presence.init_db(conn)
    return conn


def _seed_sighting(conn, mac, last_seen):
    conn.execute(
        "INSERT INTO sightings (mac, last_seen) VALUES (?,?) "
        "ON CONFLICT(mac) DO UPDATE SET last_seen=excluded.last_seen",
        (normalize_mac(mac), last_seen),
    )
    conn.commit()


def _seed_scans(conn, start, end, step=STEP):
    t = start
    while t <= end + 1e-6:
        conn.execute("INSERT INTO scans (observed_at) VALUES (?)", (t,))
        t += step
    conn.commit()


def _base_config(**overrides):
    config = {
        "presence_db": "unused.sqlite3",
        "state_db": ":memory:",
        "default_offline_minutes": 15,
        "max_coverage_gap_seconds": 300,
        "mode": "dry-run",
        "rules": [{"rule_id": "p1", "person": "Person", "phone_mac": MAC, "ac_id": "AC-1", "enabled": True}],
    }
    config.update(overrides)
    return config


def _guard(conn, config_dict, client_factory=None):
    config = GuardConfig.from_dict(config_dict)
    state = StateStore(":memory:")
    return OfflineGuard(config, PresenceReader(connection=conn), state, client_factory=client_factory), state


# --------------------------------------------------------------------- config validation
class TestConfig:
    def test_normalizes_mac_and_defaults(self):
        c = GuardConfig.from_dict(_base_config(rules=[{"person": "N", "phone_mac": "06:AA:BB:CC:DD:EE", "ac_id": "X"}]))
        assert c.rules[0].phone_mac == "06:aa:bb:cc:dd:ee"
        assert c.rules[0].offline_seconds == 900.0 and c.rules[0].mode == "dry-run"

    def test_rejects_invalid_mac(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(rules=[{"person": "N", "phone_mac": "nope", "ac_id": "X"}]))

    def test_rejects_duplicate_rule_ids(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(rules=[
                {"rule_id": "a", "person": "N", "phone_mac": MAC, "ac_id": "X"},
                {"rule_id": "a", "person": "M", "phone_mac": MAC, "ac_id": "Y"},
            ]))

    def test_rejects_power_on(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(allow_power_on=True))

    def test_rejects_nonpositive_threshold(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(default_offline_minutes=0))

    def test_live_requires_acknowledgement(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(mode="live", acknowledge_live_control=False))

    def test_stringified_acknowledgement_is_rejected(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(mode="live", acknowledge_live_control="false"))

    def test_stringified_enabled_is_rejected(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(rules=[{"rule_id": "a", "person": "N", "phone_mac": MAC, "ac_id": "X", "enabled": "false"}]))

    def test_genuine_booleans_work(self):
        c = GuardConfig.from_dict(_base_config(mode="live", acknowledge_live_control=True))
        assert c.acknowledge_live_control is True and c.rules[0].enabled is True

    def test_live_rejects_placeholder_ac_id(self):
        with pytest.raises(ValueError):
            GuardConfig.from_dict(_base_config(mode="live", acknowledge_live_control=True,
                                              rules=[{"rule_id": "a", "person": "N", "phone_mac": MAC, "ac_id": "REPLACE_WITH_CLOUD_DEVICE_ID"}]))


# --------------------------------------------------------------------- coverage math
class TestCoverageMath:
    def test_continuous_coverage_start_variants(self):
        now = 1000.0
        assert continuous_coverage_start([], now, 300) is None
        assert continuous_coverage_start([300, 420, 540], now, 300) is None  # trailing gap
        times = [now - 600, now - 480, now - 360, now - 240, now - 120, now]
        assert continuous_coverage_start(times, now, 300) == now - 600
        assert continuous_coverage_start([100, 200, now - 240, now - 120, now], now, 300) == now - 240

    def test_effective_offline_restarts_after_gap(self):
        now = 1000.0
        times = [now - 360, now - 240, now - 120, now]
        eff, ok = effective_offline_since(now - 2400, times, now, 300)
        assert ok is True and eff == now - 360
        eff, ok = effective_offline_since(now - 2400, [], now, 300)
        assert ok is False


# --------------------------------------------------------------------- end to end
class TestEvaluation:
    def test_triggers_once_after_threshold_in_dry_run(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, MAC, now - 960)
        _seed_scans(conn, now - 960, now)
        guard, state = _guard(conn, _base_config())
        d = guard.evaluate(now)[0]
        assert d.triggered is True and d.status == "dry_run"
        again = guard.evaluate(now + STEP)[0]
        assert again.triggered is False and again.reason == "already_acted"
        assert state.connection.execute("SELECT COUNT(*) FROM command_log").fetchone()[0] == 1

    def test_below_threshold(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, MAC, now - 600)
        _seed_scans(conn, now - 600, now)
        guard, _ = _guard(conn, _base_config())
        d = guard.evaluate(now)[0]
        assert d.triggered is False and d.reason == "below_threshold"

    def test_coverage_gap_prevents_trigger(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, MAC, now - 2400)
        _seed_scans(conn, now - 2400, now - 2400 + 3 * STEP)  # a few minutes, then a blackout
        _seed_scans(conn, now - 3 * STEP, now)                # fresh coverage only for the last ~6 min
        guard, _ = _guard(conn, _base_config())
        d = guard.evaluate(now)[0]
        assert d.triggered is False and d.offline_seconds < 900

    def test_stale_monitor(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, MAC, now - 960)
        _seed_scans(conn, now - 960, now)
        guard, _ = _guard(conn, _base_config())
        d = guard.evaluate(now + 3600)[0]  # newest scan is stale
        assert d.triggered is False and d.coverage_ok is False

    def test_phone_never_seen(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, "02:99:88:77:66:55", now - 100)
        _seed_scans(conn, now - 960, now)
        guard, _ = _guard(conn, _base_config())
        d = guard.evaluate(now)[0]
        assert d.known is False and d.triggered is False

    def test_reconnect_rearms(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, MAC, now - 960)
        _seed_scans(conn, now - 960, now)
        guard, state = _guard(conn, _base_config())
        assert guard.evaluate(now)[0].triggered is True
        _seed_sighting(conn, MAC, now + STEP)  # reconnect
        assert guard.evaluate(now + STEP)[0].online is True
        second = now + 2 * STEP
        _seed_sighting(conn, MAC, second)      # offline again
        _seed_scans(conn, second, second + 1200)
        assert guard.evaluate(second + 1200)[0].triggered is True
        assert state.connection.execute("SELECT COUNT(*) FROM command_log").fetchone()[0] == 2

    def test_live_sends_power_off_once_and_never_on(self, tmp_path):
        conn = _db(tmp_path)
        now = 100000.0
        _seed_sighting(conn, MAC, now - 960)
        _seed_scans(conn, now - 960, now)

        class FakeClient:
            def __init__(self):
                self.calls = []

            def set_power(self, device_id, on):
                self.calls.append((device_id, on))
                return {"confirmed": True, "power": on}

        fake = FakeClient()
        guard, _ = _guard(conn, _base_config(mode="live", acknowledge_live_control=True), client_factory=lambda: fake)
        d = guard.evaluate(now)[0]
        assert d.triggered is True and d.status == "confirmed"
        assert fake.calls == [("AC-1", False)]
        guard.evaluate(now + STEP)
        assert fake.calls == [("AC-1", False)] and all(on is False for _, on in fake.calls)


class TestCrashSafety:
    def test_acted_committed_before_cloud_call(self, tmp_path):
        conn = _db(tmp_path)
        state_db = tmp_path / "state.sqlite3"
        now = 100000.0
        _seed_sighting(conn, MAC, now - 960)
        _seed_scans(conn, now - 960, now)

        class CrashClient:
            def set_power(self, device_id, on):
                raise SystemExit("killed mid-send")  # BaseException: not caught by _dispatch

        config = GuardConfig.from_dict(_base_config(mode="live", acknowledge_live_control=True))
        guard = OfflineGuard(config, PresenceReader(connection=conn), StateStore(state_db), client_factory=lambda: CrashClient())
        with pytest.raises(SystemExit):
            guard.evaluate(now)
        # A FRESH StateStore on the same file: the acted/planned row was durably committed pre-crash.
        fresh = StateStore(state_db)
        row = fresh.get_state("p1")
        assert row.get("acted") == 1 and row.get("action_status") == "planned"
        assert fresh.connection.execute("SELECT COUNT(*) FROM command_log").fetchone()[0] == 1


class TestScanner:
    def test_record_scan_round_trip_and_prune(self, tmp_path):
        conn = _db(tmp_path)
        now = time.time()
        # An old scan beyond retention, then a fresh one.
        conn.execute("INSERT INTO scans (observed_at) VALUES (?)", (now - 10 * 3600,))
        conn.commit()
        presence.record_scan(conn, {NORMALIZED: {"hostname": "phone", "ip": "192.168.1.20"}}, now, retention_seconds=6 * 3600)
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1  # stale pruned, fresh kept
        row = conn.execute("SELECT last_seen, hostname, ip FROM sightings WHERE mac=?", (NORMALIZED,)).fetchone()
        assert row["hostname"] == "phone" and row["ip"] == "192.168.1.20" and abs(row["last_seen"] - now) < 1
