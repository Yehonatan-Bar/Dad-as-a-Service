#!/usr/bin/env python3
"""Power off an air conditioner when its owner's phone has been off the home network past a threshold.

A SEPARATE process from the scanner (``lan_scanner.py``). It only READS the presence SQLite database
the scanner maintains, and talks OUTBOUND to the Tornado/AUX cloud (``tornado_ac_client.py``) to send
a power-off command.

Safety by design:

* **Coverage.** A false "offline for 15 minutes" is avoided by requiring continuous scan coverage
  across the whole offline window (the ``scans`` heartbeat). A monitoring gap resets the effective
  clock, and no fresh coverage at all means nothing fires - a stopped scanner can never masquerade as
  a long absence.
* **At most once.** The action fires at most once per offline episode and re-arms only after the phone
  reconnects. The acted flag is committed BEFORE the cloud call, so a crash mid-send cannot repeat it.
* **Off only.** The guard only ever turns an AC OFF; ``allow_power_on`` is rejected.
* **Dry-run default.** A real power-off needs ``mode: "live"`` on a rule, a global
  ``acknowledge_live_control: true``, and a real ``ac_id`` (not a placeholder).

    python ac_offline_guard.py --config config.json --discover   # list ACs, copy ids into the rules
    python ac_offline_guard.py --config config.json --once        # one evaluation pass
    python ac_offline_guard.py --config config.json               # run continuously
"""
from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

import presence
from presence import continuous_coverage_start, effective_offline_since, normalize_mac

LOG_TAG = "[AC_GUARD]"
logger = logging.getLogger("ac_offline_guard")

STATUS_DRY_RUN = "dry_run"
STATUS_PLANNED = "planned"
STATUS_SENT = "sent"
STATUS_CONFIRMED = "confirmed"
STATUS_ERROR = "error"

_PLACEHOLDER_PREFIX = "REPLACE_"


# --------------------------------------------------------------------------- configuration
@dataclass(frozen=True)
class ACRule:
    rule_id: str
    person: str
    phone_mac: str          # normalised aa:bb:cc:dd:ee:ff
    ac_id: str
    ac_label: str
    offline_seconds: float
    mode: str               # "dry-run" or "live"
    enabled: bool


@dataclass(frozen=True)
class GuardConfig:
    credentials_file: Optional[str]
    presence_db: str
    state_db: str
    region: str
    poll_interval_seconds: float
    max_coverage_gap_seconds: float
    acknowledge_live_control: bool
    rules: tuple[ACRule, ...] = field(default_factory=tuple)

    @property
    def has_live_rule(self) -> bool:
        return any(rule.mode == "live" and rule.enabled for rule in self.rules)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, base_dir: Optional[Path] = None) -> "GuardConfig":
        if not isinstance(raw, dict):
            raise ValueError("Configuration root must be a JSON object")
        default_mode = str(raw.get("mode", "dry-run")).strip().lower()
        if default_mode not in ("dry-run", "live"):
            raise ValueError("'mode' must be 'dry-run' or 'live'")
        acknowledge_live = _strict_bool(raw.get("acknowledge_live_control", False), "acknowledge_live_control", False)
        if _strict_bool(raw.get("allow_power_on", False), "allow_power_on", False):
            raise ValueError("'allow_power_on' is not supported: the guard only powers ACs off")
        default_minutes = _positive_number(raw.get("default_offline_minutes", 15), "default_offline_minutes")
        max_gap = _positive_number(raw.get("max_coverage_gap_seconds", 300), "max_coverage_gap_seconds")
        poll_interval = _positive_number(raw.get("poll_interval_seconds", 60), "poll_interval_seconds")
        region = str(raw.get("region", "usa")).strip().lower() or "usa"

        rows = raw.get("rules")
        if not isinstance(rows, list) or not rows:
            raise ValueError("'rules' must be a non-empty list")
        rules: list[ACRule] = []
        seen_ids: set[str] = set()
        for index, entry in enumerate(rows):
            if not isinstance(entry, dict):
                raise ValueError(f"rules[{index}] must be an object")
            rule_id = str(entry.get("rule_id") or entry.get("person") or f"rule_{index}").strip()
            if not rule_id:
                raise ValueError(f"rules[{index}] needs a non-empty 'rule_id' or 'person'")
            if rule_id in seen_ids:
                raise ValueError(f"Duplicate rule_id '{rule_id}'")
            seen_ids.add(rule_id)
            person = str(entry.get("person") or rule_id).strip()
            phone_mac = normalize_mac(entry.get("phone_mac"))
            if phone_mac is None:
                raise ValueError(f"rules[{index}] ('{rule_id}') has an invalid phone_mac")
            ac_id = str(entry.get("ac_id") or "").strip()
            enabled = _strict_bool(entry.get("enabled", True), f"rules[{index}].enabled", True)
            mode = str(entry.get("mode", default_mode)).strip().lower()
            if mode not in ("dry-run", "live"):
                raise ValueError(f"rules[{index}] ('{rule_id}') has an invalid mode '{mode}'")
            if mode == "live" and enabled:
                if not acknowledge_live:
                    raise ValueError(f"rule '{rule_id}' is live but 'acknowledge_live_control' is not true")
                if not ac_id or ac_id.startswith(_PLACEHOLDER_PREFIX):
                    raise ValueError(f"rule '{rule_id}' is live but its ac_id is missing or still a placeholder")
            minutes = _positive_number(entry.get("offline_minutes", default_minutes), "offline_minutes")
            rules.append(ACRule(rule_id=rule_id, person=person, phone_mac=phone_mac, ac_id=ac_id,
                                ac_label=str(entry.get("ac_label") or ac_id or rule_id),
                                offline_seconds=minutes * 60.0, mode=mode, enabled=enabled))

        def _resolve(value: Optional[str], default: Optional[str]) -> Optional[str]:
            value = value or default
            if not value:
                return None
            path = Path(value)
            if base_dir is not None and not path.is_absolute():
                path = base_dir / path
            return str(path)

        return cls(
            credentials_file=_resolve(raw.get("credentials_file"), None),
            presence_db=_resolve(raw.get("presence_db"), "presence.sqlite3"),
            state_db=_resolve(raw.get("state_db"), "ac_guard_state.sqlite3"),
            region=region, poll_interval_seconds=poll_interval, max_coverage_gap_seconds=max_gap,
            acknowledge_live_control=acknowledge_live, rules=tuple(rules),
        )


def _strict_bool(value: Any, field_name: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise ValueError(f"'{field_name}' must be a JSON boolean (true/false), not {type(value).__name__}")


def _positive_number(value: Any, field_name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"'{field_name}' must be a number") from error
    if not (number > 0):
        raise ValueError(f"'{field_name}' must be greater than zero")
    return number


def load_config(path: str | Path) -> GuardConfig:
    config_path = Path(path)
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    return GuardConfig.from_dict(raw, base_dir=config_path.resolve().parent)


def load_credentials(path: str | Path) -> dict[str, str]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Credentials file must be a JSON object")
    email = str(raw.get("email") or "").strip()
    password = str(raw.get("password") or "")
    if not email or not password:
        raise ValueError("Credentials file must contain non-empty 'email' and 'password'")
    return {"email": email, "password": password, "region": str(raw.get("region", "")).strip().lower()}


# --------------------------------------------------------------------------- presence (read-only)
@dataclass(frozen=True)
class PresenceEpisode:
    known: bool
    online: bool
    offline_since: Optional[float]
    last_seen: Optional[float]


class PresenceReader:
    def __init__(self, path: str | Path | None = None, *, connection: Optional[sqlite3.Connection] = None):
        self.connection = connection if connection is not None else presence.connect(path, read_only=True)
        self._owns = connection is None

    def close(self) -> None:
        if self._owns:
            self.connection.close()

    def presence_episode(self, mac: str, *, now: float, max_gap: float) -> PresenceEpisode:
        normalized = normalize_mac(mac)
        if normalized is None:
            return PresenceEpisode(False, False, None, None)
        row = self.connection.execute("SELECT last_seen FROM sightings WHERE mac=?", (normalized,)).fetchone()
        if row is None or row["last_seen"] is None:
            return PresenceEpisode(row is not None, False, None, None)
        last_seen = float(row["last_seen"])
        if now - last_seen <= max_gap:
            return PresenceEpisode(True, True, None, last_seen)
        return PresenceEpisode(True, False, last_seen, last_seen)

    def complete_sample_times(self, since: float, now: float) -> list[float]:
        rows = self.connection.execute(
            "SELECT observed_at FROM scans WHERE observed_at>=? AND observed_at<=? ORDER BY observed_at",
            (since, now),
        ).fetchall()
        return [float(r["observed_at"]) for r in rows]


# --------------------------------------------------------------------------- state (autonomous commits)
class StateStore:
    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS guard_state (
                rule_id TEXT PRIMARY KEY, phone_mac TEXT NOT NULL, episode_offline_since REAL,
                acted INTEGER NOT NULL DEFAULT 0, action_status TEXT, last_online_at REAL,
                last_evaluated_at REAL, last_action_at REAL, updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS command_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, phone_mac TEXT NOT NULL,
                ac_id TEXT NOT NULL, person TEXT, episode_offline_since REAL, offline_seconds REAL,
                mode TEXT NOT NULL, status TEXT NOT NULL, reason TEXT, requested_at REAL NOT NULL,
                completed_at REAL, result_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_command_log_rule_time ON command_log(rule_id, requested_at);
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def get_state(self, rule_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM guard_state WHERE rule_id=?", (rule_id,)).fetchone()
        return dict(row) if row is not None else {}

    def _upsert(self, rule_id: str, phone_mac: str, fields: dict[str, Any]) -> None:
        fields = {**fields, "updated_at": time.time()}
        exists = self.connection.execute("SELECT 1 FROM guard_state WHERE rule_id=?", (rule_id,)).fetchone()
        with self.connection:  # autonomous commit: the write is durable before we return
            if exists is None:
                columns = ["rule_id", "phone_mac", *fields.keys()]
                placeholders = ", ".join("?" for _ in columns)
                self.connection.execute(f"INSERT INTO guard_state ({', '.join(columns)}) VALUES ({placeholders})",
                                        [rule_id, phone_mac, *fields.values()])
            else:
                assignments = ", ".join(f"{name}=?" for name in fields)
                self.connection.execute(f"UPDATE guard_state SET {assignments} WHERE rule_id=?", [*fields.values(), rule_id])

    def mark_online(self, rule_id: str, phone_mac: str, now: float) -> None:
        self._upsert(rule_id, phone_mac, {"episode_offline_since": None, "acted": 0, "action_status": None,
                                          "last_online_at": now, "last_evaluated_at": now})

    def begin_episode(self, rule_id: str, phone_mac: str, offline_since: float, now: float) -> None:
        self._upsert(rule_id, phone_mac, {"episode_offline_since": offline_since, "acted": 0,
                                          "action_status": None, "last_evaluated_at": now})

    def touch(self, rule_id: str, phone_mac: str, now: float) -> None:
        self._upsert(rule_id, phone_mac, {"last_evaluated_at": now})

    def mark_acted(self, rule_id: str, phone_mac: str, status: str, now: float) -> None:
        self._upsert(rule_id, phone_mac, {"acted": 1, "action_status": status, "last_action_at": now, "last_evaluated_at": now})

    def record_command(self, *, rule: ACRule, offline_since: Optional[float], offline_seconds: float,
                       status: str, reason: str, requested_at: float) -> int:
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO command_log (rule_id, phone_mac, ac_id, person, episode_offline_since, "
                "offline_seconds, mode, status, reason, requested_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (rule.rule_id, rule.phone_mac, rule.ac_id, rule.person, offline_since, offline_seconds,
                 rule.mode, status, reason, requested_at),
            )
            return int(cursor.lastrowid)

    def complete_command(self, command_id: int, status: str, result: Any, completed_at: float) -> None:
        with self.connection:
            self.connection.execute("UPDATE command_log SET status=?, result_json=?, completed_at=? WHERE id=?",
                                    (status, json.dumps(result, ensure_ascii=False), completed_at, command_id))


# --------------------------------------------------------------------------- the guard
@dataclass
class Decision:
    rule_id: str
    person: str
    phone_mac: str
    online: bool
    known: bool
    offline_seconds: float
    coverage_ok: bool
    triggered: bool
    mode: str
    status: Optional[str]
    reason: str


class OfflineGuard:
    def __init__(self, config: GuardConfig, reader: PresenceReader, state: StateStore, *,
                 client_factory: Optional[Callable[[], Any]] = None):
        self.config = config
        self.reader = reader
        self.state = state
        self._client_factory = client_factory
        self._client: Any = None

    def evaluate(self, now: Optional[float] = None) -> list[Decision]:
        now = time.time() if now is None else now
        return [self._evaluate_rule(rule, now) for rule in self.config.rules if rule.enabled]

    def _evaluate_rule(self, rule: ACRule, now: float) -> Decision:
        episode = self.reader.presence_episode(rule.phone_mac, now=now, max_gap=self.config.max_coverage_gap_seconds)
        prior = self.state.get_state(rule.rule_id)
        if not episode.known:
            self.state.touch(rule.rule_id, rule.phone_mac, now)
            return Decision(rule.rule_id, rule.person, rule.phone_mac, False, False, 0.0, False, False, rule.mode, None, "phone_never_seen")
        if episode.online:
            self.state.mark_online(rule.rule_id, rule.phone_mac, now)
            return Decision(rule.rule_id, rule.person, rule.phone_mac, True, True, 0.0, True, False, rule.mode, None, "online")

        offline_since = episode.offline_since if episode.offline_since is not None else now
        if prior.get("episode_offline_since") != offline_since:
            self.state.begin_episode(rule.rule_id, rule.phone_mac, offline_since, now)
            prior = self.state.get_state(rule.rule_id)

        sample_times = self.reader.complete_sample_times(offline_since, now)
        effective_since, coverage_ok = effective_offline_since(offline_since, sample_times, now, self.config.max_coverage_gap_seconds)
        offline_seconds = max(0.0, now - effective_since)
        already_acted = bool(prior.get("acted"))
        should_fire = coverage_ok and offline_seconds >= rule.offline_seconds and not already_acted
        if not should_fire:
            self.state.touch(rule.rule_id, rule.phone_mac, now)
            reason = "already_acted" if already_acted else ("coverage_gap" if not coverage_ok else "below_threshold")
            return Decision(rule.rule_id, rule.person, rule.phone_mac, False, True, offline_seconds, coverage_ok, False, rule.mode, prior.get("action_status"), reason)

        status = self._dispatch(rule, offline_since, offline_seconds, now)
        return Decision(rule.rule_id, rule.person, rule.phone_mac, False, True, offline_seconds, coverage_ok, True, rule.mode, status, "threshold_met")

    def _dispatch(self, rule: ACRule, offline_since: float, offline_seconds: float, now: float) -> str:
        minutes = offline_seconds / 60.0
        # Mark acted (autonomous commit) BEFORE the cloud call so a crash mid-send never repeats it.
        if rule.mode == "dry-run":
            self.state.mark_acted(rule.rule_id, rule.phone_mac, STATUS_DRY_RUN, now)
            self.state.record_command(rule=rule, offline_since=offline_since, offline_seconds=offline_seconds,
                                      status=STATUS_DRY_RUN, reason="threshold_met", requested_at=now)
            logger.info("%s[DRY_RUN] would power OFF '%s' (%s) - %s offline %.1f min", LOG_TAG, rule.ac_label, rule.ac_id, rule.person, minutes)
            return STATUS_DRY_RUN

        self.state.mark_acted(rule.rule_id, rule.phone_mac, STATUS_PLANNED, now)
        command_id = self.state.record_command(rule=rule, offline_since=offline_since, offline_seconds=offline_seconds,
                                               status=STATUS_PLANNED, reason="threshold_met", requested_at=now)
        logger.warning("%s[ACTION] powering OFF '%s' (%s) - %s offline %.1f min", LOG_TAG, rule.ac_label, rule.ac_id, rule.person, minutes)
        try:
            result = self._power_off(rule.ac_id)
        except Exception as error:  # noqa: BLE001 - never let a cloud fault crash the loop
            logger.error("%s[CLOUD] power-off failed for '%s': %s", LOG_TAG, rule.ac_id, error)
            self.state.complete_command(command_id, STATUS_ERROR, {"error": str(error)[:200]}, time.time())
            self.state.mark_acted(rule.rule_id, rule.phone_mac, STATUS_ERROR, time.time())
            return STATUS_ERROR
        status = STATUS_CONFIRMED if _looks_confirmed(result) else STATUS_SENT
        self.state.complete_command(command_id, status, _redact_result(result), time.time())
        self.state.mark_acted(rule.rule_id, rule.phone_mac, status, time.time())
        logger.info("%s[CLOUD] power-off %s for '%s'", LOG_TAG, status, rule.ac_id)
        return status

    def _power_off(self, ac_id: str) -> Any:
        return self._ensure_client().set_power(ac_id, False)

    def _ensure_client(self) -> Any:
        if self._client is None:
            if self._client_factory is None:
                raise RuntimeError("No Tornado client is configured for live mode")
            self._client = self._client_factory()
        return self._client


def _looks_confirmed(result: Any) -> bool:
    if isinstance(result, dict):
        if result.get("confirmed") is True:
            return True
        power = result.get("power")
        if power is not None:
            return not bool(power)
    return False


def _redact_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result
    sensitive = {"password", "token", "loginsession", "accesstoken", "access_token", "cookie"}
    return {key: ("***" if key.lower() in sensitive else value) for key, value in result.items()}


# --------------------------------------------------------------------------- cloud wiring
def build_client_factory(config: GuardConfig) -> Callable[[], Any]:
    def factory() -> Any:
        from tornado_ac_client import TornadoACClient

        if not config.credentials_file:
            raise RuntimeError("Live mode requires 'credentials_file' in the configuration")
        credentials = load_credentials(config.credentials_file)
        region = credentials.get("region") or config.region
        client = TornadoACClient(email=credentials["email"], password=credentials["password"], region=region)
        client.login()
        return client

    return factory


# --------------------------------------------------------------------------- CLI
def _format_decision(decision: Decision) -> str:
    if decision.triggered:
        state = f"TRIGGERED ({decision.status})"
    elif decision.online:
        state = "online"
    elif not decision.known:
        state = "phone-not-seen"
    else:
        state = f"offline {decision.offline_seconds / 60.0:.1f}m [{decision.reason}]"
    return f"{decision.person} ({decision.phone_mac}): {state}"


def run_discovery(config: GuardConfig) -> int:
    from tornado_ac_client import TornadoACClient

    if not config.credentials_file:
        logger.error("%s[DISCOVER] no 'credentials_file' configured", LOG_TAG)
        return 2
    credentials = load_credentials(config.credentials_file)
    region = credentials.get("region") or config.region
    client = TornadoACClient(email=credentials["email"], password=credentials["password"], region=region)
    client.login()
    print("Discovered air conditioners:")
    for device in client.list_devices():
        print(f"  id={device.get('id')!r}  name={device.get('name')!r}  online={device.get('online')}  power={device.get('power')}")
    print("\nCopy the relevant id values into the 'ac_id' fields of your config rules.")
    return 0


def _make_guard(config: GuardConfig) -> tuple[OfflineGuard, PresenceReader, StateStore]:
    reader = PresenceReader(config.presence_db)
    state = StateStore(config.state_db)
    factory = build_client_factory(config) if config.has_live_rule else None
    return OfflineGuard(config, reader, state, client_factory=factory), reader, state


def run_loop(config: GuardConfig, *, once: bool = False) -> int:
    guard, reader, state = _make_guard(config)
    logger.info("%s[START] %d rule(s), interval %.0fs, %s", LOG_TAG, len(config.rules),
                config.poll_interval_seconds, "LIVE control enabled" if config.has_live_rule else "dry-run only")
    try:
        while True:
            try:
                for decision in guard.evaluate():
                    logger.info("%s[EVAL] %s", LOG_TAG, _format_decision(decision))
            except Exception as error:  # noqa: BLE001 - keep the loop alive across transient faults
                logger.error("%s[EVAL] evaluation failed: %s", LOG_TAG, error)
            if once:
                return 0
            time.sleep(config.poll_interval_seconds)
    except KeyboardInterrupt:
        logger.info("%s[STOP] interrupted", LOG_TAG)
        return 0
    finally:
        reader.close()
        state.close()


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Power off ACs whose owner's phone has been offline past a threshold.")
    parser.add_argument("--config", required=True, type=Path, help="Path to the guard config JSON")
    parser.add_argument("--discover", action="store_true", help="List the account's ACs and exit")
    parser.add_argument("--once", action="store_true", help="Run a single evaluation pass and exit")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    import sys

    args = parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        logger.error("%s[CONFIG] %s", LOG_TAG, error)
        return 2
    if args.discover:
        try:
            return run_discovery(config)
        except Exception as error:  # noqa: BLE001
            logger.error("%s[DISCOVER] %s", LOG_TAG, error)
            return 1
    try:
        return run_loop(config, once=args.once)
    except FileNotFoundError as error:
        logger.error("%s[DB] %s (is the scanner running?)", LOG_TAG, error)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
