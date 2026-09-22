# Dad-as-a-Service

*The dad who turns off the AC after you leave.* Automatically powers off an air conditioner when the
person it belongs to has been off the home Wi‑Fi longer than a threshold (15 minutes by default).

A small, self‑contained tool: a LAN scanner watches which phones are on the home network, and a guard
powers off a mapped [Tornado / AUX](https://en.wikipedia.org/wiki/AUX_Group) (BroadLink DNA cloud) air
conditioner when its owner's phone has been off the network longer than a threshold (15 minutes by
default). No app on the phones, no cloud webhook — just the LAN and the vendor cloud.

> The guard **only ever turns an AC off**, never on. It defaults to **dry‑run** (detect and log only);
> a real power‑off requires you to explicitly opt in.

## How it works

```
lan_scanner.py  ──ARP/ping sweep every ~2 min──▶  presence.sqlite3
                                                   ├─ sightings(mac → last_seen)   "who is on the LAN"
                                                   └─ scans(observed_at)           coverage heartbeat
                                                          │  (read‑only)
ac_offline_guard.py  ──reads presence, decides──▶  tornado_ac_client.py  ──▶  AUX cloud (power off)
                     └─ ac_guard_state.sqlite3  (per‑episode idempotency + audit log)
```

Two independent processes:

- **`lan_scanner.py`** pings the local `/24` (so sleeping phones answer), reads the OS neighbour table
  (`arp -a` / `ip neigh`), and records every hardware address it sees into `presence.sqlite3`. Run it
  continuously on a machine that stays on the home network (a mini‑PC, a NAS, an always‑on display).
- **`ac_offline_guard.py`** reads that database, and for each rule (a phone MAC → an AC) decides whether
  the phone has been offline past the threshold. If so, it powers the AC off through the vendor cloud.

### Safety

- **Coverage check.** The guard fires only when it has *continuous* scan coverage across the whole
  offline window (the `scans` heartbeat). If the scanner stalls, the gap resets the clock, and with no
  fresh coverage nothing fires — a dead scanner can never look like a long absence.
- **At most once per absence.** The action fires once per offline episode and re‑arms only after the
  phone reconnects. The "acted" flag is committed *before* the cloud call, so a crash mid‑send cannot
  repeat it.
- **Off only.** `allow_power_on` is rejected outright.
- **Dry‑run by default.** Going live requires a `live` rule, a real `ac_id` (not a placeholder), and
  `acknowledge_live_control: true`.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp credentials.example.json credentials.json     # fill in your AUX/Tornado app email + password
cp config.example.json config.json               # fill in each person's phone MAC

# 1) start the scanner (leave it running; --once for a single scan)
python lan_scanner.py --db presence.sqlite3 --interval 120

# 2) discover your ACs and copy each id into config.json's "ac_id" fields
python ac_offline_guard.py --config config.json --discover

# 3) run the guard (dry-run first; watch the log / ac_guard_state.sqlite3 command_log)
python ac_offline_guard.py --config config.json
```

Finding a phone's home‑network MAC: on the phone, open the Wi‑Fi network details — the "private
address" / "randomized MAC" shown there is the stable per‑network address to put in `phone_mac`
(it stays constant for this network even though it differs from the hardware MAC).

### Going live

Once dry‑run looks right, set `acknowledge_live_control: true` and change the relevant rule's `mode`
to `"live"` (or the top‑level `mode`), with a real `ac_id`. Start with one AC to confirm the power‑off
works before enabling the rest.

## Configuration (`config.json`)

| Field | Meaning |
|---|---|
| `credentials_file` | JSON file with your AUX account (`email`, `password`, `region`). Git‑ignored. |
| `presence_db` | The SQLite database the scanner writes and the guard reads. |
| `state_db` | The guard's own database (episode state + command audit log). |
| `region` | AUX cloud region: `usa`, `eu`, `cn`, `rus`. Try `usa` first. |
| `poll_interval_seconds` | How often the guard evaluates (default 60). |
| `max_coverage_gap_seconds` | Largest gap between scans still counted as continuous coverage (default 300 — tolerate one missed ~120 s scan). |
| `default_offline_minutes` | Default threshold before a power‑off (default 15). |
| `mode` | Global `dry-run` / `live`. |
| `acknowledge_live_control` | Must be `true` (a real JSON boolean) to allow any live power‑off. |
| `rules[]` | `rule_id`, `person`, `phone_mac`, `ac_id`, `ac_label`, `offline_minutes`, `mode`, `enabled`. |

## Tests

```bash
pip install pytest
pytest -q
```

Covers the coverage math, config validation, end‑to‑end evaluation (fires once past the threshold,
never below it, refuses on a coverage gap or a stale monitor, re‑arms after reconnect, powers off at
most once and never on), crash‑safety, and the scanner's database round‑trip.

## Limitations & notes

- The AUX/Tornado cloud API is **unofficial** (reverse‑engineered). Validate login and power‑off
  against a real account (`--discover`, then one live AC) before trusting it. Reliability varies by
  model.
- Some phones rotate their randomized MAC per network. If a phone changes its home‑network MAC, its
  rule stops matching — which fails safe (it won't power anything off), but you'll need to update the
  MAC.
- A VPN or aggressive battery saver can make a phone look absent. The grace window and the coverage
  check absorb brief drops, not a phone that genuinely stops answering.
- Detection is by LAN presence only; anyone on the network (guests, other devices) is irrelevant
  unless their MAC is in a rule.

## License

MIT — see [LICENSE](LICENSE).
