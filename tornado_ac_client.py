"""Minimal synchronous client for the Tornado / AUX (BroadLink DNA) cloud.

Only three capabilities are implemented, the ones the offline guard needs:

* :meth:`TornadoACClient.login`        - authenticate an AUX-family (Tornado WIFI 3) account.
* :meth:`TornadoACClient.list_devices` - discover the account's air conditioners.
* :meth:`TornadoACClient.set_power`    - turn one AC on/off (the guard only ever turns them OFF).

The protocol constants and the request/crypto flow are ported from the open-source
``ha-aux-cloud`` integration (reverse-engineered AUX cloud) and the
``tornado-air-conditioner-control`` project. The AUX cloud is an UNOFFICIAL API: login and
discovery must be validated against a real account (``python ac_offline_guard.py --config
config.json --discover``) before the live power-off path is trusted.

Standard library for HTTP (``urllib``); ``cryptography`` for the login AES-CBC. No other
dependency.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

# --- Protocol constants (from the open-source AUX/BroadLink DNA cloud clients) ---
TIMESTAMP_TOKEN_ENCRYPT_KEY = "kdixkdqp54545^#*"
PASSWORD_ENCRYPT_KEY = "4969fj#k23#"
BODY_ENCRYPT_KEY = "xgx3d*fe3478$ukx"

# Fixed 16-byte AES IV (the vendor stores it as signed bytes).
AES_INITIAL_VECTOR = bytes((byte + 256) % 256 for byte in
    [-22, -86, -86, 58, -69, 88, 98, -94, 25, 24, -75, 119, 29, 22, 21, -86])
AES_BLOCK_SIZE = 16

# The AUX app's public license blob / ids (identical for every account; not a secret).
LICENSE = (
    "PAFbJJ3WbvDxH5vvWezXN5BujETtH/iuTtIIW5CE/SeHN7oNKqnEajgljTcL0fBQQWM0XAAAAAAn"
    "BhJyhMi7zIQMsUcwR/PEwGA3uB5HLOnr+xRrci+FwHMkUtK7v4yo0ZHa+jPvb6djelPP893k7Sag"
    "mffZmOkLSOsbNs8CAqsu8HuIDs2mDQAAAAA="
)
LICENSE_ID = "3c015b249dd66ef0f11f9bef59ecd737"
COMPANY_ID = "48eb1b36cf0202ab2ef07b880ecda60d"

SPOOF_APP_VERSION = "2.2.10.456537160"
SPOOF_USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)"

REGION_URLS = {
    "eu": "https://app-service-deu-f0e9ebbb.smarthomecs.de",
    "usa": "https://app-service-usa-fd7cc04c.smarthomecs.com",
    "cn": "https://app-service-chn-31a93883.ibroadlink.com",
    "rus": "https://app-service-rus-b8bbc3be.smarthomecs.com",
}
DEFAULT_REGION = "usa"

CONTROL_ENDPOINT = "device/control/v2/sdkcontrol"
AC_POWER = "pwr"  # 0 = off, 1 = on


class TornadoError(RuntimeError):
    """Any failure talking to the Tornado/AUX cloud."""


def _aes_cbc_zero_padded(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    padded = plaintext + b"\x00" * (-len(plaintext) % AES_BLOCK_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


class TornadoACClient:
    def __init__(self, email: str, password: str, region: str = DEFAULT_REGION, *, timeout: float = 15.0):
        self.email = email
        self._password = password
        self.region = (region or DEFAULT_REGION).lower()
        self.base_url = REGION_URLS.get(self.region, REGION_URLS["eu"])
        self.timeout = timeout
        self.loginsession: Optional[str] = None
        self.userid: Optional[str] = None
        self._devices: dict[str, dict[str, Any]] = {}

    # -- HTTP plumbing -------------------------------------------------------
    def _headers(self, **overrides: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/x-java-serialized-object",
            "licenseId": LICENSE_ID,
            "lid": LICENSE_ID,
            "language": "en",
            "appVersion": SPOOF_APP_VERSION,
            "User-Agent": SPOOF_USER_AGENT,
            "system": "android",
            "appPlatform": "android",
            "loginsession": self.loginsession or "",
            "userid": self.userid or "",
        }
        headers.update(overrides)
        return headers

    def _post(self, endpoint: str, *, data: Optional[dict[str, Any]] = None, data_raw: Optional[bytes] = None,
              params: Optional[dict[str, Any]] = None, header_overrides: Optional[dict[str, str]] = None) -> dict[str, Any]:
        url = f"{self.base_url}/{endpoint}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        if data_raw is not None:
            body: bytes = data_raw
        elif data is not None:
            body = json.dumps(data, separators=(",", ":")).encode()
        else:
            body = b""
        request = urllib.request.Request(url, data=body, method="POST", headers=self._headers(**(header_overrides or {})))
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                text = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            raise TornadoError(f"{endpoint} returned HTTP {error.code}") from error
        except (urllib.error.URLError, OSError) as error:
            raise TornadoError(f"request to {endpoint} failed: {error}") from error
        if not text:
            return {}
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise TornadoError(f"{endpoint} returned invalid JSON") from error
        return payload if isinstance(payload, dict) else {}

    # -- authentication ------------------------------------------------------
    def login(self) -> None:
        current_time = time.time()
        sha_password = hashlib.sha1(f"{self._password}{PASSWORD_ENCRYPT_KEY}".encode()).hexdigest()
        payload = {"email": self.email, "password": sha_password, "companyid": COMPANY_ID, "lid": LICENSE_ID}
        json_payload = json.dumps(payload, separators=(",", ":"))
        token = hashlib.md5(f"{json_payload}{BODY_ENCRYPT_KEY}".encode()).hexdigest()
        aes_key = hashlib.md5(f"{current_time}{TIMESTAMP_TOKEN_ENCRYPT_KEY}".encode()).digest()
        encrypted = _aes_cbc_zero_padded(aes_key, AES_INITIAL_VECTOR, json_payload.encode())
        result = self._post("account/login", data_raw=encrypted, header_overrides={"timestamp": f"{current_time}", "token": token})
        if result.get("status") != 0:
            raise TornadoError(f"login failed (status={result.get('status')})")
        session = result.get("loginsession")
        user_id = result.get("userid")
        if not isinstance(session, str) or not isinstance(user_id, str):
            raise TornadoError("login response did not include a session identity")
        self.loginsession = session
        self.userid = user_id

    def _require_login(self) -> None:
        if not self.loginsession or not self.userid:
            raise TornadoError("client is not logged in")

    # -- discovery -----------------------------------------------------------
    def get_families(self) -> list[dict[str, Any]]:
        self._require_login()
        result = self._post("appsync/group/member/getfamilylist")
        data = result.get("data")
        families = data.get("familyList") if isinstance(data, dict) else None
        if result.get("status") != 0 or not isinstance(families, list):
            raise TornadoError("could not list families")
        return families

    def _get_family_devices(self, familyid: str, shared: bool) -> list[dict[str, Any]]:
        endpoint = ("appsync/group/sharedev/querylist?querytype=shared" if shared else "appsync/group/dev/query?action=select")
        body = '{"endpointId":""}' if shared else '{"pids":[]}'
        result = self._post(endpoint, data_raw=body.encode(), header_overrides={"familyid": familyid})
        if result.get("status") != 0:
            raise TornadoError("could not list devices for family")
        data = result.get("data")
        if not isinstance(data, dict):
            return []
        if isinstance(data.get("endpoints"), list):
            return [d for d in data["endpoints"] if isinstance(d, dict)]
        if isinstance(data.get("shareFromOther"), list):
            return [item["devinfo"] for item in data["shareFromOther"] if isinstance(item, dict) and isinstance(item.get("devinfo"), dict)]
        return []

    def _query_states(self, devices: list[dict[str, Any]]) -> dict[str, int]:
        if not devices:
            return {}
        directive = {
            "header": {"namespace": "DNA.QueryState", "name": "queryState", "messageType": "controlgw.batch",
                       "interfaceVersion": "2", "senderId": "sdk", "messageId": f"{self.userid or ''}-{int(time.time())}"},
            "payload": {"studata": [{"did": d.get("endpointId"), "devSession": d.get("devSession")} for d in devices], "msgtype": "batch"},
        }
        result = self._post("device/control/v2/querystate", data={"directive": directive})
        payload = (result.get("event") or {}).get("payload") if isinstance(result.get("event"), dict) else None
        records = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return {}
        return {str(rec.get("did")): int(rec.get("state", 0)) for rec in records if isinstance(rec, dict) and rec.get("did") is not None}

    def list_devices(self, *, refresh: bool = False, read_power: bool = True) -> list[dict[str, Any]]:
        """Discover all account ACs. Caches raw device records for control."""
        self._require_login()
        if self._devices and not refresh:
            return [self._normalize(d, read_power=False) for d in self._devices.values()]
        raw_devices: list[dict[str, Any]] = []
        for family in self.get_families():
            family_id = family.get("familyid")
            if not family_id:
                continue
            for shared in (False, True):
                try:
                    raw_devices.extend(self._get_family_devices(family_id, shared))
                except TornadoError:
                    continue  # a single family/scope failure must not hide the rest
        self._devices = {}
        for device in raw_devices:
            endpoint_id = device.get("endpointId")
            if isinstance(endpoint_id, str) and endpoint_id:
                self._devices[endpoint_id] = device
        states = self._query_states(list(self._devices.values()))
        for endpoint_id, device in self._devices.items():
            device["_online"] = states.get(endpoint_id, 0) == 1
        return [self._normalize(d, read_power=read_power) for d in self._devices.values()]

    def _normalize(self, device: dict[str, Any], *, read_power: bool) -> dict[str, Any]:
        endpoint_id = device.get("endpointId")
        online = bool(device.get("_online"))
        power: Optional[bool] = None
        if read_power and online and isinstance(endpoint_id, str):
            try:
                state = self.get_state(endpoint_id)
                if AC_POWER in state:
                    power = bool(state[AC_POWER])
            except TornadoError:
                power = None
        return {"id": endpoint_id, "name": device.get("friendlyName"), "model": device.get("productId"),
                "product_id": device.get("productId"), "mac": device.get("mac"), "online": online, "power": power}

    # -- state + control -----------------------------------------------------
    def get_state(self, device_id: str) -> dict[str, Any]:
        device = self._device(device_id)
        event = self._act(device, "get", [], [])
        return _parse_std_data(event)

    def set_power(self, device_id: str, on: bool) -> dict[str, Any]:
        """Turn an AC on/off. The guard only ever calls this with ``on=False``."""
        device = self._device(device_id)
        value = 1 if on else 0
        event = self._act(device, "set", [AC_POWER], [[{"idx": 1, "val": value}]])
        echoed = _parse_std_data(event)
        power = bool(echoed[AC_POWER]) if AC_POWER in echoed else None
        return {"confirmed": power is not None and power == on, "power": power, "raw": echoed}

    def _device(self, device_id: str) -> dict[str, Any]:
        if device_id not in self._devices:
            self.list_devices(refresh=True, read_power=False)
        device = self._devices.get(device_id)
        if device is None:
            raise TornadoError(f"unknown device id: {device_id!r}")
        return device

    def _act(self, device: dict[str, Any], act: str, params: list[str], vals: list[Any]) -> dict[str, Any]:
        directive = _build_control_directive(device, act, params, vals)
        result = self._post(CONTROL_ENDPOINT, data={"directive": directive}, params={"license": LICENSE})
        event = result.get("event")
        if not isinstance(event, dict):
            raise TornadoError("device control response has no event")
        status = (event.get("payload") or {}).get("status") if isinstance(event.get("payload"), dict) else None
        if status not in (None, 0):
            raise TornadoError(f"device control failed (status={status})")
        return event


# --- pure directive/response helpers ---------------------------------------
def _decode_cookie(value: Any) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise TornadoError("device is missing its control cookie")
    encoded = value.strip()
    encoded += "=" * (-len(encoded) % 4)
    try:
        return json.loads(base64.b64decode(encoded, validate=True).decode())
    except Exception as error:  # noqa: BLE001
        raise TornadoError("could not decode device control cookie") from error


def _build_control_directive(device: dict[str, Any], act: str, params: list[str], vals: list[Any]) -> dict[str, Any]:
    cookie = _decode_cookie(device.get("cookie"))
    terminal_id = cookie.get("terminalid")
    aes_key = cookie.get("aeskey")
    if not terminal_id or not aes_key:
        raise TornadoError("device cookie is missing control metadata")
    for field in ("endpointId", "productId", "mac", "devSession", "devicetypeFlag"):
        if field not in device:
            raise TornadoError(f"device metadata is missing {field}")
    mapped_cookie = base64.b64encode(json.dumps({
        "device": {"id": terminal_id, "key": aes_key, "devSession": device["devSession"], "aeskey": aes_key,
                   "did": device["endpointId"], "pid": device["productId"], "mac": device["mac"]}
    }, separators=(",", ":")).encode()).decode()
    now = int(time.time())
    directive: dict[str, Any] = {
        "header": {"namespace": "DNA.KeyValueControl", "name": "KeyValueControl", "interfaceVersion": "2",
                   "senderId": "sdk", "messageId": f"{device['endpointId']}-{now}", "timstamp": f"{now}"},  # vendor misspelling, verbatim
        "endpoint": {
            "devicePairedInfo": {"did": device["endpointId"], "pid": device["productId"], "mac": device["mac"],
                                 "devicetypeflag": device["devicetypeFlag"], "cookie": mapped_cookie},
            "endpointId": device["endpointId"], "cookie": {}, "devSession": device["devSession"],
        },
        "payload": {"act": act, "params": list(params), "vals": list(vals), "did": device["endpointId"]},
    }
    if len(params) == 1 and act == "get":
        directive["payload"]["vals"] = [[{"val": 0, "idx": 1}]]
    return directive


def _parse_std_data(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload") if isinstance(event, dict) else None
    data = payload.get("data") if isinstance(payload, dict) else None
    if not data:
        return {}
    response = json.loads(data) if isinstance(data, str) else data
    if not isinstance(response, dict):
        return {}
    if "params" not in response or "vals" not in response:
        return dict(response)
    parsed: dict[str, Any] = {}
    for index, param in enumerate(response.get("params", [])):
        try:
            parsed[param] = response["vals"][index][0]["val"]
        except (IndexError, KeyError, TypeError):
            continue
    return parsed
