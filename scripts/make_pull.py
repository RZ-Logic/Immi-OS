#!/usr/bin/env python3
"""Pull live Make scenario blueprints into blueprints/ (read-only, GET only).

Flow:
  1. Read MAKE_API_TOKEN, MAKE_ZONE and MAKE_TEAM_ID from .env (process
     environment overrides the file).
  2. GET /scenarios?teamId=...  (paged with pg[offset] / pg[limit], sorted by
     id, until an empty page, so a server-side page cap cannot truncate it).
     An empty listing while snapshot files exist is refused unless
     --allow-empty, because it would delete the whole snapshot.
  3. For each scenario GET /scenarios/{id}/blueprint?draft=false (live), and
     unless --skip-draft-check, GET ...?draft=true to flag unpublished edits.
     A 404 on the live fetch (a concept scenario never published) is recorded
     as live_missing with no file, not a failure.
  4. Secret-scan every live blueprint in memory (secret_scan.scan_obj). A
     blueprint with any finding is withheld: never written, the manifest
     records only the pattern types and JSON-path locations. The one
     exception is audit/secret_allowlist.json: a blueprint whose ONLY findings
     are exactly matched by pinned entries (a Make webhook URL in the
     mapper.webhook of a Bland send-call module) is written, and the manifest
     lists them under allowlisted_findings. The Logger hook (logger_hook in
     the same file, Option C) is allowed only as the bare url field of a
     Logger call (R6), in any scenario, while audit/webhooks.json registers
     it with protection api_key.
     When the hook list is readable, each allowlisted URL is also compared in
     memory with the hook it must point at (the hook of the scenario a pinned
     entry names, or the Logger hook), and a mismatch withholds the blueprint.
  5. GET /hooks?teamId=... (read only, paged). The manifest keeps per hook only
     id, name, the scenario IDs it serves, enabled, apikey_count, ip_restricted
     and headers, the Logger hook included, so check L reads its apikey_count
     like F1 does. Never the URL, the token or any key material. A 403 or 401 (the token
     lacks Webhooks: View, scope hooks:read) records hooks: null with a note and
     does not fail the pull.
  6. Only after every request succeeded, write in three steps:
     a. stage every changed blueprint and the new manifest as temp files
        (a failure here removes the temps and leaves the snapshot as it was),
     b. remove manifest.json, so a snapshot interrupted from here on has no
        manifest and the audit refuses to run on it,
     c. move the staged blueprints into place, delete stale files (scenarios
        no longer returned, older copies of withheld or renamed scenarios),
        and move the new manifest into place last.
     Blueprint files: indent 2, key order as returned, UTF-8, LF, newline at EOF.

A failed request aborts the pull before anything on disk changes. A write
failure after step b leaves no manifest.json, so a later audit stops with an
input error instead of auditing a mixed snapshot. Volatile data (pull time,
version, last edit, scheduling) lives in the manifest only, so a blueprint
file changes only when the blueprint itself changes. current_version and
last_edit come from the blueprint response and describe the newest version,
draft or published (see draft_differs), not necessarily the live one.

Exit codes:
  0  pull complete, nothing withheld
  1  pull complete, at least one blueprint withheld for a secret finding
  2  configuration or usage error (missing .env key, bad zone, bad team id)
  3  API, network or filesystem failure, or a refused empty listing. A
     request failure writes nothing. A write failure says whether the
     snapshot changed, and if it did, manifest.json is gone.

The token is never printed. Standard library only.
"""

from __future__ import annotations

import argparse
import email.utils
import http.client
import json
import os
import re
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secret_scan  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ENV = os.path.join(ROOT, ".env")
DEFAULT_OUT = os.path.join(ROOT, "blueprints")

ZONES = ("eu1", "eu2", "us1", "us2")
REQUIRED_KEYS = ("MAKE_API_TOKEN", "MAKE_ZONE", "MAKE_TEAM_ID")
PAGE_LIMIT = 100
MAX_PAGES = 1000
TIMEOUT_S = 30.0
MAX_RETRIES = 5
MAX_WAIT_S = 120.0
BACKOFF_CAP_S = 60.0
# Make rate limits per organization per minute and documents no Retry-After,
# so a 429 without the header waits out a full window before retrying.
RATE_WINDOW_S = 60.0
REDACT_MIN_FRAGMENT = 6
MANIFEST = "manifest.json"
BLUEPRINT_FILE = re.compile(r"^(?P<slug>.+)__(?P<id>\d+)\.json$")
SLUG_MAX = 80

EXIT_OK = 0
EXIT_WITHHELD = 1
EXIT_CONFIG = 2
EXIT_FAILURE = 3


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class ConfigError(Exception):
    """Bad or missing configuration. Messages name keys, never values."""


class PullError(Exception):
    """API, network or filesystem failure."""


class NotFound(PullError):
    """HTTP 404."""


class Forbidden(PullError):
    """HTTP 403."""


class Unauthorized(PullError):
    """HTTP 401. Make answers a token that lacks the scope of an endpoint with 401 IM001
    (measured on GET /hooks 2026-10-28), not 403."""


class TransientError(Exception):
    """Network error or timeout raised by a transport; retried."""


class SnapshotWriteError(PullError):
    """Filesystem failure in the write phase. disk_changed says whether the
    snapshot was touched (if so, manifest.json has been removed)."""

    def __init__(self, exc_name: str, disk_changed: bool):
        self.exc_name = exc_name
        self.disk_changed = disk_changed
        super().__init__(exc_name)


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def parse_env(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines. Ignores blanks and # comments, strips matching quotes."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


@dataclass(frozen=True)
class Config:
    token: str = field(repr=False)
    zone: str
    team_id: str

    @property
    def base_url(self) -> str:
        return f"https://{self.zone}.make.com/api/v2"


def load_config(env_path: str, environ: dict | None = None) -> Config:
    values: dict[str, str] = {}
    if os.path.isfile(env_path):
        try:
            with open(env_path, encoding="utf-8-sig") as fh:
                values = parse_env(fh.read())
        except OSError as exc:
            raise ConfigError(f"cannot read the env file ({type(exc).__name__})") from None
    environ = environ if environ is not None else {}
    for key in REQUIRED_KEYS:
        if environ.get(key):
            values[key] = environ[key]
    missing = [k for k in REQUIRED_KEYS if not values.get(k, "").strip()]
    if missing:
        where = env_path if os.path.isfile(env_path) else f"{env_path} (file not found)"
        raise ConfigError(f"missing {', '.join(missing)} in {where}")
    zone = values["MAKE_ZONE"].strip().lower()
    if zone not in ZONES:
        raise ConfigError(f"MAKE_ZONE must be one of {', '.join(ZONES)}")
    team_id = values["MAKE_TEAM_ID"].strip()
    if not team_id.isdigit():
        raise ConfigError("MAKE_TEAM_ID must be a positive integer")
    token = values["MAKE_API_TOKEN"].strip()
    if any(c.isspace() for c in token):
        raise ConfigError("MAKE_API_TOKEN must not contain whitespace")
    return Config(token=token, zone=zone, team_id=team_id)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    headers: dict
    body: bytes


Transport = Callable[[str, str, dict, float], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would forward the Authorization header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_transport(method: str, url: str, headers: dict, timeout: float) -> Response:
    """Default transport. GET only, no redirects, no proxies beyond urllib defaults."""
    if method != "GET":
        raise ValueError("make_pull only issues GET requests")
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read())
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read()
        except Exception:  # noqa: BLE001
            pass
        hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return Response(exc.code, hdrs, body)
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
        # HTTPException covers IncompleteRead and RemoteDisconnected during read().
        reason = getattr(exc, "reason", exc)
        raise TransientError(type(reason).__name__) from None


def retry_after_seconds(value: str | None, now: float | None = None) -> float | None:
    """Parse Retry-After (delta seconds or HTTP date). None if absent or unparseable."""
    if not value:
        return None
    value = value.strip()
    if re.fullmatch(r"\d+(\.\d+)?", value):
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = time.time() if now is None else now
    return max(0.0, dt.timestamp() - now)


class MakeClient:
    def __init__(self, config: Config, transport: Transport | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 max_retries: int = MAX_RETRIES, timeout: float = TIMEOUT_S):
        self._config = config
        self._transport = transport or urllib_transport
        self._sleep = sleep
        self._max_retries = max_retries
        self._timeout = timeout
        self.request_count = 0

    def _headers(self) -> dict:
        return {
            "Authorization": f"Token {self._config.token}",
            "Accept": "application/json",
            "User-Agent": "immi-os-make-pull/1.0",
        }

    def get_json(self, path: str, params: list[tuple[str, str]]) -> dict:
        url = f"{self._config.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        attempt = 0
        while True:
            self.request_count += 1
            try:
                resp = self._transport("GET", url, self._headers(), self._timeout)
            except TransientError as exc:
                if attempt >= self._max_retries:
                    raise PullError(f"GET {path}: network error ({exc}) after {attempt + 1} attempts") from None
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue

            if resp.status == 200:
                try:
                    data = json.loads(resp.body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise PullError(f"GET {path}: response is not valid JSON") from None
                if not isinstance(data, dict):
                    raise PullError(f"GET {path}: response is not a JSON object")
                return data

            if resp.status == 429 or resp.status >= 500:
                if attempt >= self._max_retries:
                    raise PullError(f"GET {path}: HTTP {resp.status} after {attempt + 1} attempts")
                wait = None
                if resp.status == 429:
                    wait = retry_after_seconds(resp.headers.get("retry-after"))
                    if wait is None:
                        # Per-minute budget shared with the MCP connector and
                        # any other client in the org: wait out the window.
                        wait = max(RATE_WINDOW_S, self._backoff(attempt))
                if wait is None:
                    wait = self._backoff(attempt)
                self._sleep(min(max(wait, 0.0), MAX_WAIT_S))
                attempt += 1
                continue

            # On 401/403 only the error code is shown: an auth error message
            # may echo part of the token.
            detail = self._error_detail(resp.body, code_only=resp.status in (401, 403))
            msg = f"GET {path}: HTTP {resp.status}{detail}"
            if resp.status in (401, 403):
                msg += " (check the token is valid and has scenarios:read and teams:read)"
            if resp.status == 404:
                raise NotFound(msg)
            if resp.status == 403:
                raise Forbidden(msg)
            if resp.status == 401:
                raise Unauthorized(msg)
            raise PullError(msg)

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(BACKOFF_CAP_S, float(2 ** attempt))

    def _error_detail(self, body: bytes, code_only: bool = False) -> str:
        """Make error code and message only, token stripped, length capped."""
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return ""
        if not isinstance(data, dict):
            return ""
        keys = ("code",) if code_only else ("code", "message")
        parts = [str(data[k]) for k in keys if isinstance(data.get(k), (str, int))]
        if not parts:
            return ""
        text = redact(" ".join(parts), self._config.token)[:200]
        return f" [{text}]"


def redact(text: str, token: str | None) -> str:
    """Replace the token and any fragment of it of REDACT_MIN_FRAGMENT or more
    characters (hard rule 4: never print a token, not even partially)."""
    if not token:
        return text
    text = text.replace(token, "<redacted>")
    n = len(token)
    for size in range(n - 1, REDACT_MIN_FRAGMENT - 1, -1):
        for i in range(n - size + 1):
            frag = token[i:i + size]
            if frag in text:
                text = text.replace(frag, "<redacted>")
    return text


# --------------------------------------------------------------------------
# Make API calls
# --------------------------------------------------------------------------

def list_scenarios(client: MakeClient, team_id: str, page_limit: int = PAGE_LIMIT) -> list[dict]:
    """All scenarios for the team, paged by pg[offset]/pg[limit], sorted by id ascending.

    Pages until an empty page. A short page is not taken as the end, because
    the server may cap pg[limit] below the requested value without saying so.
    """
    out: list[dict] = []
    seen: set[int] = set()
    offset = 0
    for _ in range(MAX_PAGES):
        data = client.get_json("/scenarios", [
            ("teamId", team_id),
            ("pg[offset]", str(offset)),
            ("pg[limit]", str(page_limit)),
            ("pg[sortBy]", "id"),
            ("pg[sortDir]", "asc"),
        ])
        page = data.get("scenarios")
        if not isinstance(page, list):
            raise PullError("GET /scenarios: response has no 'scenarios' list")
        for item in page:
            if not isinstance(item, dict):
                raise PullError("GET /scenarios: scenario entry is not an object")
            sid = item.get("id")
            if not isinstance(sid, int) or isinstance(sid, bool) or sid <= 0:
                raise PullError("GET /scenarios: scenario entry has no integer id")
            if sid in seen:
                raise PullError(f"GET /scenarios: scenario {sid} returned twice (pagination not honoured)")
            seen.add(sid)
            out.append(item)
        if not page:
            return out
        offset += len(page)
    raise PullError(f"GET /scenarios: more than {MAX_PAGES} pages, aborting")


def get_blueprint(client: MakeClient, scenario_id: int, draft: bool) -> dict | None:
    """The 'response' object of GET /scenarios/{id}/blueprint (blueprint, scheduling, version, last_edit).

    With draft=True, Make returns blueprint: null when the scenario has no separate draft
    (measured 2026-10-28). That case returns None, meaning the draft equals live.
    """
    data = client.get_json(f"/scenarios/{scenario_id}/blueprint",
                           [("draft", "true" if draft else "false")])
    payload = data.get("response")
    if draft and isinstance(payload, dict) and payload.get("blueprint") is None:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("blueprint"), dict):
        raise PullError(f"GET /scenarios/{scenario_id}/blueprint: response has no blueprint object")
    return payload


HOOKS_NOTE = ("GET /hooks returned {status}: the read token lacks Webhooks: View (scope hooks:read). "
              "Check F1 (API key on the hook) cannot see hook auth state until the scope is added")
# Names under which a hook's API key list could appear in GET /hooks. The public docs do not
# document this field (checked 2026-10-28), so only these names are read and anything else
# leaves apikey_count null (unknown) instead of guessing a zero.
_APIKEY_LIST_NAMES = ("keys", "keyids", "apikeys", "keychains", "apikeyids")
_APIKEY_SCALAR_NAMES = ("keyid", "apikeyid", "keychainid", "apikey")
# Guesses too (inferred, unverified). The IP field name is still unconfirmed, so ip_restricted may stay null.
_IP_NAMES = ("iprestrict", "iprestrictions", "iprestriction", "allowedips", "allowedip", "ipwhitelist", "ipallowlist", "ips", "ip",
             "ipaddresses")


def list_hooks(client: MakeClient, team_id: str, page_limit: int = PAGE_LIMIT) -> list[dict]:
    """All hooks for the team (GET /hooks, read only). The raw objects carry the hook URL and
    token, so they stay in memory and never reach disk (use summarize_hooks).

    Asks for pages with pg[offset]/pg[limit] until an empty page. The documented parameters of
    this endpoint do not include pg, so a server that ignores them returns the same hooks again:
    a repeated hook ID ends the listing instead of failing."""
    out: list[dict] = []
    seen: set[int] = set()
    offset = 0
    for _ in range(MAX_PAGES):
        data = client.get_json("/hooks", [
            ("teamId", team_id),
            ("pg[offset]", str(offset)),
            ("pg[limit]", str(page_limit)),
        ])
        page = data.get("hooks")
        if not isinstance(page, list):
            raise PullError("GET /hooks: response has no 'hooks' list")
        fresh = 0
        for item in page:
            if not isinstance(item, dict):
                raise PullError("GET /hooks: hook entry is not an object")
            hid = item.get("id")
            if not isinstance(hid, int) or isinstance(hid, bool) or hid <= 0:
                raise PullError("GET /hooks: hook entry has no integer id")
            if hid in seen:
                continue
            seen.add(hid)
            out.append(item)
            fresh += 1
        if not page or fresh == 0:
            return out
        offset += len(page)
    raise PullError(f"GET /hooks: more than {MAX_PAGES} pages, aborting")


def _hook_data(h: dict) -> dict:
    d = h.get("data")
    return d if isinstance(d, dict) else {}


def _lookup(h: dict, names: tuple[str, ...]) -> tuple[bool, object]:
    """(found, value) for the first key of the hook or its data object whose lower-cased name is in names."""
    for src in (_hook_data(h), h):
        for k, v in src.items():
            if isinstance(k, str) and k.lower() in names:
                return True, v
    return False, None


def _is_real_key(v: object) -> bool:
    """One entry of a key list or a scalar key field that stands for a configured, enabled key.
    A null, 0, "0", empty string or object, boolean, or a key marked disabled is not evidence of a key.
    The guessed field names are still unverified, so this errs towards 0 (a FAIL), never towards a pass."""
    if isinstance(v, bool) or v is None:
        return False
    if isinstance(v, int):
        return v > 0
    if isinstance(v, str):
        return v.strip() not in ("", "0")
    if isinstance(v, dict):
        if not v or v.get("enabled") is False or v.get("disabled") is True or v.get("active") is False:
            return False
        return any(_is_real_key(x) for x in v.values() if not isinstance(x, (dict, list)))
    return False


def hook_apikey_count(h: dict) -> int | None:
    """Number of API keys configured on the hook, or None when the response has no field for it.
    Only the count is returned, never the keys. Only real, enabled entries count (see _is_real_key)."""
    # Measured on GET /hooks 2026-10-29: data.authenticationMethod.apikey is a list of keychain key IDs
    # (integers, not secrets), [] when no key is set.
    data = h.get("data")
    auth = data.get("authenticationMethod") if isinstance(data, dict) else None
    if isinstance(auth, dict) and "apikey" in auth:
        keys = auth.get("apikey")
        if isinstance(keys, list):
            return sum(1 for x in keys if isinstance(x, int) and not isinstance(x, bool) and x > 0)
        return 0 if keys is None else None
    found, v = _lookup(h, _APIKEY_LIST_NAMES)
    if found:
        if isinstance(v, list):
            return sum(1 for x in v if _is_real_key(x))
        if v is None:
            return 0
    found, v = _lookup(h, _APIKEY_SCALAR_NAMES)
    if found:
        return 1 if _is_real_key(v) else 0
    return None


def hook_ip_restricted(h: dict) -> bool | None:
    found, v = _lookup(h, _IP_NAMES)
    if not found:
        return None
    return bool(v)


def summarize_hooks(raw: list[dict], blueprint_hooks: dict[int, set[int]] | None = None) -> list[dict]:
    """Manifest rows from raw hooks: id, name, scenario_ids, enabled, apikey_count, ip_restricted,
    headers. blueprint_hooks maps hook ID -> scenario IDs whose live trigger names it, merged with
    the scenarioId the hook list reports."""
    out = []
    for h in sorted(raw, key=lambda x: x["id"]):
        ids = set((blueprint_hooks or {}).get(h["id"], set()))
        sc = h.get("scenarioId")
        if isinstance(sc, int) and not isinstance(sc, bool):
            ids.add(sc)
        headers = _hook_data(h).get("headers")
        out.append({
            "id": h["id"],
            "name": h.get("name") if isinstance(h.get("name"), str) else None,
            "scenario_ids": sorted(ids),
            "enabled": h.get("enabled") if isinstance(h.get("enabled"), bool) else None,
            "apikey_count": hook_apikey_count(h),
            "ip_restricted": hook_ip_restricted(h),
            "headers": headers if isinstance(headers, bool) else None,
        })
    return out


def fetch_hooks(client: MakeClient, team_id: str) -> tuple[list[dict] | None, str | None]:
    """(raw hooks, None), or (None, note) when the token lacks the scope. Make answers that with
    403 per its docs and with 401 IM001 in practice (measured 2026-10-28, the same token had just
    read every scenario), so both mean "scope missing" on this endpoint only."""
    try:
        return list_hooks(client, team_id), None
    except Forbidden:
        return None, HOOKS_NOTE.format(status=403)
    except Unauthorized:
        return None, HOOKS_NOTE.format(status=401)


def trigger_hook_id(blueprint: dict) -> int | None:
    flow = blueprint.get("flow") if isinstance(blueprint, dict) else None
    trig = flow[0] if isinstance(flow, list) and flow and isinstance(flow[0], dict) else None
    params = trig.get("parameters") if trig else None
    hid = params.get("hook") if isinstance(params, dict) else None
    return hid if isinstance(hid, int) and not isinstance(hid, bool) else None


def _hook_matches_token(h: dict, tokens: list[str]) -> bool:
    """In-memory comparison of a literal URL's token with the hook's own (udid or url). Every token
    must match, so a second, foreign token in the same field cannot ride on the first."""
    own = h.get("udid") if isinstance(h.get("udid"), str) else ""
    url = h.get("url") if isinstance(h.get("url"), str) else ""
    return bool(tokens) and all(t and (t == own or url.rstrip("/").endswith("/" + t)) for t in tokens)


_FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")


def hook_field_names(raw: list[dict]) -> list[str]:
    """Names only (never values) of the fields GET /hooks returned, top level and under data, so the API
    key and IP field names can be confirmed from the first scoped pull."""
    names: set[str] = set()
    for h in raw:
        names.update(k for k in h if isinstance(k, str) and _FIELD_NAME.match(k))
        names.update("data." + k for k in _hook_data(h) if isinstance(k, str) and _FIELD_NAME.match(k))
    return sorted(names)


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

def slugify(name: object) -> str:
    """Lowercase ASCII, runs of non-alphanumerics to one hyphen, trimmed."""
    text = unicodedata.normalize("NFKD", str(name or "")).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    slug = slug[:SLUG_MAX].rstrip("-")
    return slug or "scenario"


def strip_samples(blueprint: dict) -> dict:
    """Copy of the blueprint without top-level metadata.designer.samples.

    Make keeps sample run data there for the editor. It can hold client
    records (emails, phones), which hard rule 5 keeps out of the repo. The
    rest of the blueprint is written as returned.
    """
    meta = blueprint.get("metadata")
    if not (isinstance(meta, dict) and isinstance(meta.get("designer"), dict)
            and "samples" in meta["designer"]):
        return blueprint
    designer = {k: v for k, v in meta["designer"].items() if k != "samples"}
    return {**blueprint, "metadata": {**meta, "designer": designer}}


def render_json(obj: object) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def existing_blueprint_files(out_dir: str) -> dict[int, list[str]]:
    """Map scenario id -> blueprint file names currently in out_dir."""
    found: dict[int, list[str]] = {}
    for entry in sorted(os.listdir(out_dir)):
        m = BLUEPRINT_FILE.match(entry)
        if m and os.path.isfile(os.path.join(out_dir, entry)):
            found.setdefault(int(m.group("id")), []).append(entry)
    return found


# --------------------------------------------------------------------------
# Pull
# --------------------------------------------------------------------------

def _scheduling_type(*sources: object) -> str | None:
    for src in sources:
        if isinstance(src, dict) and isinstance(src.get("type"), str):
            return src["type"]
    return None


def _scheduling_interval(*sources: object) -> int | None:
    """The schedule interval in seconds (scheduling.interval) when the schedule is a plain interval, else None.
    Recorded for reference only."""
    for src in sources:
        if isinstance(src, dict) and isinstance(src.get("interval"), int) and not isinstance(src.get("interval"), bool):
            return src["interval"]
    return None


def _scheduling_restrict(*sources: object) -> list | None:
    """The time windows (scheduling.restrict, a list of {days, time}) that limit when an interval schedule runs, else None.
    The Make UI stores "Daily at 10:00" as interval 900 restricted to 10:00-10:01 on every day, so the interval alone
    reads as every 15 minutes (measured 2026-10-31 on Daily API Cost Audit)."""
    for src in sources:
        if isinstance(src, dict) and isinstance(src.get("restrict"), list) and src["restrict"]:
            return src["restrict"]
    return None


@dataclass
class PullResult:
    entries: list[dict]
    written: list[str]
    unchanged: list[str]
    removed: list[str]
    withheld: list[dict]
    draft_differs: list[dict]
    live_missing: list[dict] = field(default_factory=list)
    hooks: list[dict] | None = None
    hooks_note: str | None = None
    allowlisted: list[dict] = field(default_factory=list)   # {scenario_id, module_id, pattern_type, target_check}
    allowlist_mismatch: list[dict] = field(default_factory=list)
    hook_fields: list[str] = field(default_factory=list)   # names only, see hook_field_names
    logger: dict | None = None   # the Logger hook as recorded (see logger_hook_summary), None when no Logger is pinned

    @property
    def exit_code(self) -> int:
        return EXIT_WITHHELD if self.withheld else EXIT_OK


def _stage(out_dir: str, content: str) -> str:
    """Write content to a temp file in out_dir and return its path."""
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=out_dir)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return tmp


def _same_content(path: str, content: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read() == content.encode("utf-8")
    except FileNotFoundError:
        return False


def _unlink_all(paths: list[str]) -> None:
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass


def pull(client: MakeClient, team_id: str, out_dir: str,
         check_draft: bool = True, now: Callable[[], datetime] | None = None,
         allow_empty: bool = False, secret_allowlist: list[dict] | None = None) -> PullResult:
    """secret_allowlist: validated entries of audit/secret_allowlist.json (None means no allowance,
    every finding withholds). A secret_scan.SecretAllowlist also carries the Logger hook allowance (.logger)."""
    now = now or (lambda: datetime.now(timezone.utc))
    allow_entries = secret_allowlist or []
    logger = getattr(allow_entries, "logger", None)

    # Phase 1: every request. Any failure raises before the disk is touched.
    scenarios = list_scenarios(client, team_id)
    if not scenarios and not allow_empty and os.path.isdir(out_dir) and existing_blueprint_files(out_dir):
        raise PullError("GET /scenarios returned 0 scenarios but the snapshot holds blueprint files. "
                        "Refusing to delete them. Check MAKE_TEAM_ID, or pass --allow-empty if the team "
                        "really has no scenarios")
    fetched: list[tuple[dict, dict | None, bool | None]] = []
    for item in scenarios:
        sid = item["id"]
        try:
            live = get_blueprint(client, sid, draft=False)
        except NotFound:
            # No live version, for example a concept scenario never published.
            fetched.append((item, None, None))
            continue
        differs: bool | None = None
        if check_draft:
            try:
                draft = get_blueprint(client, sid, draft=True)
                differs = False if draft is None else draft["blueprint"] != live["blueprint"]
            except NotFound:
                differs = None
        fetched.append((item, live, differs))
    raw_hooks, hooks_note = fetch_hooks(client, team_id)

    # Phase 2: scan and build everything in memory. Nothing on disk changes.
    os.makedirs(out_dir, exist_ok=True)
    on_disk = existing_blueprint_files(out_dir)
    returned_ids = {item["id"] for item, _, _ in fetched}
    entries: list[dict] = []
    to_write: list[tuple[str, str]] = []        # (file name, content) that differ from disk
    unchanged: list[str] = []
    stale: list[str] = []
    withheld: list[dict] = []
    missing: list[dict] = []
    differs_list: list[dict] = []
    allowlisted_all: list[dict] = []
    mismatch_all: list[dict] = []

    blueprint_hooks: dict[int, set[int]] = {}
    live_by_id: dict[int, dict] = {}
    for item, live, _d in fetched:
        if live is not None:
            live_by_id[item["id"]] = live.get("blueprint") or {}
            hid = trigger_hook_id(live_by_id[item["id"]])
            if hid is not None:
                blueprint_hooks.setdefault(hid, set()).add(item["id"])
    hooks_manifest = summarize_hooks(raw_hooks, blueprint_hooks) if raw_hooks is not None else None
    hook_by_id = {h["id"]: h for h in raw_hooks or []}

    for item, live, differs in sorted(fetched, key=lambda t: t[0]["id"]):
        sid = item["id"]
        has_live = live is not None
        live = live or {}
        blueprint = live.get("blueprint") or {}
        name = item.get("name") if isinstance(item.get("name"), str) else blueprint.get("name")
        slug = slugify(name if name else f"scenario-{sid}")
        fname = f"{slug}__{sid}.json"
        findings, allowed = (secret_scan.split_findings(blueprint, sid, allow_entries) if has_live else ([], []))
        kept_allowed: list[dict] = []
        for a in allowed:
            is_logger = a.get("kind") == secret_scan.LOGGER_KIND
            target = int(a["requires_api_key_hook"] if is_logger else a["requires_fetch_back_hook"])
            check = "not checked (hook list unreadable)"
            if raw_hooks is not None:
                # In-memory only: the literal's token against the hook it must point at. A pinned entry points at the hook its
                # target scenario's trigger uses. The Logger URL points at the pinned Logger hook, which must also be the hook
                # the Logger scenario's trigger uses when the Logger is in the pull.
                trig_hook = trigger_hook_id(live_by_id.get(target, {}))
                if is_logger:
                    want = a.get("hook_id")
                    hook = hook_by_id.get(want) if trig_hook in (None, want) else None
                else:
                    hook = hook_by_id.get(trig_hook or -1)
                value = secret_scan.value_at(blueprint, a["location"])
                tokens = secret_scan.all_webhook_tokens(value) if isinstance(value, str) else []
                if hook is not None and _hook_matches_token(hook, tokens):
                    check = (f"token matches the Logger hook {a.get('hook_id')}" if is_logger
                             else f"token matches the hook of scenario {target}")
                else:
                    mismatch_all.append({"id": sid, "name": name, "module_id": a["module_id"], "target": target,
                                         "kind": a.get("kind", secret_scan.PINNED_KIND)})
                    findings.append({"pattern_type": a["pattern_type"], "location": a["location"]})
                    continue
            row = {"module_id": a["module_id"], "pattern_type": a["pattern_type"],
                   "requires_fetch_back_hook": a["requires_fetch_back_hook"],
                   "reason": a["reason"], "target_check": check}
            if is_logger:
                row = {**row, "kind": secret_scan.LOGGER_KIND, "requires_api_key_hook": a["requires_api_key_hook"],
                       "hook_id": a.get("hook_id")}
            kept_allowed.append(row)
        for a in kept_allowed:
            allowlisted_all.append({"scenario_id": sid, **a})
        is_withheld = bool(findings)
        keep = fname if has_live and not is_withheld else None

        stale.extend(old for old in on_disk.get(sid, []) if old != keep)
        if not has_live:
            missing.append({"id": sid, "name": name})
        elif is_withheld:
            withheld.append({"id": sid, "name": name,
                             "pattern_types": sorted({f["pattern_type"] for f in findings}),
                             "removed_files": sorted(on_disk.get(sid, []))})
        else:
            content = render_json(strip_samples(blueprint))
            if _same_content(os.path.join(out_dir, fname), content):
                unchanged.append(fname)
            else:
                to_write.append((fname, content))
        if differs:
            differs_list.append({"id": sid, "name": name})

        entries.append({
            "id": sid,
            "name": name,
            "slug": slug,
            "file": keep,
            "is_active": item.get("isActive") if isinstance(item.get("isActive"), bool) else None,
            "is_paused": item.get("isPaused") if isinstance(item.get("isPaused"), bool) else None,
            "concept": item.get("concept") if isinstance(item.get("concept"), bool) else None,
            "scheduling_type": _scheduling_type(live.get("scheduling"), item.get("scheduling")),
            "scheduling_interval": _scheduling_interval(live.get("scheduling"), item.get("scheduling")),
            "scheduling_restrict": _scheduling_restrict(live.get("scheduling"), item.get("scheduling")),
            "current_version": live.get("version"),
            "last_edit": live.get("last_edit") or item.get("lastEdit"),
            "draft_differs": differs,
            "live_missing": not has_live,
            "withheld": is_withheld,
            "withheld_pattern_types": sorted({f["pattern_type"] for f in findings}),
            "withheld_locations": [f"{f['pattern_type']} at {f['location']}" for f in findings],
            "allowlisted_findings": kept_allowed,
        })

    for sid, names in sorted(on_disk.items()):
        if sid not in returned_ids:
            stale.extend(names)

    manifest = {
        "pulled_at": now().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": "GET /scenarios/{id}/blueprint?draft=false",
        "version_note": "current_version and last_edit come from the blueprint response and are the "
                        "newest version, draft or published. When draft_differs is true they describe "
                        "the draft, not the live blueprint on disk.",
        "draft_check": check_draft,
        "scenario_count": len(entries),
        "withheld_count": len(withheld),
        "live_missing_count": len(missing),
        "hooks": hooks_manifest,
        "hooks_note": hooks_note,
        "scenarios": entries,
    }
    logger_row = logger_hook_summary(logger, hooks_manifest, live_by_id)
    if logger_row is not None:
        manifest["logger_hook"] = logger_row

    # Phase 3a: stage. A failure removes the temps and leaves the snapshot as it was.
    staged: list[tuple[str, str]] = []          # (temp path, final name)
    staged_manifest = None
    try:
        for fname, content in to_write:
            staged.append((_stage(out_dir, content), fname))
        staged_manifest = _stage(out_dir, render_json(manifest))
    except OSError as exc:
        _unlink_all([t for t, _ in staged])
        raise SnapshotWriteError(type(exc).__name__, disk_changed=False) from None
    temps = [t for t, _ in staged] + [staged_manifest]

    # Phase 3b: drop the old manifest. Until this succeeds nothing has changed.
    manifest_path = os.path.join(out_dir, MANIFEST)
    try:
        if os.path.exists(manifest_path):
            os.remove(manifest_path)
    except OSError as exc:
        _unlink_all(temps)
        raise SnapshotWriteError(type(exc).__name__, disk_changed=False) from None

    # Phase 3c: swap in. A failure here leaves no manifest, so the audit refuses.
    try:
        for tmp, fname in staged:
            os.replace(tmp, os.path.join(out_dir, fname))
        for old in stale:
            os.remove(os.path.join(out_dir, old))
        os.replace(staged_manifest, manifest_path)
    except OSError as exc:
        _unlink_all([t for t in temps if os.path.exists(t)])
        raise SnapshotWriteError(type(exc).__name__, disk_changed=True) from None

    written = [fname for fname, _ in to_write]
    return PullResult(entries, written, unchanged, sorted(stale), withheld, differs_list, missing,
                      hooks_manifest, hooks_note, allowlisted_all, mismatch_all,
                      hook_field_names(raw_hooks) if raw_hooks is not None else [], logger_row)


def logger_hook_summary(logger: "secret_scan.LoggerAllowance | None", hooks_manifest: list[dict] | None,
                        live_by_id: dict[int, dict]) -> dict | None:
    """The Logger hook as this pull saw it, for the manifest (logger_hook): the pinned scenario and hook, whether the allowance
    is active (audit/webhooks.json registers the hook with protection api_key) and why not, whether the Logger is in the pull
    and its trigger uses the pinned hook, and the hook's apikey_count from the hook list, the same value every other hook
    records (null when the hook list is unreadable, the hook is missing from it or it has no key field). Never the URL, the
    token or a key. None when no Logger is pinned."""
    if logger is None:
        return None
    sid = int(logger.scenario_id)
    in_pull = sid in live_by_id
    listed = None if hooks_manifest is None else next((h for h in hooks_manifest if h.get("id") == logger.hook_id), None)
    return {
        "scenario_id": sid,
        "hook_id": logger.hook_id,
        "allowance_active": logger.active,
        "inactive_reason": logger.inactive_reason,
        "in_pull": in_pull,
        "trigger_hook_matches": (trigger_hook_id(live_by_id[sid]) == logger.hook_id) if in_pull else None,
        "hook_listed": None if hooks_manifest is None else listed is not None,
        "apikey_count": listed.get("apikey_count") if listed is not None else None,
    }


def format_summary(result: PullResult, request_count: int) -> str:
    lines = [
        f"Pulled {len(result.entries)} scenarios in {request_count} requests: "
        f"{len(result.written)} written, {len(result.unchanged)} unchanged, "
        f"{len(result.withheld)} withheld."
    ]
    for w in result.withheld:
        lines.append(f"  WITHHELD {w['id']} {w['name']!r}: {', '.join(w['pattern_types'])}")
        for gone in w.get("removed_files") or []:
            lines.append(f"  WARNING {gone} was removed because the scenario is withheld. Checks A to C, E and F no longer run on it "
                         f"and make_push refuses it, so the drop in their findings is not progress. The last committed copy in git "
                         f"still holds the findings. Replace the literal in Make with a variable, then pull again")
    for a in result.allowlisted:
        lines.append(f"  ALLOWLISTED {a['scenario_id']} module {a['module_id']} {a['pattern_type']}: "
                     f"{a['target_check']} (audit/secret_allowlist.json)")
    for mm in result.allowlist_mismatch:
        what = ("the Logger hook" if mm.get("kind") == secret_scan.LOGGER_KIND else f"the hook of scenario {mm['target']}")
        lines.append(f"  ALLOWLIST MISMATCH {mm['id']} {mm['name']!r} module {mm['module_id']}: the URL does not match {what}, "
                     f"so the allowance does not apply and the scenario is withheld")
    lg = result.logger
    if lg is not None:
        state = "active" if lg["allowance_active"] else f"INACTIVE ({lg['inactive_reason']}), Logger URLs block"
        if lg["hook_listed"] is None:
            keys = "API key state unknown (hook list unreadable)"
        elif not lg["hook_listed"]:
            keys = "not in the hook list, API key state unknown"
        elif lg["apikey_count"] is None:
            keys = "API key state unknown (no key field)"
        else:
            keys = f"apikey_count {lg['apikey_count']}"
        where = ("not in the pull" if not lg["in_pull"] else
                 "trigger uses the pinned hook" if lg["trigger_hook_matches"] else "trigger does NOT use the pinned hook")
        lines.append(f"Logger hook {lg['hook_id']} (scenario {lg['scenario_id']}, {where}): allowance {state}, {keys}.")
    for m in result.live_missing:
        lines.append(f"  NO LIVE VERSION {m['id']} {m['name']!r}: draft=false returned 404, nothing to audit")
    if result.removed:
        lines.append("Removed: " + ", ".join(result.removed))
    unknown = [e for e in result.entries if e["draft_differs"] is None and not e["live_missing"]]
    if result.draft_differs:
        lines.append("Draft differs from live (unpublished edits): "
                     + ", ".join(f"{d['id']} {d['name']!r}" for d in result.draft_differs))
    if unknown:
        lines.append(f"Draft state unknown for {len(unknown)} scenario(s).")
    if result.hooks is None:
        lines.append(f"Hooks: not recorded. {result.hooks_note}.")
    else:
        unknown = sum(1 for h in result.hooks if h["apikey_count"] is None)
        lines.append(f"Hooks: {len(result.hooks)} recorded" + (f", API key state unknown for {unknown}" if unknown else "") + ".")
        if unknown or any(h["ip_restricted"] is None for h in result.hooks):
            lines.append("Hook response fields (names only, to confirm the API key and IP fields): " + (", ".join(result.hook_fields) or "none"))
    lines.append(f"Manifest: blueprints/{MANIFEST}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None, transport: Transport | None = None,
         sleep: Callable[[float], None] = time.sleep, environ: dict | None = None,
         now: Callable[[], datetime] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pull live Make blueprints (read-only).")
    parser.add_argument("--env", default=DEFAULT_ENV, help="path to the .env file")
    parser.add_argument("--out", default=DEFAULT_OUT, help="blueprints directory")
    parser.add_argument("--skip-draft-check", action="store_true",
                        help="do not fetch drafts (draft_differs becomes null)")
    parser.add_argument("--allow-empty", action="store_true",
                        help="accept an empty scenario listing and delete every snapshot file")
    parser.add_argument("--secret-allowlist", default=secret_scan.DEFAULT_SECRET_ALLOWLIST,
                        help="pinned secret allowlist (audit/secret_allowlist.json)")
    parser.add_argument("--webhooks", default=None,
                        help="webhook registry that activates the Logger hook allowance (default: webhooks.json next to the "
                             "secret allowlist, audit/webhooks.json)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_CONFIG if exc.code else EXIT_OK

    try:
        config = load_config(args.env, os.environ if environ is None else environ)
    except ConfigError as exc:
        print(f"make_pull: config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        allow_entries = secret_scan.load_secret_allowlist(args.secret_allowlist, args.webhooks)
    except secret_scan.SecretAllowlistError as exc:
        print(f"make_pull: config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    client = MakeClient(config, transport=transport, sleep=sleep)
    try:
        result = pull(client, config.team_id, args.out,
                      check_draft=not args.skip_draft_check, now=now,
                      allow_empty=args.allow_empty, secret_allowlist=allow_entries)
    except SnapshotWriteError as exc:
        if exc.disk_changed:
            print(f"make_pull: filesystem error while swapping files in ({exc.exc_name}). The snapshot "
                  f"is incomplete and manifest.json was removed, so the audit will not run on it. "
                  f"Close any program holding files in the blueprints folder and re-run.", file=sys.stderr)
        else:
            print(f"make_pull: filesystem error before any file changed ({exc.exc_name}). "
                  f"Snapshot left as it was.", file=sys.stderr)
        return EXIT_FAILURE
    except PullError as exc:
        print(f"make_pull: failed, nothing written: {redact(str(exc), config.token)}", file=sys.stderr)
        return EXIT_FAILURE
    except OSError as exc:
        # Only os.makedirs or the directory listing can raise here, before any change.
        print(f"make_pull: filesystem error before any file changed: {type(exc).__name__}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:  # noqa: BLE001
        print(f"make_pull: unexpected error: {type(exc).__name__}: "
              f"{redact(str(exc), config.token)[:200]}", file=sys.stderr)
        return EXIT_FAILURE

    print(redact(format_summary(result, client.request_count), config.token))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
