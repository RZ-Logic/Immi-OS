#!/usr/bin/env python3
"""Push one edited blueprint to one Make scenario, under CLAUDE.md hard rule 1.

Usage:
    python scripts/make_push.py --scenario <id> --candidate <edited blueprint JSON>
                                --fix <FIX-ID> --modules <id,id,...>
                                --base-version <N> --closes <CHECK:MODULE,...>
                                [--replaces OLD=NEW,...] [--apply]

--base-version is the live version the candidate was built from (the
manifest current_version of the pull the candidate was edited from).
Fix F-E5.3 is the Logger swap of F-E5 v3 (Option C, CLAUDE.md, specs/F-E5-v3-shared-logger.md): it replaces the
Shadow Ledger and Slack modules of existing error handlers with one call to the shared Logger and keeps the
directive and everything else identical (check_logger_swap). It needs the Logger registered, deployed and
passing its check on the committed pull (check_logger_ready), names every rewritten handler's B row in --closes,
adds no FAIL and no REVIEW, and may keep the FAIL count equal. Fix F-E5.2 (the simplify push of the retired
Error Monitor) is refused.
--closes names the audit findings the fix closes, e.g. B:2 or C:15,C:16 (C:- for
a scenario-level finding). A REVIEW row is named E7:5:REVIEW, or E7:5 when live has
a REVIEW and no FAIL on that module. It must be a REVIEW on live and gone on the
candidate, and the same row (the check and text, numbers blanked) must not be on a
module the push added or changed, so recreating a module under a new ID closes
nothing. The spec then names every module the push touches. Then the FAIL count may
stay equal, never rise. --replaces maps a module recreated under a new ID
(X-19 Step 2) to the ID it replaces, so its other findings carry over.

Without --apply this is a dry run: every check runs and the plan is printed,
but no PATCH is sent and no push record is written.

Each step is a hard abort with a non-zero exit:
  0. Spec: specs/<FIX>-*.md exists and names the scenario id. The snapshot
     blueprints/<slug>__<id>.json is tracked by git and clean against HEAD.
  1. Config: MAKE_API_TOKEN (every GET) and MAKE_WRITE_TOKEN (the PATCH only),
     both required, never equal, never printed.
  2. GET /scenarios/{id}: isActive must be false, and islocked and isinvalid
     must not be true.
  3. GET /scenarios/{id}/blueprint?draft=false must equal the committed
     snapshot, and its version must equal --base-version.
  4. GET ...?draft=true must be null (no unpublished UI draft).
  5. Module diff candidate vs live, every module in flow, routes[].flow and
     onerror[] recursively. Changed, added and removed module IDs must all be
     in --modules, and every ID in --modules must change. Module
     metadata.designer is noise. Adding or removing a container (even an
     empty onerror or route flow) is a change. Name and top-level metadata
     must be unchanged, including metadata.designer orphans and samples.
     Added module IDs must be above the scenario's idSequence. Each --replaces
     pair is a removal and an addition of the same module type at the same
     position. The first module (the trigger) keeps its module type. A module
     the push adds or changes that writes, or may write, the lead Status (an
     update or create, an Airtable API call, an HTTP call to the Airtable API)
     needs fix ID X-31 or F-31, and the spec must name it.
  6. The candidate must scan clean for secrets (secret_scan.split_findings with
     audit/secret_allowlist.json: only a pinned Make webhook URL in a Bland
     call module (Send a Call or Create a Call) is accepted, and the pinned Logger hook URL in any
     module while audit/webhooks.json registers that hook with api_key).
  7. audit_blueprints.audit on live and candidate: no new FAIL, fewer FAILs.
     Every --closes target closes completely, every closed FAIL is a target,
     targets sit on --modules, and the check matches the fix (X-19/X-28 C,
     F-E5 B, X-31/F-31 A). The spec names every target and removed module.
  8. --apply only: PATCH /scenarios/{id} with the write token, body
     {"blueprint": <JSON string>, "baseVersion": <live version>}. A first
     attempt 409 or SC409 means nothing changed. 400/401/403/404/422 are
     definitive rejections. Anything else is an unknown outcome.
  9. Post-check with the read token: still inactive (else a loud alarm), new
     live version, untouched modules equal live before the save, touched
     modules equal the candidate (server-filled keys are warnings), top-level
     settings unchanged, idSequence at or above the highest module ID, no
     draft left behind. An unknown outcome with no save seen is re-read once
     after a short delay.
 10. audit/pushes/<YYYY-MM-DD>__<FIX>__<id>.json: what changed, no secrets
     and no blueprint content. Written for every save and every unknown
     outcome.

HTTP: GET /scenarios/{id}, GET /scenarios/{id}/blueprint?draft=true|false and
PATCH /scenarios/{id} only. F-E5.3 adds one GET /scenarios/{logger id} on a
separate read-only transport (the Logger must be active and not invalid live).
The transport refuses any other method, path, query or host, and never follows
redirects. GETs retry like make_pull. The
PATCH is never retried, except on a 429 (the request was refused unprocessed).

Exit codes:
  0  dry run passed, or push saved and the post-check is clean
  1  a guard refused (precondition failed), nothing sent
  2  usage or configuration error
  3  API or network failure before the PATCH, nothing changed
  4  PATCH definitively rejected (first-attempt 409, or 400/401/403/404/422),
     nothing changed
  5  saved with a post-check problem, or outcome unknown (re-pull before
     retrying)
  6  ALARM: the scenario is active after the save

Tokens are never printed. Standard library only.
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.client
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import audit_blueprints  # noqa: E402
import make_pull  # noqa: E402
import secret_scan  # noqa: E402
from make_pull import (  # noqa: E402
    Config,
    ConfigError,
    MakeClient,
    NotFound,
    PullError,
    Response,
    TransientError,
    redact,
    render_json,
)

ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_ENV = os.path.join(ROOT, ".env")
DEFAULT_BLUEPRINTS = os.path.join(ROOT, "blueprints")
DEFAULT_LABELS = os.path.join(ROOT, "audit", "scenario_labels.json")
DEFAULT_SCHEMA = os.path.join(ROOT, "audit", "airtable_ledger_schema.json")
DEFAULT_LINKS = os.path.join(ROOT, "audit", "airtable_links.json")
DEFAULT_ALLOWLIST = os.path.join(ROOT, "audit", "allowlist.json")
DEFAULT_WEBHOOKS = os.path.join(ROOT, "audit", "webhooks.json")
DEFAULT_STATUS_ALLOW = os.path.join(ROOT, "audit", "status_allow_list.json")
DEFAULT_CRITICAL = os.path.join(ROOT, "audit", "critical_modules.json")
DEFAULT_SECRET_ALLOWLIST = os.path.join(ROOT, "audit", "secret_allowlist.json")
DEFAULT_BLAND_AGENTS = os.path.join(ROOT, "audit", "bland_agents.json")
DEFAULT_FF10 = os.path.join(ROOT, "audit", "ff10.json")
DEFAULT_X32 = os.path.join(ROOT, "audit", "x32.json")
DEFAULT_X16 = os.path.join(ROOT, "audit", "x16.json")
DEFAULT_PROMPTS = os.path.join(ROOT, "ref", "prompts.json")
DEFAULT_PROMPT_BINDINGS = os.path.join(ROOT, "ref", "prompt_bindings.json")
DEFAULT_SPECS = os.path.join(ROOT, "specs")
DEFAULT_PUSHES = os.path.join(ROOT, "audit", "pushes")

WRITE_KEY = "MAKE_WRITE_TOKEN"
# One fix ID, or two joined by "+" for a combined entry in FIX_CHECKS (e.g. X-23+X-41).
FIX_ID = re.compile(r"^[A-Za-z0-9]+(?:-[A-Za-z0-9.]+)+(?:\+[A-Za-z0-9]+(?:-[A-Za-z0-9.]+)+)?$")
FIX_ID_MAX = 32
ERROR_CODE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
MAX_PATHS = 25
CLOSES_ITEM = re.compile(r"^([A-Z]):(\d+|-)(?::(REVIEW))?$")

# Which audit check a fix ID closes (CLAUDE.md: F-E5 and X-31 are different
# failure modes, closing one never closes the other).
FIX_CHECKS: dict[str, tuple[str, ...]] = {
    "X-19": ("C",), "X-28": ("C",),
    "F-E5": ("B",),
    "X-31": ("A",), "F-31": ("A",),
    "X-41": ("E",),   # mapping integrity
    "X-23": ("F",),   # webhook authentication: F2 rows sit on the modules a push changes (F1 is hook configuration)
    # A fetch-back rework where the same request references are both an E2 and
    # an F2c row, so E and F must close in one push (Interview Room (B) Grader).
    "X-23+X-41": ("E", "F"),
    # Activation blockers (decided 2026-10-29). Each fix closes the rows of one rule on a fresh pull (hard rule 6).
    "X-43": ("F",),   # F3 duplicate delivery on an api_key webhook (Pending Call): lookup, aggregator, empty filter, marker row
    "X-44": ("E",),   # E9 conflicting router routes that write the same Applicants field (Interview Room (B) Grader router 5)
    "X-45": ("E",),   # E10 Voice AI Ledger cost contract (both reconciliation triggers, Pending Call 76, Grader 22)
    # Stripe money calls (decided 2026-10-30, specs/F-H9-options.md). F-H1 moves Financial Guardrail to a Stripe Invoice and
    # carries F-H2 (idempotency keys) and F-H9-prep (lead metadata) in the same create modules.
    "F-H1": ("S",), "F-H2": ("S",), "F-H9-prep": ("S",),
    # The F-H9 listener and its AR side (L3): trigger and filters on Financial Guardrail. No audit row closes, so declared only.
    "F-H9": ("S",),
    # AI model pinning (decided 2026-10-30, Anthropic only): every LLM call moves to anthropic-claude:createAMessage with a pinned model.
    "X-15": ("P",), "X-18": ("P",),
    # The prompts registry (X-36.1, decided 2026-11-13): a push that edits a Claude module's prompt or settings binds it to a
    # newly registered version in ref/prompts.json and ref/prompt_bindings.json, committed first, and closes the R row.
    "X-36": ("R",),
    # The JSON schema of a Claude call stored as JSON text (P7 reversed 2026-11-14, Rizwan): the push changes the module's
    # template, so it closes the P7 row and the R2 row of the version registered from the candidate in one push.
    "X-18+X-36": ("P", "R"),
    # Bland agents (specs/X-46-bland-agents-migration.md): Batch Outbound Caller moves from Send a Call to Create a Call 32.
    # The push configures 32 (E17 webhook, E28 agent pin), rewires the call_id references of 18 and Logger call 26 (E1, and the
    # B row on 18 for the Logger call_id) and adds a Logger call and an Ignore as the handler of 32 (B).
    "X-46": ("B", "E"),
    # F-F10, the Module F drafting chain (specs/F-F10-drafting-chain.md). Its audit rules live in check E (E29 Synthetic Test
    # Case has no writer, E30 Drafting Status has one owner, E31 the ff13 calls are pinned, E6 widened to the validator, the
    # grounding call and Claude content), so later pushes keep them passing. The build-order step 7 push writes the call-row
    # literals of both Opus stages after their prompts are registered, which closes R4b rows, so R is mapped too.
    "F-F10": ("E", "R"),
    # X-32, the exemplar layer of Module F (specs/X-32-exemplars.md). Its rules live in check E (E35 no writer of the Exemplars
    # table, E36 the selection shape, E37 the exemplar mappings, E31 widened to ff13.rank_exemplars, E6 widened to exemplar
    # text), so later X-32.x pushes keep them passing. The push rebinds the drafter to draft@2 and writes its call-row
    # literals, which closes the R2 and R4b rows the binding opens, so R is mapped too.
    "X-32": ("E", "R"),
    # X-16 Phase A, the review trail of Module F (specs/X-16-options.md, decided 2026-11-16). Its rules live in check E (E38
    # the owner's trail: the outline ParseJSON and one Draft Reviews row per outcome route, E39 only the owner writes Draft
    # Reviews, E40 no send, share or copy of the working Doc and no Claude text into a Doc outside the owner, E32 the
    # production Doc in the pinned review folder, E30 and E6 widened). X-16.1 and later X-16.x pushes prefix-map here.
    "X-16": ("E",),
    # Declared --closes only: these span several checks, so the audit check is
    # not pinned to the fix ID. An empty tuple means no restriction.
    "X-6": (), "X-9": (), "X-10": (), "X-11": (),
}

# PATCH statuses that mean Make refused the request without saving.
DEFINITIVE_REJECT = frozenset({400, 401, 403, 404, 422})
# 409 metadata.reason values that may be shown (an enum, never free text).
KNOWN_409_REASONS = frozenset({"scenario_version_conflict"})
# Delay before the second read after an unknown PATCH outcome.
UNKNOWN_RECHECK_S = 15.0
# Module keys Make may fill in or rewrite on save. A post-save difference
# under these on a touched or added module is a warning, not a problem.
SERVER_FILLED = ("version", "parameters", "metadata.restore", "metadata.expect")
# Top-level metadata.designer keys that carry content (orphan modules,
# sample data). The rest of it is layout.
DESIGNER_CONTENT = ("orphans", "samples")

EXIT_OK = 0
EXIT_ABORT = 1
EXIT_CONFIG = 2
EXIT_API = 3
EXIT_REJECTED = 4
EXIT_POSTCHECK = 5
EXIT_ALARM = 6


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class Abort(Exception):
    """A guard refused. Nothing was sent that changes anything."""

    def __init__(self, message: str, code: int = EXIT_ABORT):
        self.code = code
        super().__init__(message)


class TransportRefused(Exception):
    """The guarded transport refused a request. Never retried."""


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PushConfig:
    read: Config
    write: Config


def load_push_config(env_path: str, environ: dict | None = None) -> PushConfig:
    """Read config via make_pull.load_config, plus MAKE_WRITE_TOKEN. Messages
    name keys, never values."""
    environ = environ if environ is not None else {}
    read = make_pull.load_config(env_path, environ)
    values: dict[str, str] = {}
    if os.path.isfile(env_path):
        try:
            with open(env_path, encoding="utf-8-sig") as fh:
                values = make_pull.parse_env(fh.read())
        except OSError as exc:
            raise ConfigError(f"cannot read the env file ({type(exc).__name__})") from None
    if environ.get(WRITE_KEY):
        values[WRITE_KEY] = environ[WRITE_KEY]
    write_token = values.get(WRITE_KEY, "").strip()
    if not write_token:
        raise ConfigError(f"missing {WRITE_KEY} in {env_path}")
    if any(c.isspace() for c in write_token):
        raise ConfigError(f"{WRITE_KEY} must not contain whitespace")
    if write_token == read.token:
        raise ConfigError(f"{WRITE_KEY} equals MAKE_API_TOKEN. The write token must be a "
                          f"separate key so reads never carry write scope")
    write = Config(token=write_token, zone=read.zone, team_id=read.team_id)
    return PushConfig(read=read, write=write)


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

def urllib_transport(method: str, url: str, headers: dict, timeout: float,
                     body: bytes | None = None) -> Response:
    """GET goes through make_pull's no-redirect transport. PATCH uses the same
    no-redirect opener. Anything else is refused."""
    if method == "GET":
        if body is not None:
            raise ValueError("GET with a body")
        return make_pull.urllib_transport(method, url, headers, timeout)
    if method != "PATCH":
        raise ValueError("make_push only issues GET and PATCH requests")
    req = urllib.request.Request(url, data=body, headers=headers, method="PATCH")
    try:
        with make_pull._OPENER.open(req, timeout=timeout) as resp:
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read())
    except urllib.error.HTTPError as exc:
        data = b""
        try:
            data = exc.read()
        except Exception:  # noqa: BLE001
            pass
        hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return Response(exc.code, hdrs, data)
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransientError(type(reason).__name__) from None


class GuardedTransport:
    """Allows exactly three requests for one scenario on one host:
    GET /scenarios/{id}, GET /scenarios/{id}/blueprint?draft=true|false and
    PATCH /scenarios/{id} with a body and no query. Refuses everything else
    before the inner transport sees it."""

    def __init__(self, inner: Callable, base_url: str, scenario_id: int):
        parts = urllib.parse.urlsplit(base_url)
        self._inner = inner
        self._host = parts.netloc
        self._scenario_path = f"{parts.path.rstrip('/')}/scenarios/{int(scenario_id)}"

    def check(self, method: str, url: str, body: bytes | None) -> None:
        p = urllib.parse.urlsplit(url)
        shown = f"{method} {p.path}"
        if p.scheme != "https" or p.netloc != self._host or p.fragment or "@" in p.netloc:
            raise TransportRefused(f"refused {shown}: wrong scheme or host")
        query = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        if method == "GET" and body is None:
            if p.path == self._scenario_path and not p.query:
                return
            if p.path == self._scenario_path + "/blueprint" and query in ([("draft", "false")], [("draft", "true")]):
                return
        elif method == "PATCH" and body is not None:
            if p.path == self._scenario_path and not p.query:
                return
        raise TransportRefused(f"refused {shown}: only GET /scenarios/{{id}}, GET /scenarios/{{id}}/blueprint"
                               f"?draft=true|false and PATCH /scenarios/{{id}} for this scenario are allowed")

    def __call__(self, method: str, url: str, headers: dict, timeout: float,
                 body: bytes | None = None) -> Response:
        self.check(method, url, body)
        if body is None:
            return self._inner(method, url, headers, timeout)
        return self._inner(method, url, headers, timeout, body)


class ScenarioStateTransport(GuardedTransport):
    """Allows exactly one request: GET /scenarios/{id} for one other scenario (the Logger, F-E5.3), no query, no body. No
    blueprint read and never a PATCH, so the push target stays the one scenario GuardedTransport names (hard rule 1)."""

    def check(self, method: str, url: str, body: bytes | None) -> None:
        p = urllib.parse.urlsplit(url)
        shown = f"{method} {p.path}"
        if p.scheme != "https" or p.netloc != self._host or p.fragment or "@" in p.netloc:
            raise TransportRefused(f"refused {shown}: wrong scheme or host")
        if method == "GET" and body is None and p.path == self._scenario_path and not p.query:
            return
        raise TransportRefused(f"refused {shown}: only GET /scenarios/{{id}} of the Logger is allowed on this transport")


# --------------------------------------------------------------------------
# PATCH
# --------------------------------------------------------------------------

@dataclass
class PatchOutcome:
    kind: str                       # "saved", "rejected", "conflict", "unknown"
    status: int | None = None
    code: str | None = None
    reason: str = ""
    conflict_reason: str | None = None   # whitelisted 409 metadata.reason, "other", or None
    body_active: bool | None = None      # scenario.isActive in the 200 body
    body_invalid: bool | None = None     # scenario.isinvalid in the 200 body
    detail: str | None = None            # Make's validation message on 400/422, redacted


def _json_object(body: bytes) -> dict | None:
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def conflict_reason(body: bytes) -> str | None:
    """The 409 metadata.reason if it is a known enum value, "other" if it is
    something else, None if absent. Never free text."""
    data = _json_object(body)
    meta = data.get("metadata") if data else None
    reason = meta.get("reason") if isinstance(meta, dict) else None
    if reason is None:
        return None
    return reason if isinstance(reason, str) and reason in KNOWN_409_REASONS else "other"


def saved_flags(body: bytes) -> tuple[bool | None, bool | None]:
    """scenario.isActive and scenario.isinvalid from a PATCH 200 body."""
    data = _json_object(body)
    scen = data.get("scenario") if data else None
    if not isinstance(scen, dict):
        return None, None
    active, invalid = scen.get("isActive"), scen.get("isinvalid")
    return (active if isinstance(active, bool) else None), (invalid if isinstance(invalid, bool) else None)


def validation_detail(body: bytes, tokens: tuple[str, ...]) -> str | None:
    """Make's message and detail on a 400/422 validation rejection, redacted and
    capped. Never used for 401/403, where the message can echo token fragments."""
    data = _json_object(body)
    if not data:
        return None
    parts = [str(data[k]) for k in ("message", "detail") if isinstance(data.get(k), (str, int))]
    sub = data.get("suberrors")
    if isinstance(sub, list):
        parts += [str(s.get("message")) for s in sub[:5] if isinstance(s, dict) and s.get("message")]
    text = " | ".join(parts)
    for t in tokens:
        text = redact(text, t)
    return text[:600] or None


def error_code(body: bytes, tokens: tuple[str, ...]) -> str | None:
    """The Make error code only, never the message."""
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict) or not isinstance(data.get("code"), (str, int)) \
            or isinstance(data.get("code"), bool):
        return None
    code = str(data["code"])
    for t in tokens:
        code = redact(code, t)
    return code if ERROR_CODE.match(code) else "unrecognised"


def patch_blueprint(config: Config, transport: Callable, sleep: Callable[[float], None],
                    scenario_id: int, body: bytes, tokens: tuple[str, ...],
                    max_retries: int = make_pull.MAX_RETRIES,
                    timeout: float = make_pull.TIMEOUT_S) -> PatchOutcome:
    url = f"{config.base_url}/scenarios/{scenario_id}"
    headers = {
        "Authorization": f"Token {config.token}",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "immi-os-make-push/1.0",
    }
    attempt = 0
    while True:
        try:
            resp = transport("PATCH", url, headers, timeout, body)
        except TransientError as exc:
            # The request may have reached Make. Never retried.
            return PatchOutcome("unknown", reason=f"network error ({exc})")
        if resp.status == 429 and attempt < max_retries:
            # Refused before processing, so a retry cannot apply twice.
            wait = make_pull.retry_after_seconds(resp.headers.get("retry-after"))
            if wait is None:
                wait = make_pull.RATE_WINDOW_S
            sleep(min(max(wait, 0.0), make_pull.MAX_WAIT_S))
            attempt += 1
            continue
        code = error_code(resp.body, tokens)
        if resp.status == 200:
            active, invalid = saved_flags(resp.body)
            return PatchOutcome("saved", 200, code, body_active=active, body_invalid=invalid)
        if resp.status == 409 or code == "SC409":
            creason = conflict_reason(resp.body)
            if attempt > 0:
                # An earlier attempt may have saved after all, and this 409 is
                # its own version bump. Only the post-check can tell.
                return PatchOutcome("unknown", resp.status, code,
                                    reason=f"HTTP {resp.status} after a retried attempt",
                                    conflict_reason=creason)
            return PatchOutcome("conflict", resp.status, code, conflict_reason=creason)
        if resp.status in DEFINITIVE_REJECT:
            detail = validation_detail(resp.body, tokens) if resp.status in (400, 422) else None
            return PatchOutcome("rejected", resp.status, code, detail=detail)
        return PatchOutcome("unknown", resp.status, code, reason=f"HTTP {resp.status}")


# --------------------------------------------------------------------------
# Blueprint helpers
# --------------------------------------------------------------------------

def canon(obj: object) -> str:
    """Type-strict canonical form: true != 1, 1 != 1.0, key order ignored."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def strip_designer(meta: object) -> object:
    """A module's metadata without designer (layout only)."""
    if isinstance(meta, dict):
        return {k: v for k, v in meta.items() if k != "designer"}
    return meta


def top_level_view(bp: dict) -> dict:
    """The blueprint without flow. Top-level metadata.designer keeps only the
    keys that carry content (orphans, samples). Orphan modules are saved into
    the scenario and can be wired up later in the UI, so they are not noise."""
    view = {k: v for k, v in bp.items() if k != "flow"}
    meta = view.get("metadata")
    if isinstance(meta, dict) and isinstance(meta.get("designer"), dict):
        meta = dict(meta)
        meta["designer"] = {k: meta["designer"][k] for k in DESIGNER_CONTENT if k in meta["designer"]}
        view["metadata"] = meta
    return view


def safe_key(key: object) -> str:
    """A key for display: redacted if it looks like a credential, capped."""
    text = str(key)
    if secret_scan.scan_obj({text: 0}):
        return "<redacted-key>"
    return text if len(text) <= 60 else text[:57] + "..."


def diff_paths(a: object, b: object, path: str = "", out: list | None = None,
               subset: bool = False) -> list[str]:
    """Paths where a and b differ, never values. With subset=True, keys only
    in b are ignored (b may carry extra keys Make adds). No key is skipped:
    callers strip designer data with module_shell or top_level_view first."""
    out = [] if out is None else out
    if isinstance(a, dict) and isinstance(b, dict):
        keys = list(a.keys()) + ([] if subset else [k for k in b.keys() if k not in a])
        for k in keys:
            kp = f"{path}.{safe_key(k)}" if path else safe_key(k)
            if k not in b:
                out.append(f"{kp} (missing)" if subset else f"{kp} (removed)")
            elif k not in a:
                out.append(f"{kp} (added)")
            else:
                diff_paths(a[k], b[k], kp, out, subset)
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path or '$'} (length {len(a)} -> {len(b)})")
            return out
        for i, (x, y) in enumerate(zip(a, b)):
            diff_paths(x, y, f"{path}[{i}]", out, subset)
        return out
    if type(a) is not type(b) or a != b:
        out.append(path or "$")
    return out


def _cap(paths: list[str]) -> list[str]:
    if len(paths) <= MAX_PATHS:
        return paths
    return paths[:MAX_PATHS] + [f"... {len(paths) - MAX_PATHS} more"]


@dataclass
class ModuleInfo:
    module: dict
    parent: int | None
    container: str                    # "flow", "routes[i]" or "onerror"

    @property
    def place(self) -> str:
        return "flow" if self.parent is None else f"{self.parent}.{self.container}"


def index_modules(bp: dict, label: str) -> tuple[dict[int, ModuleInfo], dict[tuple, list[int]]]:
    """Every module by id across flow, routes[].flow and onerror[] recursively,
    plus each container's ordered child ids. Aborts on malformed structure."""
    modules: dict[int, ModuleInfo] = {}
    containers: dict[tuple, list[int]] = {}

    def visit(flow: object, parent: int | None, container: str) -> None:
        if not isinstance(flow, list):
            raise Abort(f"{label}: {container} under module {parent} is not a list")
        ids: list[int] = []
        for m in flow:
            if not isinstance(m, dict):
                raise Abort(f"{label}: a module under {parent or 'flow'} is not an object")
            mid = m.get("id")
            if not isinstance(mid, int) or isinstance(mid, bool):
                raise Abort(f"{label}: a module under {parent or 'flow'} has no integer id")
            if mid in modules:
                raise Abort(f"{label}: module id {mid} appears more than once")
            modules[mid] = ModuleInfo(m, parent, container)
            ids.append(mid)
            routes = m.get("routes")
            if routes is not None:
                if not isinstance(routes, list):
                    raise Abort(f"{label}: module {mid} routes is not a list")
                for i, r in enumerate(routes):
                    if isinstance(r, dict) and "flow" in r:
                        visit(r["flow"], mid, f"routes[{i}]")
            if m.get("onerror") is not None:
                visit(m["onerror"], mid, "onerror")
        containers[(parent, container)] = ids

    visit(bp.get("flow"), None, "flow")
    return modules, containers


def _container_marker(value: object) -> str:
    return f"<{type(value).__name__}>"


def module_shell(m: dict) -> dict:
    """The module without metadata.designer, with each nested module list
    (onerror, routes[].flow) replaced by a type marker. The child lists are
    compared separately. The marker keeps the container's presence and type,
    so adding an empty onerror or route flow still counts as a change."""
    shell = dict(m)
    if "onerror" in shell:
        shell["onerror"] = _container_marker(shell["onerror"])
    if isinstance(shell.get("routes"), list):
        shell["routes"] = [{k: (_container_marker(v) if k == "flow" else v) for k, v in r.items()}
                           if isinstance(r, dict) else r for r in shell["routes"]]
    if "metadata" in shell:
        shell["metadata"] = strip_designer(shell["metadata"])
    return shell


def module_positions(containers: dict[tuple, list[int]]) -> dict[int, tuple]:
    """Module id -> (parent id, container, index)."""
    pos: dict[int, tuple] = {}
    for (parent, container), ids in containers.items():
        for i, mid in enumerate(ids):
            pos[mid] = (parent, container, i)
    return pos


def child_lists(mid: int, containers: dict[tuple, list[int]]) -> dict[str, list[int]]:
    return {c: ids for (p, c), ids in containers.items() if p == mid}


@dataclass
class ModuleDiff:
    added: list[int] = field(default_factory=list)
    removed: list[int] = field(default_factory=list)
    changed: dict[int, list[str]] = field(default_factory=dict)   # id -> reasons / key paths

    @property
    def touched(self) -> set[int]:
        return set(self.added) | set(self.removed) | set(self.changed)


def diff_modules(live: dict, cand: dict) -> ModuleDiff:
    lmods, lcont = index_modules(live, "live blueprint")
    cmods, ccont = index_modules(cand, "candidate")
    d = ModuleDiff()
    d.added = sorted(set(cmods) - set(lmods))
    d.removed = sorted(set(lmods) - set(cmods))
    common = set(lmods) & set(cmods)
    for mid in sorted(common):
        reasons: list[str] = []
        lm, cm = lmods[mid], cmods[mid]
        reasons += diff_paths(module_shell(lm.module), module_shell(cm.module))
        lkids, ckids = child_lists(mid, lcont), child_lists(mid, ccont)
        for c in sorted(set(lkids) | set(ckids)):
            if lkids.get(c, []) != ckids.get(c, []):
                reasons.append(f"{c} modules {lkids.get(c, [])} -> {ckids.get(c, [])}")
        if lm.place != cm.place:
            reasons.append(f"moved {lm.place} -> {cm.place}")
        if reasons:
            d.changed[mid] = _cap(reasons)
    # Top-level order has no parent to carry it, so flag the reordered modules.
    lt = [i for i in lcont.get((None, "flow"), []) if i in common and cmods[i].place == "flow"]
    ct = [i for i in ccont.get((None, "flow"), []) if i in common and lmods[i].place == "flow"]
    for pos, (a, b) in enumerate(zip(lt, ct)):
        if a != b:
            for mid in (a, b):
                d.changed.setdefault(mid, [])
                if "reordered in flow" not in d.changed[mid]:
                    d.changed[mid].append("reordered in flow")
    return d


def restore_samples(live: dict, cand: dict) -> dict:
    """Candidate with live's top-level metadata.designer.samples when the
    candidate has none. A candidate that carries its own samples is left as is,
    so check_top_level still rejects samples that differ from live."""
    lmeta, cmeta = live.get("metadata"), cand.get("metadata")
    if not (isinstance(lmeta, dict) and isinstance(lmeta.get("designer"), dict)
            and "samples" in lmeta["designer"] and isinstance(cmeta, dict)):
        return cand
    cdes = cmeta.get("designer") if isinstance(cmeta.get("designer"), dict) else {}
    if "samples" in cdes:
        return cand
    return {**cand, "metadata": {**cmeta, "designer": {**cdes, "samples": lmeta["designer"]["samples"]}}}


def check_top_level(live: dict, cand: dict) -> None:
    if set(cand.keys()) != set(live.keys()):
        extra = sorted(set(cand) - set(live))
        missing = sorted(set(live) - set(cand))
        raise Abort(f"candidate top-level keys differ from live (added {[safe_key(k) for k in extra]}, "
                    f"missing {[safe_key(k) for k in missing]})")
    if canon(cand.get("name")) != canon(live.get("name")):
        raise Abort("candidate name differs from live. Renames are not pushed by this script")
    lv, cv = top_level_view(live), top_level_view(cand)
    meta_diff = diff_paths(lv.get("metadata"), cv.get("metadata"), "metadata")
    if meta_diff:
        raise Abort("candidate top-level metadata (scenario settings, orphan modules or samples) differs "
                    "from live at: " + ", ".join(_cap(meta_diff)))
    for k in live:
        if k in ("name", "flow", "metadata"):
            continue
        if canon(live[k]) != canon(cand[k]):
            raise Abort(f"candidate top-level key {safe_key(k)} differs from live")


def check_trigger_type(live: dict, cand: dict) -> None:
    """PUSH-4: the first module is the scenario's trigger. Check F reads the webhook registry only for a scenario whose
    trigger is a gateway:CustomWebHook, so swapping the trigger type would make every F row disappear. A push never
    changes the trigger's module type. Replace the trigger in the Make UI, then re-pull."""
    def first_type(bp: dict) -> object:
        flow = bp.get("flow")
        return flow[0].get("module") if isinstance(flow, list) and flow and isinstance(flow[0], dict) else None
    if first_type(live) != first_type(cand):
        raise Abort(f"candidate changes the type of the trigger module ({first_type(live)!r} -> {first_type(cand)!r}). "
                    f"A push never swaps the trigger, since the webhook checks read it. Change the trigger in the Make UI, then re-pull")


# Fix IDs that may add or change a write to the lead Status (hard rule 3: a Status write is an event dispatch).
STATUS_FIXES = ("X-31", "F-31")


# Filter-only exception (approved by Rizwan 2026-10-30 for the F-H9 listener, shape L3). Financial Guardrail's Status
# writes 3 and 4 need tighter filters once the AR trigger also fires on a paid, locked lead. A filter only narrows when
# the module runs, so this fix may change the filter of an existing Status-write module and nothing else about it.
STATUS_FILTER_ONLY_FIXES = ("F-H9",)

# LLM remap exception (approved by Rizwan 2026-10-30 for the X-15/X-18 swap to Claude). Pending Call's Status write 8 also
# saves the call summary from the OpenAI call it follows. When the OpenAI module is replaced by a Claude module in the same
# place, this fix may change such a module's mapper only by rewriting references to the removed OpenAI module into the
# Claude forms check P accepts. The Status field, filter, parameters, handlers, children and position stay equal to live.
STATUS_LLM_REMAP_FIXES = ("X-15", "X-18")
OPENAI_PREFIX = "openai-gpt-3:"
CLAUDE_MODULE = "anthropic-claude:createAMessage"
STATUS_REMAP_MODULE = "airtable:ActionUpdateRecords"

# Add-field exception (approved by Rizwan 2026-10-31 for M11, campaign targeting). VIP intake's creates 7 and 8 write the lead
# Status. This fix may add only the listed fields to such a module's record. Every live record key and value, the Status
# field, the rest of the mapper, filter, parameters, handlers, children and position stay equal to live.
STATUS_ADD_FIELD_FIXES = {"X-41.7": ("fldT1nsKs892JpfcY",)}  # Applicants Industry

# Value-only exception (approved by Rizwan 2026-10-31 for L4, the AR lock's Payment Status). Financial Guardrail's lock
# write 3 sets Payment Status to the literal Partial (check S rule S10). This fix may change only the value of the listed
# fields in the record of an existing Status-write module. The record keeps the same keys, the Status field and every
# other value, the rest of the mapper, filter, parameters, handlers, children and position stay equal to live.
STATUS_VALUE_FIXES = {"F-H1.5": ("fldqpWCzawUrtO5YA",)}  # Applicants Payment Status


def _llm_pairs(lmods: dict, cmods: dict, lpos: dict, cpos: dict, diff: ModuleDiff) -> dict[int, int]:
    """Removed OpenAI module id -> the one added Claude module that sits in exactly its place."""
    pairs: dict[int, int] = {}
    for old in diff.removed:
        if not str(lmods[old].module.get("module", "")).startswith(OPENAI_PREFIX):
            continue
        news = [n for n in diff.added if cmods[n].module.get("module") == CLAUDE_MODULE and cpos.get(n) == lpos.get(old)]
        if len(news) == 1:
            pairs[old] = news[0]
    return pairs


def _remap_llm(v: object, pairs: dict[int, int]) -> object:
    """Rewrite references to each removed OpenAI module into the Claude forms (check P5). Plain string replacement with
    a guard so module 13 never matches inside 113."""
    if isinstance(v, str):
        for old, new in pairs.items():
            o, n = str(old), str(new)
            for before, after in ((o + ".choices[].message.content", 'first(map(' + n + '.content; "text"; "type"; "text"))'),
                                  (o + ".usage.prompt_tokens", n + ".usage.input_tokens"),
                                  (o + ".usage.completion_tokens", n + ".usage.output_tokens")):
                v = re.sub(r"(?<![\w.])" + re.escape(before), lambda _m, a=after: a, v)
        return v
    if isinstance(v, list):
        return [_remap_llm(x, pairs) for x in v]
    if isinstance(v, dict):
        return {k: _remap_llm(x, pairs) for k, x in v.items()}
    return v


def _status_values(mapper: object, lead: audit_blueprints.LeadNames) -> object:
    """The Status field of an Airtable update record, under every key the audit reads as Status (lead_names)."""
    rec = mapper.get("record") if isinstance(mapper, dict) else None
    if not isinstance(rec, dict):
        return None
    return sorted((k, json.dumps(v, sort_keys=True)) for k, v in rec.items()
                  if isinstance(k, str) and k.strip().lower() in lead.keys)


def _without_mapper_or_layout(m: dict) -> dict:
    out = {k: (_strip_layout(v) if k in ("onerror", "routes") else v) for k, v in m.items() if k != "mapper"}
    if isinstance(out.get("metadata"), dict):
        out["metadata"] = {mk: mv for mk, mv in out["metadata"].items() if mk != "designer"}
    return out


def _llm_remap_only(i: int, lmods: dict, cmods: dict, lpos: dict, cpos: dict, diff: ModuleDiff,
                    pairs: dict[int, int], lead: audit_blueprints.LeadNames) -> bool:
    if i not in lmods or i not in cmods or i in diff.added or i in diff.removed or lpos.get(i) != cpos.get(i):
        return False
    lm, cm = lmods[i].module, cmods[i].module
    if lm.get("module") != STATUS_REMAP_MODULE or cm.get("module") != STATUS_REMAP_MODULE or not pairs:
        return False
    if _without_mapper_or_layout(lm) != _without_mapper_or_layout(cm):
        return False
    lmap, cmap = lm.get("mapper"), cm.get("mapper")
    if _status_values(lmap, lead) is None or _status_values(lmap, lead) != _status_values(cmap, lead):
        return False
    expected = _remap_llm(lmap, pairs)
    return expected == cmap and expected != lmap


def _add_field_only(i: int, lmods: dict, cmods: dict, lpos: dict, cpos: dict, diff: ModuleDiff,
                    fields: tuple[str, ...]) -> bool:
    if i not in lmods or i not in cmods or i in diff.added or i in diff.removed or lpos.get(i) != cpos.get(i):
        return False
    lm, cm = lmods[i].module, cmods[i].module
    if _without_mapper_or_layout(lm) != _without_mapper_or_layout(cm):
        return False
    lmap, cmap = lm.get("mapper"), cm.get("mapper")
    if not isinstance(lmap, dict) or not isinstance(cmap, dict):
        return False
    if {k: v for k, v in lmap.items() if k != "record"} != {k: v for k, v in cmap.items() if k != "record"}:
        return False
    lrec, crec = lmap.get("record"), cmap.get("record")
    if not isinstance(lrec, dict) or not isinstance(crec, dict):
        return False
    added = set(crec) - set(lrec)
    return (bool(added) and added <= set(fields) and all(k in crec and crec[k] == v for k, v in lrec.items()))


def _value_only(i: int, lmods: dict, cmods: dict, lpos: dict, cpos: dict, diff: ModuleDiff,
                fields: tuple[str, ...]) -> bool:
    if i not in lmods or i not in cmods or i in diff.added or i in diff.removed or lpos.get(i) != cpos.get(i):
        return False
    lm, cm = lmods[i].module, cmods[i].module
    if _without_mapper_or_layout(lm) != _without_mapper_or_layout(cm):
        return False
    lmap, cmap = lm.get("mapper"), cm.get("mapper")
    if not isinstance(lmap, dict) or not isinstance(cmap, dict):
        return False
    if {k: v for k, v in lmap.items() if k != "record"} != {k: v for k, v in cmap.items() if k != "record"}:
        return False
    lrec, crec = lmap.get("record"), cmap.get("record")
    if not isinstance(lrec, dict) or not isinstance(crec, dict) or set(lrec) != set(crec):
        return False
    changed = {k for k in lrec if lrec[k] != crec[k]}
    return bool(changed) and changed <= set(fields)


def _without_filter_or_layout(m: object) -> object:
    """The module with its own filter removed and metadata.designer stripped at every depth, children included."""
    if isinstance(m, list):
        return [_without_filter_or_layout(x) for x in m]
    if not isinstance(m, dict):
        return m
    out = {}
    for k, v in m.items():
        if k == "metadata" and isinstance(v, dict):
            out[k] = {mk: mv for mk, mv in v.items() if mk != "designer"}
        elif k in ("onerror", "routes"):
            out[k] = _strip_layout(v)
        else:
            out[k] = v
    out.pop("filter", None)
    return out


def _strip_layout(v: object) -> object:
    """metadata.designer removed at every depth, filters kept (children of a Status write may not change at all)."""
    if isinstance(v, list):
        return [_strip_layout(x) for x in v]
    if isinstance(v, dict):
        return {k: ({mk: mv for mk, mv in x.items() if mk != "designer"} if k == "metadata" and isinstance(x, dict)
                    else _strip_layout(x)) for k, x in v.items()}
    return v


def check_status_writes(fix: str, cand: dict, diff: ModuleDiff, links: audit_blueprints.AirtableMap | None,
                        live: dict | None = None) -> list[int]:
    """PUSH-2: modules the push adds or changes that write, or may write, the lead Status. Other scenarios trigger on
    Status values such as Send Contract and Generate Submission, so only the X-31 and F-31 fixes may touch such a
    module, and their spec must name it. The one exception is STATUS_FILTER_ONLY_FIXES: an existing Status write whose
    filter changes and nothing else (mapper, parameters, metadata, handlers, children and position all equal live).
    Returns those module IDs."""
    # Both sides: a push that makes a live Status write stop writing Status (drops the field, retargets the table,
    # deletes the module) touches a Status write too (review 2026-10-30).
    ids = audit_blueprints.status_write_module_ids(cand, links)
    if live is not None:
        ids |= audit_blueprints.status_write_module_ids(live, links)
    touched = sorted(i for i in diff.touched if i in ids)
    if not touched or any(fix == key or fix.startswith(key + ".") for key in STATUS_FIXES):
        return touched
    if any(fix == key or fix.startswith(key + ".") for key in STATUS_FILTER_ONLY_FIXES) and live is not None:
        lmods, _ = index_modules(live, "live blueprint")
        cmods, _ = index_modules(cand, "candidate")
        lpos = module_positions(index_modules(live, "live blueprint")[1])
        cpos = module_positions(index_modules(cand, "candidate")[1])
        bad = [i for i in touched
               if i not in lmods or i not in cmods or i in diff.added or i in diff.removed
               or lpos.get(i) != cpos.get(i)
               or _without_filter_or_layout(lmods[i].module) != _without_filter_or_layout(cmods[i].module)]
        if not bad:
            return touched
        raise Abort(f"fix {fix} may change only the filter of an existing lead Status write (approved 2026-10-30), but modules "
                    f"{bad} change more than their filter, or are added, removed or moved. Split the push by fix ID")
    if any(fix == key or fix.startswith(key + ".") for key in STATUS_LLM_REMAP_FIXES) and live is not None:
        lmods, lcont = index_modules(live, "live blueprint")
        cmods, ccont = index_modules(cand, "candidate")
        lpos, cpos = module_positions(lcont), module_positions(ccont)
        pairs = _llm_pairs(lmods, cmods, lpos, cpos, diff)
        lead = audit_blueprints.lead_names(links)
        bad = [i for i in touched if not _llm_remap_only(i, lmods, cmods, lpos, cpos, diff, pairs, lead)]
        if not bad:
            return touched
        raise Abort(f"fix {fix} may change an existing lead Status write only by remapping a replaced OpenAI module's output to "
                    f"its Claude module (approved 2026-10-30), but modules {bad} change more than that, change the Status field, "
                    f"or are added, removed or moved. Split the push by fix ID")
    add_fields = next((v for key, v in STATUS_ADD_FIELD_FIXES.items() if fix == key or fix.startswith(key + ".")), None)
    if add_fields is not None and live is not None:
        lmods, lcont = index_modules(live, "live blueprint")
        cmods, ccont = index_modules(cand, "candidate")
        lpos, cpos = module_positions(lcont), module_positions(ccont)
        bad = [i for i in touched if not _add_field_only(i, lmods, cmods, lpos, cpos, diff, add_fields)]
        if not bad:
            return touched
        raise Abort(f"fix {fix} may only add the fields {', '.join(add_fields)} to an existing lead Status write (approved "
                    f"2026-10-31), but modules {bad} change more than that, or are added, removed or moved. Split the push by fix ID")
    value_fields = next((v for key, v in STATUS_VALUE_FIXES.items() if fix == key or fix.startswith(key + ".")), None)
    if value_fields is not None and live is not None:
        lmods, lcont = index_modules(live, "live blueprint")
        cmods, ccont = index_modules(cand, "candidate")
        lpos, cpos = module_positions(lcont), module_positions(ccont)
        bad = [i for i in touched if not _value_only(i, lmods, cmods, lpos, cpos, diff, value_fields)]
        if not bad:
            return touched
        raise Abort(f"fix {fix} may change only the value of {', '.join(value_fields)} in an existing lead Status write "
                    f"(approved 2026-10-31), but modules {bad} change more than that, or are added, removed or moved. Split "
                    f"the push by fix ID")
    raise Abort(f"fix {fix} adds or changes lead Status writes in modules {touched}. A Status write dispatches events in other "
                f"scenarios (hard rule 3), so only {' and '.join(STATUS_FIXES)} may do that. Split the push by fix ID")


def check_replaces(live: dict, cand: dict, diff: ModuleDiff, replaces: dict[int, int],
                   allowed: set[int]) -> None:
    """Each OLD=NEW pair is a recreate: OLD removed, NEW added, both listed,
    same module type, same position (parent mapped through the pairs)."""
    if not replaces:
        return
    lmods, lcont = index_modules(live, "live blueprint")
    cmods, ccont = index_modules(cand, "candidate")
    lpos, cpos = module_positions(lcont), module_positions(ccont)
    for old, new in sorted(replaces.items()):
        tag = f"--replaces {old}={new}"
        if old not in allowed or new not in allowed:
            raise Abort(f"{tag}: both IDs must be in --modules")
        if old not in diff.removed:
            raise Abort(f"{tag}: module {old} is not removed by the candidate")
        if new not in diff.added:
            raise Abort(f"{tag}: module {new} is not added by the candidate")
        if lmods[old].module.get("module") != cmods[new].module.get("module"):
            raise Abort(f"{tag}: module types differ, a recreate keeps the module type")
        lparent, lcontainer, lindex = lpos[old]
        expected = (replaces.get(lparent, lparent), lcontainer, lindex)
        if cpos[new] != expected:
            raise Abort(f"{tag}: module {new} is not at module {old}'s position "
                        f"({lmods[old].place} index {lindex})")


# The simplify push of F-E5 v2 (F-E5.2) leaned on the central Error Monitor (the retired check G). Option C (decided by Rizwan 2026-10-29)
# drops the monitor, so F-E5.2 is retired: without a monitor, removing the ledger and Slack modules of a handler would leave the
# failure unlogged. Its successor is F-E5.3, which replaces those modules with one call to the shared Logger scenario.
SIMPLIFY_FIX = "F-E5.2"


def is_simplify_fix(fix: str) -> bool:
    return fix == SIMPLIFY_FIX or fix.startswith(SIMPLIFY_FIX + ".")


# The Logger swap push (F-E5.3, Option C, decided by Rizwan 2026-10-29). Every error handler shrinks from
# [Shadow Ledger create, Slack message, directive] to [one call to the shared Logger scenario, directive]. The Logger writes
# the ledger row and the Slack alert. The directive stays exactly as it is.
LOGGER_FIX = "F-E5.3"
# The Make HTTP module (HTTP app version 4) and its API key keychain authentication. The Logger hook needs header
# x-make-apikey, and the keychain supplies it, so no key literal sits in any blueprint (apps.make.com/http, "Make a request",
# and apps.make.com/api-key-authentication-type).
LOGGER_HTTP_TYPE = "http:MakeRequest"
LOGGER_HTTP_AUTH = tuple(getattr(audit_blueprints, "LOGGER_AUTH", {"apiKeyConnection": 0, "apiKey": 0}))
# Headers the keychain sets. A logger call never writes them by hand.
LOGGER_KEY_HEADERS = frozenset({"x-make-apikey", "authorization", "proxy-authorization"})
# "Return error if HTTP request fails" of the HTTP v4 module (apps.make.com/http). The mapper key is stopOnHttpError, as a
# public Make export of http:MakeRequest v4 shows (field label "Return error if HTTP request fails"). Confirm it on the first
# export of a real caller module. With it false, a 4xx or 5xx from the Logger returns a bundle instead of raising an error
# inside the error handler. A timeout, a DNS or TLS failure and a missing keychain still raise one.
LOGGER_STOP_ON_HTTP_ERROR = "stopOnHttpError"
# The callers read the Logger hook URL from the custom variable the registry names (url_variable of the Logger entry in
# audit/webhooks.json, var.team.IMMIOS_LOGGER_URL in specs/F-E5-v3-shared-logger.md section 5), so no blueprint holds it. The
# fallback where custom variables are not available is the literal URL pinned by token digest in audit/secret_allowlist.json
# (logger_hook), which secret_scan allows only as the bare url field of a Logger call (R6) while the hook is registered
# with api_key.
_CUSTOM_VAR = re.compile(r"^var\.(?:team|organization)\.[A-Za-z0-9_$]+$")
# The keychain field each API key authentication type of http:MakeRequest v4 uses (measured by the audit builder with the Make
# MCP module schema, audit_blueprints.LOGGER_AUTH).
LOGGER_AUTH = dict(getattr(audit_blueprints, "LOGGER_AUTH", {"apiKeyConnection": "apiKeyAccount", "apiKey": "apiKeyKeychain"}))
# Logger readiness reads the check that audits the Logger scenario (check L, audit_blueprints.LOGGER_CHECK). The letter G
# belonged to the retired Error Monitor and is not read.
LOGGER_CHECKS = (audit_blueprints.LOGGER_CHECK,)
# The phrase of a hook-key row whose state is unknown (check F1, and the Logger check for the Logger hook). The one non-PASS
# form the Logger readiness gate accepts.
HOOK_KEY_UNCONFIRMED = getattr(audit_blueprints, "HOOK_KEY_UNCONFIRMED", "UNCONFIRMED, no proof that a key exists")


@dataclass(frozen=True)
class LoggerTarget:
    """The registered Logger (audit/webhooks.json, caller make_http): its scenario and hook, the custom variable the callers read
    the URL from and the HTTP API key connection that sends the key (either None until registered), and the optional literal-URL
    pin (audit/secret_allowlist.json logger_hook, kept only while it names the same hook)."""
    scenario_id: str
    hook_id: int
    url_variable: str | None = None
    connection_id: int | None = None
    pin: secret_scan.LoggerAllowance | None = None


def is_logger_fix(fix: str) -> bool:
    return fix == LOGGER_FIX or fix.startswith(LOGGER_FIX + ".")


def logger_url_ok(url: object, target: LoggerTarget) -> bool:
    """The Logger call URL is exactly {{<url_variable>}} as the registry names it, or the literal Logger hook URL pinned and active
    in audit/secret_allowlist.json (every token hashes to the pin, nothing mapped in, no query or fragment)."""
    if not isinstance(url, str):
        return False
    var = target.url_variable
    if var and _CUSTOM_VAR.match(var) and re.fullmatch(r"\{\{\s*" + re.escape(var) + r"\s*\}\}", url.strip()):
        return True
    pin = target.pin
    if pin is None or not pin.active or pin.scenario_id != target.scenario_id or pin.hook_id != target.hook_id:
        return False
    return "{{" not in url and "?" not in url and "#" not in url and secret_scan.logger_url_matches(url, pin)


def logger_call_problems(m: dict, target: LoggerTarget) -> list[str]:
    """Why a module is not a Logger call at the transport level, or [] when it is one (specs/F-E5-v3-shared-logger.md section 5):
    an http:MakeRequest POST with an API key keychain connection (the registered connection_id when the registry names one), to
    {{<url_variable>}} as audit/webhooks.json names it (or the pinned literal), with no hand-set key header, stopOnHttpError false, allowRedirects false (the key never follows a redirect to another host), no
    filter, no routes and no error handler of its own (check B v3 holds the handler to [call, directive], and whether Make runs a
    handler inside an error route is not verified). The body contract (label, IDs, no client data) is check B, C and E6 on the
    candidate audit."""
    out: list[str] = []
    kind = audit_blueprints._mtype(m)
    if kind != LOGGER_HTTP_TYPE:
        return [f"it is {kind}, not the HTTP module {LOGGER_HTTP_TYPE}"]
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    auth = params.get("authenticationType")
    if auth not in LOGGER_HTTP_AUTH:
        out.append(f"parameters.authenticationType is not an API key keychain ({' or '.join(LOGGER_HTTP_AUTH)}), so the hook's "
                   f"x-make-apikey would have to be written into the blueprint")
    elif target.connection_id is not None and params.get(LOGGER_AUTH.get(auth, "")) != target.connection_id:
        out.append(f"parameters.{LOGGER_AUTH.get(auth)} is not the Logger key connection {target.connection_id} that audit/webhooks.json names")
    mp = audit_blueprints._mapper(m)
    if str(mp.get("method", "")).strip().lower() != "post":
        out.append("mapper.method is not post")
    if not logger_url_ok(mp.get("url"), target):
        want = f"{{{{{target.url_variable}}}}}" if target.url_variable else "the url_variable of the Logger entry (none registered)"
        out.append(f"mapper.url is not {want} (or the Logger hook pinned in audit/secret_allowlist.json)")
    headers = mp.get("headers") if isinstance(mp.get("headers"), list) else []
    named = sorted({str(h.get("name", "")).strip().lower() for h in headers if isinstance(h, dict)} & LOGGER_KEY_HEADERS)
    if named:
        out.append(f"it sets {', '.join(named)} by hand, the keychain supplies the key")
    if mp.get(LOGGER_STOP_ON_HTTP_ERROR) is not False:
        out.append(f"mapper.{LOGGER_STOP_ON_HTTP_ERROR} is not false. With Return error if HTTP request fails on, a 4xx or 5xx from the "
                   f"Logger raises an error inside the error handler and the handler's directive does not run")
    if mp.get("allowRedirects") is not False:
        out.append("mapper.allowRedirects is not false, so a redirect could carry the key to another host")
    if audit_blueprints._conditions(m):
        out.append("it carries a filter, so some errors would not be logged")
    if m.get("routes"):
        out.append("it has routes")
    if m.get("onerror"):
        out.append("it has an error handler of its own. The handler is [Logger call, directive] (check B v3)")
    return out


def _outer_owner(mods: dict[int, ModuleInfo], mid: int) -> int | None:
    """The module outside every error route whose error route (at any depth) holds mid, else None."""
    owner, cur = None, mods[mid]
    while True:
        if cur.container == "onerror":
            owner = cur.parent
        if cur.parent is None:
            return owner
        cur = mods[cur.parent]


def _descends_from(mods: dict[int, ModuleInfo], mid: int, anc: int) -> bool:
    cur = mods[mid].parent
    while cur is not None:
        if cur == anc:
            return True
        cur = mods[cur].parent
    return False


def check_logger_swap(sid: int, live: dict, cand: dict, diff: ModuleDiff, logger: LoggerTarget) -> dict[int, int]:
    """PUSH-6 (F-E5.3): the push only replaces the Shadow Ledger and Slack modules of existing error handlers with one Logger call,
    and keeps the directive and everything else identical. Returns {handler owner: Logger call module ID}.
    - it removes at least one module, and every removed module sits in an error route of a module outside any error route (its
      owner) and is a Shadow Ledger write, a Slack message or a router (never a directive). A router goes only when the removal
      leaves it empty, or when one unfiltered directive takes its place (the only move allowed). A removed module with a real
      filter has nothing after it in its route that stays
    - every owner that loses modules gets exactly one Logger call (logger_call_problems) at the top level of its handler, where
      the first removed (or emptied) module sat, so it runs ahead of the directive. Nothing else is added
    - after the push no Shadow Ledger write and no Slack message is left in such a handler, so the swap is complete
    - every other changed module is such an owner or sits in its handler, and only its child lists change (no mapper edit, no
      move, the survivors keep their order)
    The audit comparison then enforces the rest (no new FAIL, no new REVIEW, the targeted rows close)."""
    if str(sid) == logger.scenario_id:
        raise Abort(f"scenario {sid} is the Logger itself. Its handlers cannot call the Logger, a failing Logger would call itself")
    if not diff.removed:
        raise Abort(f"fix {LOGGER_FIX} replaces handler modules with a Logger call, the candidate removes none")
    lmods, lcont = index_modules(live, "live blueprint")
    cmods, ccont = index_modules(cand, "candidate")
    added = set(diff.added)

    flattened: dict[int, int] = {}   # removed router -> the directive that takes its place in the handler
    owners: dict[int, list[int]] = {}
    for mid in diff.removed:
        owner = _outer_owner(lmods, mid)
        if owner is None:
            raise Abort(f"fix {LOGGER_FIX} replaces handler modules only, module {mid} is not inside an error route")
        mod = lmods[mid].module
        kind = audit_blueprints._mtype(mod)
        # R9: a ledger create only. A ledger update in a handler carries state (it marks an existing row), so it is not a log entry
        # the Logger replaces.
        if not (audit_blueprints.is_ledger_create(mod) or audit_blueprints.is_slack_message(mod) or kind == "builtin:BasicRouter"):
            raise Abort(f"module {mid} ({kind}) is not a Shadow Ledger write (a create), a Slack message or a router. {LOGGER_FIX} removes only those, "
                        f"never a directive or anything else the handler does, because dropping a Resume, Ignore or Break changes what the "
                        f"scenario does on the main path. Changing or removing a directive needs its own fix ID and spec")
        lflow = lcont[(lmods[mid].parent, lmods[mid].container)]
        after_it = [i for i in lflow[lflow.index(mid) + 1:] if i not in diff.removed]
        if audit_blueprints._conditions(mod) and after_it:
            raise Abort(f"module {mid} carries a filter that decides whether the modules after it in its route run, and {after_it} stay. "
                        f"Removing it would change when they run")
        if kind == "builtin:BasicRouter":
            inside = [i for i in lmods if i != mid and _descends_from(lmods, i, mid) and i not in diff.removed]
            if inside:
                d = audit_blueprints.flattenable_directive(mod)
                if d is None or lmods[mid].container != "onerror" or lmods[mid].parent != owner or inside != [d.get("id")]:
                    raise Abort(f"router {mid} is removed but module(s) {inside} inside it stay. A router goes only when the removal "
                                f"leaves it empty, or when it holds one unfiltered directive that takes its place in the handler")
                flattened[mid] = d["id"]
        owners.setdefault(owner, []).append(mid)

    loggers: dict[int, int] = {}
    for aid in diff.added:
        info = cmods[aid]
        if info.container != "onerror" or info.parent not in owners:
            raise Abort(f"module {aid} is added at {info.place}. {LOGGER_FIX} adds only one Logger call to the top level of each handler "
                        f"whose ledger and Slack modules go (owners {sorted(owners)})")
        problems = logger_call_problems(info.module, logger)
        if problems:
            raise Abort(f"module {aid} is not a Logger call: " + "; ".join(problems))
        if info.parent in loggers:
            raise Abort(f"the handler of module {info.parent} gets two Logger calls ({loggers[info.parent]} and {aid}). One call logs the error")
        loggers[info.parent] = aid
    no_call = sorted(set(owners) - set(loggers))
    if no_call:
        raise Abort(f"the handlers of modules {no_call} lose their ledger and Slack modules but get no Logger call. "
                    f"{LOGGER_FIX} replaces them, it never only removes them")

    for owner in sorted(owners):
        left = [i for i, info in cmods.items() if i != owner and _outer_owner(cmods, i) == owner
                and (audit_blueprints.is_ledger_create(info.module) or audit_blueprints.is_slack_message(info.module))]
        if left:
            raise Abort(f"the handler of module {owner} still holds Shadow Ledger or Slack modules {sorted(left)}. The Logger call replaces "
                        f"all of them, otherwise the error is logged twice")

    for mid in sorted(diff.changed):
        lm, cm = lmods[mid], cmods[mid]
        if lm.place != cm.place and not (lm.parent in flattened and flattened[lm.parent] == mid
                                         and cm.place == f"{lmods[lm.parent].parent}.onerror"):
            raise Abort(f"module {mid} moves ({lm.place} -> {cm.place}). The one move {LOGGER_FIX} allows is a directive that takes the "
                        f"place of the handler router that the removal leaves around it")
        core = lambda m: canon({k: v for k, v in module_shell(m).items() if k != "onerror"})   # noqa: E731
        if core(lm.module) != core(cm.module):
            raise Abort(f"module {mid} changes beyond its error routes ({'; '.join(diff.changed[mid])}). "
                        f"{LOGGER_FIX} changes nothing but the swap of the handler's ledger and Slack modules for a Logger call")
        owner = _outer_owner(lmods, mid)
        owner = mid if owner is None else owner
        if owner not in owners:
            raise Abort(f"module {mid} changes but its handler owner {owner} loses no ledger or Slack module. {LOGGER_FIX} touches only "
                        f"the handlers it swaps")
        lkids, ckids = child_lists(mid, lcont), child_lists(mid, ccont)
        for c in sorted(set(lkids) | set(ckids)):
            before = [flattened.get(i, i) for i in lkids.get(c, [])]
            after = ckids.get(c, [])
            survivors = [i for i in after if i not in added]
            if survivors != [i for i in before if i in set(survivors)]:
                raise Abort(f"module {mid} {c} is {before} -> {after}. {LOGGER_FIX} keeps the survivors in their order")
            new_here = [i for i in after if i in added]
            if not (mid in loggers and c == "onerror"):
                if new_here:
                    raise Abort(f"module {mid} {c} gains {new_here}. Only the handler owner's onerror gets the Logger call")
                continue
            # The Logger call sits where the first removed or emptied module of the handler sat, ahead of the directive.
            orig = lkids.get(c, [])
            touched_at = next((p for p, x in enumerate(orig)
                               if x in diff.removed or any(_descends_from(lmods, r, x) for r in diff.removed)), len(orig))
            k = sum(1 for x in before[:touched_at] if x in set(survivors))
            expected = survivors[:k] + [loggers[mid]] + survivors[k:]
            if after != expected:
                raise Abort(f"module {mid} onerror is {after}, the Logger call {loggers[mid]} belongs where the first replaced module sat: "
                            f"{expected}")
    return loggers


def registered_logger(webhooks_path: str, secret_allowlist: list) -> LoggerTarget:
    """The Logger as audit/webhooks.json registers it (secret_scan.registered_loggers): exactly one registration with scenario and
    hook IDs set and protection api_key. The literal-URL pin of audit/secret_allowlist.json rides along when it names the same
    hook."""
    try:
        with open(webhooks_path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise Abort(f"fix {LOGGER_FIX} reads the Logger registration in {os.path.basename(webhooks_path)} ({type(exc).__name__})") from None
    regs = secret_scan.registered_loggers(data)
    if not regs:
        raise Abort(f"fix {LOGGER_FIX} needs the Logger, and audit/webhooks.json registers none with its scenario and hook IDs (caller "
                    f"{secret_scan.LOGGER_CALLER}). Import and activate the Logger (specs/F-E5-v3-shared-logger.md), register its IDs, "
                    f"commit, then pull")
    if len(regs) > 1:
        raise Abort(f"audit/webhooks.json registers {len(regs)} Loggers {[(r['scenario_id'], r['hook_id']) for r in regs]}. "
                    f"One shared Logger serves every handler")
    reg = regs[0]
    sid, hid, protection = reg["scenario_id"], reg["hook_id"], reg["protection"]
    if protection != secret_scan.LOGGER_PROTECTION:
        raise Abort(f"audit/webhooks.json registers the Logger hook {hid} with protection {protection!r}. It must be "
                    f"{secret_scan.LOGGER_PROTECTION}, so a caller without the x-make-apikey key is refused")
    pin = getattr(secret_allowlist, "logger", None)
    return LoggerTarget(sid, hid, reg["url_variable"], reg["connection_id"],
                        pin if pin is not None and pin.scenario_id == sid and pin.hook_id == hid else None)


def check_logger_ready(args: argparse.Namespace, secret_allowlist: list, audit_kw: dict,
                       snapshot_state: Callable[[str], str | None]) -> tuple[LoggerTarget, list[str]]:
    """F-E5.3 replaces the ledger and Slack modules of a handler with a call to the Logger, so the push refuses unless the Logger is
    deployed and works: audit/webhooks.json registers it (scenario and hook IDs, protection api_key), the Logger's snapshot and the
    pull manifest are committed, and the audit of the whole committed pull gives Logger check rows (LOGGER_CHECKS) that all PASS,
    with every F row of the Logger scenario. The one other form accepted is the UNCONFIRMED row of the hook key (the read token
    cannot see the API key state), which comes back as a note for the plan. audit_kw holds the audit inputs the push already loaded
    (labels, schema, links, allowlist, webhooks, hooks, status_designs). The scenario state (active, scheduling) comes from the
    committed manifest."""
    target = registered_logger(args.webhooks, secret_allowlist)
    manifest = os.path.join(args.blueprints, "manifest.json")
    try:
        pulled, _coverage = audit_blueprints.load_manifest_mode(args.blueprints, manifest)
    except audit_blueprints.InputError as exc:
        raise Abort(f"fix {LOGGER_FIX} reads the pull to confirm the Logger: {exc}") from None
    labels = audit_kw["labels"]
    in_scope = []
    for b in pulled:
        _sid, entry = audit_blueprints._labels_entry(b, labels, True)
        if not (isinstance(entry, dict) and entry.get("out_of_scope") is True):
            in_scope.append(b)
    lg = next((b for b in in_scope if b.scenario_id == target.scenario_id), None)
    if lg is None:
        raise Abort(f"fix {LOGGER_FIX} needs the Logger, but scenario {target.scenario_id} (the Logger in audit/webhooks.json) has no "
                    f"snapshot in {os.path.basename(args.blueprints)}/. Pull and commit first")
    for what, path in (("pull manifest", manifest), ("Logger snapshot", os.path.join(args.blueprints, lg.source))):
        not_committed = snapshot_state(path)
        if not_committed:
            raise Abort(f"the {what} {os.path.basename(path)} is not the committed version: {not_committed}. Commit the pull first")
    try:
        res = run_audit(in_scope, labels, audit_kw["schema"], links=audit_kw["links"], allowlist=audit_kw["allowlist"],
                        webhooks=audit_kw["webhooks"], hooks=audit_kw["hooks"], secret_allowlist=secret_allowlist,
                        status_designs=audit_kw["status_designs"], schedule=audit_blueprints.load_schedule_info(manifest),
                        bland_agents=audit_kw.get("bland_agents"), prompts=audit_kw.get("prompts"), ff10=audit_kw.get("ff10"),
                        x32=audit_kw.get("x32"), x16=audit_kw.get("x16"))
    except audit_blueprints.InputError as exc:
        raise Abort(f"fix {LOGGER_FIX} audits the committed pull to confirm the Logger: {exc}") from None
    l_rows = [f for f in res.findings if f.check in LOGGER_CHECKS]
    if not l_rows:
        raise Abort(f"fix {LOGGER_FIX} needs the Logger to pass its check ({'/'.join(LOGGER_CHECKS)}) on the committed pull, and that "
                    f"check returned no rows (the Logger is not deployed, or this audit has no Logger check)")
    f_rows = [f for f in res.findings if f.check == "F" and f.scenario == lg.name]
    ok = (audit_blueprints.PASS, audit_blueprints.INFO)

    def key_unconfirmed(f) -> bool:
        return f.status in (audit_blueprints.FAIL, audit_blueprints.UNCONFIRMED) and HOOK_KEY_UNCONFIRMED in f.detail

    bad = [f for f in l_rows + f_rows if f.status not in ok and not key_unconfirmed(f)]
    if bad:
        raise Abort(f"fix {LOGGER_FIX} needs the Logger to pass its check on the committed pull (only the hook key may be unconfirmed), "
                    f"and it does not:\n  " + "\n  ".join(f"{f.status} {f.check} module {f.module_id}: {f.detail}" for f in bad[:MAX_PATHS]))
    notes = [f"{f.check} module {f.module_id}: {f.detail}" for f in l_rows + f_rows if key_unconfirmed(f)]
    return target, notes


def check_logger_live(client: MakeClient, target: LoggerTarget) -> None:
    """R4: the committed manifest can be stale, because a webhook-triggered scenario is deactivated on its first unhandled error
    (CLAUDE.md, verified behavior). So F-E5.3 also reads the Logger live with the read token (GET /scenarios/{id}, the one read
    hard rule 1 allows for another scenario) and refuses unless isActive is true, isinvalid is not true (Make sets it on a
    scenario stopped by errors) and isPaused is not true. When the response carries hookId it must be the registered hook.
    Not checkable here (hard rule 1 limits make_push to GET /scenarios/{id}): that the team variable and the key connection
    exist and work. The plan says so."""
    sid = target.scenario_id
    try:
        data = client.get_json(f"/scenarios/{int(sid)}", [])
    except NotFound:
        raise Abort(f"fix {LOGGER_FIX} reads the Logger live, and GET /scenarios/{sid} returned 404. The Logger in "
                    f"audit/webhooks.json is gone (deleted or in the trash). Restore it or register the new one, then pull") from None
    scen = data.get("scenario")
    if not isinstance(scen, dict):
        raise Abort(f"fix {LOGGER_FIX} reads the Logger live, and GET /scenarios/{sid} returned no scenario object. Refusing to push blind")
    active = scen.get("isActive")
    if active is not True:
        why = "is INACTIVE" if active is False else "returned no isActive"
        raise Abort(f"the Logger (scenario {sid}) {why} live, whatever the committed manifest says. An inactive Logger queues every "
                    f"call without a run and without an alert (and Make deactivates a webhook scenario on its first unhandled error). "
                    f"Check its history, activate it in the Make UI (hard rule 2), re-pull, then push")
    for key, what in (("isinvalid", "flagged invalid (isinvalid), which Make sets on a scenario stopped by errors"),
                      ("isPaused", "paused (isPaused)")):
        if scen.get(key) is True:
            raise Abort(f"the Logger (scenario {sid}) is {what}. Check it in the Make UI, re-pull, then push")
    hook = scen.get("hookId")
    if isinstance(hook, int) and not isinstance(hook, bool) and hook != target.hook_id:
        raise Abort(f"the Logger (scenario {sid}) is live on hook {hook}, audit/webhooks.json registers hook {target.hook_id}. "
                    f"Callers would reach a hook the Logger no longer listens on. Re-register the hook, then pull")


# --------------------------------------------------------------------------
# Audit comparison
# --------------------------------------------------------------------------

def finding_key(f: audit_blueprints.Finding) -> tuple:
    return (f.check, str(f.module_id), f.status, f.detail)


def review_signature(check: str, detail: str) -> tuple:
    """A REVIEW row without its module numbers, so the same row on a renumbered module compares equal."""
    return (check, re.sub(r"\d+", "#", detail))


@dataclass
class AuditDelta:
    fails_before: int
    fails_after: int
    new_fails: list[tuple]
    closed: list[tuple]
    new_other: list[tuple]
    remaining_fails: set[tuple] = field(default_factory=set)   # (check, module_id) with a FAIL after
    live_fails: set[tuple] = field(default_factory=set)        # (check, module_id) with a FAIL on live
    live_reviews: set[tuple] = field(default_factory=set)      # (check, module_id) with a REVIEW on live
    remaining_reviews: set[tuple] = field(default_factory=set)  # (check, module_id) with a REVIEW after
    # PUSH-1: a REVIEW is the same row when its check and text match with the numbers blanked out, whatever
    # module it sits on. live_review_sigs maps (check, module_id) on live to those signatures, and
    # remaining_review_sigs holds the signatures of the REVIEW rows on touched modules of the candidate, so a
    # module recreated under a new ID cannot carry the row off and call it closed.
    live_review_sigs: dict = field(default_factory=dict)
    remaining_review_sigs: set = field(default_factory=set)


def check_interfaces_unchanged(live_bp: dict, cand_bp: dict) -> None:
    """Check E1 reads each module's metadata.interface, so a candidate that edits an
    interface could close an E1 FAIL (or turn it into an INFO skip) without fixing
    the mapping. A module that exists in both keeps its interface. Interface
    changes go through the Make UI (refresh the module there), then re-pull."""
    lmods, _ = index_modules(live_bp, "live blueprint")
    cmods, _ = index_modules(cand_bp, "candidate")

    def iface(m: dict) -> str:
        md = m.get("metadata")
        return canon(md.get("interface") if isinstance(md, dict) else None)

    changed = sorted(i for i in set(lmods) & set(cmods) if iface(lmods[i].module) != iface(cmods[i].module))
    if changed:
        raise Abort(f"candidate changes metadata.interface of modules {changed}. The audit trusts each module's interface, "
                    f"so a push cannot edit it. Refresh the module in the Make UI, then re-pull")


def run_audit(blueprints: list, labels: audit_blueprints.Labels, schema: audit_blueprints.Schema, partial: bool = False,
              **kw) -> audit_blueprints.AuditResult:
    """audit_blueprints.audit by ID with the optional inputs it accepts. The audit's optional parameters changed with check B v3
    (critical and dispatch went, schedule came), so an input the audit no longer takes is dropped here instead of raising."""
    accepted = inspect.signature(audit_blueprints.audit).parameters
    args = {k: v for k, v in kw.items() if k in accepted}
    if "partial" in accepted:
        args["partial"] = partial
    return audit_blueprints.audit(blueprints, labels, schema, True, **args)


def compare_audits(live_bp: dict, cand_bp: dict, scenario_id: int, name: str,
                   labels: audit_blueprints.Labels, schema: audit_blueprints.Schema,
                   replaces: dict[int, int] | None = None,
                   links: audit_blueprints.AirtableMap | None = None,
                   allowlist: audit_blueprints.Allowlist | None = None,
                   webhooks: audit_blueprints.Webhooks | None = None,
                   hooks: audit_blueprints.HookInfo | None = None,
                   secret_allowlist: list[dict] | None = None,
                   touched: set[int] | None = None,
                   status_designs: audit_blueprints.StatusDesigns | None = None,
                   critical: object = None,
                   dispatch: frozenset | None = None,
                   bland_agents: object = None,
                   prompts: object = None,
                   ff10: object = None,
                   x32: object = None,
                   x16: object = None) -> AuditDelta:
    """Audit live and candidate and compare. With replaces (OLD -> NEW), the
    candidate's findings on NEW are counted as OLD's, so a recreated module
    carries its other findings over instead of showing them as new. touched is
    the set of module IDs the push adds or changes: a REVIEW row on one of them
    that has the text of a live REVIEW target is the same row, moved."""
    check_interfaces_unchanged(live_bp, cand_bp)
    rekey = {str(new): str(old) for old, new in (replaces or {}).items()}

    def run(bp: dict, source: str, mapping: dict[str, str]) -> Counter:
        b = audit_blueprints.Blueprint(name=name, scenario_id=str(scenario_id), source=source, bp=bp)
        res = run_audit([b], labels, schema, True, links=links, allowlist=allowlist, webhooks=webhooks, hooks=hooks,
                        secret_allowlist=secret_allowlist, status_designs=status_designs, critical=critical, dispatch=dispatch,
                        bland_agents=bland_agents, prompts=prompts, ff10=ff10, x32=x32, x16=x16)
        keys = []
        for f in res.findings:
            check, mid, status, detail = finding_key(f)
            keys.append((check, mapping.get(mid, mid), status, detail))
        return Counter(keys)

    before, after = run(live_bp, "live", {}), run(cand_bp, "candidate", rekey)
    fail, review = audit_blueprints.FAIL, audit_blueprints.REVIEW
    fb = sum(n for k, n in before.items() if k[2] == fail)
    fa = sum(n for k, n in after.items() if k[2] == fail)
    new = after - before
    gone = before - after
    live_sigs: dict = {}
    for f in run_audit([audit_blueprints.Blueprint(name=name, scenario_id=str(scenario_id), source="live", bp=live_bp)],
                       labels, schema, True, links=links, allowlist=allowlist, webhooks=webhooks, hooks=hooks,
                       secret_allowlist=secret_allowlist, status_designs=status_designs, critical=critical, dispatch=dispatch,
                       bland_agents=bland_agents, prompts=prompts, ff10=ff10, x32=x32, x16=x16).findings:
        if f.status == review:
            live_sigs.setdefault((f.check, str(f.module_id)), set()).add(review_signature(f.check, f.detail))
    moved = {str(m) for m in (touched or set())}
    cand_sigs = {review_signature(k[0], k[3]) for k in after if k[2] == review and k[1] in moved}
    return AuditDelta(
        fails_before=fb,
        fails_after=fa,
        new_fails=sorted(k for k in new.elements() if k[2] == fail),
        closed=sorted(gone.elements()),
        new_other=sorted(k for k in new.elements() if k[2] != fail and k[2] != audit_blueprints.PASS),
        remaining_fails={(k[0], k[1]) for k in after if k[2] == fail},
        live_fails={(k[0], k[1]) for k in before if k[2] == fail},
        live_reviews={(k[0], k[1]) for k in before if k[2] == review},
        remaining_reviews={(k[0], k[1]) for k in after if k[2] == review},
        live_review_sigs=live_sigs,
        remaining_review_sigs=cand_sigs,
    )


def fix_checks(fix: str) -> tuple[str, ...] | None:
    """The audit checks a fix ID closes. () means declared --closes only (no
    check pinned), None means the fix ID is not mapped (same effect)."""
    for key, checks in FIX_CHECKS.items():
        if fix == key or fix.startswith(key + "."):
            return checks
    return None


def _fmt_target(t: tuple) -> str:
    return f"{t[0]}:{t[1]}" + (":REVIEW" if len(t) > 2 else "")


def split_targets(targets: list[tuple], delta: AuditDelta) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(FAIL targets, REVIEW targets) as (check, module). CHECK:MODULE:REVIEW always names a REVIEW. A bare
    CHECK:MODULE names the FAIL on that module, unless live has no FAIL there and does have a REVIEW, in which
    case it names the REVIEW (E7:5 closes the E7 REVIEW on module 5). When live has both, the bare form is the
    FAIL and the REVIEW needs the :REVIEW suffix."""
    fails: list[tuple[str, str]] = []
    reviews: list[tuple[str, str]] = []
    for t in targets:
        key = (t[0], t[1])
        if len(t) > 2 or (key not in delta.live_fails and key in delta.live_reviews):
            reviews.append(key)
        else:
            fails.append(key)
    return fails, reviews


_E24_DROPPED = re.compile(r"^E24 Ignore on \d+ ends this path when \d+ fails, so modules? ([\d, and]+?) never runs?\b")


def _e24_dropped(detail: str) -> set[int]:
    """Module IDs an E24 FAIL row names as dropped, or an empty set when the row is not E24."""
    m = _E24_DROPPED.match(detail or "")
    return {int(x) for x in re.findall(r"\d+", m.group(1))} if m else set()


def check_targets(fix: str, targets: list[tuple], delta: AuditDelta, allowed: set[int], lookup_ids: set[int] | None = None) -> None:
    """Hard rule 1: the audit on the candidate closes the target findings.
    Every target closes completely, nothing else closes, the check matches
    the fix, and each target sits on a module in --modules. A check F target is
    exempt from the last rule: an F2 finding sits on the module that needs a
    gate or a call-details module in front of it, and the fix may only add that
    module and a filter on the next one. The audit on the candidate still has to
    close the finding, and the diff still limits the change to --modules.

    A REVIEW target (see split_targets) must be a REVIEW on live and absent on the
    candidate, since a fix that changes the module but leaves the row has not closed
    it. Closing REVIEW rows the fix did not declare is allowed, REVIEW is advisory,
    and they are listed in the plan."""
    checks = fix_checks(fix)
    if checks:
        wrong = [t for t in targets if t[0] not in checks]
        if wrong:
            raise Abort(f"fix {fix} closes check {'/'.join(checks)} findings only, --closes names "
                        f"{', '.join(_fmt_target(t) for t in wrong)}. Split the push by fix ID")
    # A check A target on the scenario's registered no-lead lookup (audit/status_allow_list.json no_lead_lookup) is exempt
    # like an F target: the A-2 row sits on the search while the fix changes the router routes that test its aggregator.
    # An E24 target is exempt when every module its live FAIL rows name as dropped is in --modules: the row sits on the
    # Ignore owner, but a fix that rewires the dropped module so it depends on the owner's path closes it without
    # touching the owner (X-46: 18 pointed at a removed call, and rewiring it to Create a Call 32 closes E24 on 2).
    e24_exempt = {(k[0], k[1]) for k in delta.closed if k[2] == audit_blueprints.FAIL and _e24_dropped(k[3])
                  and _e24_dropped(k[3]) <= allowed}
    e24_exempt -= {(k[0], k[1]) for k in delta.closed if k[2] == audit_blueprints.FAIL
                   and not (_e24_dropped(k[3]) and _e24_dropped(k[3]) <= allowed)}
    outside = [t for t in targets if t[1] != "-" and int(t[1]) not in allowed and t[0] != "F"
               and not (t[0] == "A" and int(t[1]) in (lookup_ids or set()))
               and (t[0], t[1]) not in e24_exempt]
    if outside:
        raise Abort(f"--closes names modules not in --modules: {', '.join(_fmt_target(t) for t in outside)}")
    fail_targets, review_targets = split_targets(targets, delta)
    not_on_live = [t for t in review_targets if t not in delta.live_reviews]
    if not_on_live:
        raise Abort(f"--closes names REVIEW rows that are not on live: {', '.join(_fmt_target(t + ('REVIEW',)) for t in not_on_live)}. "
                    f"Only a REVIEW the live audit shows can be closed")
    still_open = [t for t in review_targets if t in delta.remaining_reviews]
    if still_open:
        raise Abort(f"--closes targets the candidate does not fully close: "
                    f"{', '.join(_fmt_target(t + ('REVIEW',)) for t in still_open)} (the REVIEW is still on the candidate)")
    # PUSH-1: the row must not come back on a module the push added or changed (a router recreated under a new ID).
    moved = [t for t in review_targets if delta.live_review_sigs.get(t, set()) & delta.remaining_review_sigs]
    if moved:
        raise Abort(f"--closes targets the candidate does not fully close: "
                    f"{', '.join(_fmt_target(t + ('REVIEW',)) for t in moved)} (the same REVIEW row is on a module the push added or changed, "
                    f"so recreating the module under a new ID closed nothing)")
    fail = audit_blueprints.FAIL
    closed = {(k[0], k[1]) for k in delta.closed if k[2] == fail}
    not_closed = [t for t in fail_targets if t not in closed or t in delta.remaining_fails]
    if not_closed:
        hint = ""
        if any(t in delta.live_reviews and t not in delta.live_fails for t in not_closed):
            hint = " (to close a REVIEW row name it as CHECK:MODULE:REVIEW)"
        raise Abort(f"--closes targets the candidate does not fully close: "
                    f"{', '.join(_fmt_target(t) for t in not_closed)}{hint}")
    undeclared = sorted(closed - set(fail_targets))
    if undeclared:
        raise Abort(f"candidate also closes FAILs not in --closes: "
                    f"{', '.join(_fmt_target(t) for t in undeclared)}. Declare them or split the fix")


def _fmt_finding(k: tuple) -> str:
    check, mid, status, detail = k
    return f"{status} {check} module {mid}: {detail}"


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

def find_snapshot(blueprints_dir: str, scenario_id: int) -> str:
    if not os.path.isdir(blueprints_dir):
        raise Abort(f"no blueprints folder at {blueprints_dir}. Run scripts/make_pull.py first")
    files = make_pull.existing_blueprint_files(blueprints_dir).get(scenario_id, [])
    if not files:
        raise Abort(f"no committed snapshot blueprints/<slug>__{scenario_id}.json. Run scripts/make_pull.py first")
    if len(files) > 1:
        raise Abort(f"more than one snapshot for scenario {scenario_id}: {', '.join(files)}. Re-pull first")
    return os.path.join(blueprints_dir, files[0])


def read_json_file(path: str, what: str) -> object:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise Abort(f"cannot read the {what} {os.path.basename(path)} ({type(exc).__name__})") from None


def load_candidate(path: str) -> dict:
    obj = read_json_file(path, "candidate")
    if not isinstance(obj, dict) or not isinstance(obj.get("flow"), list) \
            or not isinstance(obj.get("name"), str) or not isinstance(obj.get("metadata"), dict):
        raise Abort("candidate is not an export-format blueprint (top-level name, flow, metadata)")
    return obj


def find_specs(specs_dir: str, fix: str, scenario_id: int) -> dict[str, str]:
    """specs/<FIX>-*.md files that name this scenario id (hard rule 1), name -> text."""
    if not os.path.isdir(specs_dir):
        raise Abort(f"no specs folder at {specs_dir}. Every push needs a spec")
    pattern = re.compile(rf"(?<!\d){scenario_id}(?!\d)")
    matches: dict[str, str] = {}
    for name in sorted(os.listdir(specs_dir)):
        if not (name.startswith(f"{fix}-") and name.endswith(".md")):
            continue
        try:
            with open(os.path.join(specs_dir, name), encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        if pattern.search(text):
            matches[name] = text
    if not matches:
        raise Abort(f"no spec specs/{fix}-*.md names scenario {scenario_id}. Write the spec first (hard rule 1)")
    return matches


def spec_missing_ids(spec_texts: list[str], ids: list[int]) -> list[int]:
    """Module IDs no spec text mentions as a standalone number (not inside a
    word, a decimal, or a date such as 2026-10-28)."""
    text = "\n".join(spec_texts)
    return [i for i in ids if not re.search(rf"(?<![\w.\-]){i}(?![\w.]|-\d)", text)]


def git_snapshot_state(path: str) -> str | None:
    """None when the snapshot is tracked by git and identical to HEAD (index
    and working tree), otherwise the reason. Read-only git commands."""
    folder, base = os.path.dirname(os.path.abspath(path)), os.path.basename(path)

    def git(*args: str) -> int:
        try:
            return subprocess.run(["git", "-C", folder, *args], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=60).returncode
        except (OSError, subprocess.SubprocessError):
            return -1

    rc = git("ls-files", "--error-unmatch", "--", base)
    if rc == -1:
        return "git could not be run"
    if rc != 0:
        return "it is not tracked by git"
    rc = git("diff", "--quiet", "HEAD", "--", base)
    if rc == 1:
        return "it differs from the last commit"
    if rc != 0:
        return "git could not compare it with HEAD"
    return None


def write_push_record(pushes_dir: str, record: dict, fix: str, scenario_id: int,
                      when: datetime, tokens: tuple[str, ...]) -> str:
    os.makedirs(pushes_dir, exist_ok=True)
    stem = f"{when.date().isoformat()}__{fix}__{scenario_id}"
    path = os.path.join(pushes_dir, f"{stem}.json")
    n = 2
    while os.path.exists(path):
        path = os.path.join(pushes_dir, f"{stem}-{n}.json")
        n += 1
    text = render_json(record)
    for t in tokens:
        text = redact(text, t)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


# --------------------------------------------------------------------------
# Push
# --------------------------------------------------------------------------

class Printer:
    def __init__(self, tokens: tuple[str, ...]):
        self.tokens = tuple(t for t in tokens if t)

    def clean(self, text: str) -> str:
        for t in self.tokens:
            text = redact(text, t)
        return text

    def out(self, text: str = "") -> None:
        print(self.clean(text))

    def err(self, text: str) -> None:
        print(self.clean(text), file=sys.stderr)


@dataclass
class ScenarioState:
    active: bool | None
    name: str | None
    invalid: bool | None
    locked: bool | None


def get_scenario_state(client: MakeClient, scenario_id: int) -> ScenarioState:
    data = client.get_json(f"/scenarios/{scenario_id}", [])
    scen = data.get("scenario")
    if not isinstance(scen, dict):
        return ScenarioState(None, None, None, None)

    def flag(key: str) -> bool | None:
        v = scen.get(key)
        return v if isinstance(v, bool) else None

    name = scen.get("name") if isinstance(scen.get("name"), str) else None
    return ScenarioState(flag("isActive"), name, flag("isinvalid"), flag("islocked"))


def get_version(payload: dict, what: str) -> int:
    v = payload.get("version")
    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
        raise Abort(f"{what} has no integer version, cannot set baseVersion")
    return v


def get_id_sequence(payload: dict) -> int | None:
    """response.idSequence of GET /scenarios/{id}/blueprint (Make's module ID counter)."""
    v = payload.get("idSequence")
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _server_filled(path: str) -> bool:
    head = path.split(" (")[0]
    return any(head == k or head.startswith(k + ".") or head.startswith(k + "[") for k in SERVER_FILLED)


def compare_flow_after(before: dict, cand: dict, after: dict, touched: set[int]) -> tuple[list[str], list[str]]:
    """Problems and warnings comparing the live blueprint after the save with
    what was meant to be saved. Untouched modules must equal their state
    before the save. Touched and added modules must equal the candidate,
    except that a difference under a server-filled key is a warning. Keys
    only present after the save are keys Make adds and are ignored."""
    problems: list[str] = []
    warnings: list[str] = []
    try:
        bmods, _ = index_modules(before, "live blueprint before the save")
        cmods, ccont = index_modules(cand, "candidate")
        amods, acont = index_modules(after, "live blueprint after the save")
    except Abort as exc:
        return [str(exc)], []
    for mid in sorted(cmods):
        if mid not in amods:
            problems.append(f"module {mid} missing")
            continue
        expected = cmods[mid].module if mid in touched else bmods.get(mid, cmods[mid]).module
        for p in diff_paths(module_shell(expected), module_shell(amods[mid].module), subset=True):
            (warnings if mid in touched and _server_filled(p) else problems).append(f"module {mid} {p}")
        if cmods[mid].place != amods[mid].place:
            problems.append(f"module {mid} moved {cmods[mid].place} -> {amods[mid].place}")
    extra = sorted(set(amods) - set(cmods))
    if extra:
        problems.append(f"modules not in the candidate: {extra}")
    for key in sorted(set(ccont) | set(acont), key=lambda k: (k[0] or 0, k[1])):
        if ccont.get(key, []) != acont.get(key, []):
            where = "flow" if key[0] is None else f"{key[0]}.{key[1]}"
            problems.append(f"{where} order {ccont.get(key, [])} -> {acont.get(key, [])}")
    return problems, warnings


def post_check(client: MakeClient, scenario_id: int, base_version: int, before: dict, cand: dict,
               touched: set[int]) -> dict:
    """Read-only checks after a save. Every result is recorded, none raises."""
    pc: dict = {}
    try:
        state = get_scenario_state(client, scenario_id)
        pc["is_active"] = state.active
        pc["is_invalid"] = state.invalid
    except PullError as exc:
        pc["is_active"] = None
        pc["is_active_error"] = str(exc)
    try:
        live = make_pull.get_blueprint(client, scenario_id, draft=False)
        v = live.get("version")
        pc["version_after"] = v if isinstance(v, int) and not isinstance(v, bool) else None
        pc["version_increased"] = isinstance(pc["version_after"], int) and pc["version_after"] > base_version
        pc["id_sequence_after"] = get_id_sequence(live)
        problems, warnings = compare_flow_after(before, cand, live["blueprint"], touched)
        pc["flow_matches"] = not problems
        pc["flow_differences"] = _cap(problems)
        pc["flow_warnings"] = _cap(warnings)
        pc["top_level_differences"] = _cap(diff_paths(top_level_view(cand), top_level_view(live["blueprint"]),
                                                      subset=True))
    except PullError as exc:
        pc["version_after"] = None
        pc["version_increased"] = None
        pc["flow_matches"] = None
        pc["live_error"] = str(exc)
    try:
        draft = make_pull.get_blueprint(client, scenario_id, draft=True)
        pc["draft_null"] = draft is None
    except PullError as exc:
        pc["draft_null"] = None
        pc["draft_error"] = str(exc)
    return pc


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def push(args: argparse.Namespace, cfg: PushConfig, transport: Callable,
         sleep: Callable[[float], None], now: Callable[[], datetime], p: Printer,
         snapshot_state: Callable[[str], str | None] = git_snapshot_state) -> int:
    sid = args.scenario
    guarded = GuardedTransport(transport, cfg.read.base_url, sid)
    client = MakeClient(cfg.read, transport=guarded, sleep=sleep)
    tokens = (cfg.read.token, cfg.write.token)
    targets: list[tuple] = args.closes
    replaces: dict[int, int] = args.replaces or {}

    if is_simplify_fix(args.fix):
        raise Abort(f"fix {SIMPLIFY_FIX} is retired. It removed handler modules on the strength of the Error Monitor, which Option C "
                    f"dropped (Rizwan 2026-10-29), so the failures would go unlogged. Use {LOGGER_FIX}, which replaces the ledger and "
                    f"Slack modules with one Logger call")
    logger_fix = is_logger_fix(args.fix)
    if logger_fix and replaces:
        raise Abort(f"fix {LOGGER_FIX} swaps handler modules for a Logger call, --replaces recreates modules. Use a different fix ID")
    specs = find_specs(args.specs, args.fix, sid)
    cand = load_candidate(args.candidate)
    snap_path = find_snapshot(args.blueprints, sid)
    not_committed = snapshot_state(snap_path)
    if not_committed:
        raise Abort(f"snapshot {os.path.basename(snap_path)} is not the committed snapshot: {not_committed}. "
                    f"Commit the pull first (hard rule 1)")
    snapshot = read_json_file(snap_path, "snapshot")
    try:
        labels = audit_blueprints.load_labels(args.labels)
        schema = audit_blueprints.load_schema(args.schema)
        links = audit_blueprints.load_links(args.links, required=True)
        allowlist = audit_blueprints.load_allowlist(args.allowlist)
        webhooks = audit_blueprints.load_webhooks(args.webhooks, required=True)   # a missing registry would hide every F2 row on both sides
        secret_allowlist = secret_scan.load_secret_allowlist(args.secret_allowlist, args.webhooks)
        hooks = audit_blueprints.load_hooks_info(os.path.join(args.blueprints, "manifest.json"))
        status_designs = audit_blueprints.load_status_designs(args.status_allow)
        bland_agents = audit_blueprints.load_bland_agents(args.bland_agents, required=True)   # E28 (X-46), read once so both audits see the same registry
        prompts = audit_blueprints.load_prompts(args.prompts, args.prompt_bindings)   # check R (X-36.1), required: an empty registry hides every R row
        ff10 = audit_blueprints.load_ff10(args.ff10, required=True)   # E30 and E31 (F-F10): the owner pin decides who may write Drafting Status
        x32 = audit_blueprints.load_x32(args.x32, required=True)   # E35 to E37 (X-32): the Exemplars table, the firm literal and the Limit
        x16 = audit_blueprints.load_x16(args.x16, required=True)   # E38 to E40 and the E32 review folder (X-16): the Draft Reviews trail
        audit_blueprints.check_pins_agree(ff10, x16)
    except (audit_blueprints.InputError, secret_scan.SecretAllowlistError) as exc:
        raise Abort(f"audit inputs: {exc}") from None
    # The no-new-FAIL rule is only as strong as the files the audit reads. An
    # uncommitted edit to any of them could blind it (an emptied links map, an
    # allowlist entry that turns a FAIL into INFO, an agent registered in the
    # Bland agent registry that closes E28), so each must equal HEAD. A missing
    # registry is not skipped like a missing allowlist: an empty registry hides the
    # E28 rule on a migrated pathway, so it would loosen the audit.
    for what, path in (("allowlist", args.allowlist), ("Airtable links map", args.links),
                       ("scenario labels", args.labels), ("ledger schema", args.schema),
                       ("webhook registry", args.webhooks), ("secret allowlist", args.secret_allowlist),
                       ("status allow-list", args.status_allow), ("Bland agent registry", args.bland_agents),
                       ("prompts registry", args.prompts), ("prompt bindings", args.prompt_bindings),
                       ("F-F10 owner pin", args.ff10), ("X-32 exemplar pin", args.x32), ("X-16 review pin", args.x16)):
        if what in ("allowlist", "secret allowlist", "status allow-list") and not os.path.exists(path):
            continue  # a missing allowlist is the strictest one (the load above already refuses a missing webhook registry)
        not_committed = snapshot_state(path)
        if not_committed:
            raise Abort(f"audit input {os.path.basename(path)} ({what}) is not the committed version: {not_committed}. "
                        f"Commit it first, since the audit that gates this push reads it")
    # A registered prompt version never changes or disappears (X-36.1, decision 4). HEAD equality alone would accept a
    # version rewritten in a later commit, so every version is held to the commit that first registered it.
    try:
        prompt_history = audit_blueprints.prompt_registry.history_problems(args.prompts)
    except audit_blueprints.prompt_registry.RegistryError as exc:
        raise Abort(f"audit inputs: prompts registry history: {exc}") from None
    if prompt_history:
        raise Abort("prompts registry: " + "; ".join(prompt_history))

    logger_target: LoggerTarget | None = None
    logger_notes: list[str] = []
    if logger_fix:
        logger_target, logger_notes = check_logger_ready(
            args, secret_allowlist, {"labels": labels, "schema": schema, "links": links, "allowlist": allowlist, "webhooks": webhooks,
                                     "hooks": hooks, "status_designs": status_designs, "bland_agents": bland_agents,
                                     "prompts": prompts, "ff10": ff10, "x32": x32, "x16": x16}, snapshot_state)
        # R4: the committed manifest can be stale. Read the Logger live, on its own read-only transport.
        logger_client = MakeClient(cfg.read, transport=ScenarioStateTransport(transport, cfg.read.base_url,
                                                                              int(logger_target.scenario_id)), sleep=sleep)
        check_logger_live(logger_client, logger_target)

    # 2. Inactive, not locked, not invalid.
    state = get_scenario_state(client, sid)
    if state.active is None:
        raise Abort(f"GET /scenarios/{sid} returned no isActive. Refusing to push blind")
    if state.active:
        raise Abort(f"scenario {sid} is ACTIVE. Deactivate it in the Make UI first. make_push never "
                    f"writes to an active scenario")
    if state.locked:
        raise Abort(f"scenario {sid} is locked (islocked). Check it in the Make UI first")
    if state.invalid:
        raise Abort(f"scenario {sid} is flagged invalid (isinvalid). Check it in the Make UI first")

    # 3. Live equals the committed snapshot, at the version the candidate was built from.
    live_payload = make_pull.get_blueprint(client, sid, draft=False)
    live = live_payload["blueprint"]
    live_version = get_version(live_payload, "live blueprint")
    # Snapshots carry no sample data (make_pull.strip_samples, hard rule 5).
    if canon(make_pull.strip_samples(live)) != canon(snapshot):
        raise Abort(f"live differs from snapshot ({os.path.basename(snap_path)}, live version {live_version}). "
                    f"Re-pull, then rebuild the candidate from the new snapshot")
    if live_version != args.base_version:
        raise Abort(f"live version {live_version} is not --base-version {args.base_version}, the version the "
                    f"candidate was built from. Re-pull, then rebuild the candidate from the new snapshot")

    # 4. No unpublished draft.
    try:
        draft = make_pull.get_blueprint(client, sid, draft=True)
    except NotFound:
        raise Abort("draft state unknown (draft=true returned 404). Check the scenario in the Make UI") from None
    if draft is not None:
        raise Abort(f"scenario {sid} has an unpublished draft in the Make UI. Publish or discard it, "
                    f"re-pull, then rebuild the candidate")

    name = state.name or (live.get("name") if isinstance(live.get("name"), str) else f"scenario {sid}")

    # 5. Module diff. A candidate built from a snapshot has no sample data, so
    # carry Make's live samples over unchanged and the save leaves them as they are.
    cand = restore_samples(live, cand)
    check_top_level(live, cand)
    diff = diff_modules(live, cand)
    allowed = set(args.modules)
    if not diff.touched:
        raise Abort("candidate equals live apart from designer data. Nothing to push")
    outside = sorted(diff.touched - allowed)
    if outside:
        raise Abort(f"modules changed but not in --modules: {outside}")
    unchanged = sorted(allowed - diff.touched)
    if unchanged:
        raise Abort(f"--modules lists IDs that do not change (typo?): {unchanged}")
    check_replaces(live, cand, diff, replaces, allowed)
    check_trigger_type(live, cand)
    status_touched = check_status_writes(args.fix, cand, diff, links, live)
    swapped: dict[int, int] = {}
    if logger_fix:
        swapped = check_logger_swap(sid, live, cand, diff, logger_target)
        declared = {int(t[1]) for t in targets if t[0] == "B" and t[1] != "-"}
        undeclared = sorted(set(swapped) - declared)
        if undeclared:
            raise Abort(f"fix {LOGGER_FIX} rewrites the handlers of modules {undeclared}, and --closes does not name their B rows. "
                        f"Name each as B:<module> (the legacy handler REVIEW, or the FAIL of a partial handler), so every swap closes "
                        f"the row it targets")
    id_sequence = get_id_sequence(live_payload)
    if diff.added:
        if id_sequence is None:
            raise Abort("the live blueprint response has no idSequence, so new module IDs cannot be checked "
                        "against Make's module counter")
        low = [i for i in diff.added if i <= id_sequence]
        if low:
            raise Abort(f"new module IDs {low} are at or below the scenario's idSequence {id_sequence}. Make has "
                        f"used them already (possibly for a deleted module). Number new modules above {id_sequence}")

    # 6. Secrets.
    findings, allowed_urls = secret_scan.split_findings(cand, sid, secret_allowlist)
    _pinned = [a for a in allowed_urls if a.get("kind") != secret_scan.LOGGER_KIND]
    _logger_urls = [a for a in allowed_urls if a.get("kind") == secret_scan.LOGGER_KIND]
    if findings:
        listed = ", ".join(f"{f['pattern_type']} at {f['location']}" for f in findings[:MAX_PATHS])
        raise Abort(f"candidate has credential literals: {listed}. Use a Make connection instead")

    # 7. Audit.
    delta = compare_audits(live, cand, sid, name, labels, schema, replaces, links, allowlist,
                           webhooks, hooks, secret_allowlist, touched=diff.touched, status_designs=status_designs,
                           bland_agents=bland_agents, prompts=prompts, ff10=ff10, x32=x32, x16=x16)
    if delta.new_fails:
        raise Abort("candidate adds FAIL findings not present on live:\n  "
                    + "\n  ".join(_fmt_finding(k) for k in delta.new_fails))
    # A fix that closes a declared REVIEW row may leave the FAIL count where it is. check_targets
    # below aborts unless every declared REVIEW target is gone from the candidate, so equal counts
    # pass only when at least one declared REVIEW target closes. More FAILs never pass.
    _fail_targets, review_targets = split_targets(targets, delta)
    if logger_fix:
        # F-E5.3 swaps legacy handler modules for a Logger call. It closes REVIEW rows (and the FAIL of a partial handler at most),
        # so an equal FAIL count passes. It may add no FAIL, no REVIEW and nothing unconfirmed, and check_targets below requires
        # every targeted row to close.
        worse = [k for k in delta.new_other if k[2] in (audit_blueprints.REVIEW, audit_blueprints.UNCONFIRMED)]
        if worse:
            raise Abort(f"fix {LOGGER_FIX} adds findings it may not:\n  " + "\n  ".join(_fmt_finding(k) for k in worse))
        if delta.fails_after > delta.fails_before:
            raise Abort(f"candidate raises the FAIL count ({delta.fails_before} -> {delta.fails_after})")
    elif delta.fails_after > delta.fails_before or (delta.fails_after == delta.fails_before and not review_targets):
        raise Abort(f"candidate does not reduce the FAIL count ({delta.fails_before} -> {delta.fails_after})")
    _entry = (status_designs.entries.get(str(sid)) if status_designs is not None else None) or {}
    check_targets(args.fix, targets, delta, allowed,
                  {int(_entry["no_lead_lookup"])} if _entry.get("no_lead_lookup") is not None else set())
    must_name_set = {int(t[1]) for t in targets if t[1] != "-"} | set(diff.removed) | set(status_touched)
    if review_targets or logger_fix:
        # PUSH-2: a REVIEW row is advisory, so the spec must account for every module the push touches.
        must_name_set |= diff.touched
    must_name = sorted(must_name_set)
    unnamed = spec_missing_ids(list(specs.values()), must_name)
    if unnamed:
        raise Abort(f"the spec ({', '.join(specs)}) does not name modules {unnamed}. The spec names every "
                    f"target and every removed module")

    # Plan.
    checks = fix_checks(args.fix)
    p.out(f"make_push: {'APPLY' if args.apply else 'DRY RUN'} {args.fix} on scenario {sid} {name!r}")
    p.out(f"Spec: {', '.join('specs/' + s for s in specs)}")
    p.out(f"Live version {live_version} (= --base-version), inactive, equals committed "
          f"{os.path.basename(snap_path)}, no draft.")
    p.out(f"Modules: changed {sorted(diff.changed)}, added {diff.added}, removed {diff.removed}")
    for mid in sorted(diff.changed):
        p.out(f"  {mid}: " + "; ".join(diff.changed[mid]))
    if replaces:
        p.out("Replaces: " + ", ".join(f"{o} -> {n}" for o, n in sorted(replaces.items())))
    if logger_fix:
        p.out(f"Logger swap ({LOGGER_FIX}): {len(swapped)} handler(s) rewritten to [Logger call, directive], "
              + ", ".join(f"{o} -> call {c}" for o, c in sorted(swapped.items()))
              + f". Removed {len(diff.removed)} ledger, Slack or router module(s), the directives stay, FAIL count may stay equal.")
        p.out(f"Logger: scenario {logger_target.scenario_id}, hook {logger_target.hook_id}, registered with api_key, its check passes "
              f"on the committed pull, and it is active and not invalid live.")
        p.out(f"Not checked by this push: that the team variable ({logger_target.url_variable or 'none registered'}) and the key "
              f"connection ({logger_target.connection_id if logger_target.connection_id is not None else 'none registered'}) exist "
              f"and work. make_push may read GET /scenarios/{{id}} only (hard rule 1). Step 7 of specs/F-E5-v3-shared-logger.md "
              f"proves them once, so re-run it after any change to either.")
        for note in logger_notes:
            p.out(f"  accepted as unconfirmed (hook key): {note}")
        p.out("Residual risk: a Logger call that fails below HTTP (timeout, DNS or TLS, a missing connection or team variable) is an "
              "error inside the error route, so the run ends with an error and the handler's directive does not run.")
    if diff.added:
        p.out(f"New module IDs above idSequence {id_sequence}.")
    allowed_txt = [x for x in (f"{len(_pinned)} pinned Make webhook URL(s) in Bland call modules" if _pinned else "",
                               f"{len(_logger_urls)} pinned Logger hook URL(s)" if _logger_urls else "") if x]
    p.out("Secret scan: clean." if not allowed_txt else f"Secret scan: clean apart from {' and '.join(allowed_txt)}.")
    p.out(f"Audit inputs equal HEAD. Allowlist entries: {len(allowlist.entries)}.")
    p.out(f"Targets: {', '.join(_fmt_target(t) for t in targets)} "
          f"({args.fix} -> check {'/'.join(checks) if checks else 'as declared'}), all closed.")
    if review_targets:
        p.out(f"REVIEW targets closed: {', '.join(_fmt_target(t + ('REVIEW',)) for t in review_targets)}.")
    p.out(f"Audit FAIL {delta.fails_before} -> {delta.fails_after}. Closed:")
    for k in delta.closed:
        p.out(f"  {_fmt_finding(k)}")
    if delta.new_other:
        p.out("New REVIEW/INFO:")
        for k in delta.new_other:
            p.out(f"  {_fmt_finding(k)}")

    if not args.apply:
        p.out("Dry run: no PATCH sent. Re-run with --apply to save.")
        return EXIT_OK

    # 8. PATCH.
    body = json.dumps({"blueprint": json.dumps(cand, ensure_ascii=False), "baseVersion": live_version},
                      ensure_ascii=False).encode("utf-8")
    outcome = patch_blueprint(cfg.write, guarded, sleep, sid, body, tokens)
    pushed_at = now().astimezone(timezone.utc).replace(microsecond=0)
    code_txt = f" [{outcome.code}]" if outcome.code else ""
    if outcome.kind == "conflict":
        if outcome.conflict_reason == "scenario_version_conflict":
            why = f"a newer version was saved since version {live_version}. Re-pull and rebuild the candidate."
        elif outcome.conflict_reason == "other":
            why = ("Make reported a concurrent change during the save (reason not a version conflict). "
                   "Re-pull. If live still equals the snapshot, retry.")
        else:
            why = (f"either a newer version was saved since version {live_version}, or a concurrent change hit "
                   f"the save. Re-pull. If live still equals the snapshot, retry, else rebuild the candidate.")
        p.err(f"make_push: PATCH refused with 409{code_txt}: {why} Nothing changed.")
        return EXIT_REJECTED
    if outcome.kind == "rejected":
        hint = ""
        if outcome.code == "IM002":
            hint = " (the blueprint places a connection or key that is locked or not available to this token)"
        elif outcome.status in (401, 403):
            hint = " (check MAKE_WRITE_TOKEN is valid and has scenarios:write)"
        p.err(f"make_push: PATCH rejected, HTTP {outcome.status}{code_txt}{hint}. Nothing changed.")
        if outcome.detail:
            p.err(f"make_push: Make says: {outcome.detail}")
        return EXIT_REJECTED

    # 9. Post-check. An unknown outcome with no save seen is read again after
    # a short delay, since a save behind a gateway error can land late.
    touched = diff.touched
    pc = post_check(client, sid, live_version, live, cand, touched)
    if outcome.kind == "unknown" and pc.get("version_increased") is False:
        sleep(UNKNOWN_RECHECK_S)
        pc = post_check(client, sid, live_version, live, cand, touched)
        pc["rechecked_after_s"] = UNKNOWN_RECHECK_S
    checked_at = _utc(now())
    not_observed = outcome.kind == "unknown" and pc.get("version_increased") is False

    problems: list[str] = []
    warnings: list[str] = list(pc.get("flow_warnings") or [])
    if not_observed:
        problems.append(f"PATCH outcome unknown ({outcome.reason}{code_txt}). No save seen as of {checked_at}")
    else:
        if outcome.kind == "unknown":
            problems.append(f"PATCH outcome unknown ({outcome.reason}{code_txt}) but the scenario changed")
        if pc.get("version_increased") is not True:
            problems.append(f"live version did not increase past {live_version} "
                            f"(now {pc.get('version_after')})")
        if pc.get("flow_matches") is False:
            problems.append("live flow differs from the candidate at: " + ", ".join(pc["flow_differences"]))
        elif pc.get("flow_matches") is None:
            problems.append("could not read the live blueprint after the save")
        if pc.get("top_level_differences"):
            problems.append("top-level settings differ from the candidate at: "
                            + ", ".join(pc["top_level_differences"]))
        if "version_after" in pc and pc.get("flow_matches") is not None:
            seq_after = pc.get("id_sequence_after")
            highest = max(index_modules(cand, "candidate")[0], default=0)
            if seq_after is None:
                if diff.added:
                    problems.append("could not read idSequence after the save, check new module IDs in the UI")
            elif seq_after < highest:
                problems.append(f"idSequence {seq_after} is below the highest module ID {highest}. A later UI "
                                f"edit could reuse an ID")
        if outcome.body_invalid:
            problems.append("the PATCH response flags the scenario invalid (isinvalid)")
        if pc.get("is_invalid"):
            problems.append("the scenario is flagged invalid (isinvalid) after the save")
    if outcome.body_active:
        problems.append("the PATCH response reports the scenario active")
    if pc.get("is_active") is not False:
        problems.append("scenario is active after the save" if pc.get("is_active") else
                        "could not confirm the scenario is inactive")
    if pc.get("draft_null") is False:
        problems.append("a draft exists after the save and needs publishing or discarding in the Make UI"
                        if not_observed else "the save landed as a draft and needs publishing in the Make UI")
    elif pc.get("draft_null") is None:
        problems.append("could not read the draft state after the save")

    if pc.get("is_active") is True or outcome.body_active is True:
        result = "ALARM_ACTIVE"
    elif not_observed:
        result = "unknown_not_observed"
    elif problems:
        result = "post_check_failed"
    else:
        result = "ok"

    record = {
        "fix": args.fix,
        "scenario": {"id": sid, "name": name},
        "specs": [f"specs/{s}" for s in specs],
        "version_before": live_version,
        "version_after": pc.get("version_after"),
        "modules": {"changed": sorted(diff.changed), "added": diff.added, "removed": diff.removed},
        "replaces": {str(o): n for o, n in sorted(replaces.items())},
        "targets": [_fmt_target(t) for t in targets],
        "audit_fail_count": {"before": delta.fails_before, "after": delta.fails_after},
        "findings_closed": [dict(zip(("check", "module_id", "status", "detail"), k)) for k in delta.closed],
        "findings_new": [dict(zip(("check", "module_id", "status", "detail"), k)) for k in delta.new_other],
        "patch": {"outcome": outcome.kind, "http_status": outcome.status},
        "post_check": {k: v for k, v in pc.items() if not k.endswith("_error")},
        "problems": problems,
        "warnings": warnings,
        "result": result,
        "pushed_at": pushed_at.isoformat().replace("+00:00", "Z"),
        "checked_at": checked_at,
        "tool": "scripts/make_push.py",
    }
    try:
        rec_path = write_push_record(args.pushes_dir, record, args.fix, sid, pushed_at, tokens)
    except OSError as exc:
        # The save may already have happened, so report it rather than masking it.
        rec_path = f"NOT WRITTEN ({type(exc).__name__}), copy the lines above into the record by hand"
        problems.append("push record not written")

    if result == "ALARM_ACTIVE":
        banner = "!" * 72
        p.err(banner)
        p.err(f"ALARM: scenario {sid} {name!r} is ACTIVE after the save.")
        p.err("Rizwan: deactivate it in the Make UI NOW. An active copy fires on live data:")
        p.err("duplicate client emails, duplicate paid Bland calls, duplicate Stripe intents.")
        p.err(banner)
        for prob in problems:
            p.err(f"  - {prob}")
        p.err(f"Push record: {rec_path}")
        return EXIT_ALARM
    if not_observed:
        p.err(f"make_push: PATCH outcome unknown ({outcome.reason}{code_txt}). Not saved as of the post-check "
              f"at {checked_at}: live version still {pc.get('version_after')}. A late save is possible. "
              f"Re-pull before retrying.")
        for prob in problems[1:]:
            p.err(f"  - {prob}")
        p.err(f"Push record: {rec_path}")
        return EXIT_POSTCHECK
    if problems:
        p.err(f"make_push: saved, post-check found problems (version {live_version} -> "
              f"{pc.get('version_after')}):")
        for prob in problems:
            p.err(f"  - {prob}")
        for w in warnings:
            p.err(f"  warning: {w}")
        for k in ("is_active_error", "live_error", "draft_error"):
            if pc.get(k):
                p.err(f"  ({pc[k]})")
        p.err(f"Push record: {rec_path}")
        return EXIT_POSTCHECK
    p.out(f"Saved: version {live_version} -> {pc['version_after']}, inactive, live flow matches, no draft.")
    for w in warnings:
        p.out(f"  warning (server-filled key on a touched module): {w}")
    p.out(f"Push record: {rec_path}")
    p.out("Next: pull, audit, diff against the last commit, then commit with the fix ID first.")
    return EXIT_OK


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _modules_arg(text: str) -> list[int]:
    out: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part.isdigit() or int(part) <= 0:
            raise argparse.ArgumentTypeError("expected a comma list of positive module IDs")
        if int(part) not in out:
            out.append(int(part))
    if not out:
        raise argparse.ArgumentTypeError("expected at least one module ID")
    return out


def _scenario_arg(text: str) -> int:
    if not text.strip().isdigit() or int(text) <= 0:
        raise argparse.ArgumentTypeError("expected a positive scenario ID")
    return int(text)


def _fix_arg(text: str) -> str:
    if len(text) > FIX_ID_MAX or not FIX_ID.match(text):
        raise argparse.ArgumentTypeError("expected a fix ID such as F-E5 or X-19")
    return text


def _positive_int_arg(text: str) -> int:
    if not text.strip().isdigit() or int(text) <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return int(text)


def _closes_arg(text: str) -> list[tuple]:
    out: list[tuple] = []
    for part in text.split(","):
        m = CLOSES_ITEM.match(part.strip())
        if not m or (m.group(2) != "-" and int(m.group(2)) <= 0):
            raise argparse.ArgumentTypeError("expected CHECK:MODULE pairs such as B:2 or C:15,C:16 "
                                             "(C:- for a scenario-level finding, CHECK:MODULE:REVIEW for a REVIEW row)")
        key: tuple = (m.group(1), m.group(2) if m.group(2) == "-" else str(int(m.group(2))))
        if m.group(3):
            key = key + (m.group(3),)
        if key not in out:
            out.append(key)
    if not out:
        raise argparse.ArgumentTypeError("expected at least one CHECK:MODULE target")
    return out


def _replaces_arg(text: str) -> dict[int, int]:
    out: dict[int, int] = {}
    for part in text.split(","):
        old, sep, new = part.strip().partition("=")
        if not sep or not old.isdigit() or not new.isdigit() or int(old) <= 0 or int(new) <= 0:
            raise argparse.ArgumentTypeError("expected OLD=NEW module ID pairs such as 16=50")
        o, n = int(old), int(new)
        if o == n or o in out or n in out.values() or o in out.values() or n in out:
            raise argparse.ArgumentTypeError("each module ID may appear in one OLD=NEW pair only")
        out[o] = n
    return out


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Push one edited blueprint to one inactive Make scenario.")
    ap.add_argument("--scenario", required=True, type=_scenario_arg)
    ap.add_argument("--candidate", required=True, help="edited blueprint JSON (export format)")
    ap.add_argument("--fix", required=True, type=_fix_arg)
    ap.add_argument("--modules", required=True, type=_modules_arg,
                    help="comma list of module IDs allowed to change, be added or removed")
    ap.add_argument("--base-version", required=True, type=_positive_int_arg,
                    help="live version the candidate was built from (manifest current_version of that pull)")
    ap.add_argument("--closes", required=True, type=_closes_arg,
                    help="audit findings the fix closes, CHECK:MODULE comma list, e.g. B:2 or C:15,C:16. A REVIEW row: E7:5 (when live has no FAIL there) or E7:5:REVIEW")
    ap.add_argument("--replaces", type=_replaces_arg, default=None,
                    help="modules recreated under a new ID, OLD=NEW comma list, e.g. 16=50")
    ap.add_argument("--apply", action="store_true", help="send the PATCH (default: dry run)")
    ap.add_argument("--env", default=DEFAULT_ENV)
    ap.add_argument("--blueprints", default=DEFAULT_BLUEPRINTS)
    ap.add_argument("--labels", default=DEFAULT_LABELS)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--links", default=DEFAULT_LINKS)
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    ap.add_argument("--webhooks", default=DEFAULT_WEBHOOKS)
    ap.add_argument("--status-allow", default=DEFAULT_STATUS_ALLOW)
    ap.add_argument("--secret-allowlist", default=DEFAULT_SECRET_ALLOWLIST)
    ap.add_argument("--bland-agents", default=DEFAULT_BLAND_AGENTS, help="Bland agent registry for check E28 (audit/bland_agents.json)")
    ap.add_argument("--prompts", default=DEFAULT_PROMPTS, help="prompts registry versions for check R (ref/prompts.json)")
    ap.add_argument("--prompt-bindings", default=DEFAULT_PROMPT_BINDINGS, help="prompts registry bindings for check R (ref/prompt_bindings.json)")
    ap.add_argument("--ff10", default=DEFAULT_FF10, help="F-F10 owner pin for checks E30 and E31 (audit/ff10.json)")
    ap.add_argument("--x32", default=DEFAULT_X32, help="X-32 exemplar pin for checks E35 to E37 (audit/x32.json)")
    ap.add_argument("--x16", default=DEFAULT_X16, help="X-16 review pin for checks E38 to E40 and the E32 review folder (audit/x16.json)")
    ap.add_argument("--critical", default=DEFAULT_CRITICAL,
                    help="retired with check B v2 (Option C): accepted for old command lines and ignored, the audit no longer reads it")
    ap.add_argument("--specs", default=DEFAULT_SPECS)
    ap.add_argument("--pushes-dir", default=DEFAULT_PUSHES)
    return ap


def main(argv: list[str] | None = None, transport: Callable | None = None,
         sleep: Callable[[float], None] = time.sleep, environ: dict | None = None,
         now: Callable[[], datetime] | None = None,
         snapshot_state: Callable[[str], str | None] = git_snapshot_state) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_CONFIG if exc.code else EXIT_OK
    now = now or (lambda: datetime.now(timezone.utc))
    try:
        cfg = load_push_config(args.env, os.environ if environ is None else environ)
    except ConfigError as exc:
        print(f"make_push: config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    p = Printer((cfg.read.token, cfg.write.token))
    try:
        return push(args, cfg, transport or urllib_transport, sleep, now, p, snapshot_state)
    except Abort as exc:
        p.err(f"make_push: ABORT, nothing sent: {exc}")
        return exc.code
    except TransportRefused as exc:
        p.err(f"make_push: ABORT, transport {exc}. Nothing sent for this request")
        return EXIT_ABORT
    except PullError as exc:
        p.err(f"make_push: API failure before any save, nothing changed: {exc}")
        return EXIT_API
    except Exception as exc:  # noqa: BLE001
        p.err(f"make_push: unexpected error: {type(exc).__name__}: {str(exc)[:200]}. "
              f"If --apply was given, re-pull to see whether a save happened")
        return EXIT_POSTCHECK if args.apply else EXIT_API


if __name__ == "__main__":
    sys.exit(main())
