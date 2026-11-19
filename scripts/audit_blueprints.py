#!/usr/bin/env python3
"""Audit Make blueprints for Immi-OS checks A to F, L, M, P and S (see CLAUDE.md "Audit checks").

A  X-31 disqualification trail. Every point where a lead can become
   Disqualified needs a Shadow Ledger create at the decision point carrying
   the lead link, the decision value, the evidence and the Bland call ID.
   Routers that branch on a decision value need a fallback route that leaves a trace
   (an Error ledger row and a Slack alert). The F-31 allow-list way is credited only
   for a scenario in audit/status_allow_list.json with the whole design in place.
B  F-E5 error handling (v3, Option C, 2026-10-29). Every external-call module
   outside an error route needs a complete handler: one call to the shared
   Logger and exactly one directive (PASS), or the legacy Shadow Ledger write,
   Slack message and one directive (REVIEW, convert with F-E5.3). Missing or
   partial is FAIL.
C  X-19 / X-28 scenario labels. Every Shadow Ledger write and every Logger call
   uses the label mapped to its scenario in audit/scenario_labels.json, every
   ledger-writing scenario has an entry, every label is a Single Select option.
   The Logger's own row maps the caller's label and is exempt. While the
   labels file is unconfirmed, C findings are UNCONFIRMED, not FAIL.
D  Secrets, via scripts/secret_scan.py. Reports scenario, module and pattern
   type only, never the value. audit/secret_allowlist.json pins Make webhook
   URLs in Bland call modules (Send a Call or Create a Call), valid only while the
   hook they target passes F2.
E  Mapping integrity (static, from the blueprint and metadata.interface).
   E1 reference to a field the referenced module does not output. E2 bare
   {{name}} with no module prefix. E3 a record ID that links or addresses the
   wrong Airtable table. E4 literal record ID in a get/update/delete (allowlist
   in audit/allowlist.json). E5 filter on a zero count after a search, which
   can never fire, or any number comparison of length(<aggregator>.array) or a
   search bundle count (an empty search emits one empty bundle, 2026-10-30). E6 client PII in a Slack message or a Logger call body. E7
   router with no fallback route whose routes write state (REVIEW). E9 a router
   whose routes can both run for one bundle and update the same Applicants field.
   E10 a Voice AI Ledger create whose Call_Length and Rate per minute do not make
   Total Cost equal the Bland price (evaluated on sample calls). E12 a Watch
   Records trigger whose scenario updates the record it returned and whose formula
   still matches after the write (self-retrigger). E13 a reference to a HeyGen
   module output path the module does not output (pinned output lists). E14 a
   Bland call whose phone number passed no format test (a text:pattern filter on
   its path, or REGEX_MATCH in the formula of the search or trigger it comes from).
   E15 a Watch Records formula that tests a field its trigger field does not track.
   E16 a client email that claims an attachment it does not send, or promises a
   guaranteed outcome. E17 a Bland call with no post-call webhook. E18 a lead search
   that can return several leads and feeds a client send without excluding Disqualified
   and Do Not Call.
   E19 IML written as text (a function outside {{ }} with a mapping as an argument,
   or a quoted literal inside). E20 text mapped into an Airtable attachment field.
   E21 a Gmail search trigger that does not exclude the account's own mail
   (-from:me). E22 a client send that maps HeyGen Get a Video output without the
   render gate (status completed and video_url exists). E23 a Voice AI Ledger
   create not linked to its System Logs row. E24 an Ignore handler that ends a
   path still holding independent work. E25 a Voice AI Ledger create or System
   Logs Voice AI cost write outside a fetch_back reconciliation. E26 a search that
   can return several records whose empty bundle reaches a write, send or spend
   with no filter. E28 a Bland call to a pathway migrated to an agent
   (audit/bland_agents.json), error routes included, a Send a Call that sets
   agent_id, a Create a Call without a registered agent_id, with pathway_id or
   persona_id beside it, or with no connection, or an agent_version that is not
   exactly production. A Send a Call that maps pathway_id is a REVIEW.
   F-F10 (audit/ff10.json): E29 a module that writes Applicants Synthetic Test
   Case, or may write it and hides which fields (a mapped bulk records list or an
   API body built elsewhere). E30 a Drafting Status write outside the pinned
   owner, or one in it that is not an update keyed {{1.id}} of its Applicants
   Watch Records trigger. E31 an ff13.drafting_context or ff13.validate_draft
   call outside the owner, any module on the ff13_make connection or SQL with a
   mapped name that the audit cannot read, or a call off the pinned connection,
   settings or argument forms. While the owner ID is
   null, a scenario named like the owner gets one "owner pending" FAIL per write
   and call. E6 also covers the PostgreSQL review_note, detail and provisions
   outputs and Claude content. None of these can be allowlisted.
   X-16 Phase A (audit/x16.json): E38 the owner's review trail (the outline
   ParseJSON and one pinned Draft Reviews row per outcome route), E39 only the
   owner writes Draft Reviews and no module deletes a row, E40 no send, share
   or copy of the working Doc and no Claude text into a Doc outside the owner.
   E32 puts the production Doc in the pinned review folder, E30, E6 and E12
   are widened. None of these can be allowlisted.
F  Webhook authentication (audit/webhooks.json). api_key scenarios: the hook must
   have an API key (F1, from the hook list in manifest.json). No hook data is a
   FAIL (UNCONFIRMED), and F1 cannot be allowlisted. fetch_back scenarios: the
   call-details module re-fetches the call from Bland by call ID and is the only
   module that reads the request, a Shadow Ledger lookup in the pinned form
   gates every write, every write also waits for a completed call and an unreconciled
   ledger row (F2d: one record of the caller's row kind, the update of the looked-up
   row as the first effect, Sequential processing on), and no handler continues past
   a failed verification (F2). F2c covers Logger call bodies like any other module.
   F3 (api_key, not the Logger): every lead Status write, client send and paid call
   waits behind a duplicate lookup (System Logs pinned on the call ID and the
   scenario label, an aggregator, an empty-result filter), its path records the call
   in the ledger, and Sequential processing is on.
L  The shared Logger (the webhooks.json entry with caller make_http). It is in the
   pull, active, its hook has an API key, Process data in order and Store
   incomplete executions are off, it writes one ledger row under the caller's
   label and one Slack alert with IDs only, and every module has a handler that
   cannot error. A property of the whole pull, so a partial audit skips it.

P  X-15 / X-18 AI model pinning (decided 2026-10-30). Every LLM call is
   anthropic-claude:createAMessage v1 (P1), model claude-opus-5-5 or
   claude-haiku-5-5 as a literal (P2), no temperature, top_p or top_k and no
   fixed thinking budget (P3), a literal max_tokens with a floor per model (P4),
   text read only as first(map(N.content; "text"; "type"; "text")) (P5), and a
   stop_reason end_turn filter ahead of any client send of that text (P6).

Input:
    default   blueprints/ + blueprints/manifest.json (written by make_pull.py)
    --dir D   any folder of blueprint JSON files, either the export format
              (top-level name/flow/metadata) or an API wrapper
              ({"response": {"blueprint": ...}}).

M  Manifest coverage (manifest mode). A scenario the pull withheld for a
   credential literal is a D FAIL. A listed scenario with no blueprint file is
   an M FAIL. A scenario with no live version is M REVIEW.

Output: audit/reports/<YYYY-MM-DD>.md (unless --no-report) and a printed
summary. Exit 0 when no FAIL, 1 on any FAIL, 2 on a usage or input error.

Read-only: this script never calls the Make API. Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from collections import Counter
import glob
import json
import math
import os
import itertools
import re
import sys
from dataclasses import dataclass, field

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import secret_scan  # noqa: E402
import prompt_registry  # noqa: E402

# ---------------------------------------------------------------------------
# Airtable and Make constants (CLAUDE.md "Blueprint anatomy",
# audit/airtable_ledger_schema.json).
# ---------------------------------------------------------------------------

LEDGER_TABLE = "tblf73Cdii3CsLKfL"
LEAD_TABLE = "tblHk09sCKLcOJXr9"
STATUS_FIELD = "fldFrKT1VdHwzYwrG"
LABEL_FIELD = "fldFC0g1pzkgHOV3g"
LEAD_LINK_FIELD = "fldx9nJ4XmlQx1frF"
AI_RESPONSE_FIELD = "fld7oKusxba5RuIZR"
PAYLOAD_FIELD = "fldeAVW2SAkT6KpZw"
CALL_ID_FIELD = "fldHf8yjOMGfgyJhc"
EVIDENCE_FIELDS = (PAYLOAD_FIELD, AI_RESPONSE_FIELD)

DIRECTIVES = ("builtin:Break", "builtin:Resume", "builtin:Ignore")
INTERNAL_PREFIXES = ("builtin:", "util:", "json:")
DECISION_VALUE = "Disqualified"
TIERING_REFS = ("has_job_offer", "crs_score")

FAIL = "FAIL"
UNCONFIRMED = "UNCONFIRMED"
REVIEW = "REVIEW"
INFO = "INFO"
PASS = "PASS"
STATUS_ORDER = (FAIL, UNCONFIRMED, REVIEW, INFO, PASS)

CHECK_TITLES = {
    "A": "X-31 disqualification trail",
    "B": "F-E5 error handling",
    "C": "X-19 / X-28 scenario labels",
    "D": "Secrets",
    "E": "Mapping integrity",
    "F": "Webhook authentication",
    "L": "Logger",
    "M": "Manifest coverage",
    "P": "X-15 / X-18 AI model pinning",
    "R": "X-36 prompts registry",
    "S": "Stripe money calls",
}
CHECKS = "ABCDEFLMPRS"
# The check that audits the shared Logger scenario (F-E5 v3, Option C). make_push reads it for the F-E5.3 readiness gate.
# The letter G stays unused, so a row of the retired Error Monitor check can never be mistaken for a Logger row.
LOGGER_CHECK = "L"
# The phrase of a hook-key row whose state is unknown (check F1, and L1 for the Logger hook).
HOOK_KEY_UNCONFIRMED = "UNCONFIRMED, no proof that a key exists"
DEFAULT_LINKS = os.path.join(REPO_ROOT, "audit", "airtable_links.json")
DEFAULT_ALLOWLIST = os.path.join(REPO_ROOT, "audit", "allowlist.json")
DEFAULT_WEBHOOKS = os.path.join(REPO_ROOT, "audit", "webhooks.json")
DEFAULT_SECRET_ALLOWLIST = secret_scan.DEFAULT_SECRET_ALLOWLIST
DEFAULT_PROMPTS = prompt_registry.DEFAULT_PROMPTS
DEFAULT_PROMPT_BINDINGS = prompt_registry.DEFAULT_BINDINGS


class InputError(Exception):
    """Unreadable or unrecognised input. Exit code 2."""


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class Blueprint:
    name: str
    scenario_id: str | None
    source: str
    bp: dict


@dataclass
class Finding:
    check: str
    status: str
    scenario: str
    module_id: object
    module_type: str
    detail: str
    rule: str = ""  # sub-rule code inside a check, for example "E4"
    allowlisted: bool = False  # a FAIL or REVIEW turned into INFO by audit/allowlist.json


@dataclass
class Labels:
    confirmed: bool
    scenarios: dict  # scenario id (str) -> {"name", "expected_label", ...}


@dataclass
class Schema:
    label_options: list
    status_options: list


@dataclass
class AuditResult:
    blueprints: list
    findings: list = field(default_factory=list)
    labels_confirmed: bool = False
    unused_allowlist: list = field(default_factory=list)  # entries that matched no finding
    unused_secret_allowlist: list = field(default_factory=list)  # secret_allowlist entries that matched no finding

    def count(self, check: str, status: str) -> int:
        return sum(1 for f in self.findings if f.check == check and f.status == status)

    @property
    def failed(self) -> bool:
        return any(f.status == FAIL for f in self.findings)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_ID_SUFFIX = re.compile(r"__(\d+)\.json$", re.IGNORECASE)


def _read_json(path: str) -> object:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {os.path.basename(path)}: {exc.__class__.__name__}") from None


def unwrap_blueprint(obj: object) -> dict | None:
    """Return the blueprint dict from the export format or an API wrapper."""
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("flow"), list):
        return obj
    for key in ("response", "blueprint"):
        inner = obj.get(key)
        if isinstance(inner, dict):
            found = unwrap_blueprint(inner)
            if found is not None:
                return found
    return None


def _load_blueprint_file(path: str, scenario_id: str | None = None, name: str | None = None) -> Blueprint:
    bp = unwrap_blueprint(_read_json(path))
    if bp is None:
        raise InputError(f"{os.path.basename(path)} is not a Make blueprint (no flow)")
    if scenario_id is None:
        m = _ID_SUFFIX.search(os.path.basename(path))
        scenario_id = m.group(1) if m else None
    bp_name = bp.get("name") if isinstance(bp.get("name"), str) else None
    return Blueprint(
        name=bp_name or name or os.path.splitext(os.path.basename(path))[0],
        scenario_id=str(scenario_id) if scenario_id is not None else None,
        source=os.path.basename(path),
        bp=bp,
    )


def load_dir(folder: str) -> list[Blueprint]:
    if not os.path.isdir(folder):
        raise InputError(f"not a folder: {folder}")
    paths = sorted(p for p in glob.glob(os.path.join(folder, "*.json")) if os.path.basename(p) != "manifest.json")
    if not paths:
        raise InputError(f"no blueprint JSON files in {folder}")
    return [_load_blueprint_file(p) for p in paths]


def _manifest_entries(manifest: object) -> list[dict]:
    if isinstance(manifest, dict):
        for key in ("scenarios", "items", "entries"):
            if key in manifest:
                return _manifest_entries(manifest[key])
        if all(isinstance(v, dict) for v in manifest.values()):
            return [dict(v, id=v.get("id", k)) for k, v in manifest.items()]
        return []
    if isinstance(manifest, list):
        return [e for e in manifest if isinstance(e, dict)]
    return []


def _withheld_module_paths(e: dict) -> list[str]:
    """JSON paths of withheld findings, from manifest withheld_locations ("type at $.path")."""
    out = []
    for loc in e.get("withheld_locations") or []:
        if isinstance(loc, str) and " at " in loc:
            path = loc.split(" at ", 1)[1]
            m = re.match(r"^\$\.flow(?:\[\d+\](?:\.(?:routes\[\d+\]\.flow|onerror)\[\d+\])*)?", path)
            if m and m.group(0) != "$.flow":
                out.append(m.group(0))
    return sorted(set(out))


def load_manifest_mode(folder: str, manifest_path: str) -> tuple[list[Blueprint], list[Finding]]:
    """Blueprints listed in the manifest, plus coverage findings for every
    manifest scenario the audit cannot read.

    A scenario the pull withheld for a credential literal is a check D FAIL.
    A listed scenario whose file is missing is a check M FAIL. A scenario with
    no live version (live_missing) is M REVIEW. The audit never passes while
    a listed scenario goes unaudited without a stated reason.
    """
    if not os.path.isdir(folder):
        raise InputError(f"no blueprints folder at {folder}. Run scripts/make_pull.py first")
    if not os.path.exists(manifest_path):
        raise InputError(f"no manifest at {manifest_path}. Run scripts/make_pull.py first")
    by_id: dict[str, str] = {}
    for p in glob.glob(os.path.join(folder, "*.json")):
        m = _ID_SUFFIX.search(os.path.basename(p))
        if m:
            by_id[m.group(1)] = p
    entries = _manifest_entries(_read_json(manifest_path))
    out: list[Blueprint] = []
    coverage: list[Finding] = []
    seen: set[str] = set()
    for e in entries:
        sid = e.get("id", e.get("scenarioId"))
        if sid is None:
            continue
        sid = str(sid)
        name = e.get("name") if isinstance(e.get("name"), str) else f"scenario {sid}"
        if e.get("withheld") is True:
            types = ", ".join(str(t) for t in e.get("withheld_pattern_types") or []) or "unspecified pattern"
            where = _withheld_module_paths(e)
            at = f" at {', '.join(where)}" if where else ""
            coverage.append(Finding("D", FAIL, name, "-", "(withheld by pull)",
                                    f"Scenario {sid} withheld by make_pull for a credential literal: {types}{at}. "
                                    f"Not written to disk, so checks A to C, E and F did not run on it. "
                                    f"Do not read a drop in E or F findings after the next pull as progress"))
            seen.add(sid)
            continue
        path = None
        for key in ("file", "path", "blueprint_file"):
            if isinstance(e.get(key), str):
                cand = e[key] if os.path.isabs(e[key]) else os.path.join(folder, os.path.basename(e[key]))
                if os.path.exists(cand):
                    path = cand
                    break
        path = path or by_id.get(sid)
        if path is None:
            if e.get("live_missing") is True:
                coverage.append(Finding("M", REVIEW, name, "-", "-",
                                        f"Scenario {sid} has no live version (draft=false returned 404). "
                                        f"Nothing ran, nothing audited. Confirm it was never published"))
            else:
                coverage.append(Finding("M", FAIL, name, "-", "-",
                                        f"Scenario {sid} is in the manifest but its blueprint file is missing. "
                                        f"Not audited. Re-run scripts/make_pull.py"))
            seen.add(sid)
            continue
        out.append(_load_blueprint_file(path, scenario_id=sid, name=e.get("name")))
        seen.add(sid)
    for sid, path in sorted(by_id.items()):
        if sid not in seen:
            out.append(_load_blueprint_file(path, scenario_id=sid))
    if not out and not coverage:
        raise InputError(f"no blueprints found in {folder}. Run scripts/make_pull.py first")
    return out, coverage


def load_labels(path: str) -> Labels:
    data = _read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), dict):
        raise InputError(f"{os.path.basename(path)} has no scenarios map")
    return Labels(confirmed=data.get("_confirmed") is True, scenarios={str(k): v for k, v in data["scenarios"].items()})


def load_schema(path: str) -> Schema:
    data = _read_json(path)
    try:
        options = list(data["fields"][LABEL_FIELD]["options"])
    except (KeyError, TypeError):
        raise InputError(f"{os.path.basename(path)} has no options for {LABEL_FIELD}") from None
    status = []
    if isinstance(data.get("lead_table"), dict):
        status = list(data["lead_table"].get("status_options") or [])
    return Schema(label_options=options, status_options=status)


# ---------------------------------------------------------------------------
# Blueprint walking helpers
# ---------------------------------------------------------------------------


def _mtype(m: dict) -> str:
    return str(m.get("module", ""))


def _mapper(m: dict) -> dict:
    mp = m.get("mapper")
    return mp if isinstance(mp, dict) else {}


def _record(m: dict) -> dict:
    rec = _mapper(m).get("record")
    return rec if isinstance(rec, dict) else {}


def _routes(m: dict) -> list[list]:
    out = []
    for r in m.get("routes") or []:
        if isinstance(r, dict) and isinstance(r.get("flow"), list):
            out.append(r["flow"])
        else:
            out.append([])
    return out


def _onerror(m: dict) -> list:
    oe = m.get("onerror")
    return oe if isinstance(oe, list) else []


def walk(flow: list, in_error: bool = False, chain: tuple = ()):
    """Yield (module, in_error, chain). chain is ((flow_list, index), ...) top to module."""
    for i, m in enumerate(flow):
        if not isinstance(m, dict):
            continue
        here = chain + ((flow, i),)
        yield m, in_error, here
        for rf in _routes(m):
            yield from walk(rf, in_error, here)
        oe = _onerror(m)
        if oe:
            yield from walk(oe, True, here)


def is_airtable_write(m: dict) -> bool:
    t = _mtype(m)
    if not t.startswith("airtable:"):
        return False
    low = t.lower()
    return any(w in low for w in ("create", "update", "upsert"))


def is_ledger_write(m: dict) -> bool:
    return is_airtable_write(m) and _mapper(m).get("table") == LEDGER_TABLE


def is_ledger_create(m: dict) -> bool:
    return is_ledger_write(m) and "create" in _mtype(m).lower()


def is_slack_message(m: dict) -> bool:
    t = _mtype(m)
    return t.startswith("slack:") and "message" in t.lower()


def is_email_send(m: dict) -> bool:
    low = _mtype(m).lower()
    return ("email" in low or "gmail" in low or "outlook" in low) and "send" in low


def is_external(m: dict) -> bool:
    t = _mtype(m)
    return bool(t) and not t.startswith(INTERNAL_PREFIXES)


def fallback_index(router: dict) -> int | None:
    """Make marks the fallback route as router parameters.else = 0-based route index."""
    params = router.get("parameters")
    if not isinstance(params, dict) or "else" not in params:
        return None
    raw = params["else"]
    try:
        idx = int(raw)
    except (TypeError, ValueError):
        return None
    return idx if 0 <= idx < len(_routes(router)) else None


def _conditions(m: dict) -> list:
    f = m.get("filter")
    if not isinstance(f, dict):
        return []
    conds = f.get("conditions")
    return conds if isinstance(conds, list) else []


def _iter_conditions(m: dict):
    for group in _conditions(m):
        if isinstance(group, list):
            for c in group:
                if isinstance(c, dict):
                    yield c
        elif isinstance(group, dict):
            yield group


def is_mapping(v: object) -> bool:
    return isinstance(v, str) and "{{" in v


def nonempty(v: object) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return v.strip() != ""
    if isinstance(v, (list, tuple)):
        return any(nonempty(x) for x in v)
    if isinstance(v, dict):
        return any(nonempty(x) for x in v.values())
    return True


def has_mapping(v: object) -> bool:
    if isinstance(v, str):
        return is_mapping(v)
    if isinstance(v, (list, tuple)):
        return any(has_mapping(x) for x in v)
    if isinstance(v, dict):
        return any(has_mapping(x) for x in v.values())
    return False


def _strings(v: object):
    if isinstance(v, str):
        yield v
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _strings(x)
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)


def expr_key(expr: str) -> str:
    """Normalise a mapping for comparison: '{{ 3.status }}' -> '3.status'."""
    s = re.sub(r"\s+", "", expr)
    if s.startswith("{{") and s.endswith("}}") and s.count("{{") == 1:
        s = s[2:-2]
    return s


def _short(s: str, n: int = 60) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------------------
# Filter evaluation for the Disqualified path (check A)
# ---------------------------------------------------------------------------


def _eval_condition(c: dict, expr: str | None, value: str) -> bool | None:
    """True, False, or None when the condition does not test the decision expression."""
    if expr is None:
        return None
    a, b, op = c.get("a"), c.get("b"), str(c.get("o", ""))
    target = expr_key(expr)
    if isinstance(a, str) and expr_key(a) == target:
        other = b
    elif isinstance(b, str) and expr_key(b) == target and op.split(":")[1:2] in (["equal"], ["notequal"]):
        other = a
    else:
        return None
    parts = op.split(":")
    if parts[0] == "exist":
        return True
    if parts[0] == "notexist":
        return False
    if parts[0] != "text" or len(parts) < 2:
        return None
    if other is None or is_mapping(other):
        return None
    lit = str(other)
    ci = len(parts) > 2 and parts[2] == "ci"
    v, lt = (value.lower(), lit.lower()) if ci else (value, lit)
    tests = {
        "equal": v == lt,
        "notequal": v != lt,
        "contain": lt in v,
        "notcontain": lt not in v,
        "startwith": v.startswith(lt),
        "notstartwith": not v.startswith(lt),
        "endwith": v.endswith(lt),
        "notendwith": not v.endswith(lt),
    }
    return tests.get(parts[1])


def eval_filter(m: dict, expr: str | None, value: str = DECISION_VALUE) -> bool | None:
    """Make filters are OR of AND groups. No conditions means the bundle passes."""
    groups = _conditions(m)
    if not groups:
        return True
    group_results = []
    for g in groups:
        conds = g if isinstance(g, list) else [g]
        res: bool | None = True
        for c in conds:
            r = _eval_condition(c, expr, value) if isinstance(c, dict) else None
            if r is False:
                res = False
                break
            if r is None:
                res = None
        group_results.append(res)
    if any(r is True for r in group_results):
        return True
    if all(r is False for r in group_results):
        return False
    return None


@dataclass
class PathWrite:
    module: dict
    guaranteed: bool
    after_email: bool


def _walk_forward(flow: list, start: int, expr: str | None, guaranteed: bool, after_email: bool,
                  skip_first_filter: bool, out: list) -> None:
    for i in range(start, len(flow)):
        m = flow[i]
        if not isinstance(m, dict):
            continue
        if not (i == start and skip_first_filter):
            r = eval_filter(m, expr)
            if r is False:
                return
            if r is None:
                guaranteed = False
        if is_ledger_create(m):
            out.append(PathWrite(m, guaranteed, after_email))
        routes = _routes(m)
        if routes:
            fb = fallback_index(m)
            evals = [eval_filter(rf[0], expr) if rf and isinstance(rf[0], dict) else True for rf in routes]
            for j, rf in enumerate(routes):
                if j == fb:
                    others = [e for k, e in enumerate(evals) if k != fb]
                    if any(e is True for e in others):
                        continue
                    taken = True if all(e is False for e in others) else None
                else:
                    taken = evals[j]
                    if taken is False:
                        continue
                _walk_forward(rf, 0, expr, guaranteed and taken is True, after_email, True, out)
        if is_email_send(m):
            after_email = True


def _route_index(router: dict, flow: list) -> int | None:
    for j, rf in enumerate(_routes(router)):
        if rf is flow:
            return j
    return None


def _route_sends_email(flow: list, expr: str | None) -> bool:
    """True if the linear part of a taken route sends an email."""
    for i, m in enumerate(flow):
        if not isinstance(m, dict):
            continue
        if i > 0 and eval_filter(m, expr) is False:
            return False
        if is_email_send(m):
            return True
    return False


def ledger_writes_on_path(chain: tuple, expr: str | None) -> list[PathWrite]:
    """Shadow Ledger creates that run for a bundle carrying the decision.

    Walks execution order from the top of the chain: preceding siblings at
    every level, earlier routes of each router on the chain (Make runs routes
    in order), then the modules downstream of the decision point, following
    routers only into routes the decision value can take. A create that
    runs after an email send is marked after_email.
    """
    out: list[PathWrite] = []
    email = False
    for k, (flow, idx) in enumerate(chain):
        if k > 0:
            pflow, pidx = chain[k - 1]
            parent = pflow[pidx]
            j = _route_index(parent, flow) if isinstance(parent, dict) else None
            if j:
                fb = fallback_index(parent)
                for jj, rf in enumerate(_routes(parent)[:j]):
                    # The current route was taken, so an earlier fallback route was not.
                    if jj == fb or not rf or not isinstance(rf[0], dict):
                        continue
                    taken = eval_filter(rf[0], expr)
                    if taken is False:
                        continue
                    _walk_forward(rf, 0, expr, taken is True, email, True, out)
                    if taken is True and _route_sends_email(rf, expr):
                        email = True
        for m in flow[:idx]:
            if not isinstance(m, dict):
                continue
            if is_ledger_create(m):
                out.append(PathWrite(m, True, email))
            if is_email_send(m):
                email = True
    flow, idx = chain[-1]
    _walk_forward(flow, idx, expr, True, email, True, out)
    return out


OUTCOME_FIELD = "fldgzlLkRAwc6KGoh"
# Fields that never record the decision: the scenario label (its option text
# may say "Disqualified") and the Success/Error outcome.
NON_DECISION_FIELDS = (LABEL_FIELD, OUTCOME_FIELD)
_IML_BODY = re.compile(r"\{\{(.*?)\}\}", re.S)


def _plain_values(v: object):
    """Scalar strings of a field value, unwrapping lists and {value|label|name} dicts."""
    if isinstance(v, str):
        yield v
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _plain_values(x)
    elif isinstance(v, dict):
        for k in ("value", "label", "name"):
            if isinstance(v.get(k), str):
                yield v[k]
                return


def _literal_text(s: str) -> str:
    """Text outside {{...}}, lowercased, trimmed of whitespace and separators.
    "Disqualified" and "Disqualified: {{1.reason}}" give "disqualified". A
    prompt that merely mentions the word gives the whole prompt."""
    _exprs, outside = secret_scan._iml_segments(s)
    return outside.strip(" \t\r\n:;,.-|()[]").lower()


def _iml_bodies(v: object) -> list[str]:
    """Whitespace-stripped bodies of every {{...}} in a field value."""
    return [re.sub(r"\s+", "", m.group(1)) for s in _strings(v) for m in _IML_BODY.finditer(s)]


def _refers_to(v: object, key: str) -> bool:
    """True if a {{...}} in v references key as a whole token ({{3.status}},
    not {{13.status}} or {{3.status_reason}})."""
    rx = re.compile(r"(?<![\w.`])" + re.escape(key) + r"(?![\w.`])")
    return any(rx.search(body) for body in _iml_bodies(v))


def _is_trivial_evidence(body: str, key: str | None) -> bool:
    """A mapping that cannot explain the decision: the decision value itself,
    an error reference, or a bare id."""
    if key is not None and body == key:
        return True
    if body.startswith("error.") or body == "error":
        return True
    last = body.rsplit(".", 1)[-1].strip("`").strip().lower()
    return last == "id" or last.endswith("_id") or last.endswith(" id")


def ledger_missing(m: dict, expr: str | None, path_refs: tuple = ()) -> list[str]:
    """What a ledger create lacks for check A. expr is the mapped decision
    value, path_refs are references a filter on the path pins to
    Disqualified (either counts as recording the decision)."""
    rec = _record(m)
    missing = []
    if not nonempty(rec.get(LEAD_LINK_FIELD)):
        missing.append("lead link")
    decision_fields = [v for f, v in rec.items() if f not in NON_DECISION_FIELDS]
    literal = any(_literal_text(s) == DECISION_VALUE.lower() for v in decision_fields for s in _plain_values(v))
    key = expr_key(expr) if expr is not None else None
    keys = ([key] if key is not None else []) + [expr_key(r) for r in path_refs]
    mapped = any(_refers_to(v, k) for k in keys for v in decision_fields)
    if not (literal or mapped):
        missing.append("decision value")
    if not any(all(not _is_trivial_evidence(body, k) for k in keys or [None])
               for f in EVIDENCE_FIELDS for body in _iml_bodies(rec.get(f))):
        missing.append("evidence")
    if not nonempty(rec.get(CALL_ID_FIELD)):
        missing.append("Bland call ID")
    return missing


def _whole_call(e: str) -> tuple[str, list[str]] | None:
    """(lowercased name, args) if e is exactly one function call."""
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(", e)
    if not m:
        return None
    depth, in_str, i = 0, False, m.end() - 1
    while i < len(e):
        c = e[i]
        if in_str:
            if c == '"':
                if i + 1 < len(e) and e[i + 1] == '"':
                    i += 2
                    continue
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if i != len(e) - 1:
        return None
    args = secret_scan._split_args(e, m.end() - 1)
    return (m.group(1).lower(), args) if args is not None else None


def _formula_outputs(e: str) -> list[str] | None:
    """Literal values an IML expression can yield, or None if any output is
    dynamic. Understands quoted text, bare text, if, ifempty and switch."""
    e = e.strip()
    if len(e) >= 2 and e[0] == e[-1] == '"':
        return [e[1:-1].replace('""', '"')]
    call = _whole_call(e)
    if call:
        name, args = call
        if name == "if" and len(args) in (2, 3):
            outs = args[1:]
        elif name == "ifempty" and len(args) == 2:
            outs = args
        elif name == "switch" and len(args) >= 3:
            outs = args[2::2] + ([args[-1]] if (len(args) - 1) % 2 else [])
        else:
            return None
        result: list[str] = []
        for a in outs:
            sub = _formula_outputs(a)
            if sub is None:
                return None
            result += sub
        return result
    if not e or "(" in e or '"' in e or secret_scan._IML_REFERENCE.match(e):
        return None if e else [""]
    return [e]  # bare text is a literal in IML


def status_write_outputs(sval: str) -> list[str] | None:
    """Literal Status values a mapped write can produce, or None if dynamic."""
    exprs, outside = secret_scan._iml_segments(sval)
    if outside.strip() or len(exprs) != 1:
        return None
    return _formula_outputs(exprs[0])


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def _scenario_label(b: Blueprint) -> str:
    return b.name


@dataclass
class LeadNames:
    """How a module can name the lead table and its Status field: by ID or by name (compared case-insensitively)."""
    tables: frozenset = frozenset({LEAD_TABLE.lower()})
    keys: frozenset = frozenset({STATUS_FIELD.lower(), "status"})


def lead_names(links: "AirtableMap | None" = None) -> LeadNames:
    """The names under which a module can address the lead table and its Status field, resolved through the
    Airtable map (audit/airtable_links.json) when there is one."""
    tables, keys = {LEAD_TABLE.lower()}, {STATUS_FIELD.lower(), "status"}
    t = (links.tables.get(LEAD_TABLE) if links is not None else None) or {}
    if isinstance(t.get("name"), str) and t["name"].strip():
        tables.add(t["name"].strip().lower())
    label = (t.get("fields") or {}).get(STATUS_FIELD)
    if isinstance(label, str) and label.strip():
        keys.add(label.strip().lower())
    return LeadNames(frozenset(tables), frozenset(keys))


_DEFAULT_LEAD = lead_names()


def _status_raw(rec: dict, lead: LeadNames) -> tuple[bool, object]:
    for k, v in rec.items():
        if isinstance(k, str) and k.strip().lower() in lead.keys:
            return True, v
    return False, None


def is_lead_status_write(m: dict, lead: LeadNames = _DEFAULT_LEAD) -> bool:
    t = _mapper(m).get("table")
    return (is_airtable_write(m) and isinstance(t, str) and t.strip().lower() in lead.tables
            and _status_raw(_record(m), lead)[0])


def _status_value(val: object) -> str:
    """Status field value as text, unwrapping {value|label|name} and one-item lists."""
    if isinstance(val, list) and len(val) == 1:
        val = val[0]
    if isinstance(val, dict):
        for k in ("value", "label", "name"):
            if isinstance(val.get(k), str):
                return val[k]
    return val if isinstance(val, str) else json.dumps(val)


# The Airtable app's Make an API call (Make MCP app-modules_list, org 6184090, read 2026-11-15): Airtable v3 names it
# makeApiCall, v2 has none. Its url is relative (v0/{base}/{table}) and its method is upper case (GET, POST, PUT, PATCH,
# DELETE, default GET). The type is matched case-insensitively.
AIRTABLE_API_CALL = "airtable:makeApiCall"
# Mapper keys that carry an API or HTTP request body: body (Airtable Make an API call, any type), data (HTTP v3),
# jsonStringBodyContent, rawBodyContent, urlEncodedBodyContent and multipartBodyContent (HTTP v4, Make MCP app-module_get
# 2026-11-15).
API_BODY_KEYS = ("body", "data", "jsonStringBodyContent", "rawBodyContent", "urlEncodedBodyContent", "multipartBodyContent")
_JSON_KEY_MAPPING = re.compile(r"""(?:^|[{,])\s*["']?\s*\{\{[^{}]*\}\}\s*["']?\s*:""")
_JSON_FIELDS_MAPPING = re.compile(r"""["']fields["']\s*:\s*\{\{""", re.I)


def _airtable_api_module(m: dict) -> bool:
    t = _mtype(m)
    if t.lower() == AIRTABLE_API_CALL.lower():
        return True
    return t.startswith("http:") and any("airtable.com" in s.lower() for s in _strings(_mapper(m)))


def _api_body_unknown(m: dict) -> bool:
    """True when an API or HTTP request body hides which fields it writes: the body is one mapping (built in another
    module, such as a Create JSON or a Set variable), its fields object is a mapping, or a field name is a mapping."""
    mp = _mapper(m)
    for key in API_BODY_KEYS:
        body = mp.get(key)
        if isinstance(body, str):
            if _single_expression(body) is not None or _JSON_KEY_MAPPING.search(body) or _JSON_FIELDS_MAPPING.search(body):
                return True
        elif isinstance(body, dict):
            fields = body.get("fields")
            if is_mapping(fields) or any(is_mapping(str(k)) for k in _mapper_keys(body)):
                return True
        elif isinstance(body, list):
            if any(isinstance(it, dict) and is_mapping(it.get("name")) for it in body) or any(is_mapping(it) for it in body):
                return True
    return False


def alias_status_write(m: dict, lead: LeadNames = _DEFAULT_LEAD) -> tuple[str | None, bool]:
    """A lead Status write made through an Airtable API call or an HTTP module (a PATCH on the Airtable API
    that no create/update module type shows). Returns (Status value text, unknown). unknown is True when
    the module may write the lead table but the blueprint does not say which table or value."""
    if not _airtable_api_module(m):
        return None, False
    mp = _mapper(m)
    method = str(mp.get("method") or "").strip().lower()
    if method == "get" or (not method and _mtype(m).startswith("http:")):
        return None, False
    text = " ".join(_strings(mp)).replace("%20", " ")
    hits_lead = any(re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", text, re.I) for n in lead.tables)
    keys = "|".join(re.escape(k) for k in sorted(lead.keys))
    pair = re.search(r"""["']?(?<![\w])(?:""" + keys + r""")(?![\w])["']?\s*:\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""",
                     text, re.I)
    key_present = re.search(r"(?<![\w])(?:" + keys + r")(?![\w])", text, re.I) is not None
    if hits_lead and pair:
        return (pair.group(1) if pair.group(1) is not None else pair.group(2)), False
    if hits_lead and key_present:
        return None, True
    if hits_lead:
        return None, _api_body_unknown(m)
    url = mp.get("url")
    return None, isinstance(url, str) and "{{" in url


def lead_status(m: dict, lead: LeadNames = _DEFAULT_LEAD) -> tuple[str | None, bool]:
    """(Status value text, unknown) of a module that may write the lead Status. (None, False) for any other module."""
    if is_lead_status_write(m, lead):
        return _status_value(_status_raw(_record(m), lead)[1]), False
    return alias_status_write(m, lead)


def status_write_module_ids(bp: dict, links: "AirtableMap | None" = None) -> set:
    """IDs of the modules that write, or may write, the lead Status (make_push refuses to touch them silently)."""
    lead = lead_names(links)
    out = set()
    for m, _err, _c in walk(bp.get("flow") or []):
        sval, unknown = lead_status(m, lead)
        if sval is not None or unknown:
            out.add(m.get("id"))
    return out


def _disqualified_filter_ref(c: dict) -> str | None:
    """The mapped side of a condition that tests equality with Disqualified."""
    a, bb = c.get("a"), c.get("b")
    lit, ref = (bb, a) if is_mapping(a) else (a, bb)
    if isinstance(lit, str) and not is_mapping(lit) and lit.strip().lower() == DECISION_VALUE.lower() \
            and str(c.get("o", "")).split(":")[1:2] == ["equal"] and isinstance(ref, str) and is_mapping(ref):
        return ref
    return None


def _path_decision_refs(chain: tuple) -> tuple:
    """References pinned to Disqualified by filters on the modules of the chain."""
    refs = []
    for flow, idx in chain:
        m = flow[idx]
        if isinstance(m, dict):
            refs += [r for c in _iter_conditions(m) if (r := _disqualified_filter_ref(c))]
    return tuple(dict.fromkeys(refs))


def _decision_literals(schema: Schema) -> set[str]:
    return {s.strip().lower() for s in schema.status_options if isinstance(s, str)}


def _status_may_be_disqualified(m: dict, lead: LeadNames = _DEFAULT_LEAD) -> bool:
    """A lead Status write whose value is Disqualified or cannot be read as a fixed other value."""
    sval, unknown = lead_status(m, lead)
    if unknown:
        return True
    if sval is None:
        return False
    if is_mapping(sval):
        outs = status_write_outputs(sval)
        return outs is None or any(o.strip().lower() == DECISION_VALUE.lower() for o in outs)
    return sval.strip().lower() == DECISION_VALUE.lower()


def _allow_list_filter(m: dict, expr: str | None) -> bool:
    """The module's inbound filter is an allow-list on the decision expression: every OR group holds a
    positive text-equal condition on expr against a fixed value that is not Disqualified, and the filter
    rejects Disqualified in every case variant. A deny-list (not equal Disqualified), a text-contain
    match, a group without the decision reference, a mapped value or one that names Disqualified is not."""
    groups = _conditions(m)
    if not groups or expr is None:
        return False
    target = expr_key(expr)
    for g in groups:
        conds = g if isinstance(g, list) else [g]
        hit = False
        for c in conds:
            if not isinstance(c, dict) or not isinstance(c.get("a"), str) or expr_key(c["a"]) != target:
                continue
            lit = c.get("b")
            if str(c.get("o", "")).split(":")[:2] == ["text", "equal"] and isinstance(lit, str) and lit.strip() \
                    and not is_mapping(lit) and lit.strip().lower() != DECISION_VALUE.lower():
                hit = True
        if not hit:
            return False
    return all(eval_filter(m, expr, v) is False for v in (DECISION_VALUE, DECISION_VALUE.lower(), DECISION_VALUE.upper()))


def _allow_list_literals(m: dict, expr: str) -> list[str]:
    """The fixed values the allow-list filter of m lets through (the b side of its positive text-equal conditions on expr)."""
    target = expr_key(expr)
    out: list[str] = []
    for c in _iter_conditions(m):
        if isinstance(c.get("a"), str) and expr_key(c["a"]) == target and str(c.get("o", "")).split(":")[:2] == ["text", "equal"] \
                and isinstance(c.get("b"), str):
            out.append(c["b"].strip())
    return out


def _allow_list_guard(chain: tuple, expr: str | None) -> tuple[int, int] | None:
    """(chain level, index in that flow) of the first module on the path to the Status write, the write
    itself included, whose inbound filter is an allow-list on expr. A filter on a module stops the flow
    from there on, so the modules before the write in its own flow and in every flow above it count."""
    for k, (flow, idx) in enumerate(chain):
        for j in range(idx + 1):
            if isinstance(flow[j], dict) and _allow_list_filter(flow[j], expr):
                return k, j
    return None


# --- the status allow-list input (audit/status_allow_list.json) ----------------------------------------------


@dataclass
class StatusDesigns:
    """audit/status_allow_list.json: scenario ID -> {allowed, no_lead_lookup, reason}. The F-31 allow-list way of
    closing check A is credited only for a scenario listed here, and only for Status values inside its
    allowed set (the values the Bland pathway can send)."""
    entries: dict = field(default_factory=dict)


DEFAULT_STATUS_ALLOW = os.path.join(REPO_ROOT, "audit", "status_allow_list.json")


def load_status_designs(path: str, required: bool = False) -> StatusDesigns:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no status allow-list at {path}")
        return StatusDesigns()
    data = _read_json(path)
    name = os.path.basename(path)
    raw = data.get("scenarios") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise InputError(f"{name} has no scenarios list")
    entries: dict[str, dict] = {}
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            raise InputError(f"{name} entry {i} is not an object")
        sid = e.get("scenario_id")
        if isinstance(sid, bool) or not isinstance(sid, (int, str)) or not str(sid).strip().isdigit():
            raise InputError(f"{name} entry {i}: scenario_id must be a scenario ID (digits)")
        allowed = e.get("allowed")
        if not isinstance(allowed, list) or not allowed or any(not isinstance(x, str) or not x.strip() for x in allowed):
            raise InputError(f"{name} entry {i}: allowed must be a non-empty list of Status values")
        if any(x.strip().lower() == DECISION_VALUE.lower() for x in allowed):
            raise InputError(f"{name} entry {i}: {DECISION_VALUE} can never be an allowed value")
        lookup = e.get("no_lead_lookup")
        if lookup is not None and (isinstance(lookup, bool) or not isinstance(lookup, int) or lookup <= 0):
            raise InputError(f"{name} entry {i}: no_lead_lookup must be a module ID")
        reason = e.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 8 or not re.search(r"[A-Za-z]{3}", reason):
            raise InputError(f"{name} entry {i} needs a real reason (a sentence)")
        key = str(sid).strip()
        if key in entries:
            raise InputError(f"{name} lists scenario {key} twice")
        entries[key] = {"allowed": [x.strip() for x in allowed], "no_lead_lookup": lookup, "reason": reason.strip()}
    return StatusDesigns(entries)


@dataclass
class _ACtx:
    """What check A needs to know about the blueprint it reads."""
    lead: LeadNames
    mods: dict            # module id -> module
    trig: object          # id of the trigger module
    entry: dict | None    # this scenario's entry in audit/status_allow_list.json


def _bare_ref_to(v: object, ctx: _ACtx, kinds: tuple) -> bool:
    """v is exactly one bare reference {{N.field}} (a one-item list of it also counts) to the trigger or to a
    module whose type starts with one of kinds. A literal, a function or a reference to anything else is not."""
    if isinstance(v, list) and len(v) == 1:
        v = v[0]
    e = _single_expression(v)
    refs = iml_refs(e) if e else []
    if not e or len(refs) != 1 or refs[0].text != e.strip():
        return False
    mod = ctx.mods.get(refs[0].module)
    return refs[0].module == ctx.trig or (mod is not None and _mtype(mod).startswith(kinds))


def _is_error_row(rec: dict) -> bool:
    return any(v.strip().lower() == "error" for v in _plain_values(rec.get(OUTCOME_FIELD)))


def _reach(flow: list) -> list[dict]:
    """The top-level modules of a route that run for every bundle that takes it: up to the first module that carries a filter."""
    out = []
    for x in flow:
        if not isinstance(x, dict) or _conditions(x):
            break
        out.append(x)
    return out


def _sibling_problems(router: dict, keys: set) -> list[str]:
    """Routes other than the fallback must each filter on the decision value. A route with no filter always
    matches, so the fallback never runs and a rejected value is not traced."""
    fb = fallback_index(router)
    out = []
    for j, rf in enumerate(_routes(router)):
        if j == fb:
            continue
        first = rf[0] if rf and isinstance(rf[0], dict) else {}
        groups = _conditions(first)
        if not groups:
            out.append(f"route {j} has no filter, so it matches every value and the fallback never runs")
            continue
        for g in groups:
            conds = g if isinstance(g, list) else [g]
            if not any(isinstance(c, dict) and any(isinstance(side, str) and expr_key(side) in keys for side in (c.get("a"), c.get("b")))
                       for c in conds):
                out.append(f"route {j} has a filter group that does not test the decision value, so values that pass it never reach the fallback")
                break
    return out


def _fallback_problems(router: dict, expr: str | None, ctx: _ACtx | None = None) -> list[str]:
    """What the fallback route of a decision router lacks. The fallback takes every value no other route
    takes, Disqualified included, so it must not write a lead Status that can carry the value, and it must
    leave a trace: an unfiltered Error Shadow Ledger row whose lead link, decision value and call ID are
    mappings from the lead lookup or the trigger, the decision value and the call-details module or the
    trigger, plus an unfiltered Slack alert. No other route may match every value."""
    ctx = ctx or _ACtx(_DEFAULT_LEAD, {}, None, None)
    fb = fallback_index(router)
    if fb is None:
        return [f"router {router.get('id')} has no fallback route, so a value no route takes (Disqualified included) vanishes without a trace"]
    flow = _routes(router)[fb]
    first = flow[0] if flow and isinstance(flow[0], dict) else {}
    out: list[str] = []
    key = expr_key(expr) if expr is not None else None
    if key is not None:
        out += _sibling_problems(router, {key})
    if _conditions(first):
        out.append(f"fallback route {fb} carries filter conditions, so a rejected value can still match nothing")
    inside = [(x, err) for x, err, _c in walk(flow)]
    leaks = [x.get("id") for x, _err in inside if _status_may_be_disqualified(x, ctx.lead)]
    if leaks:
        out.append(f"fallback route {fb} writes lead Status in modules {leaks}, a value that can be Disqualified, so Disqualified still gets through")
    reach = _reach(flow)
    rows = []
    for x in reach:
        if not is_ledger_create(x):
            continue
        rec = _record(x)
        decision = key is not None and any(_refers_to(v, key) for f, v in rec.items() if f not in NON_DECISION_FIELDS)
        if _is_error_row(rec) and decision and _bare_ref_to(rec.get(LEAD_LINK_FIELD), ctx, ("airtable:",)) \
                and _bare_ref_to(rec.get(CALL_ID_FIELD), ctx, ("bland:",)):
            rows.append(x)
    if not rows:
        out.append(f"fallback route {fb} has no unfiltered Shadow Ledger row with Execution Status Error that carries the decision value, "
                   f"the lead link (a reference to the lead lookup or the trigger) and the Bland call ID (a reference to the call-details module or the trigger)")
    if not any(is_slack_message(x) for x in reach):
        out.append(f"fallback route {fb} sends no unfiltered Slack alert")
    return out


def _fallback_leaves_trace(flow: list) -> bool:
    """An unfiltered Shadow Ledger create and an unfiltered Slack message at the top of the route (E7 and the
    other generic routers; check A asks for more of a decision router)."""
    reach = _reach(flow)
    return any(is_ledger_create(x) for x in reach) and any(is_slack_message(x) for x in reach)


def _prev_status_mapped(row: dict, ctx: _ACtx) -> bool:
    """The row records the lead's Status as it was before the write: a reference to the Status output of an Airtable module."""
    for e in _value_exprs(_record(row)):
        for r in iml_refs(e):
            mod = ctx.mods.get(r.module)
            if mod is not None and _mtype(mod).startswith("airtable:") and r.field.strip().lower() in ctx.lead.keys:
                return True
    return False


def _decision_row_problems(chain: tuple, expr: str, ctx: _ACtx) -> list[str]:
    """F-31 item 1: a ledger create before the Status write on its path that carries the lead link, the decision
    value, the evidence and the call ID, and the lead's previous Status."""
    rows = [x for flow, idx in chain for x in flow[:idx] if isinstance(x, dict) and is_ledger_create(x)]
    if not rows:
        return ["there is no Shadow Ledger decision row before the Status write (lead link, decision value, previous Status, evidence, call ID)"]
    best = None
    for w in rows:
        miss = ledger_missing(w, expr, ())
        if not _prev_status_mapped(w, ctx):
            miss = miss + ["previous Status"]
        if best is None or len(miss) < len(best[1]):
            best = (w, miss)
    if best[1]:
        return [f"the decision row {best[0].get('id')} before the Status write is missing {', '.join(best[1])}"]
    return []


# Measured 2026-10-30 on the first live test runs: a Make search that finds nothing can still emit one empty bundle
# (Stripe Search Customers showed "Total number of bundles: 0", and the listener's System Logs search fed its aggregator one
# bundle with an empty id, so length(<aggregator>.array) was 1). Make documents a per-module "Continue the execution of the
# route even if the module returns no results" option that does this, and it is not visible in the blueprint. So an
# empty test on an aggregator is the first aggregated record ID not existing: true when no bundle reached the aggregator
# and when an empty one did. length(<aggregator>.array) = 0 is false in the second case and is not accepted.
AGG_EMPTY_HINT = ('a condition "does not exist" on the first record ID the aggregator collected (in Make: first of map over '
                  '<aggregator>.array with the key "id"). A search that finds nothing can still emit one empty bundle, measured '
                  '2026-10-30, so a length test on the array reads 1 and never 0')


def agg_first_id(expr: object, agg_id: object) -> bool:
    """Exactly {{first(map(<agg>.array; "id"))}} (whitespace free, either quote)."""
    if not isinstance(expr, str):
        return False
    k = expr_key(expr).replace("'", '"')
    return k == f'first(map({agg_id}.array;"id"))'


def _empty_test(c: dict, agg_ids: set) -> bool:
    """A condition that is true when the aggregator holds no real record: its first aggregated id does not exist."""
    a, op = c.get("a"), str(c.get("o", ""))
    parts = op.split(":")
    return (any(agg_first_id(a, x) for x in agg_ids)
            and (parts[-1] == "notexist" or parts[0] == "notexist"))


def _empty_case_problems(bp: dict, lookup_id: int, ctx: _ACtx) -> list[str]:
    """F-31 item 3: a search that finds no lead emits no bundle, so the scenario would stop silently. The
    aggregator pattern: an aggregator fed by the lookup always emits one bundle, a router route that tests it
    for the empty case holds an unfiltered Error ledger row with the call ID and an unfiltered Slack alert."""
    look = ctx.mods.get(lookup_id)
    if look is None:
        return [f"module {lookup_id} named in audit/status_allow_list.json is not in the blueprint"]
    aggs = [x for x in ctx.mods.values() if "aggregator" in _mtype(x).lower()
            and isinstance(x.get("parameters"), dict) and x["parameters"].get("feeder") == lookup_id]
    if not aggs:
        return [f"search module {lookup_id} has no aggregator fed by it, so a phone with no lead stops the scenario without a trace. "
                f"Add an aggregator on module {lookup_id}, then a router route for the empty result"]
    agg_ids = {x.get("id") for x in aggs}
    for r, _err, _c in walk(bp.get("flow") or []):
        for rf in _routes(r):
            first = rf[0] if rf and isinstance(rf[0], dict) else {}
            if not any(_empty_test(c, agg_ids) for c in _iter_conditions(first)):
                continue
            reach = [first] + _reach(rf[1:])
            rows = [x for x in reach if is_ledger_create(x) and _is_error_row(_record(x))
                    and _bare_ref_to(_record(x).get(CALL_ID_FIELD), ctx, ("bland:",))]
            if rows and any(is_slack_message(x) for x in reach):
                return []
    return [f"no router route tests the aggregator on module {lookup_id} for the empty result and holds an Error ledger row (with the Bland call ID) and a Slack alert"]


# --- A-3 and A-4 (bug sweep 2026-10-31, H2 and M3) -------------------------------------------------------------
# A lead Status write must address a record that exists, and a lead that is not found must not stop the write without a
# trace. A search that finds nothing can emit one empty bundle (measured 2026-10-30) or no bundle at all (F-31.1).
# A-3 (H2, Batch Outbound Caller 2): a Status write whose record ID is {{N.id}} of a search runs with an empty ID on the
# empty bundle and fails. On a scheduled poll every idle run then errors and Make deactivates the scenario after
# maxErrors. It needs a {{N.id}} exists gate after N on its path. A re-lookup is credited: N, or a module before it on its
# path, is gated on the first record ID of an aggregator fed by an identical search (same table, same formula), as
# Pending Call 121 behind aggregator 113 of search 7. Only the canonical exist test counts.
# A-4 (M3, Automating Signed Contracts 8): a filter on the path of a Status write that waits for a lead search to find the
# lead stops the bundle silently when it finds nothing. Waiting on an aggregator fed by the lead search passes only on the
# first module of a router route whose fallback or sibling route traces the empty result (an unfiltered Error ledger row
# and a Slack alert, the Pending Call 146 shape). A does-not-exist gate is a dedupe stop and out of scope (VIP intake 81).
# A search that is the scenario's first module is exempt: it is a scheduled poll and empty is its idle state (Batch 1).
_A3_SEARCH_ID = re.compile(r"(\d+)\.id")


def _exist_op(c: dict) -> bool:
    return str(c.get("o", "")).split(":")[-1] == "exist"


def _every_group(m: dict, pred) -> bool:
    """m has a filter and every OR group of it holds a condition for which pred is true."""
    groups = _conditions(m)
    return bool(groups) and all(any(isinstance(c, dict) and pred(c) for c in (g if isinstance(g, list) else [g])) for g in groups)


def _same_search(s: dict, n: dict) -> bool:
    """s searches the table n searches with the same formula (whitespace ignored)."""
    ms, mn = _mapper(s), _mapper(n)
    return ("search" in _mtype(s).lower() and isinstance(ms.get("table"), str) and ms.get("table") == mn.get("table")
            and re.sub(r"\s+", "", str(ms.get("formula", ""))) == re.sub(r"\s+", "", str(mn.get("formula", ""))))


def _a3_problem(m: dict, chain: tuple, ctx: _ACtx) -> str | None:
    """A-3: the Status write takes its record ID from a search with no {{N.id}} exists gate and no re-lookup credit."""
    if lead_status(m, ctx.lead)[0] is None:
        return None
    rid = _mapper(m).get("id")
    hit = _A3_SEARCH_ID.fullmatch(expr_key(rid)) if isinstance(rid, str) else None
    n = int(hit.group(1)) if hit else None
    src = ctx.mods.get(n)
    if src is None or "search" not in _mtype(src).lower():
        return None
    path = [x for f, i in chain for x in f[:i + 1] if isinstance(x, dict)]
    pos = next((i for i, x in enumerate(path) if x is src), None)
    if pos is None:
        return None
    if any(_every_group(x, lambda c: isinstance(c.get("a"), str) and expr_key(c["a"]) == f"{n}.id" and _exist_op(c))
           for x in path[pos + 1:]):
        return None
    aggs = {aid for aid, a in ctx.mods.items() if "aggregator" in _mtype(a).lower() and isinstance(a.get("parameters"), dict)
            and a["parameters"].get("feeder") != n and isinstance(ctx.mods.get(a["parameters"].get("feeder")), dict)
            and _same_search(ctx.mods[a["parameters"]["feeder"]], src)}
    if aggs and any(_every_group(x, lambda c: _exist_op(c) and any(agg_first_id(c.get("a"), g) for g in aggs))
                    for x in path[:pos + 1]):
        return None
    return (f"A-3 lead Status write {m.get('id')} takes its record ID from search module {n} with no {{{{{n}.id}}}} exists gate. "
            f"A search that finds nothing can emit one empty bundle (measured 2026-10-30), so the update runs with an empty "
            f"record ID and fails. On a scheduled poll every idle run errors, and Make deactivates the scenario after maxErrors "
            f"(bug sweep H2). Add a filter {{{{{n}.id}}}} exists on this module or on a module between them")


def _a4_traced(router: dict, route: int, agg: object) -> bool:
    """The router traces the empty result of the gate on route: a fallback that leaves a trace, or a sibling route whose
    first module tests the aggregator for the empty result and that holds an unfiltered Error ledger row and a Slack alert."""
    routes = _routes(router)
    fb = fallback_index(router)
    if fb is not None and fb != route and _fallback_leaves_trace(routes[fb]):
        return True
    for j, rf in enumerate(routes):
        first = rf[0] if rf and isinstance(rf[0], dict) else {}
        if j == route or not any(_empty_test(c, {agg}) for c in _iter_conditions(first)):
            continue
        reach = [first] + _reach(rf[1:])
        if any(is_ledger_create(x) and _is_error_row(_record(x)) for x in reach) and any(is_slack_message(x) for x in reach):
            return True
    return False


def _a4_problem(m: dict, chain: tuple, ctx: _ACtx, first_id: object) -> str | None:
    """A-4: a filter on the path of the Status write waits for a lead search to find the lead and leaves no trace when it
    does not. One finding per write, the first gate on the path."""
    sval, unknown = lead_status(m, ctx.lead)
    if sval is None and not unknown:
        return None
    searches = {sid for sid, s in ctx.mods.items() if sid != first_id and _mtype(s) == "airtable:ActionSearchRecords"
                and str(_mapper(s).get("table", "")).strip().lower() in ctx.lead.tables}
    if not searches:
        return None
    aggs = {aid: a["parameters"]["feeder"] for aid, a in ctx.mods.items() if "aggregator" in _mtype(a).lower()
            and isinstance(a.get("parameters"), dict) and a["parameters"].get("feeder") in searches}
    wid = m.get("id")
    for k, (flow, idx) in enumerate(chain):
        parent = chain[k - 1][0][chain[k - 1][1]] if k > 0 else None
        for j in range(idx + 1):
            x = flow[j]
            if not isinstance(x, dict):
                continue
            for c in _iter_conditions(x):
                op = str(c.get("o", "")).split(":")
                if "notexist" in (op[0], op[-1]):
                    continue  # a dedupe stop, out of scope
                for side in (c.get("a"), c.get("b")):
                    if not is_mapping(side):
                        continue
                    direct = [r.module for e in secret_scan._iml_segments(side)[0] for r in iml_refs(e) if r.module in searches]
                    if direct:
                        s = direct[0]
                        return (f"A-4 lead Status write {wid} runs only when the filter on module {x.get('id')} finds the result of "
                                f"lead search {s}. When {s} finds nothing (it can emit no bundle or one empty one, measured "
                                f"2026-10-30) the bundle stops at that filter with no trace (bug sweep M3). Gate on an aggregator fed "
                                f"by {s} (its first collected record ID exists) on the first module of a router route, with a "
                                f"sibling route that tests that the ID does not exist and holds an unfiltered Error ledger row "
                                f"and a Slack alert")
                    agg = next((g for g in aggs if agg_first_id(side, g)), None)
                    if agg is None or op[-1] != "exist":
                        continue
                    route = _route_index(parent, flow) if j == 0 and isinstance(parent, dict) else None
                    if route is not None and _a4_traced(parent, route, agg):
                        continue
                    where = (f"module {x.get('id')} is not the first module of a router route" if route is None else
                             f"router {parent.get('id')} has no fallback and no sibling route that tests the aggregator for the "
                             f"empty result with an unfiltered Error ledger row and a Slack alert")
                    return (f"A-4 lead Status write {wid} waits on module {x.get('id')} for aggregator {agg} (fed by lead "
                            f"search {aggs[agg]}) to hold a record, but {where}. A lead that is not found stops there with no "
                            f"trace (bug sweep M3). Put the found test on the first module of a router route and trace the empty "
                            f"result on a sibling route (does not exist, an unfiltered Error ledger row and a Slack alert)")
    return None


# --- A-5 (D5, 2026-11-01) -------------------------------------------------------------------------------------
# A-2 asks that the allow-list lets through nothing outside the allowed set. A-5 asks the reverse: every allowed value
# gets through. The allow-list filter of the dynamic Status write lets it pass, and when the first router after the write
# on its flow branches on the same mapping (Pending Call router 10 after write 8), the value has a route of its own that is
# not the fallback. A value the filter drops lands in the fallback of the router above (Pending Call 135) and its Status is
# never written. A value with no route of its own lands in the fallback of the router after, which logs it as unmatched.
A5_EQUAL_OPS = ("text:equal", "text:equal:ci")


def _a5_route_tests(first: dict, key: str, value: str) -> bool:
    """first carries a filter of exactly one OR group that tests key for value, text:equal (exact) or text:equal:ci, tests
    key for no other value, and has no other condition on key that the value fails (a contradictory route never runs)."""
    groups = _conditions(first)
    if len(groups) != 1:
        return False
    conds = groups[0] if isinstance(groups[0], list) else [groups[0]]
    hit = False
    for c in conds:
        if not isinstance(c, dict) or not isinstance(c.get("a"), str) or expr_key(c["a"]) != key:
            continue
        op, lit = str(c.get("o", "")), c.get("b")
        if op not in A5_EQUAL_OPS or not isinstance(lit, str) or is_mapping(lit):
            continue
        if (lit.strip() == value) if op == "text:equal" else (lit.strip().lower() == value.lower()):
            hit = True
        else:
            return False
    return hit and eval_filter(first, key, value) is not False


def _a5_problems(m: dict, chain: tuple, ctx: _ACtx) -> list[tuple[dict, str]]:
    """A-5: (module, detail) for the Status write whose allow-list drops an allowed value and for the router after it that
    has no route of its own for an allowed value. Only for a dynamic Status write behind an allow-list in a listed scenario."""
    if ctx.entry is None:
        return []
    sval = lead_status(m, ctx.lead)[0]
    if sval is None or not is_mapping(sval) or status_write_outputs(sval) is not None:
        return []
    guard = _allow_list_guard(chain, sval)
    if guard is None:
        return []
    k, j = guard
    gmod = chain[k][0][j]
    allowed = ctx.entry["allowed"]
    wid, key = m.get("id"), expr_key(sval)
    out: list[tuple[dict, str]] = []
    dropped = [v for v in allowed if eval_filter(gmod, sval, v) is False]
    if dropped:
        out.append((m, f"A-5 lead Status write {wid}: the allow-list filter on module {gmod.get('id')} rejects {dropped}, which the "
                       f"allowed set in audit/status_allow_list.json names, so that value never reaches the write and the lead keeps "
                       f"its old Status. Add one OR group per value, `{_short(sval)}` text equal the value"))
    flow, idx = chain[-1]
    router = next((x for x in flow[idx + 1:] if isinstance(x, dict) and _routes(x)), None)
    if router is None:
        return out
    routes = _routes(router)
    if not any(rf and isinstance(rf[0], dict) and any(isinstance(c.get("a"), str) and expr_key(c["a"]) == key
                                                    for c in _iter_conditions(rf[0])) for rf in routes):
        return out
    fb = fallback_index(router)
    no_route = [v for v in allowed if not any(i != fb and rf and isinstance(rf[0], dict) and _a5_route_tests(rf[0], key, v)
                                              for i, rf in enumerate(routes))]
    if no_route:
        out.append((router, f"A-5 router {router.get('id')} after lead Status write {wid} branches on `{_short(sval)}` but has no route "
                            f"of its own for {no_route}. Such a value reaches only the fallback, which logs it as unmatched, and "
                            f"the fallback alone does not count. Add a route that is not the fallback whose first module filters "
                            f"`{_short(sval)}` text equal the value (case-insensitive equal is fine)"))
    return out


def check_a(b: Blueprint, schema: Schema, links: "AirtableMap | None" = None,
            designs: StatusDesigns | None = None) -> list[Finding]:
    out: list[Finding] = []
    scen = _scenario_label(b)
    status_lits = _decision_literals(schema)
    lead = lead_names(links)
    mods = {m.get("id"): m for m, _e, _c in walk(b.bp.get("flow") or [])}
    flow0 = b.bp.get("flow") or []
    trig = flow0[0].get("id") if flow0 and isinstance(flow0[0], dict) else None
    if designs is None:
        try:
            designs = load_status_designs(DEFAULT_STATUS_ALLOW)
        except InputError:
            designs = StatusDesigns()
    entry = designs.entries.get(str(b.scenario_id)) if b.scenario_id is not None else None
    ctx = _ACtx(lead, mods, trig, entry)

    def add(status, m, detail):
        out.append(Finding("A", status, scen, m.get("id"), _mtype(m), detail))

    def evaluate_point(m, chain, expr, label):
        writes = ledger_writes_on_path(chain, expr)
        sure = [w for w in writes if w.guaranteed and not w.after_email]
        refs = _path_decision_refs(chain)
        best = None
        for w in sure:
            miss = ledger_missing(w.module, expr, refs)
            if best is None or len(miss) < len(best[1]):
                best = (w, miss)
        if best and not best[1]:
            add(PASS, m, f"{label}. Ledger create {best[0].module.get('id')} carries lead link, decision, evidence and call ID")
            return
        if best:
            add(FAIL, m, f"{label}. Ledger create {best[0].module.get('id')} is missing {', '.join(best[1])}")
            return
        late = [w for w in writes if w.guaranteed and w.after_email]
        maybe = [w for w in writes if not w.guaranteed]
        if late:
            ids = ", ".join(str(w.module.get("id")) for w in late)
            add(FAIL, m, f"{label}. Ledger row ({ids}) is written only after the rejection email, so it records the outcome, not the decision")
        elif maybe:
            ids = ", ".join(str(w.module.get("id")) for w in maybe)
            add(FAIL, m, f"{label}. Ledger create ({ids}) sits only on a conditional path the Disqualified value may not take")
        else:
            add(FAIL, m, f"{label}. No Shadow Ledger create on the Disqualified path")

    def allow_list_point(m, chain, sval):
        """A dynamic Status write. An allow-list filter that rejects Disqualified on the path to it, on a router
        route whose fallback writes no Status and leaves an Error row and a Slack alert, means the write cannot
        set Disqualified and the rejected value is traced (F-31). The allow-list is credited only when all of
        F-31 holds: the values are inside the scenario's allowed set (audit/status_allow_list.json), a decision
        row with the previous Status sits before the write, no sibling route matches every value, and the
        fallback traces the rejected value. A filter that is only a deny-list, sits on a module after the write,
        tests another reference or lets a case variant through is not an allow-list, and the write is judged as
        before: a ledger create at the decision point."""
        guard = _allow_list_guard(chain, sval)
        if guard is None:
            evaluate_point(m, chain, sval, f"Dynamic Status write `{_short(sval)}` can set Disqualified")
            return
        k, j = guard
        gflow = chain[k][0]
        gmod = gflow[j]
        parent = chain[k - 1][0][chain[k - 1][1]] if k > 0 else None
        route = _route_index(parent, gflow) if isinstance(parent, dict) else None
        label = f"Dynamic Status write `{_short(sval)}` is behind an allow-list filter on module {gmod.get('id')}"
        if route is None or j != 0:
            add(FAIL, m, f"{label}, which is not the first module of a router route. A value the allow-list rejects (Disqualified "
                         f"included) is dropped without a trace. Put the allow-list on a router route and give the router a fallback")
            return
        problems = _fallback_problems(parent, sval, ctx)
        if entry is None:
            problems.append("the scenario is not in audit/status_allow_list.json, so the values the Bland pathway can send are unknown")
        else:
            allowed = {x.lower() for x in entry["allowed"]}
            outside = sorted({x for x in _allow_list_literals(gmod, sval) if x.lower() not in allowed})
            if outside:
                problems.append(f"the allow-list lets through {outside}, outside the allowed set {entry['allowed']}")
        problems += _decision_row_problems(chain, sval, ctx)
        if problems:
            add(FAIL, m, f"{label}, but " + "; ".join(problems))
        else:
            add(PASS, m, f"{label} (route {route} of router {parent.get('id')}) that rejects Disqualified, a decision row with the previous Status sits "
                         f"before it, and the fallback route writes no lead Status and records the rejected value in an Error ledger row and a Slack alert")

    for m, _in_err, chain in walk(b.bp.get("flow") or []):
        rec = _record(m)
        mp = _mapper(m)
        point_done = False
        # 1. Status writes on the lead table, direct or through an Airtable API call or an HTTP module.
        raw_sval, unknown = lead_status(m, lead)
        if unknown:
            add(REVIEW, m, "May write the lead Status through an API call, but the blueprint does not show which table or value. "
                           "Confirm in the Make UI that it cannot set Disqualified, or write the Status with an Airtable update module")
        if raw_sval is not None:
            sval = raw_sval
            outs = status_write_outputs(sval) if is_mapping(sval) else None
            if outs is not None and any(o.strip().lower() == DECISION_VALUE.lower() for o in outs):
                evaluate_point(m, chain, sval, f"Status write `{_short(sval)}` can set Disqualified")
                point_done = True
            elif outs is not None:
                outcome = sorted(o for o in outs if "disqualif" in o.lower())
                if outcome:
                    add(INFO, m, f"Status write `{_short(sval)}` records an outcome after the decision, not the decision")
                # Otherwise every output is a fixed non-Disqualified value.
            elif is_mapping(sval):
                allow_list_point(m, chain, sval)
                point_done = True
            elif sval.strip().lower() == DECISION_VALUE.lower():
                evaluate_point(m, chain, None, "Status write sets Disqualified")
                point_done = True
            elif "disqualif" in sval.lower():
                add(INFO, m, f"Status write `{_short(sval)}` records an outcome after the decision, not the decision")
        # 2. Filters that branch on Disqualified. One finding per module: a
        # status write already evaluated above covers its own filter.
        for c in ([] if point_done else _iter_conditions(m)):
            a, bb = c.get("a"), c.get("b")
            lit, ref = (bb, a) if is_mapping(a) else (a, bb)
            if isinstance(lit, str) and not is_mapping(lit) and lit.strip().lower() == DECISION_VALUE.lower() \
                    and str(c.get("o", "")).split(":")[1:2] == ["equal"] and isinstance(ref, str):
                evaluate_point(m, chain, ref, f"Filter branches on `{_short(ref)}` = Disqualified")
                break
        # 3. Routers that branch on a decision value. The fallback must leave a trace, whatever it writes.
        routes = _routes(m)
        if routes:
            decision_refs: dict[str, str] = {}
            for rf in routes:
                if not rf or not isinstance(rf[0], dict):
                    continue
                for c in _iter_conditions(rf[0]):
                    a, bb = c.get("a"), c.get("b")
                    for lit, ref in ((bb, a), (a, bb)):
                        if isinstance(lit, str) and not is_mapping(lit) and is_mapping(ref):
                            low = lit.strip().lower()
                            if low in status_lits or "disqualif" in low:
                                decision_refs.setdefault(expr_key(ref), ref)
            if decision_refs:
                refs = ", ".join(f"`{_short(r, 40)}`" for r in sorted(decision_refs.values()))
                fb = fallback_index(m)
                if fb is None:
                    add(FAIL, m, f"Router branches on decision value {refs} with no fallback route. An unmatched value vanishes without a trace")
                else:
                    best = min((_fallback_problems(m, ref, ctx) for ref in decision_refs.values()), key=len)
                    if best:
                        add(FAIL, m, f"Router branches on {refs} and the fallback does not close it: " + "; ".join(best))
                    else:
                        add(PASS, m, f"Router branches on {refs} and its fallback route {fb} records the unmatched value in an Error ledger row and a Slack alert")
            elif fallback_index(m) is None and any(rf and isinstance(rf[0], dict) and _conditions(rf[0]) for rf in routes) \
                    and any(lead_status(x, lead)[0] is not None or lead_status(x, lead)[1] for rf in routes for x, err, _c in walk(rf) if not err):
                add(REVIEW, m, "Router has no fallback route and its routes write lead Status. A bundle that "
                               "matches no route leaves no trace. Decide whether this router is in X-31 scope")
        # 4. Lower-priority context.
        tier = sorted({t for c in _iter_conditions(m) for t in TIERING_REFS
                       if any(isinstance(x, str) and t in x for x in (c.get("a"), c.get("b")))})
        if tier:
            add(INFO, m, f"VIP tiering on {', '.join(tier)}. Tiering, not rejection")
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        formula = " ".join(str(x.get("formula", "")) for x in (params, mp))
        if "disqualif" in formula.lower() and not is_airtable_write(m):
            add(INFO, m, "Consumes leads already Disqualified. Ledger rows downstream record the outcome, not the decision, so they do not satisfy A")
    # 5. F-31 item 3: the lookup that finds the lead emits no bundle for an unknown phone.
    if entry is not None and entry.get("no_lead_lookup") is not None:
        lid = entry["no_lead_lookup"]
        look = mods.get(lid)
        if look is not None:
            problems = _empty_case_problems(b.bp, lid, ctx)
            if problems:
                add(FAIL, look, "A phone with no lead leaves no trace: " + "; ".join(problems))
            else:
                add(PASS, look, "A phone with no lead is traced: an aggregator on this search feeds a route with an Error ledger row and a Slack alert")
        else:
            out.append(Finding("A", FAIL, scen, lid, "-", f"Module {lid} named in audit/status_allow_list.json is not in the blueprint"))
    # 6. A-3 (bug sweep H2): a Status write that takes its record ID from a search needs a {{N.id}} exists gate.
    # Error routes included, since a handler that writes Status from the search runs on the same empty ID.
    for m, _in_err, chain in walk(flow0):
        why = _a3_problem(m, chain, ctx)
        if why:
            out.append(Finding("A", FAIL, scen, m.get("id"), _mtype(m), why, "A-3"))
    # 7. A-4 (bug sweep M3): no silent lookup gate on the path of a Status write. Error routes are out of scope.
    for m, in_err, chain in walk(flow0):
        why = None if in_err else _a4_problem(m, chain, ctx, trig)
        if why:
            out.append(Finding("A", FAIL, scen, m.get("id"), _mtype(m), why, "A-4"))
    # 8. A-5 (D5): every allowed value passes the allow-list of the Status write and has its own route on the router after it.
    for m, _in_err, chain in walk(flow0):
        for mod, why in _a5_problems(m, chain, ctx):
            out.append(Finding("A", FAIL, scen, mod.get("id"), _mtype(mod), why, "A-5"))
    return out


def _handler_parts(onerror: list) -> tuple[bool, bool, list[str]]:
    """Ledger write, Slack message and directives in a handler, including nested routers.

    Nested onerror routes inside the handler belong to the handler's own
    modules, so their contents do not count toward this handler.
    """
    ledger = slack = False
    directives: list[str] = []

    def visit(flow: list) -> None:
        nonlocal ledger, slack
        for m in flow:
            if not isinstance(m, dict):
                continue
            if is_ledger_write(m):
                ledger = True
            if is_slack_message(m):
                slack = True
            if _mtype(m) in DIRECTIVES:
                directives.append(_mtype(m).split(":", 1)[1])
            for rf in _routes(m):
                visit(rf)

    visit(onerror)
    return ledger, slack, directives


def _removable_leaf(x: dict) -> bool:
    return (is_ledger_write(x) or is_slack_message(x)) and not _onerror(x)


def flattenable_directive(router: dict) -> dict | None:
    """The one directive a handler router can shrink to, or None. The common handler is a router with a ledger route and a
    route with a Slack message and the directive. Once the ledger and Slack modules go, only the directive is left, and the
    router around it does nothing: it has one unfiltered route that is not the fallback, and no module ahead of the
    directive carries a filter, so the directive runs on every error either way. The router can then give its place to the
    directive, which keeps its own settings and runs exactly as before. An empty condition list (a route name only) is no filter."""
    if _mtype(router) != "builtin:BasicRouter" or _onerror(router) or _conditions(router):
        return None
    routes = _routes(router)
    fb = fallback_index(router)
    keep = None
    for i, rf in enumerate(routes):
        mods = [x for x in rf if isinstance(x, dict)]
        left = [x for x in mods if not _removable_leaf(x)]
        if not left:
            continue
        d = left[0]
        if keep is not None or len(left) != 1 or _mtype(d) not in DIRECTIVES or _conditions(d) or _onerror(d) or i == fb:
            return None
        if any(_conditions(x) for x in mods[:mods.index(d)]):
            return None
        keep = d
    return keep


def removable_handler_modules(onerror: list) -> list[dict]:
    """The modules of a legacy error handler that a Logger push (F-E5.3) replaces: Shadow Ledger writes, Slack messages, and a
    router left empty once those are gone. A router that is left holding one directive (flattenable_directive) goes too, and the
    directive takes its place. A directive is never removable (R3 of the 2026-10-29 review: dropping a Resume, Ignore or Break
    changes what the scenario does), neither is a router that still holds anything else, and neither is a module with a real
    filter that sits ahead of a module that stays, since removing the filter would change when that module runs."""
    out: list[dict] = []

    def visit(flow: list, top: bool) -> bool:
        """True when every module of the flow goes."""
        mods = [m for m in flow if isinstance(m, dict)]
        kinds: list[str] = []
        for m in mods:
            routes = _routes(m)
            if _removable_leaf(m):
                kinds.append("leaf")
            elif routes and _mtype(m) == "builtin:BasicRouter":
                if top and flattenable_directive(m) is not None:
                    kinds.append("flat")
                else:
                    inner = [visit(rf, False) for rf in routes]
                    kinds.append("router" if all(inner) and not _onerror(m) else "keep")
            else:
                kinds.append("keep")
        later_stays = False
        for i in range(len(mods) - 1, -1, -1):
            if kinds[i] in ("leaf", "router") and later_stays and _conditions(mods[i]):
                kinds[i] = "keep"
            if kinds[i] in ("keep", "flat"):
                later_stays = True
        for m, k in zip(mods, kinds):
            if k in ("leaf", "router"):
                out.append(m)
            elif k == "flat":
                for rf in _routes(m):
                    out.extend(x for x in rf if isinstance(x, dict) and _removable_leaf(x))
                out.append(m)
        return all(k in ("leaf", "router") for k in kinds)

    visit(onerror, True)
    return out


# ---------------------------------------------------------------------------
# Check B v3 (Option C, decided by Rizwan 2026-10-29). The Error Monitor and the critical-module split are
# retired. Every external-call module outside an error route keeps a complete error handler, and the
# complete handler is now [one call to the shared Logger scenario, one directive]. The Logger (check L)
# writes the Shadow Ledger row and the Slack alert for every caller. The legacy handler [Shadow Ledger
# write, Slack message, directive] still counts as complete, as a REVIEW to convert (F-E5.3).
# ---------------------------------------------------------------------------


def _emits_many(x: dict) -> bool:
    """A module that can emit more than one bundle: an iterator, a search or list that is not limited to one record, or a polling trigger."""
    t = _mtype(x)
    if t == "builtin:BasicFeeder":
        return True
    sub = t.split(":", 1)[-1]
    if re.match(r"^(?:Action)?(?:Search|List)", sub, re.I):
        return str(_mapper(x).get("maxRecords", "")).strip() != "1"
    if re.match(r"^(?:Trigger)?Watch", sub, re.I):
        params = x.get("parameters") if isinstance(x.get("parameters"), dict) else {}
        return str(_mapper(x).get("limit", params.get("limit", ""))).strip() != "1"
    return False


def _trigger_emits_many(x: dict) -> bool:
    """The first module of the flow. A polling trigger (an RSS feed, a mailbox, an Airtable watch) emits up to its limit of bundles
    per run, so it starts a loop unless the limit is 1. A webhook or mailhook starts one bundle per request."""
    t = _mtype(x)
    sub = t.split(":", 1)[-1]
    if t == "builtin:BasicFeeder":
        return True
    if t.startswith("gateway:"):
        return False
    if re.match(r"^(?:Action)?(?:Search|List)", sub, re.I):
        return _emits_many(x)
    if "trigger" in sub.lower() or "watch" in sub.lower():
        params = x.get("parameters") if isinstance(x.get("parameters"), dict) else {}
        return str(_mapper(x).get("limit", params.get("limit", ""))).strip() != "1"
    return False


def _directive_contradiction(kind: str, chain: tuple, trigger: dict | None) -> str | None:
    """Why a handler's directive contradicts the Break/Resume/Ignore pattern, or None.
    Ignore is for per-lead loops, so nothing upstream emitting several bundles means there is no loop. Resume
    substitutes output for the modules that follow, so with none following it substitutes nothing."""
    flow_list, idx = chain[-1]
    if kind == "Resume" and not any(isinstance(x, dict) for x in flow_list[idx + 1:]):
        return "no module follows it, so the substitute output feeds nothing. Use Break to keep the failed bundle, or Ignore"
    if kind == "Ignore":
        many = any(isinstance(x, dict) and (_trigger_emits_many(x) if (k == 0 and j == 0) else _emits_many(x))
                   for k, (fl, i) in enumerate(chain) for j, x in enumerate(fl[:i]))
        if not many:
            return "nothing upstream emits more than one bundle, so there is no loop for Ignore to protect. Use Break or Resume"
    return None


def _handler_modules(onerror: list) -> list[dict]:
    """Every module of a handler, routes included. Nested onerror routes belong to the handler's own modules and are left out."""
    out: list[dict] = []

    def visit(flow: list) -> None:
        for x in flow:
            if isinstance(x, dict):
                out.append(x)
                for rf in _routes(x):
                    visit(rf)

    visit(onerror)
    return out


def _directive_note(kind: str, chain: tuple, trigger: dict | None) -> str:
    """What the directive means for the trace, sourced in CLAUDE.md (Engineering patterns)."""
    if kind in ("Ignore", "Resume"):
        note = "Make marks the run a Success, so the Logger row and alert are the only trace of this failure"
    else:
        note = "Break stores an incomplete execution and each automatic retry runs the handler again, so one failure can log several rows"
    problem = _directive_contradiction(kind, chain, trigger)
    return note + (f". Check the directive: {problem}" if problem else "")


def check_b(b: Blueprint, logger: "LoggerSpec | None" = None, links: "AirtableMap | None" = None,
            webhooks: "Webhooks | None" = None) -> list[Finding]:
    """F-E5 v3. Every external-call module outside an error route, except the trigger, needs a complete handler.
    Complete is [one logger call, one directive] (PASS) or the legacy [Shadow Ledger write, Slack message, one
    directive] (REVIEW, convert to a logger call, F-E5.3). A module that is itself a Shadow Ledger write needs
    [logger call or Slack message] and one directive. Missing or partial is a FAIL. logger is the Logger entry of
    audit/webhooks.json. Without it no module is a logger call. The Logger scenario itself is judged by check L.
    links (audit/airtable_links.json) and webhooks (the registry) let the logger call contract check client data (E6),
    the table of lead_record_id (E3) and the source of call_id (F). Without them the map and the registry are empty."""
    out: list[Finding] = []
    scen = _scenario_label(b)
    top = b.bp.get("flow") or []
    trigger = top[0] if top and isinstance(top[0], dict) else None
    if logger is not None and logger.scenario_id is not None and b.scenario_id == logger.scenario_id:
        return [Finding("B", INFO, scen, "-", "-", "The Logger scenario. Its own modules need handlers that cannot error, which check L verifies")]
    ectx = _EContext(b, links if links is not None else AirtableMap(), Allowlist(), logger)
    protection = None
    if trigger is not None and _mtype(trigger) == "gateway:CustomWebHook" and webhooks is not None and b.scenario_id is not None:
        reg = webhooks.entries.get(str(b.scenario_id))
        protection = reg.protection if reg is not None else None
    for m, in_err, chain in walk(top):
        if in_err or m is trigger or not is_external(m):
            continue
        mid, t = m.get("id"), _mtype(m)
        oe = _onerror(m)
        self_ledger = is_ledger_write(m)
        if not oe:
            out.append(Finding("B", FAIL, scen, mid, t, "Missing error handler. Add one logger call and one directive (F-E5.3)"))
            continue
        inside = _handler_modules(oe)
        calls = [x for x in inside if is_logger_call(x, logger)]
        ledger, slack, directives = _handler_parts(oe)
        used = ", ".join(directives) if directives else "none"
        if calls:
            problems: list[str] = []
            if len(calls) > 1:
                problems.append(f"{len(calls)} logger calls, exactly one is needed")
            if len(directives) != 1:
                problems.append(f"exactly one directive is needed (found {len(directives)})")
            extra = [x for x in inside if all(x is not c for c in calls) and _mtype(x) not in DIRECTIVES]
            if extra:
                kinds = ", ".join(sorted({_mtype(x) for x in extra}))
                problems.append(f"the handler also holds {kinds}. The Logger writes the ledger row and the Slack alert, so the handler is "
                                f"the logger call and the directive only")
            else:
                mods = [x for x in oe if isinstance(x, dict)]
                if len(mods) == 2 and not (mods[0] is calls[0] and _mtype(mods[1]) in DIRECTIVES):
                    problems.append("the logger call must come first and the directive last")
            if any(_conditions(x) for x in inside):
                problems.append("a module in the handler carries a filter, so the log or the directive can be skipped")
            for c in calls:
                scope = LoggerScope(ectx, chain, protection, trigger.get("id") if trigger is not None else None)
                problems.extend(f"logger call {c.get('id')} {p}" for p in logger_call_problems(c, m, logger, scope))
            if problems:
                clauses = ". ".join(p[0].upper() + p[1:] for p in problems)
                out.append(Finding("B", FAIL, scen, mid, t, f"Logger handler is not complete. {clauses}. Directive {used}"))
            else:
                out.append(Finding("B", PASS, scen, mid, t, f"Logger handler: logger call {calls[0].get('id')}, then {directives[0]}. "
                                                               f"{_directive_note(directives[0], chain, trigger)}"))
            continue
        missing = []
        if not ledger and not self_ledger:
            missing.append("Shadow Ledger write")
        if not slack:
            missing.append("Slack message")
        if not directives:
            missing.append("directive")
        if len(directives) > 1:
            missing.append(f"exactly one directive (found {len(directives)})")
        note = " Ledger-write module, so a logger call (or the legacy Slack message) plus one directive is enough." if self_ledger else ""
        if missing:
            out.append(Finding("B", FAIL, scen, mid, t,
                               f"Partial handler, missing {', '.join(missing)}. Directive {used}. A complete handler is one logger call and "
                               f"one directive (F-E5.3).{note}"))
        else:
            what = "Slack message" if self_ledger and not ledger else "Shadow Ledger write, Slack message"
            out.append(Finding("B", REVIEW, scen, mid, t,
                               f"Legacy complete handler ({what}, directive {used}). Convert to a logger call (F-E5.3): one logger call, "
                               f"then the same directive.{note}"))
    out.extend(_b1_link_list_rows(ectx, logger, scen))
    return out


# B1 (bug sweep L3, 2026-10-31): a Logger call whose lead_record_id is a bare Airtable link field ({{5.`Related Applicant`}},
# {{3.`Applicant Link`}}) sends the whole link list. Make joins two links into one text 'recA, recB', the Logger's Applicant
# Link write gets a 422 and the Error row is lost. A link field set to prefer one record is still a list in Make. The fix is
# {{first(<link>)}}, which the payload contract accepts for an Applicants link (F-E5.4). The row sits on the call, not the
# owner, because the push changes only the call (make_push marks the owner unchanged when only a child's mapper changes).
# A lookup or rollup field is not in the link map, so it stays an owner contract FAIL and is not B1. Not allowlistable.


def _b1_link_list_rows(ectx: _EContext, logger: "LoggerSpec | None", scen: str) -> list[Finding]:
    out: list[Finding] = []
    for x, _err, _chain in ectx.order:
        if not is_logger_call(x, logger):
            continue
        body, _ = logger_body(x)
        e = _single_expression((body or {}).get("lead_record_id"))
        refs = iml_refs(e) if e else []
        if len(refs) != 1 or refs[0].text != e or refs[0].field == "id":
            continue
        ref = refs[0]
        table = ectx.table_of(ref.module)
        if not table or ectx.links.link_target(table, ref.field) is None:
            continue
        out.append(Finding("B", FAIL, scen, x.get("id"), _mtype(x),
                           f"B1 lead_record_id: logger call {x.get('id')} sends {{{{{ref.text}}}}}, the whole link list. Two links reach "
                           f"the Logger as one text 'recA, recB', its Applicant Link write gets a 422 and the Error row is lost. Send "
                           f"{{{{first({ref.text})}}}} (F-E5.4)", "B1"))
    return out


def _labels_entry(b: Blueprint, labels: Labels, by_id: bool) -> tuple[str | None, dict | None]:
    if b.scenario_id and b.scenario_id in labels.scenarios:
        return b.scenario_id, labels.scenarios[b.scenario_id]
    if by_id and b.scenario_id:
        return None, None
    norm = " ".join(b.name.split()).casefold()
    for sid, entry in labels.scenarios.items():
        if isinstance(entry, dict) and " ".join(str(entry.get("name", "")).split()).casefold() == norm:
            return sid, entry
    return None, None


def check_c(b: Blueprint, labels: Labels, schema: Schema, by_id: bool, logger: "LoggerSpec | None" = None) -> list[Finding]:
    """Labels of Shadow Ledger writes and of Logger calls (the body field label, which the Logger writes as the row's label).
    The Logger's own ledger write maps the caller's label ({{<trigger>.label}}) and is exempt."""
    out: list[Finding] = []
    scen = _scenario_label(b)
    fail = FAIL if labels.confirmed else UNCONFIRMED
    options = set(schema.label_options)
    flow = b.bp.get("flow") or []
    # Every scenario that writes the ledger needs an entry, updates included.
    # Label checks apply to label-bearing writes only: every create, and any
    # update that sets the label. An update that only fills a cost or status
    # column needs no label and no expected label. A Logger call writes a ledger row
    # through the Logger, so it counts as a label-bearing write.
    all_writes = [m for m, _e, _c in walk(flow) if is_ledger_write(m)]
    if logger is not None and logger.scenario_id is not None and b.scenario_id == logger.scenario_id:
        tid = flow[0].get("id") if flow and isinstance(flow[0], dict) else None
        all_writes = [m for m in all_writes if not _logger_mapped_label(m, tid)]
    calls = [m for m, _e, _c in walk(flow) if is_logger_call(m, logger)]
    if not all_writes and not calls:
        return out
    writes = [m for m in all_writes if is_ledger_create(m) or LABEL_FIELD in _record(m)]
    sid, entry = _labels_entry(b, labels, by_id)
    expected = entry.get("expected_label") if isinstance(entry, dict) else None
    if entry is None:
        what = "writes the Shadow Ledger" if all_writes else "calls the Logger"
        out.append(Finding("C", fail, scen, "-", "-", f"Scenario {what} but has no entry in scenario_labels.json"))
    if not writes and not calls:
        return out
    call_labels = {id(m): (logger_body(m)[0] or {}).get("label") for m in calls}
    if entry is None:
        pass
    elif not expected:
        observed = sorted({_short(str(_record(m).get(LABEL_FIELD))) for m in writes if LABEL_FIELD in _record(m)}
                          | {_short(str(v)) for v in call_labels.values() if v is not None})
        obs = ", ".join(f'"{o}"' for o in observed) or "none"
        out.append(Finding("C", fail, scen, "-", "-",
                           f"Scenario {sid} writes the Shadow Ledger but has no expected label. Observed {obs}"))
    elif expected not in options:
        out.append(Finding("C", fail, scen, "-", "-", f'Expected label "{expected}" is not a Single Select option in the schema'))
    items = [(m, LABEL_FIELD in _record(m), _record(m).get(LABEL_FIELD), "") for m in writes]
    items += [(m, call_labels[id(m)] is not None, call_labels[id(m)], "Logger call ") for m in calls]
    for m, present, val, kind in items:
        if not present:
            if kind:
                out.append(Finding("C", fail, scen, m.get("id"), _mtype(m), "Logger call sends no label"))
            elif is_ledger_create(m):
                out.append(Finding("C", fail, scen, m.get("id"), _mtype(m), "Ledger create has no scenario label"))
            continue
        if not isinstance(val, str) or is_mapping(val) or not val.strip():
            out.append(Finding("C", fail, scen, m.get("id"), _mtype(m), f"{kind}Scenario label is not a fixed literal"))
            continue
        notes = []
        if val not in options:
            notes.append("not a Single Select option")
        verb = "Sends" if kind else "Writes"
        if expected and val != expected:
            out.append(Finding("C", fail, scen, m.get("id"), _mtype(m),
                               f'{kind}{verb} "{_short(val)}", expected "{expected}"' + (f" ({notes[0]})" if notes else "")))
        elif notes:
            out.append(Finding("C", fail, scen, m.get("id"), _mtype(m), f'{kind}{verb} "{_short(val)}", {notes[0]}'))
        elif expected:
            out.append(Finding("C", PASS, scen, m.get("id"), _mtype(m), f'{kind}{verb} "{val}"'))
    return out


module_at = secret_scan.module_at


def check_d(b: Blueprint, secret_allow: list[dict] | None = None, f2_state: dict | None = None,
            used: set | None = None) -> list[Finding]:
    """Credential literals. A Make webhook URL in a Bland call module (BLAND_CALLS) that
    audit/secret_allowlist.json pins is INFO ("allowlisted: <reason>") while the scenario the
    entry names (requires_fetch_back_hook) passes F2, and a FAIL when it does not, since the URL is
    only an address if the hook behind it verifies the caller. f2_state maps scenario ID -> bool
    (None means this is a single-scenario run, so that scenario is not evaluated)."""
    out: list[Finding] = []
    scen = _scenario_label(b)
    blocking, allowed = secret_scan.split_findings(b.bp, b.scenario_id, secret_allow or [])
    for f in blocking:
        m = module_at(b.bp, f["location"])
        mid = m.get("id") if m else "-"
        mtype = _mtype(m) if m else "(blueprint metadata)"
        out.append(Finding("D", FAIL, scen, mid, mtype, f"Credential literal: {f['pattern_type']}"))
    for a in allowed:
        if a.get("kind") == secret_scan.LOGGER_KIND:
            # split_findings grants a Logger allowance only for the bare url of a Logger call while the hook is
            # registered and pinned. The hook's API key is proved by check L1, so a missing key fails there.
            out.append(Finding("D", INFO, scen, a["module_id"], "http:MakeRequest",
                               f"{a['pattern_type']} allowlisted: the Logger hook URL (scenario {a['requires_api_key_hook']}), "
                               f"protected by its API key, which check L1 verifies", "", True))
            continue
        if used is not None:
            used.add((str(b.scenario_id), a["module_id"], a["pattern_type"]))
        tgt = a["requires_fetch_back_hook"]
        mid = a["module_id"]
        mtype = a.get("module_type") or BLAND_CALLS[0]  # the pinned module's own type, a Send a Call or a Create a Call
        base = f"{a['pattern_type']} allowlisted: {a['reason']}"
        if f2_state is None:
            out.append(Finding("D", INFO, scen, mid, mtype, f"{base}. Scenario {tgt}, whose hook the URL targets, "
                                                                          f"is not evaluated in a single-scenario run", "", True))
        elif f2_state.get(tgt) is True:
            out.append(Finding("D", INFO, scen, mid, mtype, f"{base}", "", True))
        else:
            why = ("is not an audited fetch_back webhook scenario" if f2_state.get(tgt) is None
                   else "does not pass check F2")
            out.append(Finding("D", FAIL, scen, mid, mtype,
                               f"Credential literal: {a['pattern_type']}. An allowlist entry excuses it only while scenario {tgt}, "
                               f"whose hook the URL targets, verifies callers by fetch-back. Scenario {tgt} {why}, so the URL is a "
                               f"credential again"))
    return out


# ---------------------------------------------------------------------------
# Check S (Stripe money calls: F-H1, F-H2, F-H9-prep, decided 2026-10-30)
# ---------------------------------------------------------------------------
#
# Sourced (docs.stripe.com, read 2026-10-29 and 2026-10-30):
#   api/idempotent_requests: every v1 POST takes an Idempotency-Key header. The same key with different parameters is
#     an idempotency_error, keys are kept at least 24 h, at most 255 characters.
#   api/payment_intents/object: PaymentIntent.charges was removed in API version 2022-11-15, and a PaymentIntent has
#     no hosted page, so {{N.charges.url}} is never a link a client can pay with.
#   api/invoices/finalize: a finalized invoice carries hosted_invoice_url, the client's payment page.
#   Metadata on the Invoice reaches the invoice.* webhook events the F-H9 listener reads to find the lead.
# Make (apps.make.com/stripe): of the Stripe app's create modules only Create a Payment Intent has an Idempotency Key
# field. Make an API Call takes custom headers, so an invoice flow sends its POSTs through it.
#
# S1 every Stripe call that creates or moves money carries an idempotency key derived from the record, never from the
#    run, so a Break retry or a second trigger fire gets Stripe's first result back instead of a second object.
# S2 every Invoice or PaymentIntent create carries metadata airtable_record_id (a record ID mapping) and milestone
#    (X-30), so the listener finds the lead without matching on email.
# S3 no module maps {{N.charges...}} of a Stripe module (the unpayable link).

STRIPE_CHECK = "S"
STRIPE_NO_KEY_FIELD = frozenset({"stripe:createInvoice", "stripe:createInvoiceItem", "stripe:finalizeInvoice",
                                 "stripe:confirmPaymentIntent", "stripe:capturePaymentIntent", "stripe:createRefund",
                                 "stripe:createPayout"})
STRIPE_API_CALL = "stripe:makeAnApiCall"
STRIPE_OBJECT_PATHS = ("/v1/invoices", "/v1/payment_intents")
STRIPE_RUN_VARYING = re.compile(r"executionId|\bnow\b|timestamp|uuid|random", re.I)
_STRIPE_CHARGES = re.compile(r"\{\{[^{}]*?\b(\d+)\.charges\b")


def _stripe_key_problem(value: object) -> str | None:
    """None when value is a usable idempotency key: it holds a record ID mapping and nothing that changes per run."""
    if not isinstance(value, str) or not value.strip():
        return "is empty"
    if "{{" not in value:
        return "is a fixed text, so every lead would share one key"
    if STRIPE_RUN_VARYING.search(value):
        return "changes on every run (execution ID, now, a timestamp or a random value), so a retry creates a second object"
    if not re.search(r"\{\{[^{}]*\b\d+\.id\b", value):
        return "does not include a record ID mapping such as {{1.id}}, so two leads can collide"
    if re.search(r"[{}]", re.sub(r"\{\{[^{}]*\}\}", "", value)):
        return ("has a { or } outside a {{ }} mapping, which Make sends as literal text, so that part of the key never "
                "changes (write every mapping as {{...}})")
    if len(re.sub(r"\{\{[^{}]*\}\}", "", value)) > 200:
        return "is too long (Stripe allows 255 characters)"
    return None


def _stripe_header(m: dict, name: str) -> object:
    for h in _mapper(m).get("headers") or []:
        if isinstance(h, dict) and str(h.get("key", "")).strip().lower() == name.lower():
            return h.get("value")
    return None


def _stripe_api_path(m: dict) -> str:
    return str(_mapper(m).get("url", "")).strip().split("?")[0].rstrip("/")


def _stripe_metadata_problems(pairs: dict) -> list[str]:
    out = []
    rid = pairs.get("airtable_record_id")
    if not (isinstance(rid, str) and re.fullmatch(r"\s*\{\{\s*\d+\.id\s*\}\}\s*", rid)):
        out.append("metadata airtable_record_id must be exactly a record ID mapping such as {{1.id}}")
    ms = pairs.get("milestone")
    if not (isinstance(ms, str) and ms.strip()):
        out.append("metadata milestone must be set (X-30)")
    return out


def _stripe_body_pairs(body: object) -> dict:
    """The metadata[k]=v pairs of a form-encoded body text."""
    pairs = {}
    if isinstance(body, str):
        for part in body.split("&"):
            k, _, v = part.partition("=")
            hit = re.fullmatch(r"\s*metadata\[([A-Za-z0-9_]+)\]\s*", k)
            if hit:
                pairs[hit.group(1)] = v
    return pairs


# S4 and S5, the payment gates of the AR scenario (F-H4 and L3, approved 2026-10-30). Under L3 the AR trigger also fires
# for a locked lead the F-H9 listener marked paid, so the two Status writes must say which case they serve:
# S4 the release write (Status "Payment Verified - Ready") runs only when Payment Status is "Paid in Full". Balance Due 0
#    alone also matches a new lead with no payment yet (H.3 gap 5).
# S5 the lock write (Status "LOCKED - Payment Required") runs only when Payment Status is not "Paid in Full", so the
#    widened trigger's paid, locked case never reaches it and a lead whose balance is stale is never locked and invoiced
#    again. It tests Payment Status, not Status: a route filter on a Status literal makes the router a decision router
#    for check A (the Disqualified trail), which this scenario is not.
STRIPE_RELEASE = "Payment Verified - Ready"
STRIPE_LOCK = "LOCKED - Payment Required"
STRIPE_GATES = {STRIPE_RELEASE: ("S4", "Payment Status", ("text:equal", "text:equal:ci"), "Paid in Full", "=",
                                 "a lead with Balance Due 0 and no payment yet (a new lead) is released, and so is one whose "
                                 "payment was never confirmed"),
                STRIPE_LOCK: ("S5", "Payment Status", ("text:notequal", "text:notequal:ci"), "Paid in Full", "is not",
                              "a paid, locked lead whose balance has not caught up is locked and invoiced again when the widened "
                              "trigger fires")}


def _stripe_field_ref(expr: object, field: str, module_id: object) -> bool:
    """Exactly {{N.Field}} or {{N.`Field`}} of module N = module_id (the trigger, whose record the Status write updates)."""
    if not isinstance(expr, str):
        return False
    hit = re.fullmatch(r"\{\{(\d+)\.`?([^`{}]+?)`?\}\}", expr)
    return bool(hit) and hit.group(2) == field and str(hit.group(1)) == str(module_id)


def _stripe_literal_matches(b: object, value: str, op: str) -> bool:
    """Make compares text exactly unless the operator ends in :ci (case-insensitive). It does not trim."""
    if not isinstance(b, str):
        return False
    return b.casefold() == value.casefold() if op.endswith(":ci") else b == value


def _stripe_path_requires(chain: tuple, field: str, ops: tuple, value: str, module_id: object) -> bool:
    """A filter on the path (this module or an earlier one in any flow list of its chain) whose every OR group holds a
    condition on the trigger's field with one of ops against exactly value."""
    for fl, i in chain:
        for x in fl[: i + 1]:
            groups = _norm_groups(x) if isinstance(x, dict) else []
            if groups and all(any(_stripe_field_ref(c.get("a"), field, module_id) and str(c.get("o", "")) in ops
                                  and _stripe_literal_matches(c.get("b"), value, str(c.get("o", ""))) for c in g)
                              for g in groups):
                return True
    return False


# S6 sibling routes (decided 2026-10-30, from the second review of F-H1.1). Make pushes a bundle through every route of a
#    router in order, and a module that errors in one route (Break stores an incomplete execution) does not stop the
#    sibling routes (help.make.com, Overview of error handling: a router pushing the same bundle through several routes
#    keeps processing the remaining bundles). So two Stripe money calls on sibling routes cannot depend on each other.
#    A router FAILs when two or more of its routes hold a Stripe money call and at least one of those routes has no
#    filter on its first module and is not the fallback, so it runs whatever happened in the others.


def _stripe_money_call(m: dict) -> bool:
    t = _mtype(m)
    return (t == "stripe:createPaymentIntent" or t in STRIPE_NO_KEY_FIELD
            or (t == STRIPE_API_CALL and str(_mapper(m).get("method", "GET")).upper() == "POST"))


def _stripe_s6(m: dict) -> str | None:
    routes = _routes(m)
    if len(routes) < 2:
        return None
    fb = fallback_index(m)
    money = [i for i, rf in enumerate(routes) if any(_stripe_money_call(x) for x, err, _c in walk(rf) if not err)]
    if len(money) < 2:
        return None
    always = [i for i in money if i != fb and not (routes[i] and isinstance(routes[i][0], dict) and _norm_groups(routes[i][0]))]
    if not always:
        return None
    return (f"S6 routes {[i for i in money]} of this router hold Stripe money calls, and route(s) {always} have no filter, so "
            f"they run even when a Stripe call in a sibling route fails (Make keeps processing the other routes of a router "
            f"after a Break). A call that must succeed first (a void before a new invoice) has to sit on the same path, "
            f"ahead of the calls that depend on it")


# S7 version-bound fields (decided 2026-10-30). Stripe removed Invoice.paid_out_of_band in API 2025-03-31.basil
#    (docs.stripe.com changelog). An event's data keeps the API version it was created at, and the Stripe-Version header
#    does not change it, while a direct object request returns the object in the version that header names
#    (docs.stripe.com/sdks/set-version, api/events/list). So paid_out_of_band is read only from a Stripe Make an API Call
#    whose Stripe-Version header is a version before 2025-03-31. Anything else reads a field that may not exist.
STRIPE_REMOVED_IN_BASIL = ("paid_out_of_band",)
STRIPE_BASIL = "2025-03-31"
_STRIPE_VERSION_FIELD_REF = re.compile(r"\b(\d+)\.[A-Za-z0-9_.\[\]`]*?\b(" + "|".join(STRIPE_REMOVED_IN_BASIL) + r")\b")


def _stripe_pinned_before_basil(m: dict | None) -> bool:
    if not isinstance(m, dict) or _mtype(m) != STRIPE_API_CALL:
        return False
    v = _stripe_header(m, "Stripe-Version")
    hit = re.fullmatch(r"(\d{4}-\d{2}-\d{2})\.[a-z]+", v.strip()) if isinstance(v, str) else None
    return bool(hit) and hit.group(1) < STRIPE_BASIL


def _stripe_s7(m: dict, by_id: dict) -> str | None:
    texts = list(_strings(_mapper(m))) + [str(c.get(k, "")) for g in _norm_groups(m) for c in g for k in ("a", "b")]
    for text in texts:
        for hit in _STRIPE_VERSION_FIELD_REF.finditer(text):
            src = by_id.get(int(hit.group(1)))
            if not _stripe_pinned_before_basil(src):
                return (f"S7 reads {hit.group(2)} from module {hit.group(1)}, which is not a Stripe Make an API Call pinned with "
                        f"a Stripe-Version header before {STRIPE_BASIL}. Stripe removed the field in 2025-03-31.basil, and an "
                        f"event keeps the version it was created at, so the value may be missing. Re-fetch the object with "
                        f"Stripe-Version 2025-02-24.acacia and read it from that call")
    return None


# S8 customer from a search (measured 2026-10-30 on the first F-H1 test run). Make's Stripe Search Customers emits a
#    bundle even when it finds nothing ("Total number of bundles: 0", id empty), so the next modules run with an empty
#    customer and Stripe answers resource_missing, which a Break parks under Process data in order. A Stripe POST must
#    not take its customer straight from a search or list module. It takes it from a call that always returns one
#    (create the customer when missing, update it when found).


def _stripe_s8(m: dict, by_id: dict) -> str | None:
    t = _mtype(m)
    if t == "stripe:createPaymentIntent":
        value = _mapper(m).get("customer")
    elif t == STRIPE_API_CALL and str(_mapper(m).get("method", "GET")).upper() == "POST":
        value = None
        body = _mapper(m).get("body")
        if isinstance(body, str):
            for part in body.split("&"):
                k, _, v = part.partition("=")
                if k.strip() == "customer":
                    value = v
    else:
        return None
    hit = re.fullmatch(r"\{\{(\d+)\.id\}\}", value.strip()) if isinstance(value, str) else None
    src = by_id.get(int(hit.group(1))) if hit else None
    if src is not None and re.search(r":(search|list)", _mtype(src), re.I):
        return (f"S8 takes the customer from {{{{{hit.group(1)}.id}}}} of a search module ({_mtype(src)}). Make emits a bundle "
                f"with no id when the search finds nothing, so Stripe gets an empty customer and the run parks on a Break. "
                f"Take the customer from a call that always returns one: update it when found, create it when missing")
    return None


# S9 customer email gate (bug sweep M6, 2026-10-31). Make's Stripe Search Customers is the list endpoint with email as an
#    optional filter (module definition read 2026-10-31), so an empty email may list the newest customer (another
#    client), and the customer POST then overwrites it. Stripe answers email_invalid to a malformed address
#    (docs.stripe.com/error-codes), which a Break parks under Process data in order. Nothing tested Email. A Stripe module
#    that sends an email (mapper email, or the email= pair of a POST /v1/customers form body, encodeURL unwrapped) needs a
#    format gate on the path: a filter whose every OR group holds a text:pattern condition on that exact mapping against
#    a literal pattern holding @. The gate must also trace what it drops: it sits on the first module of a router route
#    that is not the fallback, and the fallback leaves an unfiltered Shadow Ledger row and Slack alert. The rule checks
#    the operator and the @, not the quality of the regex.
_S9_ENCODE = re.compile(r"\s*\{\{\s*encodeURL\((.*)\)\s*\}\}\s*", re.S)


def _stripe_email_expr(m: dict) -> str | None:
    """The email mapping a Stripe module sends, {{encodeURL(X)}} read as {{X}}, or None."""
    t = _mtype(m)
    if not t.startswith("stripe:"):
        return None
    value = _mapper(m).get("email")
    if not is_mapping(value) and t == STRIPE_API_CALL and str(_mapper(m).get("method", "GET")).upper() == "POST" \
            and _stripe_api_path(m).startswith("/v1/customers"):
        body = _mapper(m).get("body")
        value = next((v for k, _, v in (p.partition("=") for p in body.split("&")) if k.strip() == "email"), None) \
            if isinstance(body, str) else None
    if not is_mapping(value):
        return None
    hit = _S9_ENCODE.fullmatch(value)
    return "{{" + hit.group(1).strip() + "}}" if hit else value.strip()


def _stripe_email_gate(c: dict, key: str) -> bool:
    typ, kind, _ci = _op_parts(c)
    a, b = c.get("a"), c.get("b")
    return (typ, kind) == ("text", "pattern") and isinstance(a, str) and expr_key(a) == key \
        and isinstance(b, str) and not is_mapping(b) and "@" in b


def _stripe_s9(m: dict, chain: tuple) -> str | None:
    expr = _stripe_email_expr(m)
    if expr is None:
        return None
    key = expr_key(expr)
    gates = []
    for k, (fl, i) in enumerate(chain):
        for j, x in enumerate(fl[: i + 1]):
            groups = _norm_groups(x) if isinstance(x, dict) else []
            if groups and all(any(_stripe_email_gate(c, key) for c in g) for g in groups):
                gates.append((k, j, x))
    for k, j, _x in gates:
        if j != 0 or k == 0:
            continue
        pfl, pi = chain[k - 1]
        router = pfl[pi]
        ri, fb = _route_index(router, chain[k][0]), fallback_index(router)
        if ri is not None and fb is not None and ri != fb and _fallback_leaves_trace(_routes(router)[fb]):
            return None
    if gates:
        return (f"S9 the format test on {expr} (module {gates[0][2].get('id')}) drops the lead with no trace. Put it on the "
                f"first module of a router route that is not the fallback, and have the fallback write an unfiltered Shadow "
                f"Ledger row and an unfiltered Slack alert")
    return (f"S9 sends {expr} to Stripe with no format test. An empty email makes Search Customers list the newest customer "
            f"(another client) and a malformed one gets email_invalid, which a Break parks under Process data in order. Put a "
            f"text:pattern filter on that mapping on the first module of a router route whose fallback writes an Error ledger "
            f"row and a Slack alert")


# S10 Payment Status from a fixed value (bug sweep L4, decided 2026-10-31). The AR lock write set Payment Status to the
#    literal Partial, so a lead with Amount Paid 0 shows as partly paid in every view and portal that reads the field.
#    Payment Status is a single select (Paid in Full, Partial, Unpaid, schema read 2026-10-31). An update or upsert on
#    the lead table outside an error route that writes Payment Status as a fixed Partial or Unpaid, and does not write
#    Amount Paid in the same record, FAILs. A mapped value passes (Listener 8 derives it from the amounts). A literal Paid
#    in Full is left to S4, and a create is exempt, since a new lead has no payment yet.
PAYMENT_STATUS_FIELD = "fldqpWCzawUrtO5YA"
AMOUNT_PAID_FIELD = "fldCesYm5l1GrwSmF"
STRIPE_DERIVED_PAYMENT_VALUES = {"partial": "an unpaid lead shows as partly paid",
                                 "unpaid": "a partly paid lead shows as unpaid"}


def _lead_field_is(k: object, fid: str, name: str, links: AirtableMap | None) -> bool:
    """A record key that names the lead field fid, by ID or by name (case-insensitive), resolved through the map."""
    if not isinstance(k, str):
        return False
    key = k.strip()
    if key == fid or key.casefold() == name.casefold():
        return True
    return links is not None and links._field_id(LEAD_TABLE, key) == fid


def _stripe_s10(m: dict, trig_id: object, links: AirtableMap | None, lead: LeadNames) -> str | None:
    if not is_airtable_write(m) or "create" in _mtype(m).lower():
        return None
    t = _mapper(m).get("table")
    if not (isinstance(t, str) and t.strip().lower() in lead.tables):
        return None
    rec = _record(m)
    if any(_lead_field_is(k, AMOUNT_PAID_FIELD, "Amount Paid", links) and nonempty(v) for k, v in rec.items()):
        return None
    for k, v in rec.items():
        if not _lead_field_is(k, PAYMENT_STATUS_FIELD, "Payment Status", links):
            continue
        val = _status_value(v)
        harm = STRIPE_DERIVED_PAYMENT_VALUES.get(val.strip().casefold()) if "{{" not in val else None
        if harm:
            src = trig_id if trig_id is not None else "<trigger>"
            return (f"S10 writes Payment Status as the fixed value {val.strip()}, which ignores Amount Paid, so {harm}. "
                    f"Map it from {{{{{src}.`Amount Paid`}}}} instead, Partial when it is above 0 and Unpaid otherwise "
                    f"(the exact formula is in CLAUDE.md check S)")
    return None


def check_s(b: Blueprint, links: AirtableMap | None = None) -> list[Finding]:
    out: list[Finding] = []
    scen = _scenario_label(b)
    flow = b.bp.get("flow") or []
    lead = lead_names(links)
    stripe_ids = {m.get("id") for m, _e, _c in walk(flow) if _mtype(m).startswith("stripe:")}
    by_id = {m.get("id"): m for m, _e, _c in walk(flow) if isinstance(m.get("id"), int)}
    for m, err, _chain in walk(flow):
        t = _mtype(m)
        mid = m.get("id")
        probs: list[str] = []
        money = False
        creates_object = False
        if t == "stripe:createPaymentIntent":
            money = creates_object = True
            why = _stripe_key_problem(_mapper(m).get("idempotency_key"))
            if why:
                probs.append(f"S1 the idempotency key {why}")
            meta = {str(p.get("key", "")).strip(): p.get("value")
                    for p in _mapper(m).get("metadata") or [] if isinstance(p, dict)}
            probs += [f"S2 {p}" for p in _stripe_metadata_problems(meta)]
        elif t in STRIPE_NO_KEY_FIELD:
            money = True
            probs.append("S1 this Make module has no idempotency key field, so a retry or a second trigger fire creates a second "
                         "object. Send the call through Stripe Make an API Call with an Idempotency-Key header instead")
        elif t == STRIPE_API_CALL and str(_mapper(m).get("method", "GET")).upper() == "POST":
            money = True
            why = _stripe_key_problem(_stripe_header(m, "Idempotency-Key"))
            if why:
                probs.append(f"S1 the Idempotency-Key header {why}")
            if _stripe_api_path(m) in STRIPE_OBJECT_PATHS:
                creates_object = True
                probs += [f"S2 {p}" for p in _stripe_metadata_problems(_stripe_body_pairs(_mapper(m).get("body")))]
        sval, _unknown = lead_status(m) if not err else (None, False)
        gate = STRIPE_GATES.get(sval) if isinstance(sval, str) else None
        if gate:
            rule, field, ops, value, verb, harm = gate
            trig_id = flow[0].get("id") if flow and isinstance(flow[0], dict) else None
            if _stripe_path_requires(_chain, field, ops, value, trig_id):
                out.append(Finding(STRIPE_CHECK, PASS, scen, mid, t, f"{rule} the {sval} write requires {field} {verb} {value}"))
            else:
                probs.append(f"{rule} the Status write {sval} runs without a filter that requires {field} {verb} {value} on its "
                             f"path, so {harm}. Add {{{{<trigger>.{field}}}}} {ops[0]} {value} to the route filter")
        for text in _strings(_mapper(m)):
            hit = next((h for h in _STRIPE_CHARGES.finditer(text) if int(h.group(1)) in stripe_ids), None)
            if hit:
                probs.append(f"S3 maps {{{{{hit.group(1)}.charges...}}}}. A PaymentIntent has no payable URL (charges was removed "
                             f"in Stripe API 2022-11-15), so the client gets no link. Send the finalized invoice's hosted_invoice_url")
                break
        if not err and _routes(m):
            why6 = _stripe_s6(m)
            if why6:
                probs.append(why6)
        if not err:
            why7 = _stripe_s7(m, by_id)
            if why7:
                probs.append(why7)
            why8 = _stripe_s8(m, by_id)
            if why8:
                probs.append(why8)
            why9 = _stripe_s9(m, _chain)
            if why9:
                probs.append(why9)
            why10 = _stripe_s10(m, flow[0].get("id") if flow and isinstance(flow[0], dict) else None, links, lead)
            if why10:
                probs.append(why10)
        if probs:
            out.append(Finding(STRIPE_CHECK, FAIL, scen, mid, t, "; ".join(probs)))
        elif money and not err:
            out.append(Finding(STRIPE_CHECK, PASS, scen, mid, t, "Stripe call carries a record-derived idempotency key"
                               + (" and the lead metadata" if creates_object else "")))
        elif not err and _stripe_email_expr(m) is not None:
            out.append(Finding(STRIPE_CHECK, PASS, scen, mid, t, "S9 the email it sends passes a traced format test"))
    return out


# ---------------------------------------------------------------------------
# Check P (AI model pinning: X-15, X-18, decided by Rizwan 2026-10-30)
# ---------------------------------------------------------------------------
#
# Decision: Anthropic only. No OpenAI, no "mini" models, no Sonnet. claude-opus-5-5 drafts the Submission Letter and
# grades the Interview Room, claude-haiku-5-5 runs every other call. The Make module is anthropic-claude v1
# createAMessage ("Create a Prompt"). Its definition (read 2026-10-30 from the Make app) maps model (select),
# max_tokens (required), messages, system, thinking (type adaptive, enabled or disabled, budget_tokens with enabled),
# temperature (UI default 1), top_p, top_k, outputFormat and additionalParameters. Its output is the Messages API
# response: content is an array of blocks (type thinking, text, tool_use ...), plus stop_reason and usage
# (input_tokens, output_tokens ...). There is no choices array and no prompt_tokens or completion_tokens.
#
# P1 no OpenAI module (or other LLM app) and no HTTP or API-call module to an LLM API host anywhere in the scenario,
#    error routes included. Every LLM call is anthropic-claude:createAMessage v1.
# P2 model is a literal in CLAUDE_MODELS. A mapping, an alias without the version or any other model FAILs.
# P3 the mapper sets none of temperature, top_p, top_k (directly or through additionalParameters). thinking is never
#    type enabled and never carries budget_tokens. On claude-opus-5-5 thinking is never type disabled.
# P4 max_tokens is a literal integer of at least CLAUDE_MIN_MAX_TOKENS[model], so adaptive thinking on Opus cannot eat
#    the whole budget and leave no text.
# P7 an outputFormat of type json_schema holds its schema as JSON text that parses to an object, with no mapping in it.
#    The module defines the field as Make type "json" with a text default (module definition read 2026-11-14). Measured
#    2026-11-14 on VIP intake module 81: an object schema is refused by Make before the call ("Invalid json string in
#    parameter 'schema'. Value has to be string."), and the same schema saved as text runs. This reverses the Oct 30 rule
#    (a text schema then got 400 "Input should be an object" from the API and an object ran), decided by Rizwan
#    2026-11-14, fix X-18+X-36. Two explanations fit (Make changed the field between the dates, or the form depends on the
#    UI-saved module metadata 81 carries and the API-built modules lack), so the four API-built modules move one at a time.
#    Settled 2026-11-14 on Market Watchdog 79: pushed as text through the API, it got 400 "Input should be an object"; re-saved
#    in the UI (which wrote metadata.expect typing the schema as json), it ran. So P7 also requires that metadata.
# P5 every reference to <N>.content of a Claude module, in any other module (mapper, filter, parameters, error routes),
#    is exactly first(map(<N>.content; "text"; "type"; "text")). Thinking blocks come first on Opus, so an index or a
#    bare content reads the wrong block. A reference to an OpenAI-only output (choices, usage.prompt_tokens ...) also
#    FAILs here, because check E1 skips a module with no metadata.interface and the new Claude modules have none.
# P6 a client send (email, SMS or WhatsApp, HeyGen video, Bland call) that maps a Claude text reference runs behind a
#    filter, on itself or an earlier module of its flow after the Claude module, of exactly one OR group that requires
#    {{<N>.stop_reason}} text equal end_turn. A refusal or a max_tokens stop leaves no text, so the client would get an
#    empty or cut message.
# Fix IDs X-15 and X-18 close check P (make_push FIX_CHECKS).

AI_CHECK = "P"
CLAUDE_MODULE = "anthropic-claude:createAMessage"
CLAUDE_MODULE_VERSION = 1
CLAUDE_OPUS = "claude-opus-5-5"
CLAUDE_HAIKU = "claude-haiku-5-5"
# The one allowed set (decided 2026-10-30). Changing a model is a new decision and a new fix ID.
CLAUDE_MODELS = (CLAUDE_OPUS, CLAUDE_HAIKU)
CLAUDE_MIN_MAX_TOKENS = {CLAUDE_OPUS: 16000, CLAUDE_HAIKU: 2048}
CLAUDE_SAMPLING_KEYS = ("temperature", "top_p", "top_k")
CLAUDE_THINKING_TYPES = ("adaptive", "enabled", "disabled")
# Make apps that call a language model. Only CLAUDE_MODULE is allowed.
LLM_APP = re.compile(r"openai|anthropic|claude|gemini|mistral|perplexity|deepseek|groq|cohere|openrouter|replicate|hugging"
                     r"|vertex|bedrock|\bxai\b|together|fireworks", re.I)
# Matched as substrings of the lowered URL, so a host suffix (openai.azure.com) or prefix (bedrock-runtime.) covers
# every resource and region name.
LLM_API_HOSTS = ("api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.mistral.ai",
                 "api.perplexity.ai", "api.deepseek.com", "api.groq.com", "api.cohere.ai", "api.cohere.com",
                 "openai.azure.com", "openrouter.ai", "api.x.ai", "api.together.xyz", "api.fireworks.ai",
                 "bedrock-runtime.", "aiplatform.googleapis.com")
# A URL whose host is written out: scheme, then a host with no mapping, then a path or the end.
_LITERAL_HOST_URL = re.compile(r"^\s*https?://[^/{}\s]+(?:[/?#]|\s*$)", re.I)
# Every output a Claude message has (anthropic-claude createAMessage v1 interface, read 2026-10-30), top level and
# under usage. A read of any other field maps blank in Make, and check E1 skips a module built offline (no interface).
CLAUDE_OUTPUTS = frozenset(("files", "id", "type", "role", "content", "model", "container", "stop_reason", "stop_sequence",
                            "stop_details", "diagnostics", "usage", "tools"))
CLAUDE_USAGE = frozenset(("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens",
                          "output_tokens_details", "cache_creation", "service_tier", "server_tool_use", "inference_geo"))
CLAUDE_STOP_OK = "end_turn"
# Client sends reached through an HTTP module: these hosts send a message, a call or a video to a person.
CLIENT_SEND_HOSTS = ("api.bland.ai", "api.twilio.com", "api.resend.com", "api.sendgrid.com", "graph.facebook.com",
                     "api.heygen.com")
# Apps whose Make an API Call module reaches a client-send API.
CLIENT_SEND_APPS = ("bland", "twilio", "heygen", "resend", "sendgrid", "whatsapp", "telegram", "facebook-messenger",
                    "google-email", "microsoft-email", "gmail", "outlook")
# Report text has no semicolons (CLAUDE.md prose rule, tested), so rows name the IML form in words.
# The form itself: first(map(<N>.content; "text"; "type"; "text")).


def _text_form_words(n: object) -> str:
    return f"first of map over {n}.content with key text, filtered to type text (the IML is in CLAUDE.md check P)"


def is_claude_call(m: dict) -> bool:
    return _mtype(m) == CLAUDE_MODULE


def _claude_text_form(n: object) -> re.Pattern:
    """The one accepted read of a Claude module's text: first(map(<n>.content; "text"; "type"; "text"))."""
    return re.compile(r"first\(\s*map\(\s*" + str(n) + r"\.`?content`?\s*;\s*\"text\"\s*;\s*\"type\"\s*;\s*\"text\"\s*\)\s*\)")


def _set(v: object) -> bool:
    """A mapper value that is set: not missing, None or blank."""
    return nonempty(v)


def _additional_entries(mp: dict) -> list[tuple[str, bool]]:
    """(key stripped and lowered, key is a mapping) for every additionalParameters entry with a non-blank key."""
    out = []
    for p in mp.get("additionalParameters") or []:
        if isinstance(p, dict) and isinstance(p.get("key"), str) and p["key"].strip():
            out.append((p["key"].strip().lower(), is_mapping(p["key"])))
    return out


def _additional_keys(mp: dict) -> list[str]:
    """Literal additionalParameters keys, stripped and lowered (Make sends the key as written, the API matches it)."""
    return [k for k, mapped in _additional_entries(mp) if not mapped]


def _p_llm_problem(m: dict, logger: "LoggerSpec | None" = None) -> str | None:
    """P1 for one module: an LLM call that is not anthropic-claude:createAMessage v1."""
    t = _mtype(m)
    app = t.split(":", 1)[0]
    if t == CLAUDE_MODULE:
        if m.get("version") != CLAUDE_MODULE_VERSION:
            return (f"P1 {CLAUDE_MODULE} version {m.get('version')!r}. Use version {CLAUDE_MODULE_VERSION}, the module "
                    f"definition this check reads")
        return None
    if LLM_APP.search(app):
        return (f"P1 {t} is a language-model call outside {CLAUDE_MODULE}. X-15 and X-18 settle every LLM call on Anthropic "
                f"through {CLAUDE_MODULE} v1 with model {' or '.join(CLAUDE_MODELS)}")
    low = t.lower()
    if low.startswith("http:") or "apicall" in low:
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        for s in list(_strings(_mapper(m))) + list(_strings(params)):
            host = next((h for h in LLM_API_HOSTS if h in s.lower()), None)
            if host:
                return (f"P1 calls {host} through {t}. Every LLM call goes through {CLAUDE_MODULE} v1 so the model, "
                        f"sampling and token limits are pinned in the blueprint")
    if low.startswith("http:"):
        url = _mapper(m).get("url")
        if is_mapping(url) and not _LITERAL_HOST_URL.match(url) and not is_logger_call(m, logger):
            return (f"P1 {t} takes its host from a mapping, so the audit cannot rule out an LLM API behind it. Write the "
                    f"host as a literal (only the registered Logger call may map its URL)")
    return None


def _p_claude_problems(m: dict) -> list[str]:
    """P2 to P4 for one anthropic-claude:createAMessage module."""
    mp = _mapper(m)
    out: list[str] = []
    entries = _additional_entries(mp)
    extra = _additional_keys(mp)
    if any(mapped for _k, mapped in entries):
        out.append("P3 additionalParameters key is a mapping. Use a literal key, so the audit sees what the call sends")
    model = mp.get("model")
    if is_mapping(model):
        out.append(f"P2 model is a mapping. It must be a literal, one of {', '.join(CLAUDE_MODELS)}")
        model = None
    elif not (isinstance(model, str) and model in CLAUDE_MODELS):
        out.append(f"P2 model is {model!r}. It must be exactly one of {', '.join(CLAUDE_MODELS)} (no alias without the "
                   f"version, no other model)")
        model = None
    if "model" in extra:
        out.append("P2 additionalParameters sets model, which overrides the pinned one")
    for k in CLAUDE_SAMPLING_KEYS:
        if _set(mp.get(k)):
            out.append(f"P3 sets {k}. Leave temperature, top_p and top_k unset (the model default)")
        if k in extra:
            out.append(f"P3 additionalParameters sets {k}. Leave temperature, top_p and top_k unset")
    for k in ("thinking", "budget_tokens"):
        if k in extra:
            out.append(f"P3 additionalParameters sets {k}. Set thinking in its own field (adaptive)")
    th = mp.get("thinking")
    if _set(th):
        if not isinstance(th, dict):
            out.append("P3 thinking is not a literal setting. Use type adaptive")
        else:
            ty = th.get("type")
            if is_mapping(ty):
                out.append("P3 thinking type is a mapping. Use the literal adaptive")
            elif _set(ty) and ty not in CLAUDE_THINKING_TYPES:
                out.append(f"P3 thinking type {ty!r} is not one of {', '.join(CLAUDE_THINKING_TYPES)}")
            elif ty == "enabled":
                out.append("P3 thinking type is enabled (a fixed budget). Use adaptive")
            elif ty == "disabled" and model == CLAUDE_OPUS:
                out.append(f"P3 thinking is disabled on {CLAUDE_OPUS}. Use adaptive")
            elif not _set(ty) and model == CLAUDE_OPUS:
                out.append(f"P3 thinking on {CLAUDE_OPUS} has no type. Use type adaptive")
            if _set(th.get("budget_tokens")):
                out.append("P3 thinking carries budget_tokens. Use type adaptive with no budget")
    elif model == CLAUDE_OPUS:
        out.append(f"P3 thinking is not set on {CLAUDE_OPUS}, so the call runs on the API default. Set type adaptive")
    mt = mp.get("max_tokens")
    n = None
    if isinstance(mt, int) and not isinstance(mt, bool):
        n = mt
    elif isinstance(mt, str) and re.fullmatch(r"\d+", mt):
        n = int(mt)
    if n is None:
        out.append(f"P4 max_tokens is {mt!r}. It must be a literal integer")
    elif model is not None and n < CLAUDE_MIN_MAX_TOKENS[model]:
        out.append(f"P4 max_tokens {n} is below {CLAUDE_MIN_MAX_TOKENS[model]} for {model}, so thinking can use the whole "
                   f"budget and leave no text")
    if "max_tokens" in extra:
        out.append("P4 additionalParameters sets max_tokens, which overrides the pinned one")
    fmt = mp.get("outputFormat")
    if isinstance(fmt, dict) and str(fmt.get("type", "")).strip() == "json_schema":
        why = _p7_schema_problem(fmt.get("schema"))
        if why is None and not _p7_expect_types_schema(m):
            why = ("is not typed as json in the module's metadata.expect (a module built through the API). Make then sends the "
                   "text unparsed and Anthropic answers 400 output_format.schema: Input should be an object (measured 2026-11-14 "
                   "on Market Watchdog 79). Re-save the module in the Make UI, which adds that metadata")
        if why:
            out.append(f"P7 outputFormat schema {why}. Make's Schema field is type json and takes JSON text: an object is "
                       f"refused before the call (measured 2026-11-14, VIP intake 81). Store the schema as JSON text of an object")
    return out


def _p7_expect_types_schema(m: dict) -> bool:
    """The module's metadata.expect types outputFormat.schema as Make type json. A save in the Make UI writes it, a module
    built through the API has none (measured 2026-11-14 on VIP intake 81 and Market Watchdog 79)."""
    for e in ((m.get("metadata") or {}).get("expect") or []) if isinstance(m.get("metadata"), dict) else []:
        if isinstance(e, dict) and e.get("name") == "outputFormat" and isinstance(e.get("spec"), list):
            if any(isinstance(x, dict) and x.get("name") == "schema" and x.get("type") == "json" for x in e["spec"]):
                return True
    return False


def _p7_schema_problem(schema: object) -> str | None:
    """Why a json_schema outputFormat's schema is not JSON text of an object with no mapping, or None."""
    if not isinstance(schema, str):
        return f"is a {type(schema).__name__}, not JSON text"
    if "{{" in schema:
        return "holds a mapping, so it is not a fixed schema"
    def _reject(_c: str) -> None:
        raise ValueError("NaN or Infinity")   # Python accepts them, Make's JSON parser does not
    try:
        obj = json.loads(schema, parse_constant=_reject)
    except ValueError:
        return "is not valid JSON"
    if not isinstance(obj, dict):
        return "is JSON text of a " + type(obj).__name__ + ", not of an object"
    return None


def _p_reference_problems(m: dict, claude_ids: set, handler_of: dict | None = None) -> list[str]:
    """P5 for one module: every read of a Claude module's output in its mapper, filter and parameters. Only fields a
    Claude message has are allowed, the text only in the one accepted form. error.* is allowed in the Claude module's
    own error route, where Make fills it."""
    out: list[str] = []
    seen: set[str] = set()
    handler_of = handler_of or {}

    def add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            out.append(msg)

    for path, expr in _module_exprs(m):
        for n in sorted(claude_ids):
            if n == m.get("id"):
                continue
            # Blank the accepted reads (same length, so the rest keeps its positions), then look at what is left.
            rest = _blank_strings(_claude_text_form(n).sub(lambda h: " " * len(h.group(0)), expr))
            for r in iml_refs(rest):
                if r.module != n:
                    continue
                if r.field == "content":
                    add(f"P5 {_short_path(path)} reads {n}.content outside the one accepted form, {_text_form_words(n)}. "
                        f"Thinking blocks come first on Opus, so an index or a bare content reads the wrong block")
                elif r.field == "error" and m.get("id") in handler_of.get(n, ()):
                    continue
                elif r.field not in CLAUDE_OUTPUTS:
                    add(f"P5 {_short_path(path)} reads {n}.{r.field}, which a Claude message does not have, so it maps "
                        f"blank. Read the text as {_text_form_words(n)}")
            for h in re.finditer(r"(?<![\w.`$@])" + str(n) + r"\.`?usage`?\.`?([A-Za-z_]\w*)", rest):
                if h.group(1) not in CLAUDE_USAGE:
                    add(f"P5 {_short_path(path)} reads {n}.usage.{h.group(1)}, which a Claude message does not have. "
                        f"Use usage.input_tokens and usage.output_tokens")
            if re.search(r"\bget\(\s*" + str(n) + r"\s*(?:\.\s*`?usage`?\s*)?[;)]", rest):
                add(f"P5 {_short_path(path)} reads module {n} through get( with a quoted key, which the audit cannot "
                    f"check. Read the text as {_text_form_words(n)} and tokens as {n}.usage.input_tokens")
    return out


def _p_email_send(m: dict) -> bool:
    low = _mtype(m).lower()
    return any(w in low for w in ("email", "gmail", "outlook")) and any(w in low for w in ("send", "reply", "forward"))


def _p_client_send(m: dict) -> bool:
    """A module that sends something to a person: email (send, reply, forward), SMS, WhatsApp, Telegram or Messenger,
    a HeyGen video, a Bland call, or an HTTP or API-call module that reaches one of those APIs."""
    t = _mtype(m)
    low = t.lower()
    app = low.split(":", 1)[0]
    if _p_email_send(m):
        return True
    if any(w in low for w in ("sms", "whatsapp", "twilio", "telegram", "messenger")):
        return True
    if app in ("bland", "heygen") and _is_effect(m):
        return True
    if "apicall" in low and any(app == a or app.startswith(a + "-") for a in CLIENT_SEND_APPS):
        return True
    if low.startswith("http:") or "apicall" in low:
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        for s in list(_strings(_mapper(m))) + list(_strings(params)):
            if any(h in s.lower() for h in CLIENT_SEND_HOSTS):
                return True
    return False


def _p_data_refs(m: dict) -> list[Ref]:
    """Module references in what a module passes on (mapper and parameters, not the filter)."""
    out: list[Ref] = []
    for path, expr in _module_exprs(m):
        if path.startswith("mapper") or path.startswith("parameters"):
            out += iml_refs(_blank_strings(expr))
    return out


def _p_taint(mods: list, claude_ids: set) -> dict:
    """module ID -> the Claude modules whose text reaches it: it maps <N>.content, or any field of a module the text of
    N already reached (a Set Variable, a parser, an aggregator, an Airtable row, a Google Doc). walk() yields every
    module after the modules it can read, so one pass is enough."""
    taint: dict = {}
    for m, _err, _chain in mods:
        mid = m.get("id")
        if mid in claude_ids:
            continue
        hit = set()
        for r in _p_data_refs(m):
            if r.module in claude_ids and r.field == "content":
                hit.add(r.module)
            hit |= taint.get(r.module, set())
        if hit:
            taint[mid] = hit
    return taint


def _stop_filter(m: dict, n: object) -> bool:
    """The module's inbound filter is exactly one OR group holding {{<n>.stop_reason}} text equal end_turn. Other
    conditions may sit in the same group, since they only narrow it."""
    groups = _norm_groups(m)
    if len(groups) != 1:
        return False
    for c in groups[0]:
        e = _single_expression(c.get("a"))
        refs = iml_refs(e) if e else []
        if not (e and len(refs) == 1 and refs[0].module == n and refs[0].field == "stop_reason" and refs[0].text == e.strip()):
            continue
        op, b = str(c.get("o", "")), c.get("b")
        if op in ("text:equal", "text:equal:ci") and isinstance(b, str) and not is_mapping(b) \
                and _stripe_literal_matches(b, CLAUDE_STOP_OK, op):
            return True
    return False


def _stop_gated(chain: tuple, claude_chain: tuple, n: object) -> bool:
    """A module on the path to chain (the module itself included) that runs after the Claude module carries the
    stop_reason filter."""
    for k, (fl, i) in enumerate(chain):
        for j in range(i + 1):
            x = fl[j]
            here = chain[:k] + ((fl, j),)
            if isinstance(x, dict) and _runs_after(claude_chain, here) and _stop_filter(x, n):
                return True
    return False


def check_p(b: Blueprint, logger: "LoggerSpec | None" = None) -> list[Finding]:
    out: list[Finding] = []
    scen = _scenario_label(b)
    flow = b.bp.get("flow") or []
    mods = list(walk(flow))
    claude = {m.get("id"): chain for m, _e, chain in mods if is_claude_call(m) and isinstance(m.get("id"), int)}
    handler_of = {m.get("id"): {x.get("id") for x, _e, _c in walk(_onerror(m))}
                  for m, _e, _c in mods if m.get("id") in claude}
    taint = _p_taint(mods, set(claude))
    for m, _err, chain in mods:
        t = _mtype(m)
        mid = m.get("id")
        probs: list[str] = []
        why1 = _p_llm_problem(m, logger)
        if why1:
            probs.append(why1)
        if is_claude_call(m):
            probs += _p_claude_problems(m)
        probs += _p_reference_problems(m, set(claude), handler_of)
        if _p_client_send(m):
            for n in sorted(taint.get(mid, set())):
                if not _stop_gated(chain, claude[n], n):
                    probs.append(f"P6 this client send carries the text of Claude module {n} (directly or through an "
                                 f"earlier module that maps it) with no filter that requires "
                                 f"{{{{{n}.stop_reason}}}} text equal {CLAUDE_STOP_OK} (one OR group, on this module or an "
                                 f"earlier one after module {n}). A refusal or a max_tokens stop leaves no text, so the client "
                                 f"gets an empty or cut message")
        if probs:
            out.append(Finding(AI_CHECK, FAIL, scen, mid, t, ". ".join(p.replace(";", ",") for p in probs)))
        elif is_claude_call(m):
            mp = _mapper(m)
            out.append(Finding(AI_CHECK, PASS, scen, mid, t, f"Claude call pinned: {mp.get('model')}, max_tokens "
                                                            f"{mp.get('max_tokens')}, no sampling overrides"))
    return out


# ---------------------------------------------------------------------------
# Checks E (mapping integrity) and F (webhook authentication)
# ---------------------------------------------------------------------------

RECORD_ID = re.compile(r"^rec[A-Za-z0-9]{14}$")
# Count outputs of a search module. A search that finds nothing emits no bundle,
# so a filter that waits for these to equal 0 never runs.
COUNT_FIELDS = ("__IMTLENGTH__", "Total_Number_of_Bundles")
# Bare words that are valid IML on their own. System values such as the execution
# ID live under var (var.scenario.executionId), so they are not bare words.
# erase: Make's General functions keyword that clears a field in an update (apps.make.com Airtable modules, help.make.com
# General functions, read 2026-11-16). Added for the F-F10 lock (E34).
IML_BARE_OK = set(secret_scan._IML_KEYWORDS) | {"newline", "carriagereturn", "erase"}
IML_NAMESPACES = {"var", "error", "item"}

_REF_RX = re.compile(
    r"`[^`]*`"  # a stand-alone backtick span is consumed so it cannot hide a reference
    r"|(?<![\w.`$@])(?P<mod>\d+)\.(?P<field>`[^`]*`|[A-Za-z_][\w$@]*(?:-[A-Za-z][\w$@]*)*)"
)


@dataclass(frozen=True)
class Ref:
    module: int
    field: str  # top-level field name, backticks removed
    text: str   # as written, for example 5.`Client Name`


@dataclass
class AirtableMap:
    """Table and field facts from audit/airtable_links.json."""
    tables: dict = field(default_factory=dict)
    pii_fields: dict = field(default_factory=dict)
    # Module type -> output fields that carry client PII from outside Airtable
    # (an inbound email, a webhook body, a Drive link to a client document).
    source_pii: dict = field(default_factory=dict)
    # Table ID -> field names that hold numbers, the only fields a formula may
    # compare with an unquoted {{...}} value.
    numeric_fields: dict = field(default_factory=dict)

    def table_name(self, tid: str | None) -> str:
        t = self.tables.get(tid) if tid else None
        return f"{t['name']} ({tid})" if t else str(tid)

    def _field_id(self, tid: str | None, key: object) -> str | None:
        fields = (self.tables.get(tid) or {}).get("fields") or {}
        if key in fields:
            return str(key)
        for fid, name in fields.items():
            if name == key:
                return fid
        return None

    def has_field(self, tid: str | None, key: object) -> bool:
        return self._field_id(tid, key) is not None

    def link_target(self, tid: str | None, key: object) -> str | None:
        fid = self._field_id(tid, key)
        links = (self.tables.get(tid) or {}).get("links") or {}
        return (links.get(fid) or {}).get("target") if fid else None

    def field_label(self, tid: str | None, key: object) -> str:
        fid = self._field_id(tid, key)
        return ((self.tables.get(tid) or {}).get("fields") or {}).get(fid, str(key)) if fid else str(key)

    def is_pii(self, tid: str | None, key: object) -> bool:
        fid = self._field_id(tid, key)
        return bool(fid) and self.field_label(tid, fid) in (self.pii_fields.get(tid) or [])


def load_links(path: str, required: bool = False) -> AirtableMap:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no Airtable map at {path}")
        return AirtableMap()
    data = _read_json(path)
    name = os.path.basename(path)
    if not isinstance(data, dict) or not isinstance(data.get("tables"), dict):
        raise InputError(f"{name} has no tables map")
    for tid, t in data["tables"].items():
        if not isinstance(t, dict):
            raise InputError(f"{name} table {tid} is not an object")
        if not isinstance(t.get("name"), str) or not t["name"]:
            raise InputError(f"{name} table {tid} needs a name string")
        if not isinstance(t.get("fields"), dict):
            raise InputError(f"{name} table {tid} needs a fields object (field ID -> field name)")
        links = t.get("links", {})
        if not isinstance(links, dict):
            raise InputError(f"{name} table {tid} links must be an object")
        for fid, ln in links.items():
            if not isinstance(ln, dict) or not isinstance(ln.get("target"), str):
                raise InputError(f"{name} table {tid} link {fid} needs an object with a target table ID")

    def name_lists(key: str) -> dict:
        raw = data.get(key, {})
        if not isinstance(raw, dict) or any(not isinstance(v, list) or any(not isinstance(x, str) for x in v)
                                            for v in raw.values()):
            raise InputError(f"{name} {key} must map a key to a list of field names")
        return raw

    ledger = data["tables"].get(LEDGER_TABLE)
    if isinstance(ledger, dict):
        why = _stamp_map_problem(ledger)
        if why:
            raise InputError(f"{name} System Logs ({LEDGER_TABLE}) {why}")
    return AirtableMap(tables=data["tables"], pii_fields=name_lists("pii_fields"),
                       source_pii=name_lists("non_airtable_pii"), numeric_fields=name_lists("numeric_fields"))


# Rules an allowlist entry may name. Per-reference rules must also pin the text
# they excuse (match), so one entry cannot hide a field added to the module later.
ALLOW_RULES = ("E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8")
ALLOW_NEEDS_MATCH = ("E1", "E2", "E3", "E6", "E8")


@dataclass
class Allowlist:
    """Intended exceptions to checks E and F (audit/allowlist.json). Every entry
    names the rule, scenario ID, module ID and a reason. An E4 entry also pins
    the record ID, so changing the literal re-opens the finding. E1, E2, E3, E6
    and E8 entries pin a text (match) that the finding detail must contain."""
    entries: list = field(default_factory=list)
    used: set = field(default_factory=set)

    def reason(self, rule: str, scenario_id: str | None, module_id: object, record_id: str | None = None,
               detail: str | None = None) -> str | None:
        for i, e in enumerate(self.entries):
            if e["check"] != rule or scenario_id is None or e["scenario"] != str(scenario_id):
                continue
            if e["module"] != str(module_id):
                continue
            if e.get("record_id") and e["record_id"] != record_id:
                continue
            if e.get("match") and e["match"] not in (detail or ""):
                continue
            self.used.add(i)
            return e["reason"]
        return None

    def unused(self, scenario_ids: set[str] | None = None) -> list[dict]:
        """Entries that excused nothing in this run, limited to the audited scenarios."""
        return [e for i, e in enumerate(self.entries) if i not in self.used
                and (scenario_ids is None or e["scenario"] in scenario_ids)]


def load_allowlist(path: str) -> Allowlist:
    if not os.path.exists(path):
        return Allowlist()
    data = _read_json(path)
    name = os.path.basename(path)
    raw = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise InputError(f"{name} has no entries list")
    entries = []
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            raise InputError(f"{name} entry {i} is not an object")
        reason = e.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 8 or not re.search(r"[A-Za-z]{3}", reason):
            raise InputError(f"{name} entry {i} needs a real reason (a sentence). Every allowlist entry needs one")
        check = str(e.get("check", ""))
        if check not in ALLOW_RULES:
            raise InputError(f"{name} entry {i} names check {check!r}, which is not a rule that can be allowlisted "
                             f"({', '.join(ALLOW_RULES)})")
        if e.get("scenario") is None or e.get("module") is None:
            raise InputError(f"{name} entry {i} needs scenario and module")
        rid = e.get("record_id")
        if check == "E4" and not (isinstance(rid, str) and RECORD_ID.match(rid.strip())):
            raise InputError(f"{name} entry {i} is an E4 entry without a record_id. E4 entries pin the record ID "
                             f"(rec plus 14 characters), or they would excuse every literal on the module")
        if check != "E4" and rid:
            raise InputError(f"{name} entry {i} has a record_id, which only E4 entries use")
        match = e.get("match")
        if check in ALLOW_NEEDS_MATCH and not (isinstance(match, str) and match.strip()):
            raise InputError(f"{name} entry {i} ({check}) needs a match text from the finding, for example the "
                             f"reference as written, so the entry cannot hide a later finding on the module")
        if match is not None and not isinstance(match, str):
            raise InputError(f"{name} entry {i} match must be a string")
        entries.append({**e, "check": check, "scenario": str(e["scenario"]), "module": str(e["module"]),
                        "reason": reason.strip()})
    return Allowlist(entries)


def _blank_strings(expr: str) -> str:
    """expr with the content of "quoted" literals replaced by spaces."""
    out, i, n = [], 0, len(expr)
    while i < n:
        c = expr[i]
        if c == '"':
            j = i + 1
            while j < n:
                if expr[j] == '"':
                    if j + 1 < n and expr[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            out.append('"' + " " * max(0, j - i - 1) + '"')
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def iml_refs(expr: str) -> list[Ref]:
    """Module references (N.field) in one IML expression body, outside strings."""
    refs = []
    for m in _REF_RX.finditer(_blank_strings(expr)):
        if m.group("mod") is None:
            continue
        raw = m.group("field")
        name = raw[1:-1] if raw.startswith("`") else raw
        refs.append(Ref(int(m.group("mod")), name, f"{m.group('mod')}.{raw}"))
    return refs


def _string_paths(v: object, path: str):
    if isinstance(v, str):
        yield path, v
    elif isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            yield from _string_paths(x, f"{path}[{i}]")
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _string_paths(x, f"{path}.{k}")


def _value_exprs(v: object):
    """Every {{...}} expression body in a value."""
    for s in _strings(v):
        if "{{" in s:
            yield from secret_scan._iml_segments(s)[0]


def _module_exprs(m: dict):
    """(path, expression body) for every {{...}} a module maps (mapper, filter, parameters)."""
    for part in ("mapper", "filter", "parameters"):
        if part in m:
            for path, s in _string_paths(m[part], part):
                if "{{" in s:
                    for e in secret_scan._iml_segments(s)[0]:
                        yield path, e


def _module_table(m: dict) -> str | None:
    """Airtable table ID a module reads or writes (mapper, or parameters for triggers)."""
    if not _mtype(m).startswith("airtable:"):
        return None
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    for src in (_mapper(m), params):
        t = src.get("table")
        if isinstance(t, str) and t.startswith("tbl") and not is_mapping(t):
            return t
    return None


def _interface_fields(m: dict) -> tuple[set[str], dict[str, str]] | None:
    """(output field names, label -> name) from metadata.interface, or None.
    Make resolves a reference by the field name only. A label is for the hint."""
    md = m.get("metadata") if isinstance(m.get("metadata"), dict) else {}
    iface = md.get("interface")
    if not isinstance(iface, list):
        return None
    names: set[str] = set()
    labels: dict[str, str] = {}
    real = False
    for it in iface:
        if isinstance(it, dict):
            nm = it.get("name")
            real = real or (isinstance(nm, str) and not _is_builtin_field(nm))
            if isinstance(nm, str):
                names.add(nm)
                if isinstance(it.get("label"), str):
                    labels.setdefault(it["label"], nm)
    # A webhook with no data structure lists only the __IMT* builtins (headers).
    # Its payload fields are unknown, so there is nothing to check against.
    return (names, labels) if real else None


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _similar(field_name: str, names: set[str]) -> list[str]:
    n = _norm(field_name)
    if not n:
        return []
    exact = sorted(x for x in names if _norm(x) == n)
    if exact:
        return exact
    return sorted(x for x in names if _norm(x) and (n in _norm(x) or _norm(x) in n))[:3]


def _is_builtin_field(name: str) -> bool:
    return name.startswith("__IMT") or name == "error"


def _short_path(path: str) -> str:
    return path if len(path) <= 48 else "..." + path[-45:]


class _EContext:
    """Per-scenario index shared by the E rules."""

    def __init__(self, b: Blueprint, links: AirtableMap, allow: Allowlist, logger: "LoggerSpec | None" = None,
                 webhooks: "Webhooks | None" = None, bland_agents: "BlandAgents | None" = None,
                 ff10: "FF10Pin | None" = None, x32: "X32Pin | None" = None, x16: "X16Pin | None" = None,
                 active: bool | None = None):
        self.b, self.links, self.allow, self.logger = b, links, allow, logger
        self.active = active  # the scenario's is_active in the pull's manifest (None: unknown), for E40
        self.x16 = x16 if x16 is not None else X16Pin()  # audit/x16.json, for E38 to E40 and the E32 production folder
        self.ff10 = ff10 if ff10 is not None else FF10Pin()  # audit/ff10.json, for E30 and E31
        self.x32 = x32 if x32 is not None else X32Pin()  # audit/x32.json, for E35 to E37
        self.webhooks = webhooks  # audit/webhooks.json, for E25 (None: unknown, the rule says nothing)
        self.bland_agents = bland_agents if bland_agents is not None else BlandAgents()  # audit/bland_agents.json, for E28
        self.scen = _scenario_label(b)
        self.modules: dict[int, tuple] = {}
        self.order: list[tuple] = []
        for m, in_err, chain in walk(b.bp.get("flow") or []):
            self.order.append((m, in_err, chain))
            if isinstance(m.get("id"), int):
                self.modules.setdefault(m["id"], (m, in_err, chain))
        self.findings: list[Finding] = []

    def emit(self, rule: str, status: str, m: dict, detail: str, record_id: str | None = None, strict: bool = False) -> None:
        """strict: the row cannot be allowlisted even under a rule that otherwise can be (E6 rows F-F10 added)."""
        why = (self.allow.reason(rule, self.b.scenario_id, m.get("id"), record_id, detail)
               if status in (FAIL, REVIEW) and not strict else None)
        if why:
            self.findings.append(Finding(rule[0], INFO, self.scen, m.get("id"), _mtype(m),
                                         f"{rule} allowlisted: {why}. Was: {detail}", rule, True))
        else:
            self.findings.append(Finding(rule[0], status, self.scen, m.get("id"), _mtype(m), f"{rule} {detail}", rule))

    def aggregator_for(self, source: int, chain: tuple) -> int | None:
        """ID of an aggregator upstream of the module at chain whose feeder (source
        module) is `source`, or None."""
        for mid, (mod, _err, achain) in self.modules.items():
            params = mod.get("parameters") if isinstance(mod.get("parameters"), dict) else {}
            if params.get("feeder") != source or mid == source:
                continue
            aflow, aidx = achain[-1]
            if any(f is aflow and aidx < i for f, i in chain):
                return mid
        return None

    def table_of(self, n: int) -> str | None:
        hit = self.modules.get(n)
        return _module_table(hit[0]) if hit else None

    def produced_table(self, ref: Ref) -> tuple[str | None, str]:
        """(table of the record the reference yields, description). Table is ""
        when the source is not an Airtable record at all, None when unknown. Only
        a record ID and a link field of an Airtable module yield a record."""
        hit = self.modules.get(ref.module)
        if hit is None:
            return None, ""
        mod = hit[0]
        if ref.field == "id":
            if not _mtype(mod).startswith("airtable:"):
                return "", f"the id of module {ref.module} ({_mtype(mod)}), which is not an Airtable record"
            t = _module_table(mod)
            return (t, f"the id of a {self.links.table_name(t)} record (module {ref.module})") if t else (None, "")
        t = _module_table(mod)
        tgt = self.links.link_target(t, ref.field) if t else None
        if tgt:
            return tgt, f"link field {ref.field} of module {ref.module}, a {self.links.table_name(tgt)} record ID"
        return None, ""


# --- E1 / E2 ---------------------------------------------------------------


def _bare_token(expr: str) -> str | None:
    """The expression body if it is one bare word with no module prefix."""
    e = expr.strip()
    if not e or e.startswith('"') or re.match(r"^\d", e) or re.fullmatch(r"-?\d+(?:\.\d+)?", e):
        return None
    if re.fullmatch(r"`\d+`", e):
        return None  # the module-name token the Make UI inserts
    if re.search(r'[()";,+*/%<>=!&|]', e):
        return None
    head = re.split(r"[.\[ ]", e.strip("`"), maxsplit=1)[0].lower()
    if head in IML_NAMESPACES or e.lower() in IML_BARE_OK:
        return None
    return e if re.search(r"[A-Za-z]", e) else None


# One token of an IML expression: a backtick span, a number or module reference
# with its path, or a word with an optional path.
_E2_TOKEN = re.compile(
    r"`[^`]*`"
    r"|\d+(?:\.(?:`[^`]*`|[\w$@]+(?:-[A-Za-z][\w$@]*)*)|\[[^\]]*\])*"
    r"|[A-Za-z_]\w*(?:\.(?:`[^`]*`|[\w$@-]+)|\[[^\]]*\])*"
)


def _bare_words_in_expression(expr: str) -> list[str]:
    """Words inside a compound expression (a call, an operator) that have no
    module prefix: not a function name, a keyword or a var/error/item reference."""
    blanked = _blank_strings(expr)
    out: list[str] = []
    for m in _E2_TOKEN.finditer(blanked):
        tok = m.group(0)
        if not re.match(r"[A-Za-z_]", tok):
            continue
        head = re.match(r"[A-Za-z_]\w*", tok).group(0)
        if blanked[m.end():].lstrip().startswith("("):
            continue  # a function call
        low = head.lower()
        if low in IML_NAMESPACES or (low in IML_BARE_OK and tok == head):
            continue
        if head not in out:
            out.append(head)
    return out


def _rule_e1_e2(ctx: _EContext) -> None:
    skipped: dict[int, int] = {}
    for m, _err, chain in ctx.order:
        seen: set[tuple] = set()
        seen_bare: set[str] = set()
        for path, expr in _module_exprs(m):
            bare = _bare_token(expr)
            if bare is not None and bare not in seen_bare:
                seen_bare.add(bare)
                ctx.emit("E2", FAIL, m, f"Bare reference {{{{{bare}}}}} in {_short_path(path)} has no module prefix, so it resolves to nothing")
            elif bare is None:
                for word in _bare_words_in_expression(expr):
                    if word not in seen_bare:
                        seen_bare.add(word)
                        ctx.emit("E2", FAIL, m, f"Bare word `{word}` inside an expression in {_short_path(path)} has no module prefix, "
                                                f"so it resolves to nothing. Write it as N.{word} with the module number")
            for r in iml_refs(expr):
                key = (r.module, r.field, path.split(".", 1)[0])  # one row per part: mapper, filter, parameters
                if key in seen:
                    continue
                seen.add(key)
                hit = ctx.modules.get(r.module)
                if hit is None:
                    ctx.emit("E1", FAIL, m, f"{{{{{r.text}}}}} in {_short_path(path)} points at module {r.module}, which is not in this scenario")
                    continue
                target = hit[0]
                iface = _interface_fields(target)
                if iface is None and _mtype(target) in BLAND_CALLS:
                    iface = (set(BLAND_CALL_OUTPUTS), {})  # no interface on a Bland call, the pinned outputs stand in
                if iface is None:
                    skipped[r.module] = skipped.get(r.module, 0) + 1
                    continue
                names, labels = iface
                if _is_builtin_field(r.field) or r.field in names:
                    continue
                hint = _similar(r.field, names | set(labels))
                extra = f" Closest outputs: {', '.join(hint)}." if hint else ""
                if r.field in labels:
                    extra += f" `{r.field}` is the display label. Make resolves the field name `{labels[r.field]}`."
                t = _module_table(target)
                if t and ctx.links.has_field(t, r.field):
                    extra += f" The {ctx.links.table_name(t)} table does have this field, so the module interface may be stale."
                agg = ctx.aggregator_for(r.module, chain)
                if agg is not None:
                    extra += (f" Module {r.module} is the source of aggregator {agg} upstream of this module, so none of its outputs "
                              f"may be readable here (inferred from how the Make mapping panel behaves, not measured). "
                              f"Map the value from aggregator {agg}, or add a second aggregator for it.")
                ctx.emit("E1", FAIL, m, f"{{{{{r.text}}}}} in {_short_path(path)}: module {r.module} ({_mtype(target)}) does not output `{r.field}`.{extra}")
    for n, count in sorted(skipped.items()):
        tm = ctx.modules[n][0]
        ctx.findings.append(Finding("E", INFO, ctx.scen, n, _mtype(tm),
                                    f"E1 skipped {count} reference(s) to module {n}: no metadata.interface to check against", "E1"))


# --- E3 / E4 ---------------------------------------------------------------


def _check_record_source(ctx: _EContext, value: object, expect: str | None, m: dict, what: str) -> None:
    """Flag references in value that yield a record ID of a table other than expect."""
    seen: set[str] = set()
    for expr in _value_exprs(value):
        for r in iml_refs(expr):
            table, desc = ctx.produced_table(r)
            if table is None or r.text in seen:
                continue
            if table == "" or (expect and table != expect):
                seen.add(r.text)
                ctx.emit("E3", FAIL, m, f"{what} is fed by {{{{{r.text}}}}}, {desc}. Expected a {ctx.links.table_name(expect)} record ID")


def _rule_e3(ctx: _EContext) -> None:
    for m, _err, _chain in ctx.order:
        t = _mapper(m).get("table")
        if not (_mtype(m).startswith("airtable:") and isinstance(t, str) and t in ctx.links.tables):
            continue
        low = _mtype(m).lower()
        # Link fields in the record being written.
        if is_airtable_write(m):
            for key, val in _record(m).items():
                tgt = ctx.links.link_target(t, key)
                if tgt:
                    _check_record_source(ctx, val, tgt, m, f"Link field {ctx.links.field_label(t, key)} ({key})")
        # The record a get or update addresses.
        if ("getrecord" in low or "update" in low) and is_mapping(_mapper(m).get("id")):
            _check_record_source(ctx, _mapper(m).get("id"), t, m, f"Record ID of this {ctx.links.table_name(t)} {'get' if 'get' in low else 'update'}")


def _rule_e4(ctx: _EContext) -> None:
    for m, _err, _chain in ctx.order:
        low = _mtype(m).lower()
        if not (low.startswith("airtable:") and any(w in low for w in ("getrecord", "update", "delete"))):
            continue
        ids = _mapper(m).get("id", _mapper(m).get("ids"))
        for v in (ids if isinstance(ids, list) else [ids]):
            if isinstance(v, str) and RECORD_ID.match(v.strip()):
                rid = v.strip()
                t = _module_table(m)
                ctx.emit("E4", FAIL, m, f"Record ID is the literal {rid} in a {ctx.links.table_name(t)} {low.split(':')[1]}, not a mapping, "
                                        f"so every run touches this one record. Add it to audit/allowlist.json with a reason if that is intended",
                         record_id=rid)


# --- E5 --------------------------------------------------------------------


def _zero_count_module(c: dict) -> int | None:
    """Module ID whose bundle count the condition requires to be 0."""
    a, bb, op = c.get("a"), c.get("b"), str(c.get("o", ""))
    parts = op.split(":")
    kind = parts[1] if len(parts) > 1 else ""
    for ref, lit, ref_is_a in ((a, bb, True), (bb, a, False)):
        if not (isinstance(ref, str) and is_mapping(ref) and isinstance(lit, str) and not is_mapping(lit)):
            continue
        m = re.fullmatch(r"(\d+)\.`?(" + "|".join(COUNT_FIELDS) + r")`?", expr_key(ref))
        if not m:
            continue
        try:
            val = float(lit.strip())
        except ValueError:
            continue
        if kind == "equal" and val == 0:
            return int(m.group(1))
        if ref_is_a and ((kind == "less" and val == 1) or (kind == "lessorequal" and val == 0)):
            return int(m.group(1))
    return None


def _rule_e5(ctx: _EContext) -> None:
    for m, _err, chain in ctx.order:
        groups = _conditions(m)
        if not groups:
            continue
        dead_groups, searches = 0, set()
        for g in groups:
            conds = g if isinstance(g, list) else [g]
            zeros = [n for n in (_zero_count_module(c) for c in conds if isinstance(c, dict)) if n is not None]
            if zeros:
                dead_groups += 1
                searches.update(zeros)
        for n in sorted(searches):
            src = ctx.modules.get(n)
            if src is None or "search" not in _mtype(src[0]).lower():
                continue
            sflow, sidx = src[2][-1]
            if not any(f is sflow and sidx < i for f, i in chain):
                continue  # the search is not upstream of this filter
            status = FAIL if dead_groups == len(groups) else REVIEW
            tail = "The filter can never pass." if status == FAIL else "One alternative of the filter is dead."
            ctx.emit("E5", status, m, f"Filter `{_short((m.get('filter') or {}).get('name') or '', 40)}` tests that search module {n} returned 0 bundles. "
                                      f"A search with no result emits no bundle, so nothing downstream runs and the condition never fires. {tail}")
        _e5_count_tests(ctx, m, chain)


# E5 extension (X-41, bug sweep B1 and H1, 2026-10-30). Measured 2026-10-30: a Make search that finds nothing can emit
# ONE EMPTY BUNDLE (a hidden per-module option decides, not visible in the blueprint). So with 0 hits
# length(<aggregator>.array) reads 1 (or 0 when no bundle came), the same as with 1 hit, and a search's own bundle count
# reads 0 on the empty bundle, or the filter never runs at all when no bundle came.
#   length: FAIL a comparison that gives a different answer at 0 and at 1, because 0 hits can read either. A comparison
#     that answers the same at 0 and 1 (length > 1, the duplicate test) is sound. Only an aggregator fed by a search
#     counts, an iterator feeder involves no search.
#   count: FAIL a comparison that is true at 0 (a not-found test, it fires only when the hidden option emits the empty
#     bundle). A comparison false at 0 and true at 1 is a found test that works (count > 0), REVIEW "prefer {{N.id}}
#     exists". False at 0 and at 1 (count > 1) is sound.
# The robust tests are {{first(map(<aggregator>.array; "id"))}} exists / does not exist, or {{<search>.id}} exists /
# does not exist for a single search with no aggregator.
_E5_NUMBER_KINDS = ("equal", "notequal", "greater", "less", "greaterorequal", "lessorequal")
_E5_LENGTH_ARRAY = re.compile(r"length\((\d+)\.`?array`?\)")
_E5_CMP = {"equal": lambda x, y: x == y, "notequal": lambda x, y: x != y, "greater": lambda x, y: x > y,
           "less": lambda x, y: x < y, "greaterorequal": lambda x, y: x >= y, "lessorequal": lambda x, y: x <= y}


def _e5_count_ref(c: dict):
    """(kind, module ID, predicate) when the condition compares an aggregator array length ("length") or a search bundle
    count ("count") with a number literal. The predicate gives the condition's result for a count x, with the operator
    mirrored when the literal is on the left."""
    a, bb, op = c.get("a"), c.get("b"), str(c.get("o", ""))
    parts = op.split(":")
    if len(parts) < 2 or parts[1] not in _E5_NUMBER_KINDS:
        return None
    cmp = _E5_CMP[parts[1]]
    for ref, lit, ref_is_a in ((a, bb, True), (bb, a, False)):
        if not (isinstance(ref, str) and is_mapping(ref) and isinstance(lit, str) and not is_mapping(lit)):
            continue
        try:
            val = float(lit.strip())
        except ValueError:
            continue
        pred = (lambda x, v=val: cmp(x, v)) if ref_is_a else (lambda x, v=val: cmp(v, x))
        k = expr_key(ref)
        hit = _E5_LENGTH_ARRAY.fullmatch(k)
        if hit:
            return "length", int(hit.group(1)), pred
        hit = re.fullmatch(r"(\d+)\.`?(" + "|".join(COUNT_FIELDS) + r")`?", k)
        if hit:
            return "count", int(hit.group(1)), pred
    return None


def _e5_count_tests(ctx: _EContext, m: dict, chain: tuple) -> None:
    """E5 rows for a filter that compares an aggregator array length or a search bundle count with a number. One FAIL per
    filter for the unsound comparisons, one REVIEW per filter for found tests on a bundle count. A condition the
    zero-count rule above already reports is not repeated."""
    lengths, counts, found = set(), set(), set()
    for c in _iter_conditions(m):
        if _zero_count_module(c) is not None:
            continue
        hit = _e5_count_ref(c)
        if hit is None:
            continue
        kind, n, pred = hit
        src = ctx.modules.get(n)
        if src is None:
            continue
        low = _mtype(src[0]).lower()
        if kind == "length" and "aggregator" in low:
            params = src[0].get("parameters") if isinstance(src[0].get("parameters"), dict) else {}
            feeder = ctx.modules.get(params.get("feeder")) if isinstance(params.get("feeder"), int) else None
            if feeder is not None and "search" in _mtype(feeder[0]).lower() and pred(0) != pred(1):
                lengths.add(n)
        elif kind == "count" and "search" in low:
            sflow, sidx = src[2][-1]
            if not any(f is sflow and sidx < i for f, i in chain):
                continue
            if pred(0):
                counts.add(n)
            elif pred(1):
                found.add(n)
    name = _short((m.get("filter") or {}).get("name") or "", 40)
    if lengths or counts:
        what = [f"length({n}.array) of aggregator {n}" for n in sorted(lengths)]
        what += [f"the bundle count of search {n}" for n in sorted(counts)]
        why = []
        if lengths:
            why.append("an aggregated array length reads 1 for 0 hits as for 1 hit, so this comparison cannot tell them apart")
        if counts:
            why.append("the condition is true at a bundle count of 0, which the filter sees only when the search emits that "
                       "empty bundle, so it is no not-found test")
        fix = [f"the first record ID of aggregator {n} (first of map over {n}.array with the key id, the IML is in CLAUDE.md "
               f"check E5) with exists or does not exist" for n in sorted(lengths)]
        fix += [f"{{{{{n}.id}}}} with exists or does not exist (or an aggregator on {n} and its first record ID test)"
                for n in sorted(counts)]
        ctx.emit("E5", FAIL, m, f"Filter `{name}` compares {' and '.join(what)} with a number. A search that finds nothing can emit "
                                f"one empty bundle (measured 2026-10-30), and {' and '.join(why)}. Test {' and '.join(fix)}")
    if found:
        refs = " and ".join(f"{{{{{n}.id}}}} exists" for n in sorted(found))
        ctx.emit("E5", REVIEW, m, f"Filter `{name}` tests that the bundle count of search {' and '.join(str(n) for n in sorted(found))} "
                                  f"is above 0. That works as a found test, since the empty bundle of a search with no hit reads "
                                  f"a count of 0 (measured 2026-10-30), but prefer {refs}")


# --- E6 --------------------------------------------------------------------


def _rule_e6(ctx: _EContext) -> None:
    """Client data in a Slack message, or in the body of a Logger call (the Logger writes it to the ledger and Slack)."""
    for m, _err, _chain in ctx.order:
        logger_call = is_logger_call(m, ctx.logger)
        if not (is_slack_message(m) or logger_call):
            continue
        what, where = ("Logger call body", "the Logger call") if logger_call else ("Slack text", "Slack")
        seen: set[tuple] = set()
        for path, expr in _module_exprs(m):
            if logger_call and not path.startswith("mapper"):
                continue
            for r in iml_refs(expr):
                if (r.module, r.field) in seen:
                    continue
                t = ctx.table_of(r.module)
                if t and ctx.links.is_pii(t, r.field):
                    seen.add((r.module, r.field))
                    ctx.emit("E6", FAIL, m, f"{what} {{{{{r.text}}}}} puts the {ctx.links.table_name(t)} field `{ctx.links.field_label(t, r.field)}` "
                                            f"(client PII) in {where}. Send the record ID instead",
                             strict=ctx.x16.loaded and t == ctx.x16.table_id)  # X-16: Draft Reviews rows are never allowlisted
                    continue
                # Client data that never touched Airtable: an inbound email, a webhook body, a Drive link.
                src = ctx.modules.get(r.module)
                x16_what = _x16_pii_source(ctx, r)
                if x16_what:
                    seen.add((r.module, r.field))
                    ctx.emit("E6", FAIL, m, f"{what} {{{{{r.text}}}}} puts {x16_what} in {where}. Outline, validator and "
                                            f"Doc text stay in Airtable and the Doc (X-16). Send the record ID instead",
                             strict=True)
                    continue
                stype = _mtype(src[0]) if src else ""
                x32_what = _x32_pii_source(ctx, r)
                if x32_what:
                    seen.add((r.module, r.field))
                    ctx.emit("E6", FAIL, m, f"{what} {{{{{r.text}}}}} puts {x32_what} in {where}. Exemplar text never leaves "
                                            f"the drafter and the validator (X-32). Send the exemplar code instead", strict=True)
                    continue
                base, ff10_fields = ff10_source_pii(ctx.links, stype)
                if r.field in base or r.field in ff10_fields:
                    seen.add((r.module, r.field))
                    ctx.emit("E6", FAIL, m, f"{what} {{{{{r.text}}}}} puts `{r.field}` of module {r.module} ({stype}) in {where}. "
                                            f"That is client PII from outside Airtable. Send a record ID or a reference instead",
                             strict=r.field in ff10_fields)


# --- E7 --------------------------------------------------------------------


def _writes_state(x: dict) -> bool:
    return is_airtable_write(x) or is_email_send(x) or "sms" in _mtype(x).lower()


_COMPLEMENT = {"equal": "notequal", "startwith": "notstartwith", "endwith": "notendwith", "contain": "notcontain",
               "exist": "notexist", "greater": "lessorequal", "less": "greaterorequal", "match": "notmatch"}
_COMPLEMENT.update({v: k for k, v in list(_COMPLEMENT.items())})


def _single_condition(f: dict) -> dict | None:
    groups = _conditions(f)
    if len(groups) == 1 and isinstance(groups[0], list) and len(groups[0]) == 1 and isinstance(groups[0][0], dict):
        return groups[0][0]
    return None


def _are_complements(f1: dict, f2: dict) -> bool:
    """Two route filters that are exact opposites on the same operands, so one of them always passes."""
    c1, c2 = _single_condition(f1), _single_condition(f2)
    if c1 is None or c2 is None or c1.get("a") != c2.get("a") or c1.get("b") != c2.get("b"):
        return False
    if {str(c1.get("o", "")), str(c2.get("o", ""))} == {"exist", "notexist"}:
        return True  # Make's exists / does not exist carry no type prefix, and one of the two always holds
    o1, o2 = str(c1.get("o", "")).split(":"), str(c2.get("o", "")).split(":")
    if len(o1) < 2 or len(o2) < 2 or o1[0] != o2[0] or o1[2:] != o2[2:]:
        return False
    return _COMPLEMENT.get(o1[1]) == o2[1]


def _rule_e7(ctx: _EContext) -> None:
    """A router whose routes all have filters, with a fallback that leaves no trace or none at all, where a
    route writes state. A fallback counts only when it records the unmatched bundle: an unfiltered Shadow
    Ledger row and an unfiltered Slack alert. A fallback that only sets a variable drops the bundle the same way."""
    for m, _err, _chain in ctx.order:
        routes = _routes(m)
        if not routes:
            continue
        fb = fallback_index(m)
        if fb is not None and _fallback_leaves_trace(routes[fb]):
            continue
        others = [rf for j, rf in enumerate(routes) if j != fb]
        firsts = [rf[0] if rf and isinstance(rf[0], dict) else {} for rf in others]
        if not firsts or not all(_conditions(f) for f in firsts):
            continue
        if fb is None and len(firsts) == 2 and _are_complements(firsts[0], firsts[1]):
            continue  # exact opposites: every bundle matches one route
        writers = sorted({x.get("id") for rf in others for x, err, _c in walk(rf) if not err and _writes_state(x)}, key=str)
        if writers:
            note = _mixed_case_note(firsts)
            if fb is None:
                head = "Every route has a filter and none is the fallback, so a bundle that matches no route is dropped silently."
                tail = "Confirm no input can match nothing, or add a fallback route"
            else:
                head = (f"Every route but the fallback has a filter, and fallback route {fb} leaves no trace (it needs an unfiltered Shadow Ledger "
                        f"row and an unfiltered Slack alert), so a bundle that matches no route is dropped silently.")
                tail = "Make the fallback record the unmatched bundle"
            ctx.emit("E7", REVIEW, m, f"{head} Routes write state in modules {writers}. {tail}{note}")


def _mixed_case_note(firsts: list[dict]) -> str:
    """One sentence when routes compare the same operand with and without the case-insensitive
    form (text:equal:ci next to text:equal). A value that differs only in case then matches
    one route and misses the other."""
    seen: dict[str, set[bool]] = {}
    for f in firsts:
        for c in _iter_conditions(f):
            op = str(c.get("o", "")).split(":")
            if len(op) >= 2 and op[0] == "text" and isinstance(c.get("a"), str) and is_mapping(c.get("a")):
                seen.setdefault(expr_key(c["a"]), set()).add(op[-1] == "ci")
    mixed = sorted(k for k, flags in seen.items() if len(flags) == 2)
    if not mixed:
        return ""
    names = ", ".join("{{" + k + "}}" for k in mixed)
    return (f". Routes compare {names} both with and without the case-insensitive operator, "
            f"so a value that differs only in case can match one route and miss the other")


# --- E8 --------------------------------------------------------------------


def _formula_scan(formula: str) -> tuple[list[str], list[str]]:
    """(field names in {braces}, unquoted {{...}} values) in an Airtable formula.
    A {{...}} IML block and a quoted string are each read as one unit."""
    fields: list[str] = []
    unquoted: list[str] = []
    i, n, quote = 0, len(formula), None
    while i < n:
        c = formula[i]
        if formula.startswith("{{", i):
            end = formula.find("}}", i + 2)
            end = n if end < 0 else end + 2
            if quote is None:
                unquoted.append(formula[i:end])
            i = end
            continue
        if quote:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "{":
            end = formula.find("}", i + 1)
            if end > i:
                fields.append(formula[i + 1:end])
                i = end
        i += 1
    return fields, unquoted


def _rule_e8(ctx: _EContext) -> None:
    for m, _err, _chain in ctx.order:
        t = _module_table(m)
        if not t or t not in ctx.links.tables:
            continue
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        for part, src in (("mapper", _mapper(m)), ("parameters", params)):
            formula = src.get("formula")
            if not isinstance(formula, str) or not formula.strip():
                continue
            names, unquoted = _formula_scan(formula)
            for name in dict.fromkeys(x.strip() for x in names):
                if name and not ctx.links.has_field(t, name):
                    hint = _similar(name, set(ctx.links.tables[t]["fields"].values()))
                    extra = f" Closest fields: {', '.join(hint)}." if hint else ""
                    ctx.emit("E8", FAIL, m, f"Formula in {part}.formula uses {{{name}}}, which is not a field of the {ctx.links.table_name(t)} table, "
                                            f"so Airtable rejects the formula and the module never returns a record.{extra}")
            if unquoted:
                numeric = ctx.links.numeric_fields.get(t) or []
                # An unquoted value is fine only next to a number field, read as {Field} = {{...}}.
                bad = [u for u in dict.fromkeys(unquoted)
                       if not any(re.search(r"\{" + re.escape(f) + r"\}\s*[=<>!]*\s*" + re.escape(u), formula) for f in numeric)]
                for u in bad:
                    ctx.emit("E8", FAIL, m, f"Formula in {part}.formula compares with {u} outside quotes. A text value must be quoted "
                                            f"('{u}'), otherwise Airtable reads it as a field name and the formula errors. "
                                            f"List the field under numeric_fields in audit/airtable_links.json if it is a number")


# --- E9 --------------------------------------------------------------------
#
# Conflicting routes (X-44, decided 2026-10-29). A Make router runs every route whose filter passes, in order, and the
# fallback route (parameters.else) only when no other route passed. A route with no filter that is not the fallback
# therefore runs for every bundle. When two routes can both run for one bundle and both update the same Applicants
# field, both writes land and the later one wins (measured: The Interview Room (B) Grader router 5, route 1 sets
# Mock Interview Status to Completed for a completed call, route 2 has no filter and sets it to No Answer for every
# bundle). A write's condition is every filter on its path inside the route (the route's first module, later
# modules, nested router routes). Two writes conflict unless one route is the fallback or some filter on one path
# provably excludes some filter on the other (_filters_exclusive). Anything not proven exclusive is a FAIL.


def _norm_groups(m: dict) -> list[list[dict]]:
    """The filter as OR groups of AND conditions. A module with no filter has no groups (always passes)."""
    out = []
    for g in _conditions(m):
        if isinstance(g, list):
            out.append([c for c in g if isinstance(c, dict)])
        elif isinstance(g, dict):
            out.append([g])
    return [g for g in out if g]


def _op_parts(c: dict) -> tuple[str, str, bool]:
    """(type, kind, case-insensitive) of a condition operator: text:equal:ci -> (text, equal, True), exist -> ('', exist, False)."""
    parts = str(c.get("o", "")).split(":")
    if len(parts) == 1:
        return "", parts[0], False
    return parts[0], parts[1], parts[-1] == "ci" and len(parts) > 2


def _literal_b(c: dict) -> str | None:
    b = c.get("b")
    if isinstance(b, bool):
        return "true" if b else "false"
    if isinstance(b, (int, float)):
        return str(b)
    return b.strip() if isinstance(b, str) and not is_mapping(b) else None


def _num(s: str | None) -> float | None:
    try:
        return float(s) if s is not None else None
    except ValueError:
        return None


def _interval(kind: str, v: float) -> tuple[float, bool, float, bool] | None:
    inf = float("inf")
    return {"equal": (v, True, v, True), "greater": (v, False, inf, False), "greaterorequal": (v, True, inf, False),
            "less": (-inf, False, v, False), "lessorequal": (-inf, False, v, True)}.get(kind)


def _intervals_disjoint(a: tuple, b: tuple) -> bool:
    lo, lo_in = (a[0], a[1]) if (a[0], not a[1]) > (b[0], not b[1]) else (b[0], b[1])
    hi, hi_in = (a[2], a[3]) if (a[2], a[3]) < (b[2], b[3]) else (b[2], b[3])
    return lo > hi or (lo == hi and not (lo_in and hi_in))


def _conditions_contradict(c1: dict, c2: dict) -> bool:
    """True when no bundle can pass both conditions: same left operand, and the operators or values exclude each other."""
    a1, a2 = c1.get("a"), c2.get("a")
    if not (isinstance(a1, str) and isinstance(a2, str) and is_mapping(a1) and expr_key(a1) == expr_key(a2)):
        return False
    t1, k1, ci1 = _op_parts(c1)
    t2, k2, ci2 = _op_parts(c2)
    b1, b2 = _literal_b(c1), _literal_b(c2)
    if {k1, k2} == {"exist", "notexist"}:
        return True
    if "notexist" in (k1, k2):
        other_kind, other_b = (k2, b2) if k1 == "notexist" else (k1, b1)
        return other_kind in ("equal", "greater", "less", "greaterorequal", "lessorequal") and bool(other_b)
    if b1 is None or b2 is None or t1 != t2:
        return False
    if t1 == "number":
        v1, v2 = _num(b1), _num(b2)
        if v1 is None or v2 is None:
            return False
        if {k1, k2} == {"equal", "notequal"}:
            return v1 == v2
        i1, i2 = _interval(k1, v1), _interval(k2, v2)
        return i1 is not None and i2 is not None and _intervals_disjoint(i1, i2)
    if t1 == "boolean":
        x1, x2 = b1.lower(), b2.lower()
        if k1 == k2 == "equal":
            return x1 != x2
        return {k1, k2} == {"equal", "notequal"} and x1 == x2
    if t1 == "text":
        if k1 == k2 == "equal":
            return (b1.casefold() != b2.casefold()) if (ci1 or ci2) else b1 != b2
        if {k1, k2} == {"equal", "notequal"}:
            eq_v, eq_ci, ne_v, ne_ci = (b1, ci1, b2, ci2) if k1 == "equal" else (b2, ci2, b1, ci1)
            return (ne_ci and eq_v.casefold() == ne_v.casefold()) or (not eq_ci and not ne_ci and eq_v == ne_v)
    return _COMPLEMENT.get(k1) == k2 and b1 == b2 and ci1 == ci2


def _filters_exclusive(f1: dict, f2: dict) -> bool:
    """No bundle passes both filters: every OR group of one contradicts every OR group of the other."""
    g1, g2 = _norm_groups(f1), _norm_groups(f2)
    if not g1 or not g2:
        return False
    return all(any(_conditions_contradict(x, y) for x in a for y in b) for a in g1 for b in g2)


def _path_filters(chain: tuple) -> list[dict]:
    """Every module with a filter on the path to the module at chain (relative to a route flow)."""
    out = []
    for fl, i in chain:
        out.extend(x for x in fl[: i + 1] if isinstance(x, dict) and _norm_groups(x))
    return out


def _lead_update_fields(x: dict, links: AirtableMap, lead: LeadNames) -> set[str]:
    """Applicants fields an update or upsert writes (field IDs where the map knows them). A create makes a new record,
    so two creates never overwrite each other. A Status write through the Airtable API counts as the Status field."""
    out: set[str] = set()
    if is_airtable_write(x) and "create" not in _mtype(x).lower():
        t = _mapper(x).get("table")
        if isinstance(t, str) and t.strip().lower() in lead.tables:
            for k, v in _record(x).items():
                if not nonempty(v):
                    continue
                if isinstance(k, str) and k.strip().lower() in lead.keys:
                    out.add(STATUS_FIELD)
                else:
                    out.add(links._field_id(LEAD_TABLE, k) or str(k).strip())
    sval, unknown = alias_status_write(x, lead)
    if sval is not None or unknown:
        out.add(STATUS_FIELD)
    return out


def _rule_e9(ctx: _EContext) -> None:
    lead = lead_names(ctx.links)
    for r, _err, _chain in ctx.order:
        routes = _routes(r)
        if len(routes) < 2:
            continue
        fb = fallback_index(r)
        writes: list[list[tuple]] = []  # per route: (module, fields, path filters)
        for rf in routes:
            ws = []
            for x, err, ch in walk(rf):
                if err:
                    continue
                fields = _lead_update_fields(x, ctx.links, lead)
                if fields:
                    ws.append((x, fields, _path_filters(ch)))
            writes.append(ws)
        clashes: list[str] = []
        for i in range(len(routes)):
            for j in range(i + 1, len(routes)):
                if fb in (i, j):
                    continue
                for x1, fs1, p1 in writes[i]:
                    for x2, fs2, p2 in writes[j]:
                        common = fs1 & fs2
                        if not common or any(_filters_exclusive(a, b) for a in p1 for b in p2):
                            continue
                        names = ", ".join(sorted(ctx.links.field_label(LEAD_TABLE, f) for f in common))
                        why = []
                        for k, p in ((i, p1), (j, p2)):
                            if not p:
                                why.append(f"route {k + 1} has no filter and is not the fallback, so it runs for every bundle")
                        if not why:
                            why.append("no filter on one route excludes a filter on the other")
                        clashes.append(f"routes {i + 1} and {j + 1} both write {names} of the lead (modules {x1.get('id')} and {x2.get('id')}), "
                                       f"and {' and '.join(why)}")
        if clashes:
            ctx.emit("E9", FAIL, r, "Router runs conflicting routes for one bundle. Make runs every route whose filter passes, so both "
                                    "writes land and the later route wins: " + "; ".join(clashes) + ". Give each route a filter that excludes "
                                    "the others (for example the opposite test on the same value) or make the catch-all route the fallback "
                                    "(parameters.else), which runs only when no other route passed")


# --- E10 -------------------------------------------------------------------
#
# Voice AI Ledger cost contract (X-45, decided 2026-10-29). Every create on the Voice AI Ledger maps Call_Length and
# Rate per minute from the Bland call-details output so that Total Cost equals the Bland call price. Facts:
#   Airtable schema (get_table_schema, read 2026-10-29): Voice AI Ledger tbl5jVTyUQq7buodU. Call_Length
#     fldRjBE7U8tq8zAzo is a duration field (format h:mm), Rate per minute fldHVPuUWQArLCeMW is a number (precision 2),
#     Total Cost fldKDowLeKbobHUWK is the formula ({Call_Length}/60) * {Rate per minute} (currency, precision 4).
#   Airtable Web API field model: a duration cell is "An integer representing number of seconds".
#   Bland GET /v1/calls/{id} (docs.bland.ai/api-v1/get/calls-id): call_length is "The length of the call in minutes",
#     price is "The cost of the call in USD".
# So Call_Length takes whole seconds, round(call_length * 60), and Rate per minute takes price * 60 / those seconds,
# guarded for a call of length 0. The audit evaluates both mappings on sample calls and compares Total Cost with price.

VOICE_LEDGER_TABLE = "tbl5jVTyUQq7buodU"
VOICE_CALL_LENGTH = "fldRjBE7U8tq8zAzo"
VOICE_RATE = "fldHVPuUWQArLCeMW"
VOICE_TOTAL_FORMULA = "({Call_Length}/60) * {Rate per minute}"
VOICE_FIELD_NAMES = {VOICE_CALL_LENGTH: "Call_Length", VOICE_RATE: "Rate per minute"}
# (call_length in minutes, price in USD). The odd lengths are not whole seconds, so an unrounded duration shows up.
VOICE_SAMPLES = ((0.75, 0.068), (2.5, 0.225), (1.0, 0.09), (0.7777, 0.07), (3.1416, 0.2827), (12.0, 1.08))
VOICE_ZERO_SAMPLES = ((0.0, 0.0), (0.0, 0.015))
VOICE_TOLERANCE = 0.00005  # half the last digit of Total Cost (currency, precision 4)
VOICE_CALL_FIELDS = ("call_length", "price")


class _ExprUnsupported(Exception):
    pass


class _ExprDivZero(Exception):
    pass


_EXPR_TOKEN = re.compile(r"\s*(?:(?P<ref>\d+\.[A-Za-z_]\w*)|(?P<num>\d+(?:\.\d+)?|\.\d+)|(?P<name>[A-Za-z_]\w*)"
                         r"|(?P<op><=|>=|!=|<>|[-+*/()<>=;]))")


def _expr_tokens(s: str) -> list[tuple[str, str]]:
    out, i = [], 0
    while i < len(s):
        if s[i:].strip() == "":
            break
        m = _EXPR_TOKEN.match(s, i)
        if not m or m.end() == i:
            raise _ExprUnsupported(f"cannot read `{s[i:i + 20]}`")
        kind = next(k for k in ("ref", "num", "name", "op") if m.group(k) is not None)
        out.append((kind, m.group(kind)))
        i = m.end()
    return out


class _ExprParser:
    """Recursive descent over the arithmetic subset of Make's formula language: numbers, N.field references,
    + - * /, comparisons, and, or, and the functions if, ifempty, round, floor, ceil, max, min. Evaluation is lazy,
    so if( ) runs only the branch it takes, as in Make."""

    FUNCS = ("if", "ifempty", "round", "floor", "ceil", "max", "min")

    def __init__(self, s: str):
        self.toks, self.i = _expr_tokens(s), 0

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, val: str | None = None) -> tuple[str, str]:
        t = self.peek()
        if t is None or (val is not None and t[1].lower() != val):
            raise _ExprUnsupported(f"expected {val or 'more'}")
        self.i += 1
        return t

    def parse(self):
        node = self.or_()
        if self.peek() is not None:
            raise _ExprUnsupported(f"unexpected `{self.peek()[1]}`")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() and self.peek()[1].lower() == "or":
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.cmp()
        while self.peek() and self.peek()[1].lower() == "and":
            self.take()
            node = ("and", node, self.cmp())
        return node

    def cmp(self):
        node = self.add()
        t = self.peek()
        if t and t[0] == "op" and t[1] in ("=", "!=", "<>", "<", ">", "<=", ">="):
            self.take()
            node = ("cmp", t[1], node, self.add())
        return node

    def add(self):
        node = self.mul()
        while self.peek() and self.peek()[1] in ("+", "-"):
            op = self.take()[1]
            node = ("bin", op, node, self.mul())
        return node

    def mul(self):
        node = self.unary()
        while self.peek() and self.peek()[1] in ("*", "/"):
            op = self.take()[1]
            node = ("bin", op, node, self.unary())
        return node

    def unary(self):
        if self.peek() and self.peek()[1] == "-":
            self.take()
            return ("neg", self.unary())
        return self.primary()

    def primary(self):
        t = self.take()
        if t[0] == "num":
            return ("num", float(t[1]))
        if t[0] == "ref":
            mod, fld = t[1].split(".", 1)
            return ("ref", int(mod), fld)
        if t[1] == "(":
            node = self.or_()
            self.take(")")
            return node
        if t[0] == "name" and t[1].lower() in self.FUNCS and self.peek() and self.peek()[1] == "(":
            self.take("(")
            args = [self.or_()]
            while self.peek() and self.peek()[1] == ";":
                self.take()
                args.append(self.or_())
            self.take(")")
            return ("fn", t[1].lower(), args)
        raise _ExprUnsupported(f"`{t[1]}` is not part of the arithmetic the audit can evaluate")


def _expr_eval(node, env: dict):
    kind = node[0]
    if kind == "num":
        return node[1]
    if kind == "ref":
        key = (node[1], node[2])
        if key not in env:
            raise _ExprUnsupported(f"`{node[1]}.{node[2]}` is not call_length or price of the call-details module")
        return env[key]
    if kind == "neg":
        return -_expr_eval(node[1], env)
    if kind == "bin":
        a, b = _expr_eval(node[2], env), _expr_eval(node[3], env)
        if node[1] == "/":
            if b == 0:
                raise _ExprDivZero()
            return a / b
        return {"+": a + b, "-": a - b, "*": a * b}[node[1]]
    if kind == "cmp":
        a, b = _expr_eval(node[2], env), _expr_eval(node[3], env)
        return {"=": a == b, "!=": a != b, "<>": a != b, "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[node[1]]
    if kind == "and":
        return bool(_expr_eval(node[1], env)) and bool(_expr_eval(node[2], env))
    if kind == "or":
        return bool(_expr_eval(node[1], env)) or bool(_expr_eval(node[2], env))
    name, args = node[1], node[2]
    if name == "if":
        if len(args) != 3:
            raise _ExprUnsupported("if( ) needs three arguments")
        return _expr_eval(args[1] if _expr_eval(args[0], env) else args[2], env)
    if name == "ifempty":
        if len(args) != 2:
            raise _ExprUnsupported("ifempty( ) needs two arguments")
        v = _expr_eval(args[0], env)
        return _expr_eval(args[1], env) if v is None or v == "" else v
    vals = [_expr_eval(a, env) for a in args]
    if name in ("round", "floor", "ceil"):
        if len(vals) != 1:
            raise _ExprUnsupported(f"{name}( ) takes one argument here")
        x = vals[0]
        if name == "floor":
            return float(math.floor(x))
        if name == "ceil":
            return float(math.ceil(x))
        return float(math.floor(abs(x) + 0.5)) * (1 if x >= 0 else -1)
    return max(vals) if name == "max" else min(vals)


def _voice_value(rec: dict, links: AirtableMap, fid: str) -> object:
    for k, v in rec.items():
        if k == fid or (isinstance(k, str) and k.strip() == VOICE_FIELD_NAMES[fid]) or links._field_id(VOICE_LEDGER_TABLE, k) == fid:
            return v
    return None


def voice_cost_problems(m: dict, fetch_ids: set, links: AirtableMap | None = None) -> list[str]:
    """Why a Voice AI Ledger create does not make Total Cost equal the Bland price (empty when it does)."""
    links = links or AirtableMap()
    rec = _record(m)
    if not fetch_ids:
        return ["the scenario has no Bland call-details module (bland:getCallDetails) to read call_length and price from"]
    probs: list[str] = []
    parsed = {}
    for fid in (VOICE_CALL_LENGTH, VOICE_RATE):
        name = VOICE_FIELD_NAMES[fid]
        v = _voice_value(rec, links, fid)
        if not nonempty(v):
            probs.append(f"{name} is not mapped")
            continue
        e = _single_expression(v)
        if e is None:
            probs.append(f"{name} is `{_short(str(v))}`, which is text around {{{{ }}}} (Make sends the text as written, not a number). "
                         f"Write the whole computation inside one {{{{ }}}}")
            continue
        mods = {r.module for r in iml_refs(e)}
        if len(mods) > 1 or (mods and not mods <= fetch_ids):
            probs.append(f"{name} reads modules {sorted(mods)}, it must read only the call-details module {sorted(fetch_ids)}")
            continue
        try:
            parsed[fid] = _ExprParser(e).parse()
        except _ExprUnsupported as exc:
            probs.append(f"{name} `{_short(e)}` cannot be verified: {exc}")
    if probs:
        return probs
    used = {r.module for fid in parsed for r in iml_refs(_single_expression(_voice_value(rec, links, fid)))}
    if len(used) > 1:
        return [f"Call_Length and Rate per minute read different call-details modules {sorted(used)}"]
    src = next(iter(used)) if used else next(iter(sorted(fetch_ids)))

    def run(length: float, price: float):
        env = {(src, "call_length"): length, (src, "price"): price}
        return _expr_eval(parsed[VOICE_CALL_LENGTH], env), _expr_eval(parsed[VOICE_RATE], env)

    try:
        for length, price in VOICE_ZERO_SAMPLES:
            run(length, price)
    except _ExprDivZero:
        probs.append(f"Rate per minute divides by zero for a call with call_length 0 (a call that never connected). Guard it, for example "
                     f"{{{{if(round({src}.call_length * 60) > 0; {src}.price * 60 / round({src}.call_length * 60); 0)}}}}")
    except _ExprUnsupported as exc:
        return [f"cannot be verified: {exc}"]
    whole = total_ok = True
    for length, price in VOICE_SAMPLES:
        try:
            secs, rate = run(length, price)
        except _ExprDivZero:
            probs.append(f"the mapping divides by zero for a call of {length} minutes")
            break
        except _ExprUnsupported as exc:
            return [f"cannot be verified: {exc}"]
        if isinstance(secs, bool) or isinstance(rate, bool):
            return ["Call_Length and Rate per minute must be numbers, not comparisons"]
        if whole and abs(secs - round(secs)) > 1e-9:
            whole = False
            probs.append(f"Call_Length is {secs:g} for a call of {length} minutes. It is an Airtable duration field, which holds whole seconds "
                         f"(Airtable Web API field model), and Bland call_length is in minutes, so map {{{{round({src}.call_length * 60)}}}}")
        elif whole and abs(secs - math.floor(length * 60 + 0.5)) > 1e-9:
            # A rate that compensates (say ceil seconds with a matching rate) keeps Total Cost right but the duration wrong,
            # and Call_Length is what the reconciliation and the call reports read as the call's length.
            whole = False
            probs.append(f"Call_Length is {secs:g} seconds for a call of {length} minutes, not the call's length in seconds "
                         f"({math.floor(length * 60 + 0.5):g}). Map {{{{round({src}.call_length * 60)}}}}")
        total = secs / 60 * rate
        if total_ok and abs(total - price) > VOICE_TOLERANCE:
            total_ok = False
            probs.append(f"Total Cost = {VOICE_TOTAL_FORMULA} comes to {total:.6g} USD for a call of {length} minutes priced {price} USD, "
                         f"not the price. Call_Length is a duration in seconds and Bland call_length is minutes "
                         f"(docs.bland.ai/api-v1/get/calls-id), so map Call_Length {{{{round({src}.call_length * 60)}}}} and Rate per minute "
                         f"{{{{if(round({src}.call_length * 60) > 0; {src}.price * 60 / round({src}.call_length * 60); 0)}}}}")
    return probs


def _rule_e10(ctx: _EContext) -> None:
    fetch_ids = {mid for mid, (x, err, _c) in ctx.modules.items() if not err and _mtype(x) in FETCH_MODULES}
    for m, err, _chain in ctx.order:
        if err or not (is_airtable_write(m) and "create" in _mtype(m).lower() and _module_table(m) == VOICE_LEDGER_TABLE):
            continue
        probs = voice_cost_problems(m, fetch_ids, ctx.links)
        if probs:
            ctx.emit("E10", FAIL, m, "Voice AI Ledger row will not cost the Bland price, so Voice AI cost and the X-1 reconciliation are wrong: "
                                     + "; ".join(probs))


# --- E11 -------------------------------------------------------------------
# Measured 2026-10-30 on the first live Market Watchdog run: a System Logs create with the Applicant Link mapped as [""]
# failed with 422 Value "" is not a valid record ID. A literal empty value in an Airtable record field that is a list
# (a link or multiple select) always fails. Drop the field when there is nothing to link.
# Clause (a), bug sweep L2 (2026-10-31, Support Bot 3954492 module 18): a mapped list item fails the same way when the
# mapping reads anything but a record ID. ["{{first(5.`Related Applicant`)}}"] is [""] for a Files row with no link,
# since nothing requires the field. A record ID ({{N.id}}) is never empty. The fixed form is one string, not a list,
# that drops the empty value (remove of add over emptyarray with ifempty, the form the Logger uses for Applicant Link).
# Error routes count too, since a failed ledger write there loses the trace.


def _e11_mapped_refs(v: object) -> list[str]:
    """References (as written) that make an item of a record list value something other than a record ID: a module
    reference to a field other than id inside a {{...}} of the item."""
    if not isinstance(v, list):
        return []
    return [r.text for x in v if isinstance(x, str) for e in _value_exprs(x) for r in iml_refs(e) if r.field != "id"]


def _rule_e11(ctx: _EContext) -> None:
    for m, err, _chain in ctx.order:
        if not is_airtable_write(m):
            continue
        rec = _mapper(m).get("record")
        if not isinstance(rec, dict):
            continue
        bad = sorted(k for k, v in rec.items() if isinstance(v, list) and any(isinstance(x, str) and not x.strip() for x in v))
        if bad and not err:
            ctx.emit("E11", FAIL, m, f"record field(s) {', '.join(bad)} hold an empty value in a list. Airtable answers 422 "
                                     f"Value \"\" is not a valid record ID (measured 2026-10-30). Remove the field when there is no record to link")
        mapped = sorted(k for k, v in rec.items() if _e11_mapped_refs(v))
        if mapped:
            reads = ", ".join(sorted({t for k in mapped for t in _e11_mapped_refs(rec[k])}))
            ctx.emit("E11", FAIL, m, f"(a) record field(s) {', '.join(mapped)} map a list item that is not a record ID (it reads {reads}). "
                                     f"It is empty when the source has no value, and Airtable answers 422 Value \"\" is not a valid "
                                     f"record ID (bug sweep L2). Map one string instead of the list, the remove of add over emptyarray "
                                     f"with ifempty form, so an empty value drops out")


# --- E33 -------------------------------------------------------------------
# Measured 2026-11-15 on the first F-F10 test run (Module F Drafting Chain 7049689, execution bbfed59f): call rows 7 and
# 10 and outcome row 22 mapped System Logs Applicant Link as the text "{{1.id}}" and each failed with 422 Value is not an
# array of record IDs. The same text form runs in VIP intake 3920821 module 18, because a UI save wrote metadata.expect
# typing the field as an array and Make wraps the text in a list. A module built through the API (make_create, a push
# that adds a module) carries no such metadata, so Make sends the text as it is. A link field written as text therefore
# needs the expect spec of that field typed array, the list form ["{{N.id}}"] works either way. Error routes count, since
# a failed ledger write there loses the trace. Not allowlistable.


def _e33_array_typed(m: dict) -> set:
    """Record keys that the module's metadata.expect types as an array (the spec a UI save writes)."""
    out: set = set()
    for e in (m.get("metadata") or {}).get("expect") or []:
        if isinstance(e, dict) and e.get("name") == "record":
            for f in e.get("spec") or []:
                if isinstance(f, dict) and f.get("type") == "array" and isinstance(f.get("name"), str):
                    out.add(f["name"])
    return out


def _e33_makes_array(v: str) -> bool:
    """A value that is one {{...}} expression whose result is an array (the E11 remove of add over emptyarray form, a
    map), which Make sends as a list with or without metadata."""
    body = _single_expression(v)
    return body is not None and body.replace(" ", "").startswith(_E20_ARRAY_CALLS)


def _rule_e33(ctx: _EContext) -> None:
    for m, err, _chain in ctx.order:
        if not is_airtable_write(m):
            continue
        rec = _mapper(m).get("record")
        if not isinstance(rec, dict):
            continue
        tid = _module_table(m)
        typed = _e33_array_typed(m)
        bad = sorted(str(k) for k, v in rec.items()
                     if isinstance(v, str) and v.strip() and ctx.links.link_target(tid, k) and k not in typed
                     and not _e33_makes_array(v))
        if bad:
            where = " (in an error route)" if err else ""
            ctx.emit("E33", FAIL, m, f"maps link field(s) {', '.join(ctx.links.field_label(tid, k) + ' (' + k + ')' for k in bad)}"
                                     f"{where} as text, and its metadata.expect does not type the field as an array, so Make "
                                     f"sends the text and Airtable answers 422 Value is not an array of record IDs (measured "
                                     f"2026-11-15, 7049689 run bbfed59f). Map the list form [\"{{{{N.id}}}}\"] instead")


# --- E12 -------------------------------------------------------------------
# Bug sweep B3 (2026-10-30, measured on Auto-Celebrate 5091060): a Watch Records trigger on table T whose scenario updates
# the record the trigger returned ({{<trigger>.id}}) on T bumps the Last Modified trigger field, so the next poll returns
# the same record and the scenario runs again (a second paid video and email). The trigger formula must exclude the row
# once the write has happened. The audit evaluates the formula with each written field set to the value the update
# writes (other fields unknown). Only a formula that is then false for certain passes, for example a top-level AND clause
# NOT({F}), {F} = BLANK(), {F} = FALSE() or {F} != '<value written>', or {F} = '<other value>'. Field names come from
# audit/airtable_links.json. A Created Time trigger field never moves on an update, so it is exempt.
# Schema read 2026-10-30 (Airtable MCP get_table_schema, base appdQ4ThUSMpdVK21): these fields are createdTime.
CREATED_TIME_FIELDS = {"tblHk09sCKLcOJXr9": ("Created Time",), "tbl0IzlSUYDdZIcxZ": ("Created Time",)}
WATCH_TRIGGER = "airtable:TriggerWatchRecords"

_UNK = object()  # unknown value in the three-valued formula evaluation
_AF_TOKEN = re.compile(r"\s*(?:(?P<field>\{[^{}]*\})|(?P<str>'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")"
                       r"|(?P<num>\d+(?:\.\d+)?)|(?P<name>[A-Za-z_][A-Za-z0-9_]*)|(?P<op>!=|<>|<=|>=|=|<|>|&|\(|\)|,|\+|-|\*|/))")


class _AFParseError(Exception):
    pass


def _af_tokens(s: str) -> list[tuple[str, str]]:
    out, i = [], 0
    while i < len(s):
        if s[i:].strip() == "":
            break
        m = _AF_TOKEN.match(s, i)
        if not m or m.end() == i:
            raise _AFParseError(s[i:i + 20])
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        i = m.end()
    return out


def _af_parse(tokens: list, pos: int = 0):
    """Recursive descent over an Airtable formula. Returns (node, next position). Nodes: ("field", name), ("lit", value),
    ("call", NAME, [args]), ("cmp", op, l, r), ("other",) for arithmetic and concatenation."""
    def peek(p):
        return tokens[p] if p < len(tokens) else (None, None)

    def primary(p):
        kind, val = peek(p)
        if kind == "field":
            return ("field", val[1:-1].strip()), p + 1
        if kind == "str":
            return ("lit", val[1:-1]), p + 1
        if kind == "num":
            return ("lit", float(val)), p + 1
        if kind == "name" and peek(p + 1) == ("op", "("):
            args, q = [], p + 2
            if peek(q) == ("op", ")"):
                return ("call", val.upper(), args), q + 1
            while True:
                node, q = expr(q)
                args.append(node)
                k2, v2 = peek(q)
                if (k2, v2) == ("op", ","):
                    q += 1
                    continue
                if (k2, v2) == ("op", ")"):
                    return ("call", val.upper(), args), q + 1
                raise _AFParseError("call")
        if (kind, val) == ("op", "("):
            node, q = expr(p + 1)
            if peek(q) != ("op", ")"):
                raise _AFParseError("paren")
            return node, q + 1
        if (kind, val) == ("op", "-"):
            node, q = primary(p + 1)
            return ("other",), q
        raise _AFParseError(str(val))

    def arith(p):
        node, p = primary(p)
        while peek(p)[0] == "op" and peek(p)[1] in ("&", "+", "-", "*", "/"):
            _n2, p = primary(p + 1)
            node = ("other",)
        return node, p

    def expr(p):
        left, p = arith(p)
        kind, val = peek(p)
        if kind == "op" and val in ("=", "!=", "<>", "<", ">", "<=", ">="):
            right, p = arith(p + 1)
            return ("cmp", "!=" if val == "<>" else val, left, right), p
        return left, p

    return expr(pos)


def _af_blank(v: object) -> bool:
    return v is None or v is False or v == "" or v == 0


def _af_truthy(v: object) -> object:
    if v is _UNK:
        return _UNK
    return not _af_blank(v)


def _af_eval(node, env: dict) -> object:
    """Three-valued evaluation: a Python value, True/False, or _UNK."""
    kind = node[0]
    if kind == "field":
        return env.get(node[1], _UNK)
    if kind == "lit":
        return node[1]
    if kind == "other":
        return _UNK
    if kind == "call":
        name, args = node[1], node[2]
        if name == "BLANK" and not args:
            return None
        if name == "TRUE" and not args:
            return True
        if name == "FALSE" and not args:
            return False
        if name == "NOT" and len(args) == 1:
            t = _af_truthy(_af_eval(args[0], env))
            return _UNK if t is _UNK else (not t)
        if name in ("AND", "OR") and args:
            vals = [_af_truthy(_af_eval(a, env)) for a in args]
            if name == "AND":
                return False if any(v is False for v in vals) else (True if all(v is True for v in vals) else _UNK)
            return True if any(v is True for v in vals) else (False if all(v is False for v in vals) else _UNK)
        return _UNK
    if kind == "cmp":
        op, lv, rv = node[1], _af_eval(node[2], env), _af_eval(node[3], env)
        if lv is _UNK or rv is _UNK or op not in ("=", "!="):
            return _UNK
        if lv is None or rv is None or isinstance(lv, bool) or isinstance(rv, bool):
            same = _af_blank(lv) == _af_blank(rv)  # BLANK(), TRUE() and FALSE() compare by blankness (a checkbox)
        elif isinstance(lv, str) == isinstance(rv, str):
            same = lv == rv
        else:
            return _UNK
        return same if op == "=" else not same
    return _UNK


def watch_formula_excludes(formula: object, written: dict) -> bool:
    """True when the trigger formula is false for certain once the fields in written (name -> value) hold those values.
    An empty, mapped or unparsable formula excludes nothing."""
    if not isinstance(formula, str) or not formula.strip() or "{{" in formula:
        return False
    try:
        tokens = _af_tokens(formula)
        node, pos = _af_parse(tokens)
    except (_AFParseError, RecursionError):
        return False
    if pos != len(tokens):
        return False
    return _af_truthy(_af_eval(node, written)) is False


_E12_MAX_COMBOS = 256


def _e12_written_values(v: object) -> list | None:
    """The values a write can store: one literal, the finite literal outputs of a mapped if, ifempty or switch
    (status_write_outputs), or None when the value is dynamic. Exactly {{erase}} clears the field, so it stores blank
    (X-16 6.5: E12 read it as the text "erase", so a formula that excludes a field the scenario erases looked safe while
    the erase made it match again, and one that requires the erased field looked like a loop)."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
        return [v]
    if isinstance(v, str):
        if is_mapping(v) and _norm_iml(v).strip() == FF10_ERASE:
            return [""]
        return status_write_outputs(v) if is_mapping(v) else [v]
    return None


def _e12_excludes(formula: object, written: dict) -> bool:
    """True when the formula is false for certain under every combination of the values each field can be written with.
    A field whose value is dynamic is unknown."""
    keys = sorted(written)
    options = [written[k] if written[k] is not None else [_UNK] for k in keys]
    combos = 1
    for o in options:
        combos *= max(1, len(o))
    if combos > _E12_MAX_COMBOS:
        options = [o if len(o) == 1 else [_UNK] for o in options]
    return all(watch_formula_excludes(formula, dict(zip(keys, combo))) for combo in itertools.product(*options))


def _e12_record_aliases(ctx: _EContext, trig: dict, table: str) -> set[str]:
    """Expressions that hold the trigger's record ID: {{<trigger>.id}} and the id of every Get Record on the trigger table
    that reads that record, followed until the set stops growing."""
    aliases = {f"{trig.get('id')}.id"}
    gets = [x for x, _e, _c in ctx.modules.values() if _mtype(x) == "airtable:ActionGetRecord" and _mapper(x).get("table") == table]
    grew = True
    while grew:
        grew = False
        for g in gets:
            rid = _mapper(g).get("id")
            key = f"{g.get('id')}.id"
            if key not in aliases and isinstance(rid, str) and expr_key(rid) in aliases:
                aliases.add(key)
                grew = True
    return aliases


def _rule_e12(ctx: _EContext) -> None:
    flow = ctx.b.bp.get("flow") or []
    trig = flow[0] if flow and isinstance(flow[0], dict) else None
    if trig is None or _mtype(trig) != WATCH_TRIGGER:
        return
    params = trig.get("parameters") if isinstance(trig.get("parameters"), dict) else {}
    table = params.get("table")
    if not isinstance(table, str):
        return
    tfield = (params.get("config") or {}).get("triggerField") if isinstance(params.get("config"), dict) else None
    if tfield in CREATED_TIME_FIELDS.get(table, ()):
        return
    formula = params.get("formula")
    own_ids = _e12_record_aliases(ctx, trig, table)
    loops = []
    for m, _err, _chain in ctx.order:
        if not (is_airtable_write(m) and "update" in _mtype(m).lower() and _mapper(m).get("table") == table):
            continue
        rid = _mapper(m).get("id")
        if not (isinstance(rid, str) and expr_key(rid) in own_ids):
            continue
        rec = _record(m)
        if not rec:
            continue
        written = {ctx.links.field_label(table, k): _e12_written_values(v) for k, v in rec.items()}
        if _e12_excludes(formula, written):
            continue
        loops.append(f"module {m.get('id')} writes {', '.join(sorted(written))}")
    if loops:
        ctx.emit("E12", FAIL, trig, f"The scenario updates the record this trigger returned on {ctx.links.table_name(table)} "
                                    f"({', and '.join(loops)}), which moves the trigger field `{tfield}`, and the trigger formula "
                                    f"`{_short(str(formula or ''), 80)}` still matches the row after the write. The next poll "
                                    f"returns the same record and the scenario runs again (bug sweep B3). Exclude the written "
                                    f"field at the top level of an AND, for example AND(<current formula>, NOT({{<field>}}))")


# --- E13 -------------------------------------------------------------------
# Bug sweep B2 (2026-10-30): Auto-Celebrate mapped {{6.url}}, a field HeyGen Get a Video does not output. These modules
# carry no metadata.interface, so E1 skips them. Output lists read 2026-10-30 with the Make MCP app-module_get
# (organization 6184090, app heygen, version 1). A nested collection maps its field names; None is a plain value.
HEYGEN_OUTPUTS = {
    ("heygen:getVideo", 1): {
        "code": None, "message": None,
        "data": {"callback_id": None, "caption_url": None, "duration": None, "error": None, "gif_url": None, "id": None,
                 "status": None, "thumbnail_url": None, "video_url": None, "video_url_caption": None},
    },
    ("heygen:createAnAvatarVideoV2", 1): {"video_id": None},
    # Version 2 of the app (HeyGen API v3, read 2026-10-31 with app-module_get): no data envelope, every field at the top.
    # Version 1 calls the legacy v1/v2 endpoints HeyGen retired on 2026-11-01.
    ("heygen:getAVideo", 2): {f: None for f in ("id", "title", "status", "created_at", "completed_at", "duration", "video_url",
                                                 "captioned_video_url", "subtitle_url", "thumbnail_url", "gif_url",
                                                 "video_page_url", "folder_id", "output_language", "failure_code",
                                                 "failure_message")},
    ("heygen:createAVideo", 2): {"video_id": None, "status": None, "output_format": None},
}
HEYGEN_GET_VIDEO = "heygen:getVideo"
HEYGEN_GET_VIDEO_TYPES = {"heygen:getVideo": "data.", "heygen:getAVideo": ""}   # Get a Video module -> output prefix
_E13_PATH = re.compile(r"(?<![\w.`$@])(?P<mod>\d+)(?P<path>(?:\.(?:`[^`]*`|[A-Za-z_][\w$@]*)|\[[^\]]*\])+)")


def _e13_segments(path: str) -> list[str]:
    segs = re.findall(r"\.(`[^`]*`|[A-Za-z_][\w$@]*)", path)
    return [s[1:-1] if s.startswith("`") else s for s in segs]


def heygen_path_problem(mtype: str, version: object, segs: list[str]) -> str | None:
    """Why the output path segs is not one the pinned HeyGen module outputs, or None."""
    tree = HEYGEN_OUTPUTS.get((mtype, version))
    if tree is None:
        return None
    if not segs or _is_builtin_field(segs[0]):
        return None
    node: object = tree
    walked = []
    for s in segs:
        if not isinstance(node, dict) or s not in node:
            where = ".".join(walked) or "the top level"
            have = ", ".join(sorted(node)) if isinstance(node, dict) else "nothing (a plain value)"
            return f"`{s}` is not an output at {where} (outputs there: {have})"
        walked.append(s)
        node = node[s]
    return None


_E13_IFEMPTY = re.compile(r"(?<![\w.])ifempty\s*\(")


def _e13_covered(expr: str, heygen: dict) -> dict:
    """{path text: fallback text} for each HeyGen path that is the first argument of an ifempty(a; b) whose second argument
    is a path the pinned HeyGen module outputs, so the value comes from b. Values are lists, one entry per such call."""
    out: dict = {}
    for call in _E13_IFEMPTY.finditer(expr):
        args = secret_scan._split_args(expr, call.end() - 1)
        if not args or len(args) != 2:
            continue
        first, second = args[0].strip(), args[1].strip()
        fb = _E13_PATH.fullmatch(second)
        if not fb or not _E13_PATH.fullmatch(first):
            continue
        src = heygen.get(int(fb.group("mod")))
        if src is None or (_mtype(src), src.get("version")) not in HEYGEN_OUTPUTS:
            continue
        if heygen_path_problem(_mtype(src), src.get("version"), _e13_segments(fb.group("path"))) is None:
            out.setdefault(first, []).append(second)
    return out


def _rule_e13(ctx: _EContext) -> None:
    heygen = {mid: x for mid, (x, _e, _c) in ctx.modules.items() if _mtype(x).startswith("heygen:")}
    if not heygen:
        return
    for m, _err, _chain in ctx.order:
        # Every reference of the module first, so a path used both as a covered ifempty argument and bare is a FAIL.
        refs: dict[str, dict] = {}
        for path, expr in _module_exprs(m):
            blank = _blank_strings(expr)
            covered = _e13_covered(blank, heygen)
            for hit in _E13_PATH.finditer(blank):
                n = int(hit.group("mod"))
                if n not in heygen:
                    continue
                text = f"{n}{hit.group('path')}"
                r = refs.setdefault(text, {"n": n, "seg": hit.group("path"), "path": path, "uses": 0, "covered": 0, "fallback": None})
                r["uses"] += 1
            for text, fbs in covered.items():
                if text in refs:
                    refs[text]["covered"] += len(fbs)
                    refs[text]["fallback"] = refs[text]["fallback"] or fbs[0]
        for text, r in refs.items():
            n, src = r["n"], heygen[r["n"]]
            segs = _e13_segments(r["seg"])
            key = (_mtype(src), src.get("version"))
            if key not in HEYGEN_OUTPUTS:
                if _mtype(src) in HEYGEN_GET_VIDEO_TYPES and segs and not _is_builtin_field(segs[0]):
                    ctx.emit("E13", REVIEW, m, f"{{{{{text}}}}} reads {_mtype(src)} version {src.get('version')}, which has no pinned "
                                               f"output list. Read it with app-module_get and pin it in HEYGEN_OUTPUTS")
                continue
            why = heygen_path_problem(key[0], key[1], segs)
            if not why:
                continue
            if r["covered"] >= r["uses"]:
                ctx.emit("E13", REVIEW, m, f"{{{{{text}}}}} in {_short_path(r['path'])}: dead first argument of ifempty, module {n} "
                                           f"({_mtype(src)}) does not output this path ({why}). The value comes from "
                                           f"{{{{{r['fallback']}}}}}, so map that alone")
                continue
            ctx.emit("E13", FAIL, m, f"{{{{{text}}}}} in {_short_path(r['path'])}: module {n} ({_mtype(src)}) does not output this path, "
                                     f"{why}, so this reference maps empty. The video link of Get a Video is data.video_url (read 2026-10-30)")


# --- E14 -------------------------------------------------------------------
# Bug sweep H5 (2026-10-30): VIP intake stored Phone "Unknown" and Batch Outbound Caller, VIP 10 and The Interview Room
# (A) 2 dial Phone without checking its format. Bland rejects a number that is not E.164 (documented 400), and a lead
# set to Calling first is stranded. A Bland call module must dial a number that a format test let through: a filter
# with the text:pattern operator on the same mapping, on the module or upstream on its path, or a REGEX_MATCH on the
# same field in the formula of the Airtable search or watch trigger the number comes from.
# The Bland call modules. Send a Call is deprecated in Make and cannot dial an agent, so X-46 moves the calls to Create a
# Call (same connection type and the same status, message and call_id outputs). Every rule that judges a Bland call (E14,
# E17, E18, E28 and F3) reads both.
BLAND_CALLS = ("bland:sendACall", "bland:createACall")
# Their outputs, read 2026-10-31 from the module definitions (X-46 spec 5.1). Bland call modules carry no
# metadata.interface in any pull (measured 2026-11-01, and the Create a Call added in the UI got none either), so E1
# checks a reference to one against this list instead of skipping it.
BLAND_CALL_OUTPUTS = frozenset({"status", "message", "call_id"})
_E14_FIELD = re.compile(r"(\d+)\.`?([^`]+?)`?")


def _e14_formula_gates(m: dict, field: str) -> bool:
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    for src in (_mapper(m), params):
        f = src.get("formula") if isinstance(src, dict) else None
        if isinstance(f, str) and re.search(r"REGEX_MATCH\s*\(\s*\{\s*" + re.escape(field) + r"\s*\}", f, re.I):
            return True
    return False


def _rule_e14(ctx: _EContext) -> None:
    for m, in_err, chain in ctx.order:
        if in_err or _mtype(m) not in BLAND_CALLS:
            continue
        phone = _mapper(m).get("phone_number")
        if not is_mapping(phone):
            continue
        key = expr_key(phone)
        path = [x for f, i in chain for x in f[:i + 1] if isinstance(x, dict)]
        if m not in path:
            path.append(m)
        gated = any(str(c.get("o", "")).split(":")[:2] == ["text", "pattern"] and isinstance(c.get("a"), str)
                    and expr_key(c["a"]) == key for x in path for c in _iter_conditions(x))
        hit = _E14_FIELD.fullmatch(key)
        src = ctx.modules.get(int(hit.group(1))) if hit else None
        selects = src is not None and (_mtype(src[0]) == "airtable:ActionSearchRecords" or _mtype(src[0]) == WATCH_TRIGGER)
        if not gated and selects:
            gated = _e14_formula_gates(src[0], hit.group(2))
        if gated:
            continue
        why = (f"Bland {m.get('id')} dials {_short(phone, 40)} with no format test on it. A value that is not E.164 (Unknown, "
               f"empty, a local number) gets a 400 from Bland (bug sweep H5).")
        # A router between the source and the call splits its records, and a formula gate would also drop them from the
        # routes that never dial (Campaign Launcher 3961751, X-41.5). Then the gate is a filter on the call's route.
        here, idx = chain[-1]
        if selects and any(x is src[0] for x in here[:idx]):
            # The number comes from the records this module selects, so the gate belongs in its formula: ahead of any write
            # the scenario makes on the lead (a Status write before the call would strand the lead).
            ctx.emit("E14", FAIL, src[0], f"{why} Add REGEX_MATCH({{{hit.group(2)}}}, '^[+][1-9][0-9]{{7,14}}$') to the formula "
                                          f"of this module, so a lead without a valid number is never selected, and trace those leads")
        else:
            ctx.emit("E14", FAIL, m, f"{why} Put a filter with the text:pattern operator on that mapping ahead of the call, and "
                                     f"trace the leads it stops")


# --- E15 -------------------------------------------------------------------
# Bug sweep B4 (2026-10-30): The Interview Room (A) watched Applicants Last Modified, which tracks only Status and Payment
# Status, while its formula tests Mock Interview Status. Setting Ready to Call never moved the trigger field, so the lead
# was never returned. A Watch Records trigger returns a record only when its trigger field moves, so every field the
# formula tests must be one that field tracks. Schema read 2026-10-31 (Airtable MCP get_table_schema, base
# appdQ4ThUSMpdVK21): the fields each lastModifiedTime field tracks, None when it tracks every field.
TRACKED_FIELDS: dict[str, dict[str, tuple[str, ...] | None]] = {
    "tblHk09sCKLcOJXr9": {"Last Modified": ("Status", "Payment Status"),
                          "Mock Interview Modified": ("Phone", "Mock Interview Status"),
                          "Drafting Modified": ("Drafting Status",)},
    "tblSFR7Sg8uh8noO2": {"Last Modified": None},
    "tbl0IzlSUYDdZIcxZ": {"Status Changed At": ("Status",)},
    "tbl6nVmBLK2Ohe2RA": {"Last Updated": None},
}


def _rule_e15(ctx: _EContext) -> None:
    for m, in_err, _chain in ctx.order:
        if in_err or _mtype(m) != WATCH_TRIGGER:
            continue
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        table, formula = params.get("table"), params.get("formula")
        tfield = (params.get("config") or {}).get("triggerField") if isinstance(params.get("config"), dict) else None
        if not isinstance(table, str) or not isinstance(formula, str) or not formula.strip():
            continue
        if tfield in CREATED_TIME_FIELDS.get(table, ()):
            continue  # a Created Time trigger returns each record once, at creation, which E15 does not judge
        pinned = TRACKED_FIELDS.get(table, {})
        if tfield not in pinned:
            ctx.emit("E15", REVIEW, m, f"Trigger field `{tfield}` on {ctx.links.table_name(table)} has no pinned list of the fields it "
                                       f"tracks. Read it with get_table_schema and add it to TRACKED_FIELDS")
            continue
        tracked = pinned[tfield]
        if tracked is None:
            continue
        names, _ = _formula_scan(formula)
        missing = sorted({n for n in names if n not in tracked and n != tfield})  # the trigger field itself always moves
        if missing:
            ctx.emit("E15", FAIL, m, f"The formula tests {', '.join(missing)}, but trigger field `{tfield}` tracks only "
                                     f"{', '.join(tracked)}. A change to an untracked field never moves the trigger field, so the "
                                     f"record is not returned (bug sweep B4). Point the trigger at a Last modified time field that "
                                     f"tracks every field the formula tests")


# --- E16 -------------------------------------------------------------------
# Bug sweep L6 (2026-10-30): the Pending Call Nurture email says "I have attached a free guide" and attaches nothing, and
# it says a higher score will "guarantee an invitation". A client email may not claim an attachment it does not send, and
# may not promise an outcome (the CICC Code of Professional Conduct bars licensees from guaranteeing results).
_E16_ATTACH = re.compile(r"\b(attach(?:ed|ing|ments?)|enclos(?:ed|ing|ures?))\b", re.I)
_E16_GUARANTEE = re.compile(r"\bguarantee", re.I)


def _e16_text(m: dict) -> str:
    mp = _mapper(m)
    parts = [mp.get("subject"), mp.get("html"), mp.get("content")]
    contents = mp.get("contents")
    if isinstance(contents, list):
        parts.extend(c.get("text") for c in contents if isinstance(c, dict))
    return "\n".join(p for p in parts if isinstance(p, str))


def _rule_e16(ctx: _EContext) -> None:
    for m, in_err, _chain in ctx.order:
        if in_err or not is_email_send(m):
            continue
        text = _e16_text(m)
        if _E16_ATTACH.search(text) and not _carries(_mapper(m).get("attachments")):
            ctx.emit("E16", FAIL, m, "The email body says something is attached or enclosed, but the module sends no attachment "
                                     "(bug sweep L6). Attach it, link it, or cut the sentence")
        if _E16_GUARANTEE.search(text):
            ctx.emit("E16", FAIL, m, "The email promises a guaranteed outcome. A licensed consultant may not guarantee a result "
                                     "(CICC Code of Professional Conduct, bug sweep L6). Reword it as a likelihood or a next step")


# --- E17 -------------------------------------------------------------------
# Bug sweep M10 (2026-10-30): VIP intake's Bland call sets no post-call webhook, so Reconciliation Trigger for VIP client
# never runs and the call's cost never reaches the ledger. Every Bland call (BLAND_CALLS) outside an error route sets a post-call
# webhook, unless its cost reaches the ledger another way (an allowlist entry with the reason, for example Batch Outbound
# Caller, whose pathway webhook node feeds Pending Call, which fetches the call and writes the Voice AI Ledger row).


def _rule_e17(ctx: _EContext) -> None:
    for m, in_err, _chain in ctx.order:
        if in_err or _mtype(m) not in BLAND_CALLS or _carries(_mapper(m).get("webhook")):
            continue
        ctx.emit("E17", FAIL, m, f"Bland {m.get('id')} sets no post-call webhook, so no reconciliation scenario fetches the call "
                                 f"and its cost never reaches the ledger (bug sweep M10). Set the webhook to the hook of the "
                                 f"fetch-back reconciliation scenario for this call and pin it in audit/secret_allowlist.json")


# --- E18 -------------------------------------------------------------------
# Bug sweep M11 (2026-10-30): Campaign Launcher selects its audience with a lead search that never tests Status, so a
# Disqualified lead (already sent a rejection) gets the campaign email and a paid call. A search on the lead table that
# can return several records and feeds a client send (email, SMS or Bland call) must exclude both Disqualified statuses:
# its formula, evaluated with Status set to each, is false for certain. A mapped value counts as unknown.
DISQUALIFIED_STATUSES = ("Disqualified", "Disqualified - Rejection Sent")
# D5 (2026-11-01): a lead who asked not to be called again has Status Do Not Call (F-31.5), and a bulk send must skip it too.
E18_EXCLUDED_STATUSES = DISQUALIFIED_STATUSES + ("Do Not Call",)
_E18_MAPPING = re.compile(r"\{\{(?:(?!\}\}).)*\}\}", re.S)
_E18_QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def _e18_probe(formula: str) -> str:
    """The formula with every mapped value read as an unknown field. Each {{...}} becomes a marker first, then any quoted
    string that holds a marker becomes the unknown field as a whole. So no text between two mappings is lost, and a
    literal that holds a mapping never reads as a fixed value (review 2026-10-31)."""
    marked = _E18_MAPPING.sub("\x00", formula)
    marked = _E18_QUOTED.sub(lambda q: "{__mapped__}" if "\x00" in q.group(0) else q.group(0), marked)
    return marked.replace("\x00", "{__mapped__}")


def _is_client_send(m: dict) -> bool:
    return is_email_send(m) or _mtype(m) in BLAND_CALLS or "sms" in _mtype(m).lower()


def _rule_e18(ctx: _EContext) -> None:
    lead_tables = {tid for tid, t in ctx.links.tables.items() if isinstance(t, dict) and t.get("role") == "lead"}
    done: set[int] = set()
    for m, in_err, chain in ctx.order:
        if in_err or not _is_client_send(m):
            continue
        path = [x for f, i in chain for x in f[:i] if isinstance(x, dict)]
        for s in path:
            mp = _mapper(s)
            if _mtype(s) != "airtable:ActionSearchRecords" or mp.get("table") not in lead_tables:
                continue
            if str(mp.get("maxRecords", "")).strip() == "1" or id(s) in done:
                continue
            done.add(id(s))
            formula = mp.get("formula")
            probe = _e18_probe(formula) if isinstance(formula, str) else formula
            open_to = [st for st in E18_EXCLUDED_STATUSES if not watch_formula_excludes(probe, {"Status": st})]
            if open_to:
                ctx.emit("E18", FAIL, s, f"Search {s.get('id')} can return several leads and feeds client send {m.get('id')}, but its "
                                         f"formula does not exclude Status {' or '.join(open_to)}, so a rejected or do-not-call lead "
                                         f"is contacted again (bug sweep M11, D5). Add {{Status}} != '<value>' for each at the top "
                                         f"level of an AND")


# --- E19 -------------------------------------------------------------------
# Bug sweep H3 (2026-10-31, measured on The Closer 3974028 module 5): the retainer Date was mapped as
# formatDate({{4.`Last Modified`}}; "MMMM D, YYYY"), so only the reference is IML and Make sends the call as literal text,
# and the folder fallback was written """<id>""", which Make reads as the ID wrapped in quote characters. Two sub-tests on
# every string a module maps (mapper, filter, parameters), at any depth, error routes included. (a) A known IML function
# written as text outside {{ }} with a mapping as an argument. (b) A string literal inside {{ }} that decodes (a doubled
# quote is an escaped quote) to text that starts and ends with a quote character. A literal that is one quote passes.
IML_FUNCTIONS = ("if", "ifempty", "switch", "omit", "pick", "get", "merge", "contains", "ascii", "base64", "capitalize",
                 "decodeURL", "encodeURL", "escapeHTML", "escapeMarkdown", "indexOf", "length", "lower", "md5", "replace",
                 "replaceEmojiCharacters", "sha1", "sha256", "sha512", "split", "startcase", "stripHTML", "substring",
                 "toBinary", "toString", "trim", "upper", "average", "ceil", "floor", "formatNumber", "max", "min",
                 "parseNumber", "round", "sum", "addDays", "addHours", "addMinutes", "addMonths", "addSeconds", "addYears",
                 "formatDate", "parseDate", "setDate", "setDay", "setHour", "setMinute", "setMonth", "setSecond", "setYear",
                 "add", "deduplicate", "distinct", "first", "flatten", "join", "keys", "last", "map", "remove", "reverse",
                 "shuffle", "slice", "sort", "toArray", "toCollection", "emptyarray", "emptystring", "now")
_E19_MARK = "\x00"
_E19_CALL = re.compile(r"(?<![\w.])(" + "|".join(sorted(IML_FUNCTIONS, key=len, reverse=True)) + r")\(([^()]*)(\)|$)")


def _e19_marked(s: str) -> tuple[str, list[str]]:
    """(s with each {{...}} replaced by a marker, the expression bodies in order). Split with secret_scan._iml_segments,
    one expression at a time, so the outside text keeps a marker where each expression was."""
    out: list[str] = []
    exprs: list[str] = []
    i = 0
    while True:
        start = s.find("{{", i)
        if start < 0:
            out.append(s[i:])
            break
        found, _ = secret_scan._iml_segments(s[start:])
        if not found:  # unterminated: the rest is plain text
            out.append(s[i:])
            break
        out.append(s[i:start] + _E19_MARK)
        exprs.append(found[0])
        i = start + 2 + len(found[0]) + 2
    return "".join(out), exprs


def _rule_e19(ctx: _EContext) -> None:
    for m, _err, _chain in ctx.order:
        calls: list[str] = []
        quoted: list[str] = []
        for part in ("mapper", "filter", "parameters"):
            if part not in m:
                continue
            for path, s in _string_paths(m[part], part):
                if "{{" not in s:
                    continue
                marked, exprs = _e19_marked(s)
                for hit in _E19_CALL.finditer(marked):
                    if _E19_MARK in hit.group(2):
                        calls.append(f"{_short_path(path)} holds {hit.group(1)}( ... )")
                        break
                if any(len(lit) >= 2 and lit.startswith('"') and lit.endswith('"')
                       for e in exprs for lit in secret_scan._quoted_literals(e)):
                    quoted.append(_short_path(path))
        if calls:
            ctx.emit("E19", FAIL, m, f"{', '.join(calls)} outside {{{{ }}}}, so Make sends it as literal text (bug sweep H3). Put "
                                     f"the whole call inside the braces")
        if quoted:
            ctx.emit("E19", FAIL, m, f"{', '.join(quoted)} holds a string literal wrapped in quote characters (\"\"\"...\"\"\"), so "
                                     f"the value carries the quotes (bug sweep H3). Use one pair of quotes")


# --- E20 -------------------------------------------------------------------
# Bug sweep H4 (2026-10-31, measured on Automating Signed Contracts 3974254 module 9): the Files create maps
# {{3.webViewLink}} into Attachment, a multipleAttachments field that metadata.expect types as an array of {url, filename}
# collections. A text value fails validation, and even a url item would make Airtable fetch a private Drive viewer page.
# For every Airtable create, update or upsert (error routes included) whose metadata.expect record spec types a field as
# an array of collections (spec.spec a list, unlike a link field whose spec.spec is one collection Make wraps), a string
# value passes only as one {{...}} that makes an array or as one bare reference to a field its module's interface types
# as an array. A JSON list value and a module with no metadata.expect are skipped.
_E20_ARRAY_CALLS = ("map(", "add(", "merge(", "flatten(", "slice(", "emptyarray", "remove(", "distinct(", "sort(", "reverse(",
                    "split(", "deduplicate(", "toArray(")


def _e20_record_spec(m: dict) -> dict:
    """Field name -> spec entry from the module's metadata.expect record collection, or {}."""
    md = m.get("metadata") if isinstance(m.get("metadata"), dict) else {}
    for it in md.get("expect") or []:
        if isinstance(it, dict) and it.get("name") == "record" and isinstance(it.get("spec"), list):
            return {s["name"]: s for s in it["spec"] if isinstance(s, dict) and isinstance(s.get("name"), str)}
    return {}


def _e20_array_ref(ctx: _EContext, body: str) -> bool:
    """body is one bare reference N.field and module N's interface types that field as an array."""
    refs = iml_refs(body)
    if len(refs) != 1 or body.strip() != refs[0].text:
        return False
    hit = ctx.modules.get(refs[0].module)
    md = hit[0].get("metadata") if hit and isinstance(hit[0].get("metadata"), dict) else {}
    iface = md.get("interface")
    return isinstance(iface, list) and any(isinstance(it, dict) and it.get("name") == refs[0].field
                                           and it.get("type") == "array" for it in iface)


def _rule_e20(ctx: _EContext) -> None:
    for m, _err, _chain in ctx.order:
        if not is_airtable_write(m):
            continue
        spec = _e20_record_spec(m)
        for k, v in _record(m).items():
            s = spec.get(k)
            if not (s and s.get("type") == "array" and isinstance(s.get("spec"), list)):
                continue
            if not isinstance(v, str) or not v.strip():
                continue
            body = _single_expression(v)
            if body is not None and (body.startswith(_E20_ARRAY_CALLS) or _e20_array_ref(ctx, body)):
                continue
            label = s.get("label") if isinstance(s.get("label"), str) else k
            shown = f"`{_short(v, 40)}`" if ";" not in v else "a text value"
            ctx.emit("E20", FAIL, m, f"Field {label} ({k}) is an attachment field and gets the text {shown}. Make expects a list "
                                     f"of {{url, filename}} items, and Airtable fetches the url publicly (bug sweep H4). Upload "
                                     f"the file with airtable:uploadAnAttachment")


# --- E21 -------------------------------------------------------------------
# Bug sweep M4 (2026-10-31, measured on Automating Signed Contracts 3974254 trigger 1): a Gmail search with no in: or
# -from: term covers Sent mail too, so the retainer The Closer sends from the same connection (a PDF with Retainer in the
# subject) is picked up as a signed contract. A Gmail Watch Emails trigger with filterType gmailSearch must exclude the
# account's own mail with -from:me (or -in:sent, -label:sent). in:inbox alone is not accepted, because mail sent to
# oneself sits in both Inbox and Sent. Folder and label watches are skipped.
GMAIL_WATCH = "google-email:triggerWatchNewEmails"
_E21_NOT_SENT = re.compile(r"(^|[\s(])-(from:me|in:sent|label:sent)\b")


def _rule_e21(ctx: _EContext) -> None:
    flow = ctx.b.bp.get("flow") or []
    m = flow[0] if flow and isinstance(flow[0], dict) else None
    if m is None or _mtype(m) != GMAIL_WATCH:
        return
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    if params.get("filterType") != "gmailSearch":
        return
    q = params.get("q") if isinstance(params.get("q"), str) else ""
    if not _E21_NOT_SENT.search(q.lower()):
        ctx.emit("E21", FAIL, m, "The search query also matches mail this account sends (Sent), so an outgoing email that fits "
                                 "the query, such as The Closer's retainer, runs this scenario (bug sweep M4). Add -from:me")


# --- E22 -------------------------------------------------------------------
# Bug sweep M8 (2026-10-30, measured on Support Bot 3954492): HeyGen renders asynchronously, and Get a Video after a fixed
# sleep can return a render that is still processing or failed, with data.video_url empty. Email 13 maps the getVideo
# output with no filter, so a slow render emails a dead link and the run logs Success. A client send (the P6 predicate,
# HeyGen modules and Logger calls excluded) whose mapper reads the output of a heygen:getVideo module G runs behind the
# render gate: a filter on the send or on an earlier module of its path after G, of exactly one OR group holding
# {{G.data.status}} text equal completed (case-insensitive equal is fine) and {{G.data.video_url}} exists. A second OR
# group lets a bundle through without both, so it voids the gate. Auto-Celebrate 5091060 module 7 has it (X-41.4).
HEYGEN_RENDER_DONE = "completed"


def _e22_render_gate(m: dict, g: object, prefix: str = "data.") -> bool:
    """The module's filter is exactly one OR group holding {{g.<prefix>status}} text equal completed and
    {{g.<prefix>video_url}} exists (prefix data. on app version 1, none on version 2). Other conditions may sit in the same
    group, since they only narrow it."""
    groups = _norm_groups(m)
    if len(groups) != 1:
        return False
    status = url = False
    for c in groups[0]:
        a = c.get("a")
        if not isinstance(a, str):
            continue
        key, op, b = expr_key(a), str(c.get("o", "")), c.get("b")
        if key == f"{g}.{prefix}status" and op in ("text:equal", "text:equal:ci") and not is_mapping(b) \
                and _stripe_literal_matches(b, HEYGEN_RENDER_DONE, op):
            status = True
        elif key == f"{g}.{prefix}video_url" and op == "exist":
            url = True
    return status and url


def _e22_gated(chain: tuple, g_chain: tuple, g: object, prefix: str = "data.") -> bool:
    """A module on the path to chain (the module itself included) that runs after getVideo g carries the render gate."""
    for k, (fl, i) in enumerate(chain):
        for j in range(i + 1):
            x = fl[j]
            here = chain[:k] + ((fl, j),)
            if isinstance(x, dict) and _runs_after(g_chain, here) and _e22_render_gate(x, g, prefix):
                return True
    return False


def _rule_e22(ctx: _EContext) -> None:
    videos = {mid: chain for mid, (x, err, chain) in ctx.modules.items() if not err and _mtype(x) in HEYGEN_GET_VIDEO_TYPES}
    prefix = {mid: HEYGEN_GET_VIDEO_TYPES[_mtype(x)] for mid, (x, _err, _c) in ctx.modules.items() if mid in videos}
    if not videos:
        return
    for m, in_err, chain in ctx.order:
        if in_err or _mtype(m).startswith("heygen:") or not _p_client_send(m) or is_logger_call(m, ctx.logger):
            continue
        read = sorted({r.module for path, expr in _module_exprs(m) if path.startswith("mapper")
                       for r in iml_refs(_blank_strings(expr)) if r.module in videos})
        open_ = [g for g in read if _runs_after(videos[g], chain) and not _e22_gated(chain, videos[g], g, prefix[g])]
        for g in open_:
            pre = prefix[g]
            ctx.emit("E22", FAIL, m, f"Client send {m.get('id')} maps the output of HeyGen Get a Video {g} with no render gate. A "
                                     f"render still processing or failed after the wait has an empty {pre}video_url, so the client "
                                     f"gets a dead link and the run logs Success (bug sweep M8). Put a filter of one OR group "
                                     f"holding {{{{{g}.{pre}status}}}} text equal completed and {{{{{g}.{pre}video_url}}}} exists on "
                                     f"this module or an earlier one after {g}, and trace the renders it stops")


# --- E23 -------------------------------------------------------------------
# Bug sweep L5 (2026-10-30): the Voice AI Ledger rows of Reconciliation Trigger for Campaign 4218934 (module 2) and The
# Interview Room (B) Grader 3975156 (module 22) are never linked to the System Logs row of the call, so a call's cost
# cannot be traced to the run that made it. Schema read 2026-10-31 (get_table_schema): Voice AI Ledger System Log Link
# (fldZOmFsO25WfXU3c) and System Logs Voice AI Ledger (fldOEPxYOQwWj1v6p) are one reciprocal link, so either side fills
# both. Every Voice AI Ledger create outside an error route links its System Logs row: (a) its record maps System Log
# Link to a value whose every module reference is K.id, K an Airtable module on System Logs outside error routes that
# runs before the create (Batch Call Reconciliation 6847022 module 5, Recon VIP 4226754 module 4), or (b) a System Logs
# create or update outside error routes that runs after the create on its path maps Voice AI Ledger to a value
# referencing <create>.id (Batch Call Reconciliation 7, Pending Call 3943741 81 and 136 for ledger row 76). (b) passes
# when any one later path links, so a sibling route that does not link is not caught.
VOICE_SYSLOG_LINK = ("fldZOmFsO25WfXU3c", "System Log Link")   # Voice AI Ledger -> System Logs
SYSLOG_VOICE_LINK = ("fldOEPxYOQwWj1v6p", "Voice AI Ledger")   # System Logs -> Voice AI Ledger (the inverse)


def _e23_field(rec: dict, field: tuple) -> object:
    """The record value under the field ID or its name (case-insensitive), or None."""
    fid, name = field
    for k, v in rec.items():
        if k == fid or (isinstance(k, str) and k.strip().casefold() == name.casefold()):
            return v
    return None


def _e23_value_refs(v: object) -> list[Ref]:
    return [r for e in _value_exprs(v) for r in iml_refs(_blank_strings(e))]


def _rule_e23(ctx: _EContext) -> None:
    syslogs = [(x, chain) for x, err, chain in ctx.order
               if not err and _mtype(x).startswith("airtable:") and _module_table(x) == LEDGER_TABLE]
    for m, in_err, chain in ctx.order:
        if in_err or not (is_airtable_write(m) and "create" in _mtype(m).lower() and _module_table(m) == VOICE_LEDGER_TABLE):
            continue
        before = {x.get("id"): x for x, xc in syslogs if _runs_after(xc, chain)}
        refs = _e23_value_refs(_e23_field(_record(m), VOICE_SYSLOG_LINK))
        if refs and all(r.field == "id" and r.module in before for r in refs):
            continue  # (a) the row links the System Logs record this run found or wrote
        if any(is_ledger_write(x) and _runs_after(chain, xc)
               and any(r.module == m.get("id") and r.field == "id"
                       for r in _e23_value_refs(_e23_field(_record(x), SYSLOG_VOICE_LINK))) for x, xc in syslogs):
            continue  # (b) a later System Logs write on its path links back to this row
        hint = next((f"[{{{{{k}.id}}}}]" for k, x in before.items() if not is_airtable_write(x)), None) \
            or next((f"[{{{{{k}.id}}}}]" for k in before), None)
        fix = (f"Map System Log Link ({VOICE_SYSLOG_LINK[0]}) to {hint}, the System Logs row this run found" if hint else
               f"Map System Log Link ({VOICE_SYSLOG_LINK[0]}) to the record ID of the run's System Logs row, or map Voice AI "
               f"Ledger ({SYSLOG_VOICE_LINK[0]}) to this row's id on a later System Logs write")
        ctx.emit("E23", FAIL, m, f"Voice AI Ledger create {m.get('id')} is not linked to its System Logs row, so the call's cost "
                                 f"cannot be traced to the run that made it (bug sweep L5). {fix}. The link is reciprocal, so "
                                 f"one side fills both")


# --- E24 -------------------------------------------------------------------
# Bug sweep M7 (2026-10-31, X-41.13): Market Watchdog ends each route with [Logger call, Ignore] on every module, and Ignore
# drops the bundle from the rest of its path. So a failed Intel create also loses the campaign draft, the High-urgency alert
# email and the System Logs cost row, none of which reads the Intel record. An Ignore handler may not end a path that still
# holds independent work. Later modules on the module's own flow (nested routes included, error routes not) depend on it when
# they reference it, or a module that does, or read its table (a search may find the record it creates). FAIL when an
# independent external module remains and the module is an Airtable create, or when every independent module is a Shadow
# Ledger create (the run's Success or cost row). An update can be a lock step (Batch Outbound Caller 2 sets Calling before
# it dials) and skipping the follow-ups after a failed send is a business choice, so those are out of scope otherwise.
# The last module on a flow drops nothing (critic 1B.2: the Signed Contracts upload goes last, after the ledger row 10).


def _e24_later(flow: list, idx: int) -> list[dict]:
    """Modules after flow[idx] on the same flow, depth first through router routes, never into error routes."""
    out: list[dict] = []

    def visit(f: list) -> None:
        for x in f:
            if isinstance(x, dict):
                out.append(x)
                for rf in _routes(x):
                    visit(rf)

    visit(flow[idx + 1:])
    return out


def _e24_reads(x: dict, dep: set) -> bool:
    if any(r.module in dep for _p, e in _module_exprs(x) for r in iml_refs(e)):
        return True
    params = x.get("parameters") if isinstance(x.get("parameters"), dict) else {}
    return params.get("feeder") in dep


def _rule_e24(ctx: _EContext) -> None:
    for m, in_err, chain in ctx.order:
        if in_err or not is_external(m) or not isinstance(m.get("id"), int):
            continue
        flow, idx = chain[-1]
        if len(chain) == 1 and idx == 0:
            continue  # the trigger: a failed trigger emits no bundle, so nothing after it can run anyway
        _ledger, _slack, directives = _handler_parts(_onerror(m))
        if directives != ["Ignore"]:
            continue
        later = _e24_later(flow, idx)
        table = _module_table(m)
        dep = {m["id"]}
        grew = True
        while grew:
            grew = False
            for x in later:
                if x.get("id") in dep:
                    continue
                reads_table = (table is not None and _module_table(x) == table
                               and bool(_READ_ONLY_MODULE.match(_mtype(x).split(":", 1)[1])))
                if reads_table or _e24_reads(x, dep):
                    if isinstance(x.get("id"), int):
                        dep.add(x["id"])
                        grew = True
        indep = [x for x in later if x.get("id") not in dep and is_external(x)]
        if not indep:
            continue
        if _mtype(m) != "airtable:ActionCreateRecord" and not all(is_ledger_create(x) for x in indep):
            continue
        ids = ", ".join(str(x.get("id")) for x in indep)
        lost = f"modules {ids} never run, and none of them reads" if len(indep) > 1 else f"module {ids} never runs, and it does not read"
        ctx.emit("E24", FAIL, m, f"Ignore on {m['id']} ends this path when {m['id']} fails, so {lost} the output of {m['id']} "
                                 f"(bug sweep M7). The Logger call already records the "
                                 f"failure. Use Resume, which continues with an empty output, or move the independent modules "
                                 f"ahead of {m['id']}")


# --- E25 -------------------------------------------------------------------
# Bug sweep L9 (2026-10-31, X-41.14, approved by Rizwan 2026-10-31): Pending Call wrote a Voice AI Ledger row and Voice AI
# cost on its System Logs rows 45 seconds after the pathway webhook node fired, while the call was still in progress, and
# the post-call reconciliation of the caller (4226754 for VIP intake, 6847022 for Batch Outbound Caller) writes both again
# once Bland reports the call ended. System Logs Grand Total sums Voice AI cost, so the call was counted twice. One owner
# for voice cost: only a fetch_back scenario in audit/webhooks.json (its F2d gate runs the write once, for an ended call)
# may create a Voice AI Ledger row or write System Logs Voice AI cost, whatever the value (a literal 0 included). Error
# routes count. With no registry (a partial audit without it) the rule says nothing, since the owner is unknown.
VOICE_COST_FIELD = "fldx2WzOb94Iyf5pK"   # System Logs: Voice AI cost (currency), summed by Grand Total


def _e25_table(m: dict, links: AirtableMap) -> str | None:
    """The table an Airtable module writes, by ID or by its name in audit/airtable_links.json."""
    t = _module_table(m)
    if t:
        return t
    raw = _mapper(m).get("table")
    if isinstance(raw, str) and not is_mapping(raw):
        for tid, tab in links.tables.items():
            if isinstance(tab, dict) and str(tab.get("name", "")).strip().lower() == raw.strip().lower():
                return tid
    return None


def _e25_cost_key(k: object, links: AirtableMap) -> bool:
    key = str(k).strip()
    name = ((links.tables.get(LEDGER_TABLE) or {}).get("fields") or {}).get(VOICE_COST_FIELD, "Voice AI cost")
    return key == VOICE_COST_FIELD or key.lower() == str(name).strip().lower()


def _rule_e25(ctx: _EContext) -> None:
    if ctx.webhooks is None or not ctx.webhooks.entries:
        return
    reg = ctx.webhooks.entries.get(str(ctx.b.scenario_id)) if ctx.b.scenario_id is not None else None
    if reg is not None and reg.protection == "fetch_back":
        return  # F2d already puts the completion, found and unreconciled gates in front of every write here
    for m, _in_err, _chain in ctx.order:
        if not is_airtable_write(m):
            continue
        t = _e25_table(m, ctx.links)
        if t == VOICE_LEDGER_TABLE and "create" in _mtype(m).lower():
            what = "creates a Voice AI Ledger row"
        elif t == LEDGER_TABLE and any(_e25_cost_key(k, ctx.links) for k in _record(m)):
            what = "writes Voice AI cost on a System Logs row"
        else:
            continue
        ctx.emit("E25", FAIL, m, f"Module {m.get('id')} {what}, but voice cost belongs to the post-call reconciliation of the "
                                 f"call (a fetch_back scenario in audit/webhooks.json, whose F2d gate runs it once Bland reports "
                                 f"the call ended). This scenario is not one, so the write can run while the call is still in "
                                 f"progress (price and length so far) and counts the call a second time beside the "
                                 f"reconciliation's Voice AI Ledger row and Voice AI cost in System Logs Grand Total (bug sweep "
                                 f"L9). Remove the write")


# --- E26 -------------------------------------------------------------------
# Bug sweep L8a (2026-10-31): Campaign Launcher search 3 (maxRecords 50) feeds router 6. When the campaign has no
# audience the search emits one empty bundle (measured 2026-10-30, a hidden module option decides), route 0's filter
# {{3.Phone}} starts with +1 is false on it, and route 1's not-starts-with +1 is TRUE, so Gmail 8 sends to "" and the
# Logger posts a false alert. A search that can return several records must not reach a module that writes, sends or
# spends (the F2b effect set) unless a filter after it on the path is false for certain on the empty record. A condition
# counts only when its operand is exactly one {{S.<field>}} of that search, read as empty text: exist is false,
# text:equal, startwith, endwith and contain against a non-empty literal are false, their not-forms against an empty
# literal are false, and text:pattern is false when the pattern does not match "". Functions around the reference,
# number, date and boolean operators and a mapped b are unknown and never gate. An aggregator after the search that
# collapses its bundles (fed by the search or an earlier module) owns that case (F3, A and E5). maxRecords 1 stays out:
# Pending Call 121 is gated by an aggregator first-ID test on search 7, and Batch Outbound Caller 2 is a Status write that
# H2 (check A) owns. One row per search, on the module right after it in its flow, where one {{S.id}} exists filter
# covers every route. The detail names no effect module, because a later push that adds one would reword the row and
# compare_audits keys FAIL rows on the full text (critic 1B.3).
E26_AGGREGATORS = ("builtin:BasicAggregator", "util:TextAggregator", "builtin:NumericAggregator")


def _e26_false_on_empty(c: dict, sid: int) -> bool:
    """The condition is false for certain when {{sid.<field>}} is empty text."""
    e = _single_expression(c.get("a"))
    refs = iml_refs(e) if e else []
    if not (e and len(refs) == 1 and refs[0].module == sid and refs[0].text == e.strip()):
        return False
    typ, kind, ci = _op_parts(c)
    if typ == "" and kind == "exist":
        return True
    if typ != "text":
        return False
    b = c.get("b")
    if isinstance(b, (int, float)) and not isinstance(b, bool):
        b = str(b)
    if not isinstance(b, str) or is_mapping(b):
        return False
    if kind in ("equal", "startwith", "endwith", "contain"):
        return b != ""
    if kind in ("notequal", "notstartwith", "notendwith", "notcontain"):
        return b == ""
    if kind in ("pattern", "notpattern"):
        try:
            hit = re.search(b, "", re.I if ci else 0) is not None
        except re.error:
            return False
        return not hit if kind == "pattern" else hit
    return False


def _e26_blocks_empty(x: dict, sid: int) -> bool:
    groups = _norm_groups(x)
    return bool(groups) and all(any(_e26_false_on_empty(c, sid) for c in g) for g in groups)


def _rule_e26(ctx: _EContext) -> None:
    flagged: set[int] = set()
    for m, in_err, chain in ctx.order:
        if in_err or not _is_effect(m):
            continue
        path = [x for f, i in chain for x in f[:i + 1] if isinstance(x, dict)]
        for k, s in enumerate(path):
            sid = s.get("id")
            if _mtype(s) != "airtable:ActionSearchRecords" or not isinstance(sid, int) or sid in flagged:
                continue
            if str(_mapper(s).get("maxRecords", "")).strip() == "1":
                continue
            after = path[k + 1:]
            upto = {x.get("id") for x in path[:k + 1]}
            if any(_mtype(x) in E26_AGGREGATORS and isinstance(x.get("parameters"), dict)
                   and x["parameters"].get("feeder") in upto for x in after):
                continue  # the aggregator emits one bundle for the whole search, which F3, A and E5 judge
            if any(_e26_blocks_empty(x, sid) for x in after):
                continue
            nxt = next((f[j + 1] for f, _i in chain for j, x in enumerate(f) if x is s and j + 1 < len(f)), None)
            if not isinstance(nxt, dict):
                continue
            flagged.add(sid)
            ctx.emit("E26", FAIL, nxt, f"Search {sid} can return several records and emits one empty bundle when it finds none "
                                       f"(measured 2026-10-30), and the modules after it that write, send or spend run on that "
                                       f"bundle with no filter that is false on an empty record (bug sweep L8). Put a filter "
                                       f"{{{{{sid}.id}}}} exists on this module")


# --- E28 -------------------------------------------------------------------
# X-46 (2026-11-01): Bland moves pathways to v2 agents, and a migrated pathway is retired, so a call that still dials it
# runs the old flow. audit/bland_agents.json registers each migrated pathway with the agent that replaces it. Every Bland
# call module, error routes included (a call in a handler dials too), is judged:
# (a) a pathway_id that is a registered pathway FAILs. A Send a Call that maps pathway_id is a REVIEW while the registry
#     lists a pathway, since the mapped value can still be a migrated one.
# (b) a Send a Call that sets agent_id FAILs. Its definition has no agent_id (spec 5.1), so Make drops the value and the
#     call dials by pathway_id or task.
# (c) a Create a Call FAILs when its agent_id is empty, missing, not a string, a mapping, padded with spaces, not a Bland
#     UUID or not a registered agent. Create a Call exists here only for migrated agents, so one that dials by pathway_id
#     or persona_id alone, or by nothing, FAILs too. With an agent_id set, a pathway_id or persona_id that holds a value
#     FAILs, because Make takes only one of the three (spec 5.1) and the audit cannot tell which one Bland dials. A Create
#     a Call with no connection (parameters.__IMTCONN__) FAILs, since it cannot run. agent_id needs a bland2 connection
#     made from an organization API key (X-46.1 decision D3).
# (d) a Create a Call with an agent_id whose agent_version is not exactly the literal production FAILs. Any other value
#     runs staging, a fixed version or an experiment arm instead of the production pin, and a typo is a 400 from Bland,
#     so nothing dials (X-46 spec 5.2).
# A row names an agent_id only when it is a Bland UUID or one plain mapping, and an agent_version only when it looks like
# a version name, so a key pasted into either field never reaches the console or the report. Not allowlistable.
BLAND_AGENT_CALL = "bland:createACall"
BLAND_AGENT_VERSION = "production"
DEFAULT_BLAND_AGENTS = os.path.join(REPO_ROOT, "audit", "bland_agents.json")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_E28_VERSION_SHOWN = re.compile(r"[A-Za-z0-9._ -]{1,24}")
_E28_MAPPING_SHOWN = re.compile(r"\{\{[^{}]{1,60}\}\}")


@dataclass
class BlandAgents:
    """audit/bland_agents.json: the migrated pathways and their agents, keyed by lowercase UUID. An empty registry is
    strictest for E28 (c), since every Create a Call FAILs, and loosest for (a), since no pathway counts as migrated. So
    the audit and make_push refuse a missing file, and only a test passes an empty registry on purpose."""
    pathways: dict = field(default_factory=dict)   # pathway_id -> entry
    agents: dict = field(default_factory=dict)     # agent_id -> entry


def load_bland_agents(path: str, required: bool = True) -> BlandAgents:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no Bland agent registry at {path}. Check E28 needs it, since an empty registry hides a call "
                             f"to a migrated pathway")
        return BlandAgents()
    data = _read_json(path)
    name = os.path.basename(path)
    raw = data.get("agents") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise InputError(f"{name} has no agents list")
    reg = BlandAgents()
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            raise InputError(f"{name} entry {i} is not an object")
        ids = {}
        for key in ("pathway_id", "agent_id"):
            v = e.get(key)
            if not isinstance(v, str) or not _UUID.fullmatch(v.strip()):
                raise InputError(f"{name} entry {i}: {key} must be a Bland UUID")
            ids[key] = v.strip().lower()
        if not isinstance(e.get("name"), str) or not e["name"].strip():
            raise InputError(f"{name} entry {i} needs the agent name")
        reason = e.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 8 or not re.search(r"[A-Za-z]{3}", reason):
            raise InputError(f"{name} entry {i} needs a real reason (a sentence)")
        if ids["pathway_id"] in reg.pathways:
            raise InputError(f"{name} lists pathway {ids['pathway_id']} twice")
        if ids["agent_id"] in reg.agents:
            raise InputError(f"{name} lists agent {ids['agent_id']} twice")
        entry = {"pathway_id": ids["pathway_id"], "agent_id": ids["agent_id"], "name": e["name"].strip(), "reason": reason.strip()}
        reg.pathways[ids["pathway_id"]] = entry
        reg.agents[ids["agent_id"]] = entry
    return reg


def _e28_id(v: object) -> str:
    return v.strip().lower() if isinstance(v, str) else ""


def _e28_shown(v: object) -> str:
    """How a row names an agent_id or a mapped pathway_id: a Bland UUID or one plain mapping, never any other value."""
    if isinstance(v, str) and _UUID.fullmatch(v.strip()):
        return v.strip().lower()
    if isinstance(v, str) and _E28_MAPPING_SHOWN.fullmatch(v.strip()):
        return v.strip()
    return "a value that is not a Bland UUID"


def _e28_version(v: object) -> str:
    """How a row names an agent_version: the value in quotes when it looks like a version name, else a description."""
    if not isinstance(v, str) or v == "":
        return "nothing"
    if _E28_VERSION_SHOWN.fullmatch(v) or _E28_MAPPING_SHOWN.fullmatch(v.strip()):
        return f'"{v}"'
    return f"a value that is not {BLAND_AGENT_VERSION}, staging or a version number"


def _rule_e28(ctx: _EContext) -> None:
    reg = ctx.bland_agents
    for m, _err, _chain in ctx.order:
        mtype = _mtype(m)
        if mtype not in BLAND_CALLS:
            continue
        mp = _mapper(m)
        mid = m.get("id")
        pathway, agent = mp.get("pathway_id"), mp.get("agent_id")
        hit = reg.pathways.get(_e28_id(pathway))
        if hit:
            ctx.emit("E28", FAIL, m, f"Bland {mid} dials pathway {hit['pathway_id']}, which X-46 migrated to agent {hit['name']} "
                                     f"({hit['agent_id']}), so the call runs the retired pathway. Dial the agent with "
                                     f"{BLAND_AGENT_CALL}, agent_id {hit['agent_id']} and agent_version {BLAND_AGENT_VERSION}")
        if mtype != BLAND_AGENT_CALL:
            if is_mapping(pathway) and reg.pathways:
                ctx.emit("E28", REVIEW, m, f"Send a Call {mid} maps pathway_id {_e28_shown(pathway)}, so the audit cannot tell "
                                           f"whether it dials a pathway audit/bland_agents.json lists as migrated. Confirm the "
                                           f"mapped value never holds one, or dial the agent with {BLAND_AGENT_CALL}")
            if _carries(agent):
                ctx.emit("E28", FAIL, m, f"Send a Call {mid} sets agent_id, but the module has no agent_id field (X-46 spec 5.1), "
                                         f"so Make drops it and the call dials by pathway_id or task. Dial the agent with "
                                         f"{BLAND_AGENT_CALL}")
            continue
        if not _carries(agent):
            by = [k for k in ("pathway_id", "persona_id") if _carries(mp.get(k))]
            how = f"dials by {' and '.join(by)} only" if by else "dials nothing"
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} sets no agent_id and {how}. This module type is used only for a "
                                     f"migrated agent in audit/bland_agents.json, so set agent_id to the registered agent "
                                     f"and agent_version to {BLAND_AGENT_VERSION}")
        elif not isinstance(agent, str):
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} sets agent_id to a {type(agent).__name__}, not a Bland agent UUID. "
                                     f"Set it to a registered agent ID from audit/bland_agents.json")
        elif is_mapping(agent):
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} maps agent_id {_e28_shown(agent)}, so the audit cannot tell which "
                                     f"agent dials. Set it to a registered agent ID from audit/bland_agents.json")
        elif agent != agent.strip():
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} sets agent_id {_e28_shown(agent)} with spaces around it. Bland gets "
                                     f"the raw value, which matches no agent, so nothing dials. Remove the spaces")
        elif not _UUID.fullmatch(agent):
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} sets agent_id to {_e28_shown(agent)}. Set it to a registered agent "
                                     f"ID from audit/bland_agents.json")
        elif agent.lower() not in reg.agents:
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} dials agent {agent.lower()}, which is not in audit/bland_agents.json. "
                                     f"Register the agent with the pathway it replaces, or dial a registered agent")
        if _carries(agent):
            also = [k for k in ("pathway_id", "persona_id") if _carries(mp.get(k))]
            if also:
                ctx.emit("E28", FAIL, m, f"Create a Call {mid} sets agent_id and also {' and '.join(also)}. Make takes only one of "
                                         f"pathway_id, persona_id and agent_id (X-46 spec 5.1), so the audit cannot tell which one "
                                         f"Bland dials. Leave {' and '.join(also)} empty")
            ver = mp.get("agent_version")
            if not (isinstance(ver, str) and ver == BLAND_AGENT_VERSION):
                ctx.emit("E28", FAIL, m, f"Create a Call {mid} sets agent_version {_e28_version(ver)}, not exactly "
                                         f"{BLAND_AGENT_VERSION}. Anything else runs another version or an experiment arm "
                                         f"instead of the production pin, and a typo is a 400 from Bland, so nothing dials. "
                                         f"Set it to the literal {BLAND_AGENT_VERSION}")
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        if not _carries(params.get("__IMTCONN__")):
            ctx.emit("E28", FAIL, m, f"Create a Call {mid} has no connection (parameters.__IMTCONN__), so it cannot run. "
                                     f"agent_id needs a bland2 connection made from an organization API key (X-46.1 decision "
                                     f"D3). Rizwan makes it in the Make UI, then the push sets its ID")


# --- E29 to E31 (F-F10, the Module F drafting chain) -----------------------
# specs/F-F10-drafting-chain.md "Audit additions", decided 2026-11-15. None can be allowlisted.
# E29 Synthetic Test Case (Applicants) is ticked by Rizwan by hand. No module of any scenario writes it: a record key (field
#     ID or name, case-insensitive, at any depth of the mapper) in an Airtable create, update or upsert, a column id of a
#     bulk one, or the field named in an Airtable Make an API call (airtable:makeApiCall) or an HTTP call that can write
#     (not a GET), error routes included. A write that may reach Applicants and hides its fields (a mapped record or
#     records list, or an API or HTTP body built in another module) FAILs too, since the audit cannot tell.
# E30 Drafting Status (Applicants) has one owner, the scenario pinned in audit/ff10.json. Every write there is an Airtable
#     update on Applicants whose id is exactly {{1.id}}, where module 1 is the first module and an Airtable Watch Records
#     trigger on Applicants. A create, an upsert, a bulk write or an API call that writes it FAILs, since none is keyed by
#     the trigger. A write that hides its fields FAILs as in E29, in every scenario.
# E31 ff13.drafting_context and ff13.validate_draft run only from the owner, through postgres:StoredProcedure v2 on the
#     pinned ff13_make connection with isToManageDataInSharedTransaction false and spname the literal function name. The
#     rule matches arguments by the values they hold: every value is one recognised form, every required form appears
#     exactly once, and anything else FAILs (a literal, an unknown mapping, a second copy). When every argument key is a
#     parameter name of the migration (FF13_PARAMS), each key must also hold its own role, so swapped arguments FAIL. The
#     argument keys of Execute a function come from an RPC and are not measured yet, so other keys fall back to value
#     matching with one REVIEW row. Re-read the rule against the shape the first UI save shows.
#     The stamps come from the drafter's call row by field name, or by field ID only when the call row has useColumnId
#     true, since the other form maps blank. Any module on the ff13_make connection is an ff13 call (the role can do
#     nothing else), and one that names no ff13 function as a literal FAILs anywhere, as does SQL text with a mapping
#     where a function, schema or table name sits.
# Pending owner: while owner_scenario_id is null, a scenario named exactly owner_name is held to the full rules and each of
# its Drafting Status writes and ff13 calls gets one more "owner pending" FAIL row. Every other scenario is not the owner.
DEFAULT_FF10 = os.path.join(REPO_ROOT, "audit", "ff10.json")
FF10_SYNTHETIC = ("fldsCjg7ftgursZvl", "Synthetic Test Case")
FF10_DRAFTING_STATUS = ("fld5BxjXujOOFzzoE", "Drafting Status")
# Applicants fields an ff13 call maps from the trigger (audit/airtable_links.json, schema read 2026-11-15). The IDs are the
# fallback when the links map does not list the field, and are used only when the trigger reads fields by ID (useColumnId).
FF13_TRIGGER_FIELDS = {"visa code": ("flducJsQNA4cND9xC", "Visa Code"), "document type": ("fldnau52BJIL6MS3K", "Document Code"),
                       "applicant name": ("fldWeOrgnVgfDO21O", "Name"), "case facts": ("fld3Tw8mbpQKMqYbo", "Case Facts")}
FF13_FUNCTIONS = ("drafting_context", "validate_draft", "rank_exemplars")
FF13_MODULE = "postgres:StoredProcedure"
FF13_MODULE_VERSION = 2
# Keys of Execute a function that are settings, not function arguments (Make MCP app-module_get, 2026-11-15).
FF13_SETTING_KEYS = frozenset(("account", "__IMTCONN__", "spname", "ignore", "isToManageDataInSharedTransaction",
                               "returnsMultipleBundles"))
_FF13_NAMED = re.compile(r"(?<![A-Za-z0-9_])(drafting_context|validate_draft|rank_exemplars)(?![A-Za-z0-9_])", re.I)
# The arguments each function takes (supabase/migrations, 16 for the validator, 5 for the grounding call). The validator's
# exemplar terms are empty in v1, so an empty value is allowed once there and nowhere else.
FF13_REQUIRED = {
    "drafting_context": ("record ID", "execution ID", "visa code", "document type", "synthetic flag"),
    "validate_draft": ("record ID", "execution ID", "visa code", "document type", "draft", "applicant name", "case facts",
                       "model requested", "model served", "stop reason", "prompt version", "prompt SHA256", "input tokens",
                       "output tokens", "request ID"),
    # X-32 (specs/X-32-exemplars.md section 3): the exemplar ranker. outline is the P5 text of the outline module (the Claude
    # module the drafter reads inside <outline>), candidates the Rank Key lines of the Exemplars aggregator.
    "rank_exemplars": ("record ID", "execution ID", "visa code", "document type", "outline", "candidates"),
}
# The argument keys of each function as Make's Execute a function stores them, positional "@NN:text" in the function's
# argument order (measured 2026-11-15 with the Make MCP rpc_execute RcpGetStoredProcedureOrRecordsetColumns on connection
# 12330102 after migration 20261115000006 was applied; labels were the migration's parameter names), and the argument role
# each one takes. When every argument key of a call is one of these, E31 also holds each key to its own role, so two swapped
# arguments (input and output tokens, model requested and served) FAIL even though every value is still a recognised form.
# Other keys fall back to matching by value and add one REVIEW row until the keys are re-pinned from a measured save.
def _ff13_positional(roles: tuple[str, ...]) -> dict[str, str]:
    return {f"@{i:02d}:text": role for i, role in enumerate(roles, 1)}


def _ff13_key_of(fn: str, role: str) -> str:
    return next((k for k, r in _ff13_params(fn).items() if r == role), role)


def _ff13_params(fn: str) -> dict[str, str]:
    """The positional argument keys of an ff13 function: measured (FF13_PARAMS) or, for the X-32 ranker, pinned from the
    planned migration's argument order (FF13_PARAMS_X32) until rpc_execute reads them after the migration is applied."""
    return FF13_PARAMS.get(fn) or FF13_PARAMS_X32.get(fn) or {}


# X-32: ff13.rank_exemplars(p_airtable_record_id, p_make_execution_id, p_visa_code, p_document_type, p_outline,
# p_candidates), every argument TEXT (specs/X-32-exemplars.md section 3). Not measured: the migration is not applied yet.
# Re-read the keys with the Make MCP rpc_execute RcpGetStoredProcedureOrRecordsetColumns on connection 12330102 after it is
# applied, and move the entry into FF13_PARAMS (whose test reads the applied F-F10 migration) in a reviewed commit.
FF13_PARAMS_X32 = {
    "rank_exemplars": _ff13_positional(("record ID", "execution ID", "visa code", "document type", "outline", "candidates")),
}
FF13_PARAMS = {
    "drafting_context": _ff13_positional(("record ID", "execution ID", "visa code", "document type", "synthetic flag")),
    "validate_draft": _ff13_positional(("record ID", "execution ID", "visa code", "document type", "draft", "applicant name",
                                        "case facts", "exemplar terms", "model requested", "model served", "stop reason",
                                        "prompt version", "prompt SHA256", "input tokens", "output tokens", "request ID")),
}
# E6 widened by F-F10: the validator's and the grounding call's free-text outputs and a Claude message's content are client
# data (they carry the draft, the facts or the provision text chosen for the case). A Slack or Logger mapping of them FAILs,
# and these rows cannot be allowlisted. A key ending in ":" covers every module type of that app.
FF10_SOURCE_PII = {"postgres:": ("review_note", "detail", "provisions"), CLAUDE_MODULE: ("content",)}


@dataclass
class FF10Pin:
    """audit/ff10.json. owner_scenario_id None means the owner is not created yet (the pending state)."""
    owner_scenario_id: str | None = None
    owner_name: str = "Module F Drafting Chain"
    connection_id: int = 12330102


def load_ff10(path: str = DEFAULT_FF10, required: bool = True) -> FF10Pin:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no F-F10 owner pin at {path}. Checks E30 and E31 need it")
        return FF10Pin()
    data = _read_json(path)
    name = os.path.basename(path)
    if not isinstance(data, dict):
        raise InputError(f"{name} is not an object")
    known = {"owner_scenario_id", "owner_name", "ff13_connection_id"}
    extra = sorted(k for k in data if not str(k).startswith("_") and k not in known)
    if extra:
        raise InputError(f"{name} has unknown keys {extra}")
    sid = data.get("owner_scenario_id")
    if sid is not None and not ((isinstance(sid, int) and not isinstance(sid, bool) and sid > 0)
                                or (isinstance(sid, str) and re.fullmatch(r"[1-9]\d*", sid))):
        raise InputError(f"{name} owner_scenario_id must be null or a Make scenario ID")
    owner = data.get("owner_name")
    if not isinstance(owner, str) or not owner.strip():
        raise InputError(f"{name} needs owner_name, the scenario name of the F-F10 owner")
    conn = data.get("ff13_connection_id")
    if not (isinstance(conn, int) and not isinstance(conn, bool) and conn > 0):
        raise InputError(f"{name} needs ff13_connection_id, the Make connection ID of ff13_make")
    return FF10Pin(str(sid) if sid is not None else None, owner.strip(), conn)


def ff10_source_pii(links: AirtableMap, stype: str) -> tuple[set, set]:
    """(fields from audit/airtable_links.json non_airtable_pii, fields FF10_SOURCE_PII names) that carry client data for a
    module type. The second set is never reduced by the first: whether an E6 row can be allowlisted depends on
    FF10_SOURCE_PII alone, so listing the same field in the links map never makes an F-F10 row allowlistable."""
    base = set(links.source_pii.get(stype) or [])
    ff10: set = set()
    for key, fields in FF10_SOURCE_PII.items():
        if stype == key or (key.endswith(":") and stype.startswith(key)):
            ff10 |= set(fields)
    return base, ff10


def _ff10_role(b: Blueprint, pin: FF10Pin) -> str:
    """owner, pending (the owner ID is not pinned and the scenario has the owner's name) or other."""
    if pin.owner_scenario_id is not None:
        return "owner" if b.scenario_id is not None and str(b.scenario_id) == pin.owner_scenario_id else "other"
    return "pending" if str(b.name).strip() == pin.owner_name else "other"


def _ff10_is_lead(table: object, links: AirtableMap) -> bool:
    if not isinstance(table, str) or is_mapping(table):
        return False
    lead = str((links.tables.get(LEAD_TABLE) or {}).get("name") or "Applicants")
    return table.strip() == LEAD_TABLE or table.strip().lower() == lead.strip().lower()


def _ff10_trigger(ctx: "_EContext") -> tuple[dict | None, str | None]:
    """(module 1, why it is not an Applicants Watch Records trigger at the head of the flow, or None)."""
    flow = ctx.b.bp.get("flow") or []
    first = flow[0] if flow and isinstance(flow[0], dict) else None
    if first is None or first.get("id") != 1:
        return None, "the scenario's first module is not module 1, so {{1.id}} is not the trigger's record"
    if _mtype(first) != WATCH_TRIGGER:
        return first, f"module 1 is {_mtype(first) or 'untyped'}, not an Airtable Watch Records trigger"
    params = first.get("parameters") if isinstance(first.get("parameters"), dict) else {}
    if not _ff10_is_lead(params.get("table"), ctx.links):
        return first, f"module 1 watches {ctx.links.table_name(params.get('table'))}, not Applicants ({LEAD_TABLE})"
    return first, None


def _mapper_keys(v: object):
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from _mapper_keys(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _mapper_keys(x)


def _ff10_http_write(m: dict, logger: "LoggerSpec | None") -> bool:
    """An Airtable API call or an HTTP call that can write (a GET, or an HTTP module with no method, only reads). The Logger
    call is never one: its body is the payload contract of check B."""
    t = _mtype(m)
    if not (_airtable_api_module(m) or t.startswith("http:")) or is_logger_call(m, logger):
        return False
    method = str(_mapper(m).get("method") or "").strip().lower()
    return not (method == "get" or (not method and t.startswith("http:")))


def _ff10_column_hit(key: object, fid: str, name: str, by_name: bool) -> bool:
    k = str(key).strip()
    return k == fid or (by_name and k.lower() == name.lower())


def _ff10_bulk_write(records: object, fid: str, name: str, by_name: bool) -> str | None:
    """The records of an Airtable bulk create, update or upsert (airtable v3, Make MCP app-module_get 2026-11-15). In the
    default Enter manually mode every column is an item {id: <field ID or name>, type, value} of records[].record[], so the
    field is a value of the key id. A mapped records list, record or column ID hides which fields it writes."""
    if is_mapping(records):
        return "unknown" if by_name else None
    if not isinstance(records, list):
        return None
    unknown = False
    for item in records:
        if is_mapping(item):
            unknown = True
            continue
        rec = item.get("record") if isinstance(item, dict) else None
        if is_mapping(rec):
            unknown = True
        elif isinstance(rec, list):
            for col in rec:
                if is_mapping(col):
                    unknown = True
                elif isinstance(col, dict):
                    cid = col.get("id")
                    if isinstance(cid, str) and not is_mapping(cid) and _ff10_column_hit(cid, fid, name, by_name):
                        return "record"
                    if is_mapping(cid):
                        unknown = True
    return "unknown" if unknown and by_name else None


def _ff10_api_unknown(m: dict, links: AirtableMap) -> bool:
    """An Airtable API or HTTP write that may write Applicants (its URL names Applicants by ID or name, or names no table
    the audit knows) and whose body hides which fields it writes (_api_body_unknown). An HTTP module counts only when it
    reaches the Airtable API or names the Applicants table, so a call to another service with a mapped body is not one."""
    url = _mapper(m).get("url")
    text = (url if isinstance(url, str) else "").replace("%20", " ")
    lead = str((links.tables.get(LEAD_TABLE) or {}).get("name") or "Applicants")

    def names(tid: str, tname: str) -> bool:
        return tid in text or (bool(tname.strip()) and re.search(r"(?<![\w])" + re.escape(tname.strip()) + r"(?![\w])",
                                                                  text, re.I) is not None)

    hits_lead = names(LEAD_TABLE, lead)
    if not (_airtable_api_module(m) or hits_lead):
        return False
    other = any(names(tid, str(tab.get("name") or "")) for tid, tab in links.tables.items()
                if tid != LEAD_TABLE and isinstance(tab, dict))
    if other and not hits_lead:
        return False
    return _api_body_unknown(m)


def ff10_field_write(m: dict, links: AirtableMap, field_pair: tuple, logger: "LoggerSpec | None" = None) -> str | None:
    """How module m writes an Applicants field: "record" (a record key of a native create, update or upsert, or a column
    of a bulk one), "api" (an Airtable API or HTTP write whose request names it), "unknown" (a write that may reach
    Applicants and hides which fields it writes: a mapped record or records list, or an API or HTTP body built in another
    module) or None. The field ID counts on any table, since it exists only on Applicants. The name counts on Applicants
    and on a table the audit cannot resolve (a mapped or unknown table)."""
    fid, name = field_pair
    if is_airtable_write(m):
        table = _e25_table(m, links)
        by_name = table is None or table == LEAD_TABLE
        mp = _mapper(m)
        if any(_ff10_column_hit(k, fid, name, by_name) for k in _mapper_keys(mp)):
            return "record"
        if "bulk" in _mtype(m).lower():
            return _ff10_bulk_write(mp.get("records"), fid, name, by_name)
        return "unknown" if by_name and is_mapping(mp.get("record")) else None
    if _ff10_http_write(m, logger):
        text = " ".join(list(_strings(_mapper(m))) + [str(k) for k in _mapper_keys(_mapper(m))]).replace("%20", " ")
        # X-16.1 review: the field name counts only in a request that can reach Airtable (an Airtable API call, an HTTP
        # call to the Airtable API, or one whose URL is a mapping or missing). A call to another service whose text
        # happens to hold the name ("open the Draft Doc Link") writes no Airtable field. The field ID counts anywhere.
        url = _mapper(m).get("url")
        by_name = _airtable_api_module(m) or not (isinstance(url, str) and url.strip() and "{{" not in url)
        if fid in text or (by_name and re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text, re.I)):
            return "api"
        if _ff10_api_unknown(m, links):
            return "unknown"
    return None


_FF10_VIA = {"record": "a record key", "api": "an Airtable API or HTTP call that names it",
             "unknown": "a write that may reach Applicants and whose fields the audit cannot tell (a mapped record or "
                        "records list, or an API or HTTP body built in another module)"}


def _ff10_owner_text(pin: FF10Pin) -> str:
    if pin.owner_scenario_id is not None:
        return f"scenario {pin.owner_scenario_id} ({pin.owner_name}, audit/ff10.json)"
    return f"the scenario named {pin.owner_name!r} (audit/ff10.json, owner_scenario_id not pinned yet)"


def _ff10_pending(pin: FF10Pin) -> str:
    return (f"owner pending: audit/ff10.json owner_scenario_id is null, so this scenario is the F-F10 owner by its name "
            f"{pin.owner_name!r} only. Commit its Make scenario ID as owner_scenario_id after make_create")


def _rule_e29(ctx: "_EContext") -> None:
    for m, in_err, _chain in ctx.order:
        how = ff10_field_write(m, ctx.links, FF10_SYNTHETIC, ctx.logger)
        if how is None:
            continue
        where = " (in an error route)" if in_err else ""
        verb = "may write" if how == "unknown" else "writes"
        fix = ("Map the record or the body as fixed keys in the module itself, so the audit can see which fields it writes"
               if how == "unknown" else "Remove it from the module")
        ctx.emit("E29", FAIL, m, f"{verb} Applicants `{FF10_SYNTHETIC[1]}` ({FF10_SYNTHETIC[0]}) through {_FF10_VIA[how]}{where}. "
                                 f"The field is test factor 1 of F-F10 and is ticked by Rizwan by hand only, so no module "
                                 f"writes it (specs/F-F10-drafting-chain.md). {fix}")


# X-16 (6.5) widened E30 to Draft Doc Link and Drafting Review Note, the two fields that carry the drafting chain's Doc link
# and the validator's flags to staff. Only the owner writes them, through the same update keyed {{1.id}} (its lock erases
# them, its outcome routes set them), so no other scenario can point staff or a client at another Doc. Hidden writes count
# as for Drafting Status.
E30_FIELDS = (("fld5BxjXujOOFzzoE", "Drafting Status"), ("fldPxDXPA1OSfbZsW", "Draft Doc Link"),
              ("fld4Qm3T5ys4E3qJM", "Drafting Review Note"))


def _rule_e30(ctx: "_EContext") -> None:
    role = _ff10_role(ctx.b, ctx.ff10)
    trig_problem = None
    for m, in_err, _chain in ctx.order:
        hits = [(pair, how) for pair in E30_FIELDS
                for how in (ff10_field_write(m, ctx.links, pair, ctx.logger),) if how is not None]
        if not hits:
            continue
        how = next((h for _p, h in hits if h != "unknown"), "unknown")
        names = [p for p, h in hits if h == how] if how != "unknown" else [p for p, _h in hits]
        label = " and ".join(f"Applicants `{n}` ({fid})" for fid, n in names)
        verb = "may write" if how == "unknown" else "writes"
        if role == "other":
            if [p for p, _h in hits] == [E30_FIELDS[0]]:
                ctx.emit("E30", FAIL, m, f"{verb} {label} through {_FF10_VIA[how]}, which only {_ff10_owner_text(ctx.ff10)} writes. "
                                         f"Staff set Ready for AI Draft in Airtable and the drafting chain sets every other value")
            else:
                ctx.emit("E30", FAIL, m, f"{verb} {label} through {_FF10_VIA[how]}, which only {_ff10_owner_text(ctx.ff10)} writes. "
                                         f"The drafting chain alone sets the Doc link and the review note (X-16), so no other "
                                         f"scenario can point staff or a client at a different Doc")
            continue
        if role == "pending":
            ctx.emit("E30", FAIL, m, f"{_ff10_pending(ctx.ff10)} (a write of {label})")
        problems = []
        low = _mtype(m).lower()
        if how == "unknown":
            problems.append(f"is {_FF10_VIA[how]}, so the audit cannot tell which fields it writes")
        elif how == "api":
            problems.append("writes it through an API or HTTP call, whose record the audit cannot tie to the trigger")
        elif "bulk" in low:
            problems.append(f"is {_mtype(m)}, and only a single-record update keyed by the trigger may write it")
        else:
            if "update" not in low or "upsert" in low:
                problems.append(f"is {_mtype(m)}, and only an update keyed by the trigger may write it (a create or an upsert "
                                f"can make a second record)")
            elif _e25_table(m, ctx.links) != LEAD_TABLE:
                problems.append(f"updates {ctx.links.table_name(_e25_table(m, ctx.links))}, not Applicants")
            idv = _mapper(m).get("id")
            if not (isinstance(idv, str) and _norm_iml(idv) == "{{1.id}}"):
                problems.append(f"is keyed {_short(idv) if is_mapping(idv) else 'by a value that is not a mapping'}, "
                                f"not exactly {{{{1.id}}}}")
        if trig_problem is None:
            trig_problem = _ff10_trigger(ctx)[1] or ""
        if trig_problem:
            problems.append(trig_problem)
        if problems:
            where = " (in an error route)" if in_err else ""
            ctx.emit("E30", FAIL, m, f"writes {label}{where} and {', and '.join(problems)}. Every write is an Airtable update on "
                                     f"Applicants keyed exactly {{{{1.id}}}} of the Applicants Watch Records trigger")


def _sql_name_mapped(sql: object) -> bool:
    """True when SQL text holds a mapping where a function, schema or table name could sit, so the audit cannot tell what
    it calls: the whole text is a mapping, or a mapping outside a quoted SQL literal starts the text, follows a dot, a
    double quote or a keyword that names an object (select, from, join, call, exec, execute, perform, into, update, table,
    function, schema), or is followed by a parenthesis, a dot or a double quote. A mapping that is a value, such as
    = {{1.id}} or '{{1.id}}', passes."""
    if not isinstance(sql, str) or "{{" not in sql:
        return False
    if _single_expression(sql) is not None:
        return True
    marks: list[str] = []

    def mark(hit: re.Match) -> str:
        marks.append(hit.group(0))
        return f"\x00{len(marks) - 1}\x00"

    text = re.sub(r"\{\{.*?\}\}", mark, sql, flags=re.S)
    text = re.sub(r"'(?:[^']|'')*'", "''", text)
    keywords = {"select", "from", "join", "call", "exec", "execute", "perform", "into", "update", "table", "function", "schema"}
    for hit in re.finditer(r"\x00\d+\x00", text):
        before, after = text[:hit.start()].rstrip(), text[hit.end():].lstrip()
        word = re.search(r"([A-Za-z_]+)$", before)
        if not before or before[-1] in '."' or (after[:1] and after[0] in '(."') \
                or (word is not None and word.group(1).lower() in keywords):
            return True
    return False


_SQL_TEXT_KEYS = ("command", "query", "sql", "statement")


def ff13_function(m: dict, logger: "LoggerSpec | None" = None, connection_id: int | None = None) -> str | None:
    """The ff13 function a database or HTTP module names (drafting_context or validate_draft), "mapped" when the audit
    cannot read which function it calls (a postgres:StoredProcedure whose spname is a mapping, or SQL text with a mapping
    in a name position, _sql_name_mapped), "connection" for any other module on the ff13_make connection (the role holds
    only USAGE on ff13 and EXECUTE on its functions, so every module on it is an ff13 call), or None. A Logger call is
    never one."""
    t = _mtype(m)
    app = t.split(":", 1)[0].lower()
    if not (app in ("postgres", "supabase", "http") or "sql" in app) or is_logger_call(m, logger):
        return None
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    if t == FF13_MODULE and is_mapping(params.get("spname", _mapper(m).get("spname"))):
        return "mapped"
    for part in (params, _mapper(m)):
        for s in list(_strings(part)) + [str(k) for k in _mapper_keys(part)]:
            hit = _FF13_NAMED.search(s)
            if hit:
                return hit.group(1).lower()
    if app == "http":
        return None
    if t != FF13_MODULE and any(_sql_name_mapped(src.get(k)) for src in (_mapper(m), params) for k in _SQL_TEXT_KEYS):
        return "mapped"
    if connection_id is not None and any(k in params and str(params[k]).strip() == str(connection_id)
                                         for k in ("account", "__IMTCONN__")):
        return "connection"
    return None


def _ff13_name_forms(fid: str, name: str, use_ids: bool) -> set:
    if use_ids:
        return {f"{{{{1.{fid}}}}}"}
    forms = {f"{{{{1.`{name}`}}}}"}
    if re.fullmatch(r"[A-Za-z_]\w*", name):
        forms.add(f"{{{{1.{name}}}}}")
    return forms


def _ff13_forms(ctx: "_EContext", fn: str, trig: dict | None, chain: tuple) -> tuple[dict, list[str]]:
    """normalised value -> argument role for one ff13 call, and notes on sources the rule could not find. A stamp role
    carries the drafter's module ID after a colon (prompt version:25), so the rule can tell the drafter's call row apart."""
    params = (trig or {}).get("parameters") if isinstance((trig or {}).get("parameters"), dict) else {}
    ids = params.get("useColumnId") is True
    lead = (ctx.links.tables.get(LEAD_TABLE) or {}).get("fields") or {}

    def field_forms(role: str) -> set:
        fid, name = FF13_TRIGGER_FIELDS[role]
        fid = next((k for k, v in lead.items() if v == name), fid)
        return _ff13_name_forms(fid, name, ids)

    forms: dict = {"{{1.id}}": "record ID", "{{var.scenario.executionId}}": "execution ID"}
    for role in ("visa code", "document type"):
        for f in field_forms(role):
            forms[f] = role
    notes: list[str] = []
    if fn == "drafting_context":
        sfid = next((k for k, v in lead.items() if v == FF10_SYNTHETIC[1]), FF10_SYNTHETIC[0])
        synth = f"1.{sfid}" if ids else f"1.`{FF10_SYNTHETIC[1]}`"
        forms[f'{{{{if({synth};"true";"false")}}}}'] = "synthetic flag"
        return forms, notes
    before = _before_ids(chain)
    if fn == "rank_exemplars":
        # X-32: the outline's P5 text (E31 then holds it to the module the drafter reads inside <outline>) and the Rank Key
        # lines of an aggregator fed by the Exemplars search.
        for d, (dm, d_err, _dc) in ctx.modules.items():
            if is_claude_call(dm) and not d_err and d in before:
                forms[f'{{{{first(map({d}.content;"text";"type";"text"))}}}}'] = f"outline:{d}"
        for a in _x32_aggregators(ctx):
            if a.get("id") in before:
                forms[x32_forms(a.get("id"), 0)["candidates"]] = "candidates"
        return forms, notes
    for a, r in _x32_pairs(ctx, before):
        forms[x32_forms(a, r)["terms"]] = "exemplar terms"
    for role in ("applicant name", "case facts"):
        for f in field_forms(role):
            forms[f] = role
    stamps = _stamp_map(ctx.links) or {}
    ledger = (ctx.links.tables.get(LEDGER_TABLE) or {}).get("fields") or {}
    for d, (dm, d_err, d_chain) in ctx.modules.items():
        if not is_claude_call(dm) or d_err or d not in before:
            continue
        forms[f'{{{{first(map({d}.content;"text";"type";"text"))}}}}'] = f"draft:{d}"
        dflow, didx = d_chain[-1]
        row = dflow[didx + 1] if didx + 1 < len(dflow) and isinstance(dflow[didx + 1], dict) else None
        if row is None or "create" not in _mtype(row).lower() or not _is_ledger_write_any(row, ctx.links) or not _uses_usage(row, d):
            notes.append(f"Claude module {d} has no call row at the next flow position, so its stamps have no source")
            continue
        c = row.get("id")
        # The call row outputs its fields by ID only when it maps by column ID (mapper.useColumnId true), and by name
        # otherwise (every Airtable action of the committed pull has it false, measured 2026-11-15). The other form maps
        # blank in Make, so only the form that matches the call row counts, as for the trigger fields.
        row_ids = _mapper(row).get("useColumnId") is True
        for role, fid in (("prompt version", stamps.get("prompt_version")), ("prompt SHA256", stamps.get("prompt_sha256")),
                          ("model requested", stamps.get("model_requested")), ("model served", stamps.get("model_served")),
                          ("stop reason", stamps.get("stop_reason")), ("request ID", stamps.get("message_id")),
                          ("input tokens", TOKEN_IN_FIELD), ("output tokens", TOKEN_OUT_FIELD)):
            if not fid:
                continue
            if row_ids:
                forms[f"{{{{{c}.{fid}}}}}"] = f"{role}:{d}"
                continue
            fname = ledger.get(fid)
            if isinstance(fname, str):
                for f in _ff13_name_forms(fid, fname, False):
                    forms[f.replace("{{1.", f"{{{{{c}.", 1)] = f"{role}:{d}"
    return forms, notes


def _ff13_leaves(v: object, path: str):
    if isinstance(v, dict):
        for k, x in v.items():
            if path == "mapper" and k in FF13_SETTING_KEYS:
                continue
            yield from _ff13_leaves(x, f"{path}.{k}")
    elif isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            yield from _ff13_leaves(x, f"{path}[{i}]")
    else:
        yield path, v


def ff13_keyed(m: dict, fn: str) -> bool:
    """Every argument of the call sits at mapper.<key> with key one of the measured positional keys (FF13_PARAMS), so
    E31 can hold each key to its own role. False when any argument sits under another name or deeper."""
    params = _ff13_params(fn)
    keys = [path[len("mapper."):] for path, v in _ff13_leaves(_mapper(m), "mapper") if v is not None]
    return bool(keys) and all(k in params for k in keys)


def ff13_argument_problems(ctx: "_EContext", m: dict, fn: str, trig: dict | None, chain: tuple) -> list[str]:
    """What is wrong with the arguments of one ff13 call, matched by value, and by key when ff13_keyed holds. A literal is
    never shown, only its path."""
    forms, notes = _ff13_forms(ctx, fn, trig, chain)
    keyed = ff13_keyed(m, fn)
    params = _ff13_params(fn)
    seen: dict = {}
    problems: list[str] = []
    empty = 0
    for path, v in _ff13_leaves(_mapper(m), "mapper"):
        if v is None:
            continue
        want = params.get(path[len("mapper."):]) if keyed else None
        if isinstance(v, str) and v == "":
            empty += 1
            if fn != "validate_draft" or empty > 1:
                problems.append(f"{_short_path(path)} is empty, which is no argument of ff13.{fn}")
            elif keyed and want != "exemplar terms":
                problems.append(f"{_short_path(path)} is empty, but only {_ff13_key_of(fn, 'exemplar terms')} may be empty")
            continue
        role = forms.get(_norm_iml(v)) if isinstance(v, str) else None
        if role is None:
            shown = (f"maps {_short(v)}" if isinstance(v, str) and _E28_MAPPING_SHOWN.fullmatch(v.strip())
                     else "holds a literal or a value the rule does not recognise")
            problems.append(f"{_short_path(path)} {shown}")
            continue
        if keyed and role.partition(":")[0] != want:
            problems.append(f"{_short_path(path)} holds the pinned form of the {role.partition(':')[0]}, but the argument of "
                            f"that name takes the {want}")
        seen.setdefault(role, []).append(path)
    drafts = sorted(r for r in seen if r.startswith("draft:"))
    drafter = drafts[0].split(":", 1)[1] if len(drafts) == 1 else None
    if len(drafts) > 1:
        problems.append("maps the text of more than one Claude module")
    outlines = sorted(r for r in seen if r.startswith("outline:"))
    if len(outlines) > 1:
        problems.append("maps the text of more than one Claude module")
    elif outlines:
        why = _x32_outline_problem(ctx, int(outlines[0].split(":", 1)[1]))
        if why:
            problems.append(why)
    for role, paths in seen.items():
        base, _, src = role.partition(":")
        if src and base not in ("draft", "outline") and src != drafter:
            problems.append(f"{_short_path(paths[0])} maps the {base} of the call row of Claude module {src}, which is not "
                            f"the drafter")
    counts: Counter = Counter()
    for role, paths in seen.items():
        counts[role.partition(":")[0]] += len(paths)
    missing = [r for r in FF13_REQUIRED[fn] if counts[r] == 0]
    twice = [r for r in FF13_REQUIRED[fn] + ("exemplar terms",) if counts[r] > 1]
    if missing:
        problems.append(f"no argument maps the {', '.join(missing)} in its pinned form")
        problems.extend(notes)
    if twice:
        problems.append(f"maps the {', '.join(twice)} more than once")
    return problems


def _rule_e31(ctx: "_EContext") -> None:
    role = _ff10_role(ctx.b, ctx.ff10)
    for m, in_err, chain in ctx.order:
        fn = ff13_function(m, ctx.logger, ctx.ff10.connection_id)
        if fn is None:
            continue
        if fn == "mapped" and _mtype(m) == FF13_MODULE:
            ctx.emit("E31", FAIL, m, "is a PostgreSQL Execute a function whose function (spname) is a mapping, so the audit cannot "
                                     "tell which ff13 function it calls (drafting_context, validate_draft or rank_exemplars). Name the function as a literal")
            continue
        if fn == "mapped":
            ctx.emit("E31", FAIL, m, f"is {_mtype(m)} whose SQL is a mapping or holds one where a function, schema or table name "
                                     f"sits, so the audit cannot tell which ff13 function it calls (drafting_context, "
                                     f"validate_draft or rank_exemplars). ff13 calls run only through {FF13_MODULE} with a literal spname")
            continue
        if fn == "connection":
            ctx.emit("E31", FAIL, m, f"is {_mtype(m)} on the ff13_make connection {ctx.ff10.connection_id}, which can only call "
                                     f"ff13 functions, and names none of ff13.drafting_context, ff13.validate_draft and "
                                     f"ff13.rank_exemplars as a literal. Only {_ff10_owner_text(ctx.ff10)} calls them, through {FF13_MODULE} with a "
                                     f"literal spname")
            continue
        if role == "other":
            ctx.emit("E31", FAIL, m, f"names ff13.{fn}, which only {_ff10_owner_text(ctx.ff10)} calls")
            continue
        if role == "pending":
            ctx.emit("E31", FAIL, m, f"{_ff10_pending(ctx.ff10)} (an ff13.{fn} call)")
        if _mtype(m) != FF13_MODULE:
            ctx.emit("E31", FAIL, m, f"names ff13.{fn} from {_mtype(m)}. ff13 calls run only through {FF13_MODULE} "
                                     f"(PostgreSQL Execute a function) on the ff13_make connection {ctx.ff10.connection_id}")
            continue
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        problems = []
        if m.get("version") != FF13_MODULE_VERSION:
            problems.append(f"the module version is {m.get('version')!r}, not {FF13_MODULE_VERSION} (the measured app version)")
        if "account" not in params:
            problems.append(f"parameters.account is not set (the ff13_make connection is {ctx.ff10.connection_id})")
        for key in ("account", "__IMTCONN__"):
            if key in params and str(params[key]).strip() != str(ctx.ff10.connection_id):
                problems.append(f"parameters.{key} is not the ff13_make connection {ctx.ff10.connection_id}")
        shared = [src["isToManageDataInSharedTransaction"] for src in (params, _mapper(m))
                  if "isToManageDataInSharedTransaction" in src]
        if not shared:
            problems.append("isToManageDataInSharedTransaction is not set, and it must be false")
        elif any(v is not False for v in shared):
            problems.append("isToManageDataInSharedTransaction is not false")
        sp = params.get("spname", _mapper(m).get("spname"))
        if not (isinstance(sp, str) and re.sub(r'["\s]', "", sp) == f"ff13.{fn}"):
            problems.append(f"spname is not the literal ff13.{fn}")
        trig, trig_problem = _ff10_trigger(ctx)
        if trig_problem:
            problems.append(trig_problem)
        problems.extend(ff13_argument_problems(ctx, m, fn, trig, chain))
        keyed = ff13_keyed(m, fn)
        if problems:
            where = " (in an error route)" if in_err else ""
            how = ("Arguments are matched by key (the measured positional keys, FF13_PARAMS) and by value" if keyed else
                   "The argument keys are not the measured positional keys (FF13_PARAMS), so arguments are matched by value only")
            ctx.emit("E31", FAIL, m, f"calls ff13.{fn}{where} and {', and '.join(problems)}. {how}. Re-pin the rule from the "
                                     f"first UI save if the shape differs")
        if not keyed:
            ctx.emit("E31", REVIEW, m, f"calls ff13.{fn} with argument keys that are not the parameter names of the migration "
                                       f"(FF13_PARAMS), so E31 matches the arguments by value only and two swapped arguments "
                                       f"(input and output tokens, model requested and served) would pass. Re-pin "
                                       f"FF13_PARAMS from the shape the UI save shows")


# --- E34 (F-F10, the lock clears the last run's output) -------------------
# Found on the F-F10 test runs of 2026-11-15/16: a run that ended at Draft Failed or Draft Rejected left Draft Doc Link
# (and, after a run that died on an Ignore, the review note) from an earlier run, so staff could open an old draft as
# this run's result. In the owner, the lock (the Drafting Status write of the literal Drafting, on the main flow before
# any router) also writes Draft Doc Link and Drafting Review Note as exactly {{erase}}. Make's Airtable Update a Record
# ignores an empty value and clears a field only with the erase keyword (apps.make.com Airtable modules, read
# 2026-11-16). Only the Draft Ready routes then write a link. Not allowlistable.
FF10_DOC_LINK = ("fldPxDXPA1OSfbZsW", "Draft Doc Link")
FF10_REVIEW_NOTE = ("fld4Qm3T5ys4E3qJM", "Drafting Review Note")
FF10_ERASE = "{{erase}}"


def _rule_e34(ctx: "_EContext") -> None:
    if _ff10_role(ctx.b, ctx.ff10) == "other":
        return
    locks = []
    for m in ctx.b.bp.get("flow") or []:
        if m.get("routes"):
            break
        rec = _mapper(m).get("record")
        if not (is_airtable_write(m) and isinstance(rec, dict)):
            continue
        for k, v in rec.items():
            if (k == FF10_DRAFTING_STATUS[0] or str(k).strip().casefold() == FF10_DRAFTING_STATUS[1].casefold())                     and isinstance(v, str) and v.strip() == "Drafting":
                locks.append(m)
    if not locks:
        trig = (ctx.b.bp.get("flow") or [{}])[0]
        ctx.emit("E34", FAIL, trig, "has no lock: no update on the main flow before the first router writes Drafting Status "
                                    "Drafting, so nothing clears the last run's Draft Doc Link and review note")
        return
    for m in locks:
        rec = _mapper(m)["record"]
        missing = []
        for fid, name in (FF10_DOC_LINK, FF10_REVIEW_NOTE):
            vals = [v for k, v in rec.items() if k == fid or str(k).strip().casefold() == name.casefold()]
            if not any(isinstance(v, str) and v.replace(" ", "") == FF10_ERASE for v in vals):
                missing.append(f"{name} ({fid})")
        if missing:
            ctx.emit("E34", FAIL, m, f"is the F-F10 lock and does not clear {', '.join(missing)} with exactly {FF10_ERASE}, so a run "
                                     f"that ends at Draft Failed or Draft Rejected shows the last run's Doc link or note. Make's "
                                     f"Airtable update ignores an empty value and clears a field only with erase")


# --- E32 (F-F10, the Docs the drafting chain creates) ----------------------
# Found in the F-F10 blueprint review of 2026-11-15: the test path's safety bounds (a fixed test folder, the TEST title,
# only validated text) sat in the blueprint and in no rule, so a later push or a UI edit could move a test draft into a
# client folder with the audit green. In the owner (or the pending owner), every Google Docs create:
#   - runs after an ff13.validate_draft call V, and its content is exactly the P5 form of the drafter D whose text V maps
#     as the draft (only text the validator checked reaches a Doc)
#   - sits behind filters on its path where every OR group of one filter holds {{V.verdict}} text equal pass or
#     pass_with_flags, every OR group of one filter holds {{D.stop_reason}} text equal end_turn (a draft cut off at
#     max_tokens never reaches a Doc, even when the call row failed and the validator saw no stop reason), and every OR
#     group of one filter holds {{G.gate_mode}} text equal one mode, G an ff13.drafting_context call before it
#   - test mode: every OR group of one filter holds {{V.review_note}} text starts with F-F13 TEST MODE, folderId is one
#     literal folder (a slash and an ID, no mapping, no __PLACEHOLDER__) and the name starts with the TEST title
#   - production mode: {{V.review_note}} text does not start with F-F13 TEST MODE. Changed by X-16 (2026-11-16, Rizwan):
#     folderId is exactly /<review_folder_id of audit/x16.json>, the staff-only Under RCIC review folder, never the
#     client's Drive Folder ID, and the name holds {{1.id}}. That part is its own row, "E32 (X-16) ...", and FAILs as owner
#     pending while review_folder_id is null. The production route may keep its Drive Folder ID exists test, which no
#     rule requires any more.
# Any other module of the owner outside error routes whose mapper carries D's text (a Drive upload, an email) FAILs too.
# An audit rule cannot tell whether a literal folder is a client folder, only that it is fixed. Not allowlistable.
FF10_TEST_DOC_TITLE = "TEST, UNREVIEWED CITATION ROWS, NOT FOR CLIENT USE"
FF10_TEST_NOTE = "F-F13 TEST MODE"
FF10_DRIVE_FOLDER = ("fldaRRoXEF6J9zydX", "Drive Folder ID")
_FF10_P5 = re.compile(r'^\{\{first\(map\((\d+)\.content;"text";"type";"text"\)\)\}\}$')
_BUILD_PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*__")


def _e32_has(chain: tuple, test) -> bool:
    """One filter module on the path whose every OR group holds a condition test(c) accepts."""
    return any(all(any(test(c) for c in g) for g in _norm_groups(x)) for x in _path_filters(chain))


def _e32_cond(form: str, ops: tuple, values: tuple | None):
    def test(c: dict) -> bool:
        if _norm_iml(c.get("a")) != form or str(c.get("o", "")) not in ops:
            return False
        return values is None or _literal_b(c) in values
    return test


def _e32_modes(chain: tuple, groundings: list) -> set:
    """The gate modes the path pins: every filter on it whose every OR group tests {{G.gate_mode}} text equal a literal
    adds those literals. More than one mode means the path pins none (a contradiction or a group per mode)."""
    forms = {f"{{{{{gid}.gate_mode}}}}" for gid in groundings}
    out: set = set()
    for x in _path_filters(chain):
        found = []
        for g in _norm_groups(x):
            vals = {_literal_b(c) for c in g if str(c.get("o", "")) in ("text:equal", "text:equal:ci")
                    and _norm_iml(c.get("a")) in forms}
            if not vals:
                found = []
                break
            found.append(vals)
        for vals in found:
            out |= vals
    return out


def _rule_e32(ctx: "_EContext") -> None:
    if _ff10_role(ctx.b, ctx.ff10) == "other":
        return
    fn_of = {id(m): ff13_function(m, ctx.logger, ctx.ff10.connection_id) for m, _e, _c in ctx.order if _mtype(m) == FF13_MODULE}
    validators = [m for m, _e, _c in ctx.order if fn_of.get(id(m)) == "validate_draft"]
    groundings = [m for m, _e, _c in ctx.order if fn_of.get(id(m)) == "drafting_context"]
    drafters: set = set()
    for v in validators:
        for _path, val in _ff13_leaves(_mapper(v), "mapper"):
            hit = _FF10_P5.match(_norm_iml(val)) if isinstance(val, str) else None
            if hit:
                drafters.add(int(hit.group(1)))
    for m, in_err, chain in ctx.order:
        t = _mtype(m)
        if not (t.startswith("google-docs:") and "create" in t.lower()):
            if in_err or m.get("id") in drafters or any(m is v for v in validators) or is_logger_call(m, ctx.logger):
                continue
            carried = sorted({r.module for path, expr in _module_exprs(m) if path.startswith("mapper")
                              for r in iml_refs(_blank_strings(expr))
                              if r.module in drafters and str(r.field).startswith("content")})
            if carried:
                ctx.emit("E32", FAIL, m, f"carries the text of drafter {', '.join(map(str, carried))} in its mapper. In the "
                                         f"F-F10 owner only the validator and a Google Docs create behind the verdict gate "
                                         f"may carry the draft", strict=True)
            continue
        before = _before_ids(chain)
        mine = [v for v in validators if v.get("id") in before]
        if not mine:
            ctx.emit("E32", FAIL, m, f"is {t} with no ff13.validate_draft call before it on its path, so nothing checked the "
                                     f"text it writes. A Doc of the drafting chain runs after the validator and behind its "
                                     f"verdict", strict=True)
            continue
        vid = mine[-1].get("id")
        problems: list[str] = []
        content = _norm_iml(_mapper(m).get("content"))
        hit = _FF10_P5.match(content) if isinstance(content, str) else None
        d = int(hit.group(1)) if hit else None
        if d is None or d not in drafters:
            problems.append(f"its content is not exactly the P5 form of the drafter whose text validator {vid} maps as the "
                            f"draft")
        if not _e32_has(chain, _e32_cond(f"{{{{{vid}.verdict}}}}", ("text:equal", "text:equal:ci"), ("pass", "pass_with_flags"))):
            problems.append(f"no filter on its path holds {{{{{vid}.verdict}}}} text equal pass or pass_with_flags in every "
                            f"OR group")
        for dd in (sorted(drafters) if d is None or d not in drafters else [d]):
            if not _e32_has(chain, _e32_cond(f"{{{{{dd}.stop_reason}}}}", ("text:equal", "text:equal:ci"), ("end_turn",))):
                problems.append(f"no filter on its path holds {{{{{dd}.stop_reason}}}} text equal end_turn in every OR group, "
                                f"so a draft cut off at max_tokens reaches a Doc when the call row failed and the validator "
                                f"saw no stop reason")
        modes = _e32_modes(chain, [g.get("id") for g in groundings if g.get("id") in before])
        folder = _mapper(m).get("folderId")
        name = _mapper(m).get("name")
        note = f"{{{{{vid}.review_note}}}}"
        if len(modes) != 1 or not modes <= {"test", "production"}:
            problems.append("no filter on its path pins one grounding mode ({{<drafting_context>.gate_mode}} text equal "
                            "test or production in every OR group)")
        elif modes == {"test"}:
            if not _e32_has(chain, _e32_cond(note, ("text:startwith",), (FF10_TEST_NOTE,))):
                problems.append(f"the test Doc's path does not require {note} to start with {FF10_TEST_NOTE}")
            if not (isinstance(folder, str) and re.fullmatch(r"/[A-Za-z0-9_-]{10,}", folder.strip())
                    and not _BUILD_PLACEHOLDER.search(folder)):
                problems.append("the test Doc's folderId is not one literal folder (a slash and a Drive folder ID, no "
                                "mapping, no placeholder), so a test draft could land in a client folder or nowhere")
            elif ctx.x16.loaded and ctx.x16.test_folder_id and folder.strip() != f"/{ctx.x16.test_folder_id}":
                problems.append(f"the test Doc's folderId is not exactly /{ctx.x16.test_folder_id}, the Generated Submission "
                                f"test folder of audit/x16.json, where test Docs stay (X-16, 2026-11-16)")
            if not (isinstance(name, str) and name.startswith(FF10_TEST_DOC_TITLE)):
                problems.append(f"the test Doc's name does not start with {FF10_TEST_DOC_TITLE}")
        else:
            if not _e32_has(chain, _e32_cond(note, ("text:notstartwith",), (FF10_TEST_NOTE,))):
                problems.append(f"the production Doc's path does not require {note} not to start with {FF10_TEST_NOTE}")
            x16 = _e32_x16_problems(ctx, folder, name)
            if x16:
                where = " (in an error route)" if in_err else ""
                ctx.emit("E32", FAIL, m, f"(X-16) is the production Doc of the drafting chain{where} and {', and '.join(x16)}",
                         strict=True)
        if problems:
            where = " (in an error route)" if in_err else ""
            ctx.emit("E32", FAIL, m, f"is a Google Docs create of the F-F10 drafting chain{where} and {', and '.join(problems)}",
                     strict=True)


def _e32_x16_problems(ctx: "_EContext", folder: object, name: object) -> list[str]:
    """X-16 (decided 2026-11-16): a production draft goes to the staff-only Under RCIC review folder pinned in audit/x16.json,
    never the client's folder, and its title holds {{1.id}} so drafts of different clients in that one folder stay apart.
    While review_folder_id is null every production Doc FAILs as owner pending."""
    pin = ctx.x16
    out: list[str] = []
    if not pin.loaded or pin.review_folder_id is None:
        out.append("owner pending: audit/x16.json review_folder_id is null, so no production Doc can pass until Rizwan creates "
                   "the staff-only Under RCIC review folder and its Drive folder ID is committed there")
    elif not (isinstance(folder, str) and folder.strip() == f"/{pin.review_folder_id}"):
        out.append("its folderId is not exactly a slash and the review_folder_id of audit/x16.json, the staff-only Under RCIC "
                   "review folder, so the draft could reach a client folder before the RCIC signs off")
    if not (isinstance(name, str) and "{{1.id}}" in _norm_iml(name)):
        out.append("its name does not hold {{1.id}}, so drafts of different clients in the shared review folder cannot be told "
                   "apart")
    return out


# --- E35 to E37 (X-32, the exemplar layer of Module F) --------------------
# specs/X-32-exemplars.md section 8, pin audit/x32.json. None can be allowlisted.
# E35 No Make module of any scenario writes the Exemplars table: an Airtable create, update, upsert or delete (bulk ones
#     included) on it by ID or by name, an Airtable Make an API call or an HTTP call to the Airtable API that is not a GET
#     and names it, error routes included. A native Airtable write whose table is a mapping may reach it and FAILs too,
#     since the audit cannot tell. Only the F-F10 owner (audit/ff10.json) reads the table, and there only through native
#     Search Records modules (E36 pins the one it may hold). An Airtable get, list or API read of it FAILs anywhere. Any
#     Airtable module whose table or base is a mapping, reads included, and any Airtable API or HTTP call whose URL holds a
#     mapping where the base or the table sits (unless a literal there names another table) FAILs in every scenario, since
#     it may reach the table and the audit cannot tell.
# E36 In the owner, when an Exemplars search exists: exactly one, outside error routes, on the drafter's flow before the
#     drafter, behind a filter on its path (itself included) whose every OR group holds {{<outline>.stop_reason}} text equal
#     end_turn, after one ff13.drafting_context call G, with exactly the pinned formula (the firm literal of the pin, the
#     document and visa codes from module 1, the status clause {{if(G.gate_mode = "test"; "TEST"; "Active")}}), maxRecords
#     the pin, sort Exemplar Code ascending only, no view, output fields exactly the four the aggregator reads, useColumnId
#     false and the trigger's base. The next module is an array aggregator fed by it with exactly the four keys id, rank_key,
#     skeleton and terms, then the ff13.rank_exemplars call. No filter on either. A second Exemplars search, a second
#     aggregator fed by the search or a second ranker FAILs. The search's and the ranker's error handlers are each exactly
#     [Logger call, the pin's selection_directive] (Ignore or Break, go-ahead 8). A Resume FAILs whatever the pin says,
#     because its substitute output would reach the ranker or the drafter as if Airtable or the database had returned it.
# E37 The aggregator A is read only by the drafter (the skeleton, exactly once, inside <exemplar> and </exemplar> of its user
#     message, in the form below), the validator (@08, exactly the terms form) and the ranker (the Rank Key lines). Any
#     other module that maps A, or that maps the search's output other than A (and the search's own error route reading
#     its error), FAILs. A drafter that maps a skeleton while @08 is empty, or the reverse, FAILs.
# E31 also covers ff13.rank_exemplars (FF13_REQUIRED, FF13_PARAMS_X32) and E6 the aggregator and the Exemplars fields the
# pin lists under pii_fields, in any Slack message or Logger call body.
DEFAULT_X32 = os.path.join(REPO_ROOT, "audit", "x32.json")
X32_SEARCH = "airtable:ActionSearchRecords"
X32_AGGREGATOR = "builtin:BasicAggregator"
X32_ROLES = ("exemplar_code", "status", "document_code", "visa_code", "firm", "fact_pattern_tags", "skeleton", "terms",
             "rank_key", "term_count")
# The aggregator keys and the Exemplars field role each one reads, in the order of specs/X-32-exemplars.md section 4.
X32_AGG_KEYS = (("id", None), ("rank_key", "rank_key"), ("skeleton", "skeleton"), ("terms", "terms"))
_X32_FIRM = re.compile(r"[A-Z0-9][A-Z0-9-]{1,30}")
_X32_FIELD_NAME = re.compile(r"[^{}'\"`|\n]{1,60}")


@dataclass
class X32Pin:
    """audit/x32.json. table_id None means the table is not created yet, and the table is then recognised by its name."""
    table_id: str | None = None
    table_name: str = "Exemplars"
    firm_code: str | None = None
    max_candidates: int = 100
    fields: dict = field(default_factory=lambda: {
        "exemplar_code": "Exemplar Code", "status": "Status", "document_code": "Document Code", "visa_code": "Visa Code",
        "firm": "Firm", "fact_pattern_tags": "Fact Pattern Tags", "skeleton": "Skeleton",
        "terms": "Residual Quasi-Identifiers", "rank_key": "Rank Key", "term_count": "Term Count"})
    pii_fields: tuple = ("Skeleton", "Residual Quasi-Identifiers", "Source Note", "Consent Reference")
    selection_directive: str = "Ignore"


# The directives go-ahead 8 may pin on the Exemplars search and the ranker. Resume is never one of them (spec section 4).
X32_DIRECTIVES = ("Ignore", "Break")


def load_x32(path: str = DEFAULT_X32, required: bool = True) -> X32Pin:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no X-32 pin at {path}. Checks E35 to E37 need it")
        return X32Pin()
    data = _read_json(path)
    name = os.path.basename(path)
    if not isinstance(data, dict):
        raise InputError(f"{name} is not an object")
    known = {"exemplars_table_id", "exemplars_table_name", "firm_code", "max_candidates", "fields", "field_ids", "pii_fields",
             "selection_directive"}
    extra = sorted(k for k in data if not str(k).startswith("_") and k not in known)
    if extra:
        raise InputError(f"{name} has unknown keys {extra}")
    tid = data.get("exemplars_table_id")
    if tid is not None and not (isinstance(tid, str) and re.fullmatch(r"tbl[A-Za-z0-9]{14}", tid)):
        raise InputError(f"{name} exemplars_table_id must be null or an Airtable table ID")
    tname = data.get("exemplars_table_name")
    if not (isinstance(tname, str) and _X32_FIELD_NAME.fullmatch(tname.strip() or "")):
        raise InputError(f"{name} needs exemplars_table_name, the Airtable name of the Exemplars table")
    firm = data.get("firm_code")
    if not (isinstance(firm, str) and _X32_FIRM.fullmatch(firm)):
        raise InputError(f"{name} firm_code must be 2 to 31 capital letters, digits or hyphens (the Firm option and the "
                         f"literal of the search formula)")
    cap = data.get("max_candidates")
    if not (isinstance(cap, int) and not isinstance(cap, bool) and 1 <= cap <= 100):
        raise InputError(f"{name} max_candidates must be an integer from 1 to 100 (the search's Limit)")
    fields = data.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(X32_ROLES):
        raise InputError(f"{name} fields must name exactly the roles {list(X32_ROLES)}")
    for role, fname in fields.items():
        if not (isinstance(fname, str) and fname == fname.strip() and _X32_FIELD_NAME.fullmatch(fname)):
            raise InputError(f"{name} fields.{role} must be an Airtable field name with no quote, brace, backtick or bar")
    if len({f.casefold() for f in fields.values()}) != len(fields):
        raise InputError(f"{name} fields names one field for two roles")
    ids = data.get("field_ids", {})
    if not isinstance(ids, dict) or any(k not in X32_ROLES for k in ids) \
            or any(v is not None and not (isinstance(v, str) and re.fullmatch(r"fld[A-Za-z0-9]{14}", v)) for v in ids.values()):
        raise InputError(f"{name} field_ids maps roles to null or an Airtable field ID")
    pii = data.get("pii_fields")
    if not (isinstance(pii, list) and pii and all(isinstance(p, str) and _X32_FIELD_NAME.fullmatch(p) for p in pii)):
        raise InputError(f"{name} pii_fields must list the Exemplars field names that carry exemplar text")
    for role in ("skeleton", "terms"):
        if fields[role] not in pii:
            raise InputError(f"{name} pii_fields must hold the {role} field {fields[role]!r}")
    directive = data.get("selection_directive")
    if directive not in X32_DIRECTIVES:
        raise InputError(f"{name} selection_directive must be one of {list(X32_DIRECTIVES)} (go-ahead 8: the directive of the "
                         f"Exemplars search and the ranker, never Resume)")
    return X32Pin(tid, tname.strip(), firm, cap, dict(fields), tuple(pii), directive)


def _x32_field_ref(mid: object, fname: str) -> str:
    return f"{mid}.{fname}" if re.fullmatch(r"[A-Za-z_]\w*", fname) else f"{mid}.`{fname}`"


def x32_formula(pin: X32Pin, grounding_id: object, trig: dict | None = None, links: "AirtableMap | None" = None) -> str:
    """The one search formula E36 accepts (specs/X-32-exemplars.md section 4), before normalisation."""
    f = pin.fields
    params = (trig or {}).get("parameters") if isinstance((trig or {}).get("parameters"), dict) else {}
    ids = params.get("useColumnId") is True
    lead = ((links.tables.get(LEAD_TABLE) or {}).get("fields") or {}) if links is not None else {}

    def trig_ref(role: str) -> str:
        fid, fname = FF13_TRIGGER_FIELDS[role]
        fid = next((k for k, v in lead.items() if v == fname), fid)
        return f"{{{{1.{fid}}}}}" if ids else f"{{{{{_x32_field_ref(1, fname)}}}}}"

    status = f'{{{{if({grounding_id}.gate_mode = "test"; "TEST"; "Active")}}}}'
    return (f"AND({{{f['firm']}}} = '{pin.firm_code}', {{{f['document_code']}}} = '{trig_ref('document type')}', "
            f"{{{f['visa_code']}}} = '{trig_ref('visa code')}', {{{f['status']}}} = '{status}')")


def _x32_formula_norm(v: object) -> str | None:
    """A search formula with whitespace runs collapsed and the whitespace next to ( ) , = ; removed, the mappings inside
    through _norm_iml. The pinned and the live formula pass through the same function, so only layout differs."""
    if not isinstance(v, str):
        return None
    out = _norm_iml(v)
    out = re.sub(r"\s+", " ", str(out).strip())
    return re.sub(r"\s*([(),=;])\s*", r"\1", out)


def x32_agg_mapper(pin: X32Pin, sid: object) -> dict:
    return {k: (f"{{{{{sid}.id}}}}" if role is None else f"{{{{{_x32_field_ref(sid, pin.fields[role])}}}}}")
            for k, role in X32_AGG_KEYS}


def x32_forms(agg: object, rank: object) -> dict:
    """The three exemplar mappings, normalised: skeleton (the drafter), terms (the validator's @08), candidates (the ranker)."""
    return {"skeleton": f'{{{{replace(first(map({agg}.array;"skeleton";"id";{rank}.exemplar_record_id));"/</g";" less than ")}}}}',
            "terms": f'{{{{first(map({agg}.array;"terms";"id";{rank}.exemplar_record_id))}}}}',
            "candidates": f'{{{{join(map({agg}.array;"rank_key");newline)}}}}'}


def _x32_table(m: dict, pin: X32Pin) -> str | None:
    """"yes" when an Airtable module's table is the Exemplars table (by ID, or by name case-insensitive), "mapped" when its
    table or base is a mapping, else None. Airtable API and HTTP modules: "yes" when the URL names the table."""
    t = _mtype(m)
    if t.startswith("airtable:") and t.lower() != AIRTABLE_API_CALL.lower():
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        for src in (_mapper(m), params):
            raw = src.get("table")
            if is_mapping(raw) or is_mapping(src.get("base")):
                return "mapped"
            if isinstance(raw, str) and raw.strip() and (raw.strip() == (pin.table_id or "\x00")
                                                          or raw.strip().casefold() == pin.table_name.casefold()):
                return "yes"
        return None
    if _airtable_api_module(m):
        text = " ".join(_strings(_mapper(m))).replace("%20", " ")
        names = [re.escape(pin.table_name)] + ([re.escape(pin.table_id)] if pin.table_id else [])
        if any(re.search(r"(?<![\w])" + n + r"(?![\w])", text, re.I) for n in names):
            return "yes"
        if _x32_api_url_mapped(_mapper(m).get("url")):
            return "mapped"
    return None


def _x32_api_url_mapped(url: object) -> bool:
    """True when an Airtable API or HTTP URL holds a mapping where the base or the table sits (/v0/<base>/<table>), so the
    request may reach any table. A literal table segment (another table) or the meta API is not mapped. A URL with a
    mapping and no /v0/ path the audit can read counts as mapped. A missing or literal URL is not."""
    if not isinstance(url, str) or "{{" not in url:
        return False
    at = url.find("/v0/")
    if at < 0:
        return True
    segs = url[at + 4:].split("?", 1)[0].split("/")
    if segs[0].strip().lower() == "meta":
        return False
    if len(segs) < 2 or not segs[1].strip():
        return True
    return "{{" in segs[1]


def _x32_writes(m: dict) -> bool:
    low = _mtype(m).lower()
    if low.startswith("airtable:") and low != AIRTABLE_API_CALL.lower():
        return any(w in low for w in ("create", "update", "upsert", "delete"))
    return _api_write(m)


def _x32_searches(ctx: "_EContext") -> list[tuple]:
    return [(m, e, c) for m, e, c in ctx.order if _mtype(m) == X32_SEARCH and _x32_table(m, ctx.x32) == "yes"]


def _x32_aggregators(ctx: "_EContext") -> list[dict]:
    """Array aggregators fed by an Exemplars search."""
    sids = {m.get("id") for m, _e, _c in _x32_searches(ctx)}
    out = []
    for m, _e, _c in ctx.order:
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        if _mtype(m) == X32_AGGREGATOR and params.get("feeder") in sids:
            out.append(m)
    return out


def _x32_rankers(ctx: "_EContext") -> list[tuple]:
    return [(m, e, c) for m, e, c in ctx.order
            if _mtype(m) == FF13_MODULE and ff13_function(m, ctx.logger, ctx.ff10.connection_id) == "rank_exemplars"]


def _x32_pairs(ctx: "_EContext", before: set) -> list[tuple]:
    """(aggregator ID, ranker ID) pairs that both run before a module (before is its _before_ids)."""
    aggs = [a.get("id") for a in _x32_aggregators(ctx) if a.get("id") in before]
    ranks = [r.get("id") for r, _e, _c in _x32_rankers(ctx) if r.get("id") in before]
    return [(a, r) for a in aggs for r in ranks]


def _x32_drafters(ctx: "_EContext") -> dict:
    """drafter ID -> validator modules that map its P5 text as the draft (the E32 reading)."""
    out: dict = {}
    for m, _e, _c in ctx.order:
        if _mtype(m) != FF13_MODULE or ff13_function(m, ctx.logger, ctx.ff10.connection_id) != "validate_draft":
            continue
        for _path, val in _ff13_leaves(_mapper(m), "mapper"):
            hit = _FF10_P5.match(_norm_iml(val)) if isinstance(val, str) else None
            if hit:
                out.setdefault(int(hit.group(1)), []).append(m)
    return out


def _x32_reads_content(m: dict, n: object) -> bool:
    return any(r.module == n and str(r.field).startswith("content") for _p, e in _module_exprs(m) for r in iml_refs(e))


def _x32_outline_problem(ctx: "_EContext", o: int) -> str | None:
    """Why Claude module o is not the outline: the drafter's own text, or text no later Claude module reads."""
    if o in _x32_drafters(ctx):
        return f"maps the text of Claude module {o}, which is the drafter, not the outline the drafter reads"
    readers = [m.get("id") for m, e, _c in ctx.order if is_claude_call(m) and not e and m.get("id") != o
               and _x32_reads_content(m, o)]
    if not readers:
        return f"maps the text of Claude module {o}, which no later Claude module reads, so it is not the outline"
    return None


def _x32_pii_source(ctx: "_EContext", r: "Ref") -> str | None:
    """What client exemplar text a reference carries (E6 widened by X-32), or None."""
    hit = ctx.modules.get(r.module)
    if hit is None:
        return None
    src = hit[0]
    if _mtype(src) == X32_AGGREGATOR and src in _x32_aggregators(ctx):
        return f"the Exemplars aggregator {r.module} (skeletons and quasi-identifier terms)"
    if _mtype(src).startswith("airtable:") and _x32_table(src, ctx.x32) in ("yes", "mapped"):
        if str(r.field).strip().casefold() in {p.casefold() for p in ctx.x32.pii_fields}:
            return f"the Exemplars field `{r.field}` of module {r.module}"
    return None


def _rule_e35(ctx: "_EContext") -> None:
    role = _ff10_role(ctx.b, ctx.ff10)
    name = ctx.x32.table_name + (f" ({ctx.x32.table_id})" if ctx.x32.table_id else "")
    for m, in_err, _chain in ctx.order:
        hit = _x32_table(m, ctx.x32)
        if hit is None:
            continue
        where = " (in an error route)" if in_err else ""
        if hit == "mapped":
            if _x32_writes(m):
                ctx.emit("E35", FAIL, m, f"is {_mtype(m)}{where} with a mapped table or base, so it may write the {name} "
                                         f"table, which no Make module writes (specs/X-32-exemplars.md). Name the table as a "
                                         f"literal", strict=True)
            else:
                ctx.emit("E35", FAIL, m, f"is {_mtype(m)}{where} with a mapped table or base, so it may read the {name} "
                                         f"table, which only {_ff10_owner_text(ctx.ff10)} reads through the one search E36 "
                                         f"pins, and E6 cannot tell which fields it hands on. Name the table as a literal",
                         strict=True)
            continue
        if _x32_writes(m):
            ctx.emit("E35", FAIL, m, f"writes the {name} table{where}. No Make module writes it: the RCIC and staff edit "
                                     f"exemplars in Airtable and the Status formula decides what is selectable", strict=True)
            continue
        if role == "other":
            ctx.emit("E35", FAIL, m, f"reads the {name} table{where}, which only {_ff10_owner_text(ctx.ff10)} reads, through "
                                     f"the one search E36 pins", strict=True)
        elif _mtype(m) != X32_SEARCH:
            ctx.emit("E35", FAIL, m, f"reads the {name} table through {_mtype(m)}{where}. The owner reads it only through the "
                                     f"one Search Records module E36 pins", strict=True)


def _rule_e36(ctx: "_EContext") -> None:
    if _ff10_role(ctx.b, ctx.ff10) == "other":
        return
    pin = ctx.x32
    searches = _x32_searches(ctx)
    for m, _e, _c in searches[1:]:
        ctx.emit("E36", FAIL, m, f"is a second Exemplars search. The drafting chain holds exactly one (module "
                                 f"{searches[0][0].get('id')})", strict=True)
    rankers = _x32_rankers(ctx)
    if not searches:
        for m, _e, _c in rankers:
            ctx.emit("E36", FAIL, m, "calls ff13.rank_exemplars with no Exemplars search in the scenario, so its candidates "
                                     "come from nowhere E36 pins", strict=True)
        return
    s, s_err, s_chain = searches[0]
    sid = s.get("id")
    problems: list[str] = []
    if s_err:
        problems.append("it sits in an error route")
    drafters = _x32_drafters(ctx)
    flow, idx = s_chain[-1]
    on_flow = [x.get("id") for x in flow[idx + 1:] if isinstance(x, dict)]
    mine = [d for d in sorted(drafters) if d in on_flow]
    if len(mine) != 1:
        problems.append("no drafter (the Claude module whose text ff13.validate_draft checks) follows it on its flow"
                        if not mine else f"more than one drafter follows it on its flow ({', '.join(map(str, mine))})")
    d = mine[0] if len(mine) == 1 else None
    before = _before_ids(s_chain)
    if d is not None:
        dm = ctx.modules[d][0]
        outlines = [o for o in sorted(before) if isinstance(o, int) and o in ctx.modules
                    and is_claude_call(ctx.modules[o][0]) and _x32_reads_content(dm, o)]
        if len(outlines) != 1:
            problems.append("the drafter reads no outline that runs before the search" if not outlines else
                            f"the drafter reads more than one Claude module before the search ({', '.join(map(str, outlines))})")
        else:
            o = outlines[0]
            if not _e32_has(s_chain, _e32_cond(f"{{{{{o}.stop_reason}}}}", ("text:equal", "text:equal:ci"), ("end_turn",))):
                problems.append(f"no filter on its path (itself included) holds {{{{{o}.stop_reason}}}} text equal end_turn "
                                f"in every OR group, so a cut-off outline would still select an exemplar")
    groundings = [g for g in sorted(x for x in before if isinstance(x, int)) if g in ctx.modules
                  and ff13_function(ctx.modules[g][0], ctx.logger, ctx.ff10.connection_id) == "drafting_context"]
    if len(groundings) != 1:
        problems.append("no ff13.drafting_context call runs before it" if not groundings else
                        "more than one ff13.drafting_context call runs before it")
    else:
        trig = (ctx.b.bp.get("flow") or [{}])[0]
        want = x32_formula(pin, groundings[0], trig if isinstance(trig, dict) else None, ctx.links)
        if _x32_formula_norm(_mapper(s).get("formula")) != _x32_formula_norm(want):
            problems.append(f"its formula is not exactly the pinned one ({want})")
    mp = _mapper(s)
    if str(mp.get("maxRecords", "")).strip() != str(pin.max_candidates):
        problems.append(f"maxRecords is not exactly {pin.max_candidates} (audit/x32.json)")
    if mp.get("sort") != [{"field": pin.fields["exemplar_code"], "direction": "asc"}]:
        problems.append(f"sort is not exactly {pin.fields['exemplar_code']} ascending")
    if mp.get("view") not in (None, ""):
        problems.append("it reads through a view, whose filter the blueprint does not show")
    want_fields = {pin.fields[r] for _k, r in X32_AGG_KEYS if r}
    want_fields.add(pin.fields["exemplar_code"])
    if not (isinstance(mp.get("fields"), list) and set(mp["fields"]) == want_fields and len(mp["fields"]) == len(want_fields)):
        problems.append(f"its output fields are not exactly {', '.join(sorted(want_fields))}")
    if mp.get("useColumnId") is not False:
        problems.append("useColumnId is not false, and the formula, sort and aggregator read fields by name")
    trig = (ctx.b.bp.get("flow") or [{}])[0]
    tbase = (trig.get("parameters") or {}).get("base") if isinstance(trig, dict) else None
    if not (isinstance(mp.get("base"), str) and mp.get("base") == tbase):
        problems.append("its base is not the trigger's base")
    nxt = flow[idx + 1] if idx + 1 < len(flow) and isinstance(flow[idx + 1], dict) else None
    agg = None
    if nxt is None or _mtype(nxt) != X32_AGGREGATOR or (nxt.get("parameters") or {}).get("feeder") != sid:
        problems.append(f"the next module is not an array aggregator fed by it ({X32_AGGREGATOR}, feeder {sid})")
    else:
        agg = nxt
        got = {k: _norm_iml(v) for k, v in _mapper(agg).items()} if isinstance(agg.get("mapper"), dict) else None
        if got != {k: _norm_iml(v) for k, v in x32_agg_mapper(pin, sid).items()}:
            problems.append(f"aggregator {agg.get('id')} does not map exactly id, rank_key, skeleton and terms from module {sid}")
        if _norm_groups(agg):
            problems.append(f"aggregator {agg.get('id')} carries a filter")
    nxt2 = flow[idx + 2] if agg is not None and idx + 2 < len(flow) and isinstance(flow[idx + 2], dict) else None
    if agg is not None:
        if nxt2 is None or not any(nxt2 is r for r, _e, _c in rankers):
            problems.append(f"the module after aggregator {agg.get('id')} is not the ff13.rank_exemplars call")
        elif _norm_groups(nxt2):
            problems.append(f"the ranker {nxt2.get('id')} carries a filter")
    for a in _x32_aggregators(ctx):
        if a is not agg:
            ctx.emit("E36", FAIL, a, f"is a second aggregator fed by the Exemplars search {sid}", strict=True)
    for r, _e, _c in rankers:
        if r is not nxt2:
            ctx.emit("E36", FAIL, r, "is an ff13.rank_exemplars call that is not the one right after the Exemplars aggregator",
                     strict=True)
    why = _x32_handler_problem(ctx, s)
    if why:
        problems.append(why)
    for r, _e, _c in rankers:
        why = _x32_handler_problem(ctx, r)
        if why:
            ctx.emit("E36", FAIL, r, f"is the ff13.rank_exemplars call of the drafting chain and {why}", strict=True)
    if problems:
        ctx.emit("E36", FAIL, s, f"is the Exemplars search of the drafting chain and {', and '.join(problems)}", strict=True)


def _x32_handler_problem(ctx: "_EContext", m: dict) -> str | None:
    """Why the error handler of the Exemplars search or of the ranker is not exactly [Logger call, the pinned directive],
    or None. A Resume is named on its own: its substitute output (a literal row, or a literal exemplar_record_id) would
    reach the aggregator, the ranker or the drafter as if Airtable or the database had returned it, past the Status
    formula and the ranker's test-seed refusal (specs/X-32-exemplars.md section 4)."""
    want = ctx.x32.selection_directive
    oe = _onerror(m)
    mods = _handler_modules(oe)
    types = [_mtype(x) for x in mods]
    if "builtin:Resume" in types:
        return (f"its error handler holds a Resume, whose substitute output would reach the ranker or the drafter as if "
                f"Airtable or the database had returned it. The handler is exactly [Logger call, {want}] (audit/x32.json "
                f"selection_directive)")
    if not (len(oe) == 2 and len(mods) == 2 and is_logger_call(oe[0], ctx.logger) and types[1] == f"builtin:{want}"):
        return f"its error handler is not exactly [Logger call, {want}] (audit/x32.json selection_directive, go-ahead 8)"
    return None


def _rule_e37(ctx: "_EContext") -> None:
    if _ff10_role(ctx.b, ctx.ff10) == "other":
        return
    searches = _x32_searches(ctx)
    if not searches:
        return
    s = searches[0][0]
    sid = s.get("id")
    aggs = [a for a in _x32_aggregators(ctx) if (a.get("parameters") or {}).get("feeder") == sid]
    rankers = _x32_rankers(ctx)
    agg = aggs[0] if aggs else None
    rank = rankers[0][0] if rankers else None
    handler_of_s = {x.get("id") for x in _handler_modules(_onerror(s))}
    drafters = _x32_drafters(ctx)
    forms = x32_forms(agg.get("id"), rank.get("id")) if agg is not None and rank is not None else {}
    seen_skeleton: dict = {}
    seen_terms: dict = {}
    for m, in_err, _chain in ctx.order:
        mid = m.get("id")
        if m is s or m is agg:
            continue
        exprs = [(p, e) for p, e in _module_exprs(m)]
        s_refs = [(p, e) for p, e in exprs if any(r.module == sid for r in iml_refs(e))]
        bad_s = [p for p, e in s_refs if not (mid in handler_of_s and all(r.module != sid or str(r.field).startswith("error")
                                                                         for r in iml_refs(e)))]
        if bad_s:
            ctx.emit("E37", FAIL, m, f"maps the output of the Exemplars search {sid} ({_short_path(bad_s[0])}). Only the "
                                     f"aggregator reads it", strict=True)
        if agg is None:
            continue
        a_refs = [(p, e) for p, e in exprs if any(r.module == agg.get("id") for r in iml_refs(e))]
        if not a_refs:
            continue
        normed = [_norm_iml("{{" + e + "}}") for _p, e in a_refs]
        if rank is not None and m is rank:
            if normed != [forms["candidates"]]:
                ctx.emit("E37", FAIL, m, f"maps aggregator {agg.get('id')} other than once as exactly {forms['candidates']}",
                         strict=True)
        elif mid in drafters and not in_err:
            content = ((_mapper(m).get("messages") or [{}])[0] or {}).get("content") if isinstance(_mapper(m).get("messages"), list) else None
            ok = bool(forms) and normed == [forms["skeleton"]] and all(p == "mapper.messages[0].content" for p, _e in a_refs)
            if ok:
                at = content.find("{{" + a_refs[0][1] + "}}") if isinstance(content, str) else -1
                ok = (at >= 0 and content.count("<exemplar>") == 1 and content.count("</exemplar>") == 1
                      and content.index("<exemplar>") < at < content.index("</exemplar>"))
            seen_skeleton[mid] = ok
            if not ok:
                ctx.emit("E37", FAIL, m, f"is the drafter and does not map the exemplar skeleton exactly once, inside <exemplar> "
                                         f"and </exemplar> of its user message, as {forms.get('skeleton', 'the pinned form')}",
                         strict=True)
        elif _mtype(m) == FF13_MODULE and ff13_function(m, ctx.logger, ctx.ff10.connection_id) == "validate_draft" and not in_err:
            key = _ff13_key_of("validate_draft", "exemplar terms")
            ok = bool(forms) and normed == [forms["terms"]] and [p for p, _e in a_refs] == [f"mapper.{key}"]
            seen_terms[mid] = ok
            if not ok:
                ctx.emit("E37", FAIL, m, f"is the validator and does not map {key} exactly as {forms.get('terms', 'the pinned form')}",
                         strict=True)
        else:
            ctx.emit("E37", FAIL, m, f"maps the Exemplars aggregator {agg.get('id')} (skeletons and quasi-identifier terms). "
                                     f"Only the drafter, the validator's {_ff13_key_of('validate_draft', 'exemplar terms')} and "
                                     f"the ranker may", strict=True)
    if agg is None or rank is None:
        return
    for d, validators in sorted(drafters.items()):
        if d not in ctx.modules or ctx.modules[d][1]:
            continue
        for v in validators:
            vid = v.get("id")
            if d in seen_skeleton and vid not in seen_terms:
                ctx.emit("E37", FAIL, v, f"leaves {_ff13_key_of('validate_draft', 'exemplar terms')} without the terms of the "
                                         f"exemplar drafter {d} reads, so the validator cannot check the draft against them",
                         strict=True)
            if vid in seen_terms and d not in seen_skeleton:
                ctx.emit("E37", FAIL, ctx.modules[d][0], f"maps no exemplar skeleton while validator {vid} receives exemplar terms",
                         strict=True)


# --- X-16 Phase A (X-16.1, the review trail of Module F) -------------------
# specs/X-16-options.md sections 3.0 and 6.5, decided by Rizwan 2026-11-16 (Phase A only, staff-only review folder for
# production Docs, test Docs stay in Generated Submission). Pin audit/x16.json. None of these rows can be allowlisted.
# E38 In the X-16 owner, a json:ParseJSON P sits on the outline's flow right after the outline's call row and right
#     before the outline router (flow [outline, call row, P, router]), its input exactly the P5 text of the outline, no
#     filter, handler exactly [Logger call, Resume] with no substitute output. Each of the seven outcome routes, found by
#     the module ID of its Applicants update and that update's router and route position (X16_ROUTES, read from the
#     committed 7049689 snapshot 2026-11-16), creates exactly one Draft Reviews row, after the update on the route's own
#     flow, unfiltered, with handler [Logger call, Resume] and exactly the pinned record (X16_FIELDS roles): the execution
#     ID, Applicant as the list ["{{1.id}}"], the route's Outcome literal, Gate Mode and Grounding ID from the
#     drafting_context call, the six validator fields on the routes after the validator, Risk Flags and Weak Grounds from
#     P, Outline JSON as the outline's P5 text, Assigned RCIC from RCIC of Record and the Sign-off State literal (Pending on
#     the two Draft Ready routes, Not approvable on the other five). On the two Draft Ready routes the route's Doc create
#     is followed by one google-docs:getADocument G that reads exactly {{<doc>.id}}, unfiltered, with handler [Logger call,
#     Resume], ahead of the row, and the row adds Doc ID {{<doc>.id}}, Doc Link {{<doc>.webViewLink}} and Generated Text
#     SHA256 as the guarded hash {{if(G.text; sha256(G.text); "")}} (a Resume after a failed read gives no digest of empty
#     text). The row sits right after the update, with only G between on the Draft Ready routes, and G's mapper is exactly
#     select map, document, includeTabsContent false and filter image (both required, Make validator 2026-11-16). Any other
#     Draft Reviews create of the owner FAILs, and so does any other owner write of the table (an update, an upsert, an API
#     or HTTP write, a record key that is a Draft Reviews field ID), since the owner writes each row once (6.2). An
#     Applicants Drafting Status write outside error routes after the outline that is not one of the seven pinned updates
#     FAILs (an unpinned outcome route). A missing row sits on the router that holds the route, since the push that adds it
#     changes that router's child list and nothing else on the route.
#     X-16.2 (measured 2026-11-17, T1 run f9939a2e): Make hands the validator's JSONB detail to Airtable as an object
#     although the module's interface types it text, and Airtable refused the row with 422 "Cannot parse value" for
#     Validator Detail, so no route wrote its row. So a json:TransformToJSON J sits right after the validator V on V's own
#     flow, its mapper exactly {"object": "{{V.detail}}"}, parameters empty or only space, no filter, handler exactly
#     [Logger call, Resume], and Validator Detail is {{J.json}}. Validation ID and Grounding ID are BIGINT columns, which
#     node-postgres returns as text by default (Make's interface says integer, not measured at run time), so they are
#     {{parseNumber(V.ledger_id)}} and {{parseNumber(G.grounding_id)}}, a number either way (the one-argument form runs in
#     Daily API Cost Audit 4229542). A missing J sits on the module whose child list holds V.
# E39 Only the X-16 owner creates Draft Reviews rows or writes a Draft Reviews field (a native write on the table by ID or
#     name, a record key that is a Draft Reviews field ID, an Airtable API or HTTP write that names the table). No module
#     of any scenario deletes a Draft Reviews row, and none writes the Applicants inverse link (Draft Reviews), since the
#     row's own Applicant field links it. A write whose table is a mapping is E35's row. Error routes count.
# E40 No client send (the P6 predicate), Drive or Docs share, access change, copy, move, shortcut, template copy, API call,
#     Doc create, append or replace, Drive upload, text file or content update, and no HTTP call to the Drive or Docs API
#     that is not a GET, in any scenario, maps the working Doc: Applicants Draft Doc Link, a Draft Reviews Doc ID or Doc
#     Link, a Google Docs create of the owner, or any module output fed by one of those (a download or an export included,
#     Airtable rows excepted, a later read of the field is caught by name). And no scenario but the owner creates a Google
#     Doc or uploads a file that carries Claude content (directly or through a parser, a variable or a Doc): FAIL when the
#     manifest shows the scenario active or its state is unknown, REVIEW while it is inactive (question 8 of the options).
# E6 widened: the Draft Reviews fields x16.json lists as PII, every output of a json:ParseJSON fed by Claude content, the
#     text and title of a Google Docs getADocument, the data of an export or a download and the body of a Docs or Drive API
#     call are client data in a Slack message or a Logger call body (strict), directly or through a transform module (a
#     variable, a parser, an aggregator, a text or regex step) that maps one of them.
# E32 changed (production Doc): folderId exactly /<review_folder_id of audit/x16.json> and a name that holds {{1.id}}. While
#     review_folder_id is null every production Doc FAILs as owner pending. A test Doc's folderId is exactly /<test_folder_id>.
DEFAULT_X16 = os.path.join(REPO_ROOT, "audit", "x16.json")
X16_FIELD_ROLES = ("draft_execution_id", "applicant", "outcome", "gate_mode", "verdict", "validation_id", "grounding_id",
                   "hard_fails", "soft_flags", "risk_flags", "weak_grounds", "validator_note", "validator_detail",
                   "outline_json", "assigned_rcic", "doc_id", "doc_link", "generated_text_sha256", "signoff_state")
X16_VALIDATOR_ROLES = ("verdict", "validation_id", "hard_fails", "soft_flags", "validator_note", "validator_detail")
X16_DOC_ROLES = ("doc_id", "doc_link", "generated_text_sha256")
# (Applicants update ID, its router, 0-based route index, Outcome literal, route runs after the validator, Doc create ID).
# Read from blueprints/module-f-drafting-chain__7049689.json 2026-11-16. Re-pin in a reviewed commit when a push moves them.
X16_ROUTES = (
    (14, 13, 0, "No Draft - Inputs Read as Instructions", True, None),
    (17, 13, 1, "No Draft - Facts Do Not Support", True, None),
    (21, 12, 1, "Draft Ready", True, 20),
    (25, 12, 2, "Draft Ready", True, 24),
    (28, 12, 3, "Validator Rejected", True, None),
    (31, 12, 4, "Validator Fallback", True, None),
    (34, 8, 1, "Outline Failed", False, None),
)
X16_OUTLINE_ROUTER = 8   # the router on the outline's stop reason. P sits right before it.
X16_PENDING_STATE = {True: "Pending", False: "Not approvable"}
X16_PARSE = "json:ParseJSON"
X16_DETAIL_JSON = "json:TransformToJSON"   # X-16.2: the validator's JSONB detail as text (see E38 above)
X16_GET_DOC = "google-docs:getADocument"
# Outputs of Get Content of a Document that carry the Doc's text (Make MCP app-module_get google-docs v1, 2026-11-16).
X16_DOC_TEXT_OUTPUTS = ("text", "body", "tabs", "headers", "footers", "footnotes", "title", "lists", "inlineObjects")
# The pinned Get a Document mapper (document is the route's Doc, checked on its own).
X16_GET_DOC_MAPPER = {"select": "map", "document": None, "includeTabsContent": False, "filter": "image"}
# Other module outputs that carry a Doc's or a Drive file's content (E6): an export or a download (data) and the body of a
# Docs or Drive API call.
X16_FILE_CONTENT_OUTPUTS = {"google-docs:exportADocument": ("data",), "google-docs:makeApiCall": ("body",),
                            "google-drive:getAFile": ("data",), "google-drive:downloadAFile": ("data",),
                            "google-drive:exportAFile": ("data",), "google-drive:makeApiCall": ("body",)}
_X16_FOLDER = re.compile(r"[A-Za-z0-9_-]{10,}")
_X16_FIELD_ID = re.compile(r"fld[A-Za-z0-9]{14}")


def x16_weak_grounds(p: object) -> str:
    """The pinned Weak Grounds value: every ground the outline marks not_supported, then partly_supported, by provision key,
    each list followed by the gaps of the same grounds in the same order (specs/F-F10-prompts.md, outline schema)."""
    def keys(support: str, key: str) -> str:
        return f'{{{{join(map({p}.grounds; "{key}"; "support"; "{support}"); newline)}}}}'
    return (f"Not supported:\n{keys('not_supported', 'provision_key')}\n\nTheir gaps, in the same order:\n"
            f"{keys('not_supported', 'gap')}\n\nPartly supported:\n{keys('partly_supported', 'provision_key')}\n\n"
            f"Their gaps, in the same order:\n{keys('partly_supported', 'gap')}")


def x16_doc_hash(g: object) -> str:
    return f'{{{{if({g}.text; sha256({g}.text); "")}}}}'


@dataclass
class X16Pin:
    """audit/x16.json. loaded False (no file read) switches the X-16 rules off, the state of a partial unit test."""
    loaded: bool = False
    owner_scenario_id: str | None = None
    owner_name: str = "Module F Drafting Chain"
    table_id: str | None = None
    table_name: str = "Draft Reviews"
    fields: dict = field(default_factory=dict)        # role -> field ID
    pii_roles: tuple = ()
    applicants_link_field: str | None = None
    review_folder_id: str | None = None
    test_folder_id: str | None = None


def load_x16(path: str = DEFAULT_X16, required: bool = True) -> X16Pin:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no X-16 review pin at {path}. Checks E38 to E40 and the E32 production folder need it")
        return X16Pin()
    data = _read_json(path)
    name = os.path.basename(path)
    if not isinstance(data, dict):
        raise InputError(f"{name} is not an object")
    known = {"owner_scenario_id", "owner_name", "draft_reviews_table_id", "draft_reviews_table_name", "fields", "pii_fields",
             "applicants_link_field", "review_folder_id", "test_folder_id"}
    extra = sorted(k for k in data if not str(k).startswith("_") and k not in known)
    if extra:
        raise InputError(f"{name} has unknown keys {extra}")
    sid = data.get("owner_scenario_id")
    if sid is not None and not ((isinstance(sid, int) and not isinstance(sid, bool) and sid > 0)
                                or (isinstance(sid, str) and re.fullmatch(r"[1-9]\d*", sid))):
        raise InputError(f"{name} owner_scenario_id must be null or a Make scenario ID")
    owner = data.get("owner_name")
    if not isinstance(owner, str) or not owner.strip():
        raise InputError(f"{name} needs owner_name")
    tid = data.get("draft_reviews_table_id")
    if not (isinstance(tid, str) and re.fullmatch(r"tbl[A-Za-z0-9]{14}", tid)):
        raise InputError(f"{name} draft_reviews_table_id must be an Airtable table ID")
    tname = data.get("draft_reviews_table_name")
    if not (isinstance(tname, str) and tname.strip() and _X32_FIELD_NAME.fullmatch(tname.strip())):
        raise InputError(f"{name} needs draft_reviews_table_name")
    fields = data.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(X16_FIELD_ROLES):
        raise InputError(f"{name} fields must name exactly the roles {list(X16_FIELD_ROLES)}")
    if any(not (isinstance(v, str) and _X16_FIELD_ID.fullmatch(v)) for v in fields.values()) \
            or len(set(fields.values())) != len(fields):
        raise InputError(f"{name} fields must map each role to a distinct Airtable field ID")
    pii = data.get("pii_fields")
    if not (isinstance(pii, list) and pii and all(p in X16_FIELD_ROLES for p in pii) and len(set(pii)) == len(pii)):
        raise InputError(f"{name} pii_fields must be a non-empty list of field roles")
    link = data.get("applicants_link_field")
    if not (isinstance(link, str) and _X16_FIELD_ID.fullmatch(link)) or link in fields.values():
        raise InputError(f"{name} applicants_link_field must be the Applicants inverse link field ID")
    test = data.get("test_folder_id")
    if not (isinstance(test, str) and _X16_FOLDER.fullmatch(test)):
        raise InputError(f"{name} test_folder_id must be a Drive folder ID (the F-F10 test folder)")
    review = data.get("review_folder_id")
    if review is not None and not (isinstance(review, str) and _X16_FOLDER.fullmatch(review)):
        raise InputError(f"{name} review_folder_id must be null or a Drive folder ID")
    if review is not None and review == test:
        raise InputError(f"{name} review_folder_id is the test folder. Production Docs go to the staff-only review folder")
    return X16Pin(True, str(sid) if sid is not None else None, owner.strip(), tid, tname.strip(), dict(fields), tuple(pii),
                  link, review, test)


def check_pins_agree(ff10: FF10Pin, x16: X16Pin) -> None:
    """The X-16 owner is the F-F10 owner (the drafting chain writes the review trail), so the two pins name one scenario."""
    if x16.loaded and (ff10.owner_scenario_id != x16.owner_scenario_id or ff10.owner_name != x16.owner_name):
        raise InputError("audit/x16.json and audit/ff10.json name different owners. The review trail's owner is the F-F10 "
                         "drafting chain")


def _x16_role(b: Blueprint, pin: X16Pin) -> str:
    if not pin.loaded:
        return "off"
    if pin.owner_scenario_id is not None:
        return "owner" if b.scenario_id is not None and str(b.scenario_id) == pin.owner_scenario_id else "other"
    return "pending" if str(b.name).strip() == pin.owner_name else "other"


def _x16_owner_text(pin: X16Pin) -> str:
    if pin.owner_scenario_id is not None:
        return f"scenario {pin.owner_scenario_id} ({pin.owner_name}, audit/x16.json)"
    return f"the scenario named {pin.owner_name!r} (audit/x16.json, owner_scenario_id not pinned yet)"


def _x16_pending(pin: X16Pin) -> str:
    return (f"owner pending: audit/x16.json owner_scenario_id is null, so this scenario is the X-16 owner by its name "
            f"{pin.owner_name!r} only. Commit its Make scenario ID")


def _x16_table_text(pin: X16Pin) -> str:
    return f"{pin.table_name} ({pin.table_id})"


def _x16_table(m: dict, pin: X16Pin) -> str | None:
    """"yes" when an Airtable module's table is Draft Reviews (by ID, or by name case-insensitive), or an Airtable API or
    HTTP call names it. "mapped" when a native module's table or base is a mapping (E35 owns that row). Else None.
    An API or HTTP request whose URL holds a literal table segment (/v0/<base>/<table>) is read by that segment alone,
    since the inverse link on Applicants shares the table's name and may sit in the body of an Applicants request."""
    if _airtable_api_module(m):
        url = _mapper(m).get("url")
        if isinstance(url, str) and "/v0/" in url:
            segs = url[url.find("/v0/") + 4:].split("?", 1)[0].split("/")
            seg = segs[1].replace("%20", " ").strip() if len(segs) > 1 else ""
            if seg and "{{" not in seg and seg.lower() != "meta" and "{{" not in segs[0]:
                return "yes" if seg == pin.table_id or seg.casefold() == pin.table_name.casefold() else None
    return _x32_table(m, X32Pin(table_id=pin.table_id, table_name=pin.table_name))


def _x16_field_names(ctx: "_EContext", roles) -> dict:
    """field ID -> name (the links map name, or the ID when the map lacks the table) for the given roles."""
    names = ((ctx.links.tables.get(ctx.x16.table_id) or {}).get("fields") or {}) if ctx.x16.table_id else {}
    return {ctx.x16.fields[r]: str(names.get(ctx.x16.fields[r], ctx.x16.fields[r])) for r in roles if r in ctx.x16.fields}


def _x16_claude_taint(ctx: "_EContext") -> dict:
    cached = getattr(ctx, "_x16_taint", None)
    if cached is None:
        claude = {m.get("id") for m, _e, _c in ctx.order if is_claude_call(m) and isinstance(m.get("id"), int)}
        cached = _p_taint(ctx.order, claude)
        ctx._x16_taint = cached
    return cached


def _x16_pii_source(ctx: "_EContext", r: "Ref") -> str | None:
    """What client data a reference carries under the X-16 widening of E6, or None. A direct source, or any field of a
    transform module (a variable, a parser, an aggregator, a text or regex step) that one of them reaches."""
    if not ctx.x16.loaded or _is_builtin_field(r.field):
        return None
    direct = _x16_pii_direct(ctx, r)
    if direct:
        return direct
    via = _x16_e6_taint(ctx).get(r.module)
    return f"`{r.field}` of module {r.module}, which carries {via}" if via else None


# Modules that only reshape the data they are given, so X-16 client data they map reaches every field they output.
_X16_TRANSFORM_APPS = ("util:", "json:", "regexp:", "text:", "markdown:", "builtin:BasicAggregator", "builtin:BasicFeeder")


def _x16_e6_taint(ctx: "_EContext") -> dict:
    """module ID -> what X-16 client data reaches it, for transform modules only (one pass, walk() order)."""
    cached = getattr(ctx, "_x16_e6", None)
    if cached is not None:
        return cached
    taint: dict = {}
    for m, _err, _chain in ctx.order:
        mid = m.get("id")
        if not isinstance(mid, int) or not _mtype(m).startswith(_X16_TRANSFORM_APPS):
            continue
        for r in _p_data_refs(m):
            if _is_builtin_field(r.field):
                continue
            what = taint.get(r.module) or _x16_pii_direct(ctx, r) or _ff10_taint_source(ctx, r)
            if what:
                taint[mid] = what
                break
    ctx._x16_e6 = taint
    return taint


def _ff10_taint_source(ctx: "_EContext", r: "Ref") -> str | None:
    """X-16.2 review (2026-11-17): an F-F10 client data output (FF10_SOURCE_PII, the validator's detail and review_note,
    the grounding provisions, Claude content) mapped into a transform module taints the transform, so its text copy (the
    TransformToJSON of the detail) is as strict in Slack or a Logger body as the field it copies. Only the taint uses this,
    so a direct reference keeps its own E6 message."""
    hit = ctx.modules.get(r.module)
    if hit is None:
        return None
    stype = _mtype(hit[0])
    head = re.split(r"[.\[]", str(r.field).strip(), maxsplit=1)[0]
    if head in ff10_source_pii(ctx.links, stype)[1]:
        return f"`{head}` of module {r.module} ({stype}), F-F10 client data"
    return None


def _x16_pii_direct(ctx: "_EContext", r: "Ref") -> str | None:
    hit = ctx.modules.get(r.module)
    if hit is None:
        return None
    src = hit[0]
    t = _mtype(src)
    if t.startswith("airtable:") and _x16_table(src, ctx.x16) in ("yes", "mapped"):
        pii = _x16_field_names(ctx, ctx.x16.pii_roles)
        key = str(r.field).strip()
        if key in pii or key.casefold() in {n.casefold() for n in pii.values()}:
            return f"the {ctx.x16.table_name} field `{r.field}` of module {r.module} (X-16 review trail)"
    if t == X16_PARSE and r.module in _x16_claude_taint(ctx):
        return f"`{r.field}` of module {r.module}, a JSON parse of Claude content"
    head = re.split(r"[.\[]", str(r.field).strip(), maxsplit=1)[0]
    if t == X16_GET_DOC and head in X16_DOC_TEXT_OUTPUTS:
        return f"`{r.field}` of module {r.module}, the text of a Google Doc"
    if head in X16_FILE_CONTENT_OUTPUTS.get(t, ()):
        return f"`{r.field}` of module {r.module} ({t}), the content of a Doc or a Drive file"
    return None


def _x16_handler_problem(ctx: "_EContext", m: dict, chain: tuple, check_contract: bool) -> str | None:
    """Why the handler of m is not exactly [Logger call, Resume] with no substitute output. check_contract also holds the
    Logger call to its payload contract (check B does that for every external module, not for a json module)."""
    mods = [x for x in _onerror(m) if isinstance(x, dict)]
    if not (len(mods) == 2 and is_logger_call(mods[0], ctx.logger) and _mtype(mods[1]) == "builtin:Resume"
            and not nonempty(mods[1].get("mapper")) and not any(_conditions(x) for x in mods)):
        return "its handler is not exactly [Logger call, Resume] with no substitute output, so a failure here either stops " \
               "the route before the row, the ledger row and the Slack alert, or leaves no trace"
    if check_contract:
        flow = ctx.b.bp.get("flow") or []
        trig = flow[0].get("id") if flow and isinstance(flow[0], dict) else None
        probs = logger_call_problems(mods[0], m, ctx.logger, LoggerScope(ctx, chain, None, trig))
        if probs:
            return f"its Logger call {mods[0].get('id')} {'. '.join(probs)}"
    return None


def _x16_parse(ctx: "_EContext") -> tuple[dict | None, int | None, dict | None, str | None]:
    """(P, outline module ID, the module that should hold the row, why P is missing or wrong). P is the module right before
    the outline router in its flow when that flow reads [outline, call row, P, router]."""
    router = ctx.modules.get(X16_OUTLINE_ROUTER)
    if router is None or _mtype(router[0]) != "builtin:BasicRouter":
        return None, None, None, f"has no outline router {X16_OUTLINE_ROUTER} (X16_ROUTES), so the trail cannot be found. Re-pin E38"
    rflow, ridx = router[2][-1]
    # The row for a missing P sits on the router whose route holds the outline (its child list is what the push changes).
    owner = router[2][-2][0][router[2][-2][1]] if len(router[2]) > 1 else router[0]
    p = rflow[ridx - 1] if ridx >= 1 else None
    if not (isinstance(p, dict) and _mtype(p) == X16_PARSE):
        return None, None, owner, (f"has no json:ParseJSON right before the outline router {X16_OUTLINE_ROUTER} (after the "
                                   f"outline's call row), so the outline's risk flags and weak grounds reach no one")
    o, row = (rflow[ridx - 3], rflow[ridx - 2]) if ridx >= 3 else (None, None)
    if not (isinstance(o, dict) and is_claude_call(o) and isinstance(row, dict) and _is_ledger_write_any(row, ctx.links)
            and "create" in _mtype(row).lower() and _uses_usage(row, o.get("id"))):
        return p, None, owner, (f"has ParseJSON {p.get('id')} right before router {X16_OUTLINE_ROUTER}, but the two modules ahead "
                                f"of it are not the outline and its call row")
    return p, o.get("id"), owner, None


def _x16_detail_json(ctx: "_EContext", v: dict) -> tuple[dict | None, dict, list[str]]:
    """(J, the module a row sits on, problems): J is the json:TransformToJSON right after the validator V on V's own flow
    (X-16.2). A missing J's row sits on the module whose child list holds V, since the push that adds J changes that list."""
    _m, _e, chain = ctx.modules[v.get("id")]
    vflow, vidx = chain[-1]
    owner = chain[-2][0][chain[-2][1]] if len(chain) > 1 else v
    j = vflow[vidx + 1] if vidx + 1 < len(vflow) else None
    if not (isinstance(j, dict) and _mtype(j) == X16_DETAIL_JSON):
        return None, owner, [f"has no json:TransformToJSON right after the validator {v.get('id')}, so the validator's "
                             f"JSONB detail reaches Airtable as an object and every Draft Reviews row after it gets a 422 "
                             f"(measured 2026-11-17)"]
    probs: list[str] = []
    mp = _mapper(j)
    if set(mp) != {"object"} or _norm_iml(mp.get("object")) != f"{{{{{v.get('id')}.detail}}}}":
        probs.append(f"its mapper is not exactly object {{{{{v.get('id')}.detail}}}}")
    params = j.get("parameters") if isinstance(j.get("parameters"), dict) else {}
    if set(params) - {"space"}:
        probs.append(f"its parameters hold keys other than space ({', '.join(sorted(set(params) - {'space'}))})")
    if _conditions(j):
        probs.append("it carries a filter, so a run can skip it and every row reads an empty Validator Detail")
    h = _x16_handler_problem(ctx, j, ctx.modules[j.get("id")][2], True)
    if h:
        probs.append(h)
    return j, j, probs


def _x16_route_flow(ctx: "_EContext", anchor: int, router_id: int, route: int) -> tuple[list | None, dict | None, str | None]:
    hit = ctx.modules.get(router_id)
    if hit is None or _mtype(hit[0]) != "builtin:BasicRouter":
        return None, None, f"router {router_id} is gone"
    routes = _routes(hit[0])
    if route >= len(routes):
        return None, hit[0], f"router {router_id} has no route {route + 1}"
    flow = routes[route]
    if not any(isinstance(x, dict) and x.get("id") == anchor for x in flow):
        return None, hit[0], f"route {route + 1} of router {router_id} does not hold update {anchor}"
    return flow, hit[0], None


def _x16_subtree(flow: list) -> list[dict]:
    out: list[dict] = []
    for x in flow:
        if isinstance(x, dict):
            out.append(x)
            for rf in _routes(x):
                out.extend(_x16_subtree(rf))
    return out


def _x16_is_create(m: dict, pin: X16Pin) -> bool:
    return _mtype(m).startswith("airtable:") and "create" in _mtype(m).lower() and _x16_table(m, pin) == "yes"


def _rule_e38(ctx: "_EContext") -> None:
    role = _x16_role(ctx.b, ctx.x16)
    if role in ("off", "other"):
        return
    pin = ctx.x16
    if role == "pending":
        ctx.emit("E38", FAIL, (ctx.b.bp.get("flow") or [{}])[0], _x16_pending(pin), strict=True)
    fn_of = {id(m): ff13_function(m, ctx.logger, ctx.ff10.connection_id) for m, _e, _c in ctx.order if _mtype(m) == FF13_MODULE}
    p, outline, p_owner, why = _x16_parse(ctx)
    if why:
        target = p if p is not None else (p_owner or (ctx.b.bp.get("flow") or [{}])[0])
        ctx.emit("E38", FAIL, target, why, strict=True)
    if p is not None and outline is not None:
        probs = []
        if _norm_iml(_mapper(p).get("json")) != f'{{{{first(map({outline}.content;"text";"type";"text"))}}}}':
            probs.append(f"its input (json) is not exactly the P5 text of the outline {outline}")
        if _conditions(p):
            probs.append("it carries a filter, so a run can skip the parse and every row reads empty flags")
        h = _x16_handler_problem(ctx, p, ctx.modules[p.get("id")][2], True)
        if h:
            probs.append(h)
        if probs:
            ctx.emit("E38", FAIL, p, f"is the outline's ParseJSON and {', and '.join(probs)}", strict=True)
    pid = p.get("id") if p is not None else None
    j_of: dict = {}

    def detail_json_of(vid: object) -> object:
        """The ID of the TransformToJSON right after validator vid, or None. Its own rows are emitted once per validator,
        from the validator on each row's path (X-16.2)."""
        if vid not in j_of:
            j, j_target, j_probs = _x16_detail_json(ctx, ctx.modules[vid][0])
            j_of[vid] = j.get("id") if j is not None else None
            if j_probs:
                what = f"is the TransformToJSON of the validator detail and {', and '.join(j_probs)}" if j is not None                     else j_probs[0]
                ctx.emit("E38", FAIL, j_target, what, strict=True)
        return j_of[vid]
    matched: set = set()
    for anchor, router_id, route, outcome, after_validator, doc_id in X16_ROUTES:
        flow, router, why = _x16_route_flow(ctx, anchor, router_id, route)
        label = f"the {outcome} route (update {anchor}, router {router_id} route {route + 1})"
        if why:
            ctx.emit("E38", FAIL, router or (ctx.b.bp.get("flow") or [{}])[0],
                     f"cannot find {label}: {why}. Re-pin X16_ROUTES from the snapshot in a reviewed commit", strict=True)
            continue
        creates = [x for x in _x16_subtree(flow) if _x16_is_create(x, pin)]
        if len(creates) != 1:
            what = "creates no Draft Reviews row" if not creates else f"creates {len(creates)} Draft Reviews rows"
            ctx.emit("E38", FAIL, router, f"{label} {what}. Each outcome route writes exactly one row of {_x16_table_text(pin)}, "
                                          f"so staff see the outline flags and the validator flags of every run", strict=True)
            matched.update(id(x) for x in creates)
            continue
        d = creates[0]
        matched.add(id(d))
        dchain = ctx.modules[d.get("id")][2] if d.get("id") in ctx.modules else ()
        before = _before_ids(dchain)
        idx = {x.get("id"): i for i, x in enumerate(flow) if isinstance(x, dict)}
        probs: list[str] = []
        if d.get("id") not in idx or idx[d.get("id")] < idx[anchor]:
            probs.append(f"it does not sit after update {anchor} on the route's own flow")
        if _conditions(d):
            probs.append("it carries a filter, so the row can be skipped")
        h = _x16_handler_problem(ctx, d, dchain, False)
        if h:
            probs.append(h)
        groundings = [m.get("id") for m, _e, _c in ctx.order if fn_of.get(id(m)) == "drafting_context" and m.get("id") in before]
        validators = [m.get("id") for m, _e, _c in ctx.order if fn_of.get(id(m)) == "validate_draft" and m.get("id") in before]
        f = pin.fields
        want: dict = {f["draft_execution_id"]: "{{var.scenario.executionId}}", f["applicant"]: ["{{1.id}}"],
                      f["outcome"]: outcome, f["assigned_rcic"]: "{{1.`RCIC of Record`}}",
                      f["signoff_state"]: X16_PENDING_STATE[doc_id is not None]}
        if len(groundings) == 1:
            g = groundings[0]
            want[f["gate_mode"]] = f"{{{{{g}.gate_mode}}}}"
            want[f["grounding_id"]] = f"{{{{parseNumber({g}.grounding_id)}}}}"
        else:
            probs.append(f"{len(groundings)} ff13.drafting_context calls run before it, exactly one is needed")
        if after_validator:
            if len(validators) == 1:
                v = validators[0]
                for r, out in zip(X16_VALIDATOR_ROLES, ("verdict", "ledger_id", "hard_fail_count", "soft_flag_count",
                                                       "review_note", "detail")):
                    want[f[r]] = f"{{{{{v}.{out}}}}}"
                # X-16.2: BIGINT through parseNumber, the JSONB detail through the TransformToJSON J right after V.
                j_id = detail_json_of(v)
                want[f["validation_id"]] = f"{{{{parseNumber({v}.ledger_id)}}}}"
                want[f["validator_detail"]] = f"{{{{{j_id}.json}}}}" if j_id is not None                     else f"{{{{<the TransformToJSON right after {v}>.json}}}}"
                if j_id is not None and j_id not in before:
                    probs.append(f"the TransformToJSON {j_id} of the validator detail does not run before it")
            else:
                probs.append(f"{len(validators)} ff13.validate_draft calls run before it, exactly one is needed")
        if pid is not None and pid in before:
            want[f["risk_flags"]] = f"{{{{join({pid}.risk_flags;newline)}}}}"
            want[f["weak_grounds"]] = _norm_iml(x16_weak_grounds(pid))
        else:
            probs.append("the outline's ParseJSON does not run before it")
        if outline is not None:
            want[f["outline_json"]] = f'{{{{first(map({outline}.content;"text";"type";"text"))}}}}'
        between_ok: list = []
        if doc_id is not None:
            doc = ctx.modules.get(doc_id)
            gets = [x for x in flow if isinstance(x, dict) and _mtype(x) == X16_GET_DOC]
            if doc is None or not (_mtype(doc[0]).startswith("google-docs:") and "create" in _mtype(doc[0]).lower()) \
                    or doc_id not in idx:
                probs.append(f"the route has no Google Docs create {doc_id} (X16_ROUTES). Re-pin E38")
            elif len(gets) != 1:
                probs.append(f"the route holds {len(gets)} google-docs:getADocument modules, exactly one reads the new Doc "
                             f"ahead of the row")
            else:
                gm = gets[0]
                gid = gm.get("id")
                if not (idx[doc_id] < idx[gid] < idx.get(d.get("id"), -1)):
                    probs.append(f"Get a Document {gid} does not sit between Doc {doc_id} and the row")
                gmp = _mapper(gm)
                if _norm_iml(gmp.get("document")) != f"{{{{{doc_id}.id}}}}" or gmp.get("select") != "map":
                    probs.append(f"Get a Document {gid} does not read exactly {{{{{doc_id}.id}}}} (select map)")
                # Make MCP app-module_get and validate_module_configuration (google-docs v1 getADocument, 2026-11-16):
                # includeTabsContent and filter are required and not mappable, and a module without them fails
                # validation. includeTabsContent false keeps the text the hash covers the one a Phase B approval read sees.
                if set(gmp) != set(X16_GET_DOC_MAPPER) or any(not (type(gmp.get(k)) is type(v) and gmp.get(k) == v)
                                                             for k, v in X16_GET_DOC_MAPPER.items() if k != "document"):
                    probs.append(f"Get a Document {gid} does not hold exactly the mapper keys {sorted(X16_GET_DOC_MAPPER)} "
                                 f"with select map, includeTabsContent false and filter image")
                if _conditions(gm):
                    probs.append(f"Get a Document {gid} carries a filter")
                hg = _x16_handler_problem(ctx, gm, ctx.modules[gid][2], False)
                if hg:
                    probs.append(f"on Get a Document {gid}, {hg}")
                want[f["doc_id"]] = f"{{{{{doc_id}.id}}}}"
                want[f["doc_link"]] = f"{{{{{doc_id}.webViewLink}}}}"
                want[f["generated_text_sha256"]] = _norm_iml(x16_doc_hash(gid))
                between_ok = [gid]
        if d.get("id") in idx and idx[d.get("id")] > idx[anchor]:
            between = [x.get("id") for x in flow[idx[anchor] + 1:idx[d.get("id")]] if isinstance(x, dict)]
            if between != between_ok:
                allowed = f" with only Get a Document {between_ok[0]} between" if between_ok else ""
                probs.append(f"it does not sit right after update {anchor}{allowed} (modules {between} sit between), so a "
                             f"filter or a stop there can skip the row")
        mp = _mapper(d)
        rec = mp.get("record") if isinstance(mp.get("record"), dict) else {}
        if pin.table_id and str(mp.get("table") or "").strip() != pin.table_id:
            probs.append(f"its table is not the literal {pin.table_id}")
        names = _x16_field_names(ctx, X16_FIELD_ROLES)

        def norm(v: object) -> object:
            return [_norm_iml(x) for x in v] if isinstance(v, list) else _norm_iml(v)

        extra = sorted(str(k) for k in rec if k not in want)
        missing = sorted(names.get(k, k) for k in want if k not in rec)
        wrong = sorted(names.get(k, k) for k, v in want.items() if k in rec and norm(rec[k]) != norm(v))
        if extra:
            probs.append(f"its record writes keys outside the pinned set ({', '.join(extra)})")
        if missing:
            probs.append(f"its record does not write {', '.join(missing)}")
        if wrong:
            probs.append(f"its record does not hold the pinned form of {', '.join(wrong)}")
        if probs:
            ctx.emit("E38", FAIL, d, f"is the Draft Reviews row of {label} and {', and '.join(probs)}", strict=True)
    anchors = {r[0] for r in X16_ROUTES}
    outline_any = outline
    if outline_any is None and X16_OUTLINE_ROUTER in ctx.modules:
        rflow, ridx = ctx.modules[X16_OUTLINE_ROUTER][2][-1]
        outline_any = next((x.get("id") for x in reversed(rflow[:ridx]) if isinstance(x, dict) and is_claude_call(x)), None)
    for m, in_err, chain in ctx.order:
        where = " in an error route" if in_err else ""
        if id(m) in matched:
            continue
        if _x16_is_create(m, pin):
            ctx.emit("E38", FAIL, m, f"creates a Draft Reviews row{where} outside the seven pinned outcome routes (X16_ROUTES)",
                     strict=True)
            continue
        if not _x16_deletes(m) and ((_x16_table(m, pin) == "yes" and _x32_writes(m)) or _x16_writes_field_ids(m, pin)):
            # specs/X-16-options.md 6.2: the owner writes each row once, at its creation, with the first Sign-off State.
            # An update, an upsert or an API or HTTP write would change a row after the run (deletes are E39's row).
            ctx.emit("E38", FAIL, m, f"writes {_x16_table_text(pin)}{where} outside the seven pinned row creates. The drafting "
                                     f"chain writes each row once, when it creates it, and sets only the first Sign-off "
                                     f"State", strict=True)
            continue
        if in_err or outline_any is None or m.get("id") in anchors:
            continue
        if ff10_field_write(m, ctx.links, FF10_DRAFTING_STATUS, ctx.logger) is not None                 and outline_any in _before_ids(chain):
            ctx.emit("E38", FAIL, m, f"writes Applicants Drafting Status after the outline {outline_any} outside the seven "
                                     f"pinned outcome routes (X16_ROUTES), so a run that ends here leaves no Draft Reviews "
                                     f"row. Add its row and pin the route in X16_ROUTES in a reviewed commit", strict=True)


def _x16_writes_field_ids(m: dict, pin: X16Pin) -> bool:
    if not is_airtable_write(m):
        return False
    ids = set(pin.fields.values())
    return any(str(k).strip() in ids for k in _mapper_keys(_mapper(m))) or \
        any(isinstance(s, str) and s.strip() in ids for s in _strings(_mapper(m).get("records")))


def _x16_deletes(m: dict) -> bool:
    low = _mtype(m).lower()
    if low.startswith("airtable:") and low != AIRTABLE_API_CALL.lower():
        return "delete" in low
    return _api_write(m) and str(_mapper(m).get("method") or "").strip().lower() == "delete"


def _rule_e39(ctx: "_EContext") -> None:
    role = _x16_role(ctx.b, ctx.x16)
    if role == "off":
        return
    pin = ctx.x16
    tname = _x16_table_text(pin)
    inverse = (pin.applicants_link_field, ((ctx.links.tables.get(LEAD_TABLE) or {}).get("fields") or {})
               .get(pin.applicants_link_field, pin.table_name))
    for m, in_err, _chain in ctx.order:
        where = " (in an error route)" if in_err else ""
        hit = _x16_table(m, pin)
        if hit == "yes" and _x16_deletes(m):
            ctx.emit("E39", FAIL, m, f"deletes rows of {tname}{where}. No module deletes one: the row is the review trail of a "
                                     f"drafting run", strict=True)
            continue
        how = ff10_field_write(m, ctx.links, inverse, ctx.logger) if pin.applicants_link_field else None
        if how == "api" and inverse[0] not in " ".join(_strings(_mapper(m))):
            # Matched by name only. The inverse link shares its name with the table, so a request that names Draft
            # Reviews as its table is the table write below, and the name is the inverse link only in a request whose
            # URL names Applicants.
            url = str(_mapper(m).get("url") or "").replace("%20", " ")
            lead = str((ctx.links.tables.get(LEAD_TABLE) or {}).get("name") or "Applicants")
            names_lead = LEAD_TABLE in url or re.search(r"(?<![\w])" + re.escape(lead) + r"(?![\w])", url, re.I) is not None
            if hit == "yes" or not names_lead:
                how = None
        if how in ("record", "api"):
            ctx.emit("E39", FAIL, m, f"writes Applicants `{inverse[1]}` ({inverse[0]}){where}. Only the Draft Reviews create "
                                     f"links a row, through its own Applicant field", strict=True)
            continue
        writes = (hit == "yes" and _x32_writes(m)) or _x16_writes_field_ids(m, pin)
        if not writes:
            continue
        if role == "other":
            ctx.emit("E39", FAIL, m, f"writes {tname}{where}, which only {_x16_owner_text(pin)} writes. The drafting chain creates "
                                     f"one row per run that reached the outline", strict=True)
        elif role == "pending":
            ctx.emit("E39", FAIL, m, f"{_x16_pending(pin)} (a write of {tname})", strict=True)


_X16_DRIVE_EXPOSE = re.compile(r"share|access|copy|moveafileintoafolder|shortcut|fromtemplate|makeapicall", re.I)
_X16_DOC_WRITE = re.compile(r"^google-docs:(?:create|append|replace|insert|makeapicall)|^google-drive:(?:upload|createafilefromtext"
                            r"|updateafile|makeapicall)", re.I)
# An HTTP call to the Drive or Docs API (upload endpoint included). A request that is not a GET can share, copy, move or
# write the working Doc, so it is exposing like the native modules. A GET only reads, and what it returns carries the Doc.
_X16_GOOGLE_API = re.compile(r"googleapis\.com/(?:upload/)?drive|docs\.googleapis\.com", re.I)


def _x16_google_http_write(m: dict) -> bool:
    if not _mtype(m).startswith("http:"):
        return False
    if not any(_X16_GOOGLE_API.search(s) for s in _strings(_mapper(m))):
        return False
    method = str(_mapper(m).get("method") or "").strip().lower()
    return bool(method) and method != "get"


def _x16_exposes(m: dict) -> str | None:
    """The kind of exposure a module that carries the working Doc is (E40), or None for a read. A client send, a Drive or
    Docs share, access change, copy, move, shortcut, template copy or API call, a Doc create, append or replace and a Drive
    upload, text file or content update (a download then an upload is a copy outside the pinned folders), and an HTTP call
    to the Drive or Docs API that is not a GET."""
    t = _mtype(m)
    if _p_client_send(m):
        return "a client send"
    app, _sep, op = t.partition(":")
    if app.lower() in ("google-drive", "google-docs") and (_X16_DRIVE_EXPOSE.search(op) or _X16_DOC_WRITE.search(t)):
        return f"a Drive {op}" if app.lower() == "google-drive" else f"a Docs {op}"
    if _x16_google_http_write(m):
        return "an HTTP call to the Google Drive or Docs API"
    return None


def _x16_doc_ref(ctx: "_EContext", r: "Ref", tainted: set, owner: bool) -> str | None:
    """What working-Doc reference r carries (E40), or None."""
    if r.module in tainted:
        return f"the output of module {r.module}, which carries the working Doc"
    hit = ctx.modules.get(r.module)
    if hit is None:
        return None
    src = hit[0]
    t = _mtype(src)
    key = str(r.field).strip()
    if t.startswith("airtable:"):
        table = _e25_table(src, ctx.links)
        if (table is None or table == LEAD_TABLE) and (key == FF10_DOC_LINK[0] or key.casefold() == FF10_DOC_LINK[1].casefold()):
            return f"Applicants `{FF10_DOC_LINK[1]}` of module {r.module}"
        if _x16_table(src, ctx.x16) == "yes":
            names = _x16_field_names(ctx, ("doc_id", "doc_link"))
            if key in names or key.casefold() in {n.casefold() for n in names.values()}:
                return f"the {ctx.x16.table_name} field `{r.field}` of module {r.module}"
    if owner and t.startswith("google-docs:") and "create" in t.lower():
        return f"the output of the drafting chain's Doc create {r.module}"
    return None


def _rule_e40(ctx: "_EContext") -> None:
    role = _x16_role(ctx.b, ctx.x16)
    if role == "off":
        return
    owner = role in ("owner", "pending")
    tainted: set = set()
    for m, in_err, _chain in ctx.order:
        t = _mtype(m)
        app = t.split(":", 1)[0].lower()
        carried = []
        for r in _p_data_refs(m):
            what = _x16_doc_ref(ctx, r, tainted, owner)
            if what and what not in carried:
                carried.append(what)
        if not carried:
            continue
        kind = _x16_exposes(m)
        if kind:
            where = " (in an error route)" if in_err else ""
            ctx.emit("E40", FAIL, m, f"is {kind}{where} that maps {', and '.join(carried)}. The working Doc stays with staff until "
                                     f"the RCIC signs off (X-16), so no send, share, copy, move or upload carries its link, ID "
                                     f"or text", strict=True)
        elif not t.startswith("airtable:") and isinstance(m.get("id"), int):
            tainted.add(m["id"])
    if owner:
        return
    taint = _x16_claude_taint(ctx)
    for m, in_err, _chain in ctx.order:
        if _X16_DOC_WRITE.search(_mtype(m)) and taint.get(m.get("id")):
            where = " (in an error route)" if in_err else ""
            ns = ", ".join(str(n) for n in sorted(taint[m["id"]]))
            head = (f"is {_mtype(m)}{where} carrying the text of Claude module {ns}. Only {_x16_owner_text(ctx.x16)} writes "
                    f"Claude text to a Doc, behind the validator and the review trail (E32, E38)")
            # specs/X-16-options.md question 8 and 6.5: the inactive fallback drafter (Submission Letter 3974513, kept by
            # the F-F10 decision of 2026-11-15) FAILs only once it is activated. While the pull shows it inactive the row is
            # a REVIEW, so it stays visible. An unknown state (a --dir run, no manifest) FAILs.
            if ctx.active is False:
                ctx.emit("E40", REVIEW, m, f"{head}. The pull shows this scenario inactive, so this is a REVIEW. It FAILs "
                                           f"once the scenario is active, so retire it or remove the Doc step before anyone "
                                           f"activates it", strict=True)
            else:
                state = "active" if ctx.active else "of unknown state (no manifest entry)"
                ctx.emit("E40", FAIL, m, f"{head}. The scenario is {state}", strict=True)


def check_e(b: Blueprint, links: AirtableMap, allow: Allowlist, logger: "LoggerSpec | None" = None,
            webhooks: "Webhooks | None" = None, bland_agents: BlandAgents | None = None,
            ff10: FF10Pin | None = None, x32: "X32Pin | None" = None, x16: "X16Pin | None" = None,
            active: bool | None = None) -> list[Finding]:
    """bland_agents is the E28 registry. None reads audit/bland_agents.json, and a missing file is an InputError.
    ff10 is the F-F10 owner pin for E30 and E31. None reads audit/ff10.json, and a missing file is an InputError.
    x32 is the X-32 pin for E35 to E37. None reads audit/x32.json, and a missing file is an InputError.
    x16 is the X-16 pin for E38 to E40 and the E32 production folder. None reads audit/x16.json (a missing file is an
    InputError). X16Pin() (loaded False) switches E38 to E40 off, while a production Doc of the drafting chain still FAILs
    E32 (X-16) as owner pending, since no review folder is pinned. active is the scenario's is_active in the manifest
    (None: unknown), which only E40 reads: Claude text into a Doc outside the owner is a REVIEW while the pull shows the
    scenario inactive and a FAIL when it is active or its state is unknown."""
    if bland_agents is None:
        bland_agents = load_bland_agents(DEFAULT_BLAND_AGENTS)
    if ff10 is None:
        ff10 = load_ff10(DEFAULT_FF10)
    if x32 is None:
        x32 = load_x32(DEFAULT_X32)
    if x16 is None:
        x16 = load_x16(DEFAULT_X16)
    ctx = _EContext(b, links, allow, logger, webhooks, bland_agents, ff10, x32, x16, active)
    for rule in (_rule_e1_e2, _rule_e3, _rule_e4, _rule_e5, _rule_e6, _rule_e7, _rule_e8, _rule_e9, _rule_e10,
                 _rule_e11, _rule_e12, _rule_e13, _rule_e14, _rule_e15, _rule_e16, _rule_e17, _rule_e18, _rule_e19,
                 _rule_e20, _rule_e21, _rule_e22, _rule_e23, _rule_e24, _rule_e25, _rule_e26, _rule_e28,
                 _rule_e29, _rule_e30, _rule_e31, _rule_e32, _rule_e33, _rule_e34, _rule_e35, _rule_e36, _rule_e37,
                 _rule_e38, _rule_e39, _rule_e40):
        rule(ctx)
    return ctx.findings


def _single_expression(v: object) -> str | None:
    """The body of a value that is exactly one {{...}} expression, else None."""
    if not isinstance(v, str):
        return None
    exprs, outside = secret_scan._iml_segments(v)
    if outside.strip() or len(exprs) != 1:
        return None
    return exprs[0].strip()


# --- F ---------------------------------------------------------------------
#
# Webhook authentication (X-23, decided 2026-10-28). Every scenario triggered by a custom
# webhook is listed in audit/webhooks.json with who calls it and how it is protected.
#   api_key     The caller is a Bland pathway webhook node, which can send headers. The hook
#               itself must require a Make API key (header x-make-apikey). Hook configuration,
#               not blueprint content, so F1 reads it from the hook list make_pull records.
#   fetch_back  The caller is a Bland post-call webhook, which cannot carry a custom header.
#               The scenario takes only the call ID from the request, re-fetches the call from
#               Bland through the authenticated Bland connection, continues only for a call the
#               system created, and never reads another request field. F2 checks that in the
#               blueprint.


@dataclass
class WebhookEntry:
    scenario_id: str
    hook_id: int
    caller: str
    protection: str
    reason: str
    # fetch_back only: the Shadow Ledger label of the row the calling scenario creates, which the lookup pins
    # with {Scenario name} = '<label>' so only that scenario's own row can match.
    lookup_label: str = ""
    # fetch_back only: the Bland call statuses the completion gate may let through (F2d). Default completed only. A scenario
    # that must act on calls nobody answered (Batch Call Reconciliation, M1) lists the other statuses Bland reports only
    # for an ended call.
    ended_statuses: tuple = ("completed",)


# Bland call statuses that mean the call has ended (docs.bland.ai/api-v1/get/calls-id, read 2026-10-31: completed is
# answered by a human or voicemail, then failed, busy, no-answer, canceled). A status outside this set may be a call in
# progress, so no completion gate may let it through.
BLAND_ENDED_STATUSES = ("completed", "no-answer", "busy", "failed", "canceled")


def _ended_statuses(name: str, where: str, e: dict, protection: str) -> tuple:
    raw = e.get("ended_statuses")
    if raw is None:
        return ("completed",)
    if protection != "fetch_back":
        raise InputError(f"{name} {where}: ended_statuses belongs to fetch_back scenarios only")
    if not isinstance(raw, list) or not raw or not all(isinstance(x, str) for x in raw) or "completed" not in raw \
            or len(set(raw)) != len(raw) or not set(raw) <= set(BLAND_ENDED_STATUSES):
        raise InputError(f"{name} {where}: ended_statuses must list distinct Bland statuses of an ended call, completed included, "
                         f"from {', '.join(BLAND_ENDED_STATUSES)}")
    return tuple(raw)


@dataclass
class Webhooks:
    """audit/webhooks.json: scenario ID -> WebhookEntry. logger is the shared Logger (the one entry with caller make_http),
    from the top-level logger key while its IDs are null or from scenarios once they are known."""
    entries: dict = field(default_factory=dict)
    logger: "LoggerSpec | None" = None


@dataclass
class HookInfo:
    """Hooks as make_pull recorded them in manifest.json. available is False when the read token
    could not list hooks (403) or there is no manifest."""
    available: bool = False
    by_id: dict = field(default_factory=dict)
    note: str = ""


# --- The shared Logger (Option C, decided by Rizwan 2026-10-29) ---------------------------------------------
#
# One webhook-triggered scenario writes one Shadow Ledger row and one Slack alert (IDs only) for every error
# handler of every scenario (specs/F-E5-v3-shared-logger.md). It is registered in audit/webhooks.json as the one
# entry with caller make_http and protection api_key (its hook requires a Make API key, header x-make-apikey):
# under the top-level logger key while its scenario_id and hook_id are null, in scenarios once they are known.
# The entry also names how a caller reaches it: url_variable (the team or organization custom variable that holds
# the hook URL, so no blueprint carries the URL, which is a bearer secret that make_pull withholds) and
# connection_id (the HTTP API key connection, keychain, that sends the key, null until Rizwan creates it). Measured with the Make MCP
# app-module_get and validate_module_configuration on http:MakeRequest v4 (2026-10-29): authenticationType
# apiKeyConnection with parameters.apiKeyAccount (or the legacy apiKey with apiKeyKeychain), mapper.url, method,
# headers, contentType urlEncoded with urlEncodedBodyContent [{name, value}], and stopOnHttpError ("Return
# error if HTTP request fails", default true, treats 4xx and 5xx as errors). Custom webhooks accept query
# string, form data and JSON (apps.make.com/gateway). A urlencoded body is encoded by Make, a JSON string body
# is not escaped (apps.make.com/http), so an error message with a quote would break it.

LOGGER_CALLER = "make_http"
# The body of a logger call: these keys and nothing else (no client data, check E6).
LOGGER_BODY_REQUIRED = ("label", "outcome", "module_id", "module_name", "error_type", "error_message", "execution_id")
LOGGER_BODY_OPTIONAL = ("lead_record_id", "call_id")
# What the Logger's Slack alert may carry from the request: IDs only, never the error message or the module name (E6,
# specs/F-E5-v3-shared-logger.md section 3).
LOGGER_SLACK_FIELDS = frozenset(("label", "outcome", "module_id", "error_type", "execution_id", "lead_record_id", "call_id"))
LOGGER_AUTH = {"apiKeyConnection": "apiKeyAccount", "apiKey": "apiKeyKeychain"}
_CUSTOM_VAR = re.compile(r"^var\.(?:team|organization)\.[A-Za-z0-9_$]+$")


@dataclass
class LoggerSpec:
    """The Logger entry of audit/webhooks.json. scenario_id and hook_id are None until Rizwan imports the Logger."""
    scenario_id: str | None
    hook_id: int | None
    url_variable: str | None = None
    connection_id: int | None = None
    reason: str = ""
    # Literal-URL mode (no team variables below Make Pro, Rizwan 2026-10-29): the SHA-256 of the Logger hook token.
    # A caller's URL must then be exactly the bare hook URL whose token hashes to this value.
    url_sha256: str | None = None


def _pos_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _logger_url_var(m: dict) -> str | None:
    """The custom variable a module's URL is, when the URL is exactly one {{var.team.X}} or {{var.organization.X}}."""
    e = _single_expression(_mapper(m).get("url"))
    return e if e is not None and _CUSTOM_VAR.match(e) else None


def _logger_literal_url_ok(m: dict, spec: "LoggerSpec | None") -> bool:
    """Literal-URL mode: the module's URL is exactly the bare Logger hook URL pinned by url_sha256 in audit/webhooks.json."""
    if spec is None or not spec.url_sha256:
        return False
    url = _mapper(m).get("url")
    mt = secret_scan._BARE_HOOK_URL.fullmatch(url) if isinstance(url, str) else None
    return mt is not None and secret_scan.token_digest(mt.group("t")) == spec.url_sha256


def is_logger_call(m: dict, spec: "LoggerSpec | None") -> bool:
    """An HTTP module whose URL is the registered Logger URL variable (or, in literal-URL mode, the pinned hook URL), or whose
    keychain connection is the registered Logger connection."""
    if spec is None or not _mtype(m).lower().startswith("http:"):
        return False
    var = _logger_url_var(m)
    if var is not None and var == spec.url_variable:
        return True
    if _logger_literal_url_ok(m, spec):
        return True
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    key = params.get(LOGGER_AUTH.get(params.get("authenticationType"), ""))
    return _pos_int(key) and key == spec.connection_id


def logger_body(m: dict) -> tuple[dict | None, list[str]]:
    """(name -> value, problems) of a logger call's urlencoded body. None when the body is not a urlencoded field list."""
    mp = _mapper(m)
    if mp.get("contentType") != "urlEncoded":
        return None, ["does not send its body as application/x-www-form-urlencoded (contentType urlEncoded). Make encodes those fields, "
                      "while a JSON string body is not escaped and an error message with a quote breaks it"]
    items = mp.get("urlEncodedBodyContent")
    if not isinstance(items, list) or not items:
        return None, ["has no body fields"]
    body: dict = {}
    problems: list[str] = []
    for it in items:
        name = it.get("name") if isinstance(it, dict) else None
        if not isinstance(name, str) or not name.strip():
            problems.append("has a body field with no name")
            continue
        if name in body:
            problems.append(f"sends {name} twice")
        body[name] = it.get("value", "")
    return body, problems


def _is_literal(v: object) -> bool:
    return isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip() != "" and "{{" not in str(v)


def _one_ref(v: object) -> bool:
    """Exactly one {{...}} that references one module output, nothing around it."""
    e = _single_expression(v)
    return bool(e) and len(iml_refs(e)) == 1 and iml_refs(e)[0].text == e


@dataclass
class LoggerScope:
    """What a logger call can see in its scenario. ectx indexes the scenario's modules with the Airtable map (check E3
    and E6 facts), owner_chain is the walk chain of the module whose handler holds the call, protection the webhook
    registry's protection for the scenario (None when the scenario is not a registered webhook scenario) and trigger_id
    the first module."""
    ectx: "_EContext"
    owner_chain: tuple
    protection: str | None = None
    trigger_id: object = None


# Only these mapper keys may carry a mapping: the URL (the team variable) and the form body. Headers, query strings and
# every other key must carry nothing, so the keychain connection and the body are the only things a call sends.
LOGGER_MAPPED_KEYS = ("url", "urlEncodedBodyContent")
LOGGER_EMPTY_KEYS = ("queryParameters", "qs")
_KEY_HEADERS = ("x-make-apikey", "authorization")


def _carries(v: object) -> bool:
    """A value holds something: a non-blank string or a number anywhere in it."""
    if isinstance(v, bool) or v is None:
        return False
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        return v.strip() != ""
    if isinstance(v, (list, tuple)):
        return any(_carries(x) for x in v)
    if isinstance(v, dict):
        return any(_carries(x) for x in v.values())
    return False


def _in_scope(scope: LoggerScope, module_id: object) -> bool:
    """module_id runs before the owner on the owner's path, so its output exists when the owner fails."""
    hit = scope.ectx.modules.get(module_id) if isinstance(module_id, int) else None
    return hit is not None and _runs_after(hit[2], scope.owner_chain)


def _logger_pii(scope: LoggerScope, name: str, value: object) -> list[str]:
    """Check E6 on one body value: references to a client PII field of an Airtable table, or to client data from outside Airtable."""
    out: list[str] = []
    ectx = scope.ectx
    for expr in _value_exprs(value):
        for r in iml_refs(expr):
            t = ectx.table_of(r.module)
            src = ectx.modules.get(r.module)
            stype = _mtype(src[0]) if src else ""
            if t and ectx.links.is_pii(t, r.field):
                out.append(f"sends client data (E6) in {name}: {{{{{r.text}}}}} is the {ectx.links.table_name(t)} field "
                           f"`{ectx.links.field_label(t, r.field)}`. Send record IDs only")
            elif r.field in set().union(*ff10_source_pii(ectx.links, stype)):
                out.append(f"sends client data (E6) in {name}: {{{{{r.text}}}}} is `{r.field}` of module {r.module} ({stype}), client "
                           f"data from outside Airtable. Send record IDs only")
    return out


_FIRST_OF = re.compile(r"^first\s*\(\s*(.*?)\s*\)$", re.S)


def _first_of_ref(v: object) -> Ref | None:
    """The reference inside a value that is exactly {{first(N.field)}}, nothing around it, else None (B1, F-E5.4)."""
    e = _single_expression(v)
    mt = _FIRST_OF.match(e) if e else None
    refs = iml_refs(mt.group(1)) if mt else []
    return refs[0] if len(refs) == 1 and refs[0].text == mt.group(1) else None


def _lead_record_problem(scope: LoggerScope, value: object) -> str | None:
    """lead_record_id must yield one Applicants record ID (check E3 inference) from a module that runs before the owner: one
    bare reference, or first() of an Applicants link field (B1, F-E5.4: a link field is a list in Make, first() takes one ID)."""
    inner = _first_of_ref(value)
    ref = inner or iml_refs(_single_expression(value))[0]
    shown = f"first({ref.text})" if inner is not None else ref.text
    if inner is not None and ref.field == "id":
        return (f"sends lead_record_id {{{{{shown}}}}}, but first() belongs on a link field only. A record ID is one value, "
                f"send {{{{{ref.text}}}}}")
    table, desc = scope.ectx.produced_table(ref)
    if table != LEAD_TABLE:
        what = desc or f"module {ref.module}, which yields no Airtable record ID the audit can place"
        return (f"sends lead_record_id {{{{{shown}}}}}, but lead_record_id is not an Applicants record ID "
                f"({scope.ectx.links.table_name(LEAD_TABLE)}): it is {what}")
    if not _in_scope(scope, ref.module):
        return (f"sends lead_record_id {{{{{shown}}}}} from module {ref.module}, which is not in scope: it does not run before "
                f"the owner, so its output does not exist when the owner fails. Leave lead_record_id out when no lead is in scope")
    return None


def _call_id_problem(scope: LoggerScope, value: object) -> str | None:
    """call_id must be one bare reference {{N.call_id}} that check F allows: in a fetch-back scenario only from the
    call-details module (the request is unauthenticated free text, F2c), elsewhere from a Bland module or from the trigger
    of a webhook the registry protects with an API key. N runs before the owner, so the call-details module's own handler
    sends none."""
    ref = iml_refs(_single_expression(value))[0]
    hit = scope.ectx.modules.get(ref.module) if isinstance(ref.module, int) else None
    kind = _mtype(hit[0]) if hit else ""
    if scope.protection == "fetch_back":
        allowed = kind in FETCH_MODULES
        rule = (f"in a fetch-back scenario call_id comes only from the call-details module ({FETCH_MODULES[0]}), never from the "
                f"request or another module (F2c)")
    else:
        allowed = kind.startswith("bland:") or (scope.protection == "api_key" and ref.module == scope.trigger_id)
        rule = ("call_id is not a Bland call ID check F allows. Map it from a Bland module, or from the trigger of a webhook "
                "that audit/webhooks.json protects with an API key")
    if not allowed or ref.field not in CALL_ID_FIELDS:
        return f"sends call_id {{{{{ref.text}}}}}, but {rule}. The field is call_id"
    if not _in_scope(scope, ref.module):
        return (f"sends call_id {{{{{ref.text}}}}} from module {ref.module}, which is not in scope: it does not run before the owner. "
                f"The call-details module's own handler sends no call ID")
    return None


def logger_call_problems(m: dict, owner: dict | None, spec: "LoggerSpec | None", scope: LoggerScope | None = None) -> list[str]:
    """Why a logger call does not meet the contract, as clauses ("is ..."). owner is the module whose handler holds it. scope
    is what the call can see in its scenario (check B builds it). Without it lead_record_id and call_id cannot be confirmed."""
    problems: list[str] = []
    spec = spec or LoggerSpec(None, None)
    mp = _mapper(m)
    params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
    if _mtype(m) != "http:MakeRequest":
        problems.append(f"is {_mtype(m)}. Use the HTTP app's Make a request module (http:MakeRequest)")
    auth = params.get("authenticationType")
    key = params.get(LOGGER_AUTH.get(auth, ""))
    if auth not in LOGGER_AUTH or not _pos_int(key):
        problems.append("is not authenticated by a keychain connection (authenticationType apiKeyConnection with an HTTP API key connection "
                        "whose key goes in the x-make-apikey header)")
    elif spec.connection_id is None:
        problems.append("cannot be confirmed: the Logger entry of audit/webhooks.json names no connection_id yet")
    elif key != spec.connection_id:
        problems.append(f"uses connection {key}, not the Logger connection {spec.connection_id} named in audit/webhooks.json")
    var = _logger_url_var(m)
    literal_ok = spec.url_variable is None and _logger_literal_url_ok(m, spec)
    if not literal_ok and (var is None or var != spec.url_variable):
        problems.append(f"has a URL that is not exactly {{{{{spec.url_variable or 'var.team.<name>'}}}}}, the Logger URL variable named in "
                        f"audit/webhooks.json. A literal hook URL is a bearer secret")
    if str(mp.get("method", "")).strip().lower() != "post":
        problems.append("is not a POST")
    headers = mp.get("headers")
    header_list = headers if isinstance(headers, list) else ([headers] if _carries(headers) else [])

    def key_header(h: object) -> bool:
        return isinstance(h, dict) and str(h.get("name", "")).strip().lower() in _KEY_HEADERS

    if any(key_header(h) for h in header_list):
        problems.append("sets the key header by hand. The keychain connection supplies it")
    others = [h for h in header_list if _carries(h) and not key_header(h)]
    if others:
        names = ", ".join(sorted({(str(h.get("name", "")).strip() or "(no name)") if isinstance(h, dict) else "(not a name and value)"
                                  for h in others}))
        problems.append(f"sets header {names}. A logger call sends no header of its own, only the keychain connection's key")
    for k in LOGGER_EMPTY_KEYS:
        if _carries(mp.get(k)):
            problems.append(f"sends {k}. A logger call carries nothing in the query string, everything goes in the form body")
    mapped = sorted(k for k, v in mp.items() if k not in LOGGER_MAPPED_KEYS + LOGGER_EMPTY_KEYS + ("headers",)
                    and any("{{" in x for x in _strings(v)))
    if mapped:
        problems.append(f"maps data outside the form body ({', '.join(mapped)}). Only the URL variable and the form body may hold a mapping")
    if mp.get("allowRedirects") is not False:
        problems.append("does not set allowRedirects false, so a redirect could carry the key to another host")
    if mp.get("stopOnHttpError") is not False:
        problems.append("treats a 4xx or 5xx reply as an error (Return error if HTTP request fails, stopOnHttpError, defaults to on). "
                        "An error inside an error route ends the run with an error, so turn it off")
    if _onerror(m):
        problems.append("has its own error handler. On a Logger failure the directive after it would not run and Make would skip the "
                        "original error (help.make.com, Overview of error handling). Not accepted until Rizwan decides (spec section 9)")
    body, body_problems = logger_body(m)
    problems.extend(body_problems)
    if body is None:
        return problems
    missing = [k for k in LOGGER_BODY_REQUIRED if k not in body]
    if missing:
        problems.append(f"does not send {', '.join(missing)}")
    unknown = sorted(k for k in body if k not in LOGGER_BODY_REQUIRED + LOGGER_BODY_OPTIONAL)
    if unknown:
        problems.append(f"sends {', '.join(unknown)}, outside the Logger body (label, outcome, module_id, module_name, error_type, "
                        f"error_message, execution_id, lead_record_id, call_id). Nothing else goes in, no client data (E6)")
    oid = owner.get("id") if owner is not None else None
    if "outcome" in body and str(body["outcome"]).strip() != "Error":
        problems.append("does not send outcome Error")
    if "label" in body and not _is_literal(body["label"]):
        problems.append("does not send the label as a fixed literal")
    if "module_id" in body and (oid is None or str(body["module_id"]).strip() != str(oid)):
        problems.append(f"does not send module_id {oid}, the module whose handler holds it")
    if "module_name" in body and not _is_literal(body["module_name"]):
        problems.append("does not send module_name as a fixed literal")
    for k, fld in (("error_type", "type"), ("error_message", "message")):
        e = _single_expression(body.get(k)) if k in body else None
        if k in body and (e is None or re.fullmatch(rf"{oid}\.error\.{fld}", e) is None):
            problems.append(f"does not send {k} as exactly {{{{{oid}.error.{fld}}}}}")
    if "execution_id" in body and (_single_expression(body["execution_id"]) or "") != "var.scenario.executionId":
        problems.append("does not send execution_id as exactly {{var.scenario.executionId}}")
    for k in LOGGER_BODY_OPTIONAL:
        if k not in body:
            continue
        if not _one_ref(body[k]) and not (k == "lead_record_id" and _first_of_ref(body[k]) is not None):
            problems.append(f"sends {k} that is not one mapped reference (leave it out when none is in scope)")
        elif scope is None:
            problems.append(f"sends {k} that cannot be confirmed without the scenario it sits in")
        else:
            p = _lead_record_problem(scope, body[k]) if k == "lead_record_id" else _call_id_problem(scope, body[k])
            if p:
                problems.append(p)
    if scope is not None:
        for name, value in body.items():
            problems.extend(_logger_pii(scope, name, value))
    return problems


# The Cloudflare Worker of F-H9 (worker/stripe-verify, option A3): it checks the Stripe signature, then calls the Make
# listener with the hook's API key and forwards only event_id, type, object_id, object_type, livemode and created.
STRIPE_CALLER = "stripe_verifier"
# The request field that identifies one delivery for the F3 duplicate gate, per caller (default call_id).
F3_DELIVERY_FIELD = {STRIPE_CALLER: "event_id"}
CALLERS = ("bland_pathway_node", "bland_post_call", LOGGER_CALLER, STRIPE_CALLER)
PROTECTIONS = ("api_key", "fetch_back")
# The Bland call-details module. It is the only module the blueprints use to read a call from Bland.
FETCH_MODULES = ("bland:getCallDetails",)
# The one request field a fetch-back scenario may read: the Bland call ID.
CALL_ID_FIELDS = ("call_id",)
# Tables a call ID must match a record in: System Logs (the Shadow Ledger) and Applicants (leads).
GATE_TABLES = (LEDGER_TABLE, LEAD_TABLE)
_READ_ONLY_MODULE = re.compile(r"^(?:Action)?(?:Search|Get|List|Watch|Read|Fetch|Download|Trigger)", re.I)


def _logger_spec(name: str, where: str, e: dict, sid: str | None, hid: int | None) -> LoggerSpec:
    """The Logger fields of an entry with caller make_http: url_variable (a custom variable name such as
    var.team.IMMIOS_LOGGER_URL, without braces) and connection_id (the HTTP API key connection, or null until it exists).
    A missing url_variable is allowed while the Logger is not deployed, and check L flags it once it is."""
    var = e.get("url_variable")
    if var is not None and not (isinstance(var, str) and _CUSTOM_VAR.match(var.strip())):
        raise InputError(f"{name} {where}: url_variable must name a team or organization custom variable, for example "
                         f"var.team.IMMIOS_LOGGER_URL (no braces). A literal hook URL is a bearer secret and never goes in the registry")
    conn = e.get("connection_id")
    if conn is not None and not _pos_int(conn):
        raise InputError(f"{name} {where}: connection_id must be null or the positive ID of the Logger's HTTP API key connection")
    digest = e.get("url_sha256")
    if digest is not None and not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise InputError(f"{name} {where}: url_sha256 must be the 64 lower-case hex characters of the SHA-256 of the Logger hook token")
    if digest is not None and var is not None:
        raise InputError(f"{name} {where}: set url_variable or url_sha256, not both")
    return LoggerSpec(sid, hid, var.strip() if isinstance(var, str) else None, conn, str(e.get("reason", "")).strip(), digest)


def _check_entry(name: str, where: str, e: object, logger_pending: bool = False) -> tuple:
    """(scenario ID, hook ID, caller, protection, reason, lookup label) of one registry entry. logger_pending allows the
    null scenario_id and hook_id of the top-level logger entry, before Rizwan imports the Logger."""
    if not isinstance(e, dict):
        raise InputError(f"{name} {where} is not an object")
    sid, hid = e.get("scenario_id"), e.get("hook_id")
    if logger_pending and sid is None and hid is None:
        pass
    else:
        if isinstance(sid, bool) or not isinstance(sid, (int, str)) or not str(sid).strip().isdigit():
            raise InputError(f"{name} {where}: scenario_id must be a scenario ID (digits)")
        if isinstance(hid, bool) or not isinstance(hid, int) or hid <= 0:
            raise InputError(f"{name} {where}: hook_id must be a positive integer")
    caller, protection = e.get("caller"), e.get("protection")
    if caller not in CALLERS:
        raise InputError(f"{name} {where}: caller must be one of {', '.join(CALLERS)}")
    if protection not in PROTECTIONS:
        raise InputError(f"{name} {where}: protection must be one of {', '.join(PROTECTIONS)}")
    if caller == "bland_post_call" and protection != "fetch_back":
        raise InputError(f"{name} {where}: a Bland post-call webhook cannot send a custom header, so it must use fetch_back")
    if caller == STRIPE_CALLER and protection != "api_key":
        raise InputError(f"{name} {where}: the Stripe verifier Worker sends the Make API key, so it must use api_key")
    if caller == LOGGER_CALLER and protection != "api_key":
        raise InputError(f"{name} {where}: the Logger is called by Make HTTP modules that send the key, so it must use api_key")
    reason = e.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < 8 or not re.search(r"[A-Za-z]{3}", reason):
        raise InputError(f"{name} {where} needs a real reason (a sentence)")
    lookup_label = e.get("lookup_label", "")
    if protection == "fetch_back":
        if not isinstance(lookup_label, str) or not lookup_label.strip() or "'" in lookup_label or "{" in lookup_label:
            raise InputError(f"{name} {where}: a fetch_back scenario needs lookup_label, the Shadow Ledger label of the row its caller "
                             f"creates (a plain label, no quote or brace)")
    elif lookup_label not in ("", None):
        raise InputError(f"{name} {where}: lookup_label belongs to fetch_back scenarios only")
    if caller != LOGGER_CALLER and ("url_variable" in e or "connection_id" in e):
        raise InputError(f"{name} {where}: url_variable and connection_id belong to the Logger entry (caller {LOGGER_CALLER}) only")
    return (None if sid is None else str(sid).strip(), hid, caller, protection, reason.strip(), (lookup_label or "").strip())


def load_webhooks(path: str, required: bool = False) -> Webhooks:
    if not os.path.exists(path):
        if required:
            raise InputError(f"no webhook registry at {path}")
        return Webhooks()
    data = _read_json(path)
    name = os.path.basename(path)
    raw = data.get("scenarios") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise InputError(f"{name} has no scenarios list")
    entries: dict[str, WebhookEntry] = {}
    logger: LoggerSpec | None = None
    for i, e in enumerate(raw):
        key, hid, caller, protection, reason, lookup_label = _check_entry(name, f"entry {i}", e)
        if key in entries:
            raise InputError(f"{name} lists scenario {key} twice")
        entries[key] = WebhookEntry(key, hid, caller, protection, reason, lookup_label,
                                    _ended_statuses(name, f"entry {i}", e, protection))
        if caller == LOGGER_CALLER:
            if logger is not None:
                raise InputError(f"{name} lists two Logger entries (caller {LOGGER_CALLER}). There is one shared Logger")
            logger = _logger_spec(name, f"entry {i}", e, key, hid)
    top = data.get("logger")
    if top is not None:
        if logger is not None:
            raise InputError(f"{name} has the Logger both under logger and in scenarios. Once its IDs are known it lives in scenarios only")
        key, hid, caller, protection, reason, lookup_label = _check_entry(name, "logger", top, logger_pending=True)
        if caller != LOGGER_CALLER:
            raise InputError(f"{name} logger: caller must be {LOGGER_CALLER}")
        logger = _logger_spec(name, "logger", top, key, hid)
        if key is not None:
            if key in entries:
                raise InputError(f"{name} lists scenario {key} twice")
            entries[key] = WebhookEntry(key, hid, caller, protection, reason, lookup_label)
    return Webhooks(entries, logger)


def load_hooks_info(manifest_path: str | None) -> HookInfo:
    """The hooks make_pull recorded. Never raises: no manifest, no hooks key and hooks: null all
    mean the auth state is unknown."""
    if not manifest_path or not os.path.exists(manifest_path):
        return HookInfo(note="no manifest")
    try:
        data = _read_json(manifest_path)
    except InputError:
        return HookInfo(note="manifest unreadable")
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, list):
        note = data.get("hooks_note") if isinstance(data, dict) and isinstance(data.get("hooks_note"), str) else "manifest has no hook list"
        return HookInfo(note=note)
    return HookInfo(True, {h["id"]: h for h in hooks if isinstance(h, dict) and isinstance(h.get("id"), int)})


def _trigger_refs(m: dict, tid: object) -> dict[str, str]:
    """Fields of the trigger a module references -> the path of the first reference."""
    out: dict[str, str] = {}
    for path, expr in _module_exprs(m):
        for r in iml_refs(expr):
            if r.module == tid:
                out.setdefault(r.field, path)
    return out


def _is_effect(m: dict) -> bool:
    """A module that writes, sends or spends: external and not a read."""
    t = _mtype(m)
    return is_external(m) and not _READ_ONLY_MODULE.match(t.split(":", 1)[-1])


def _is_call_id_ref(v: object, module: object) -> bool:
    """Exactly one bare reference {{module.call_id}} with nothing around it."""
    e = _single_expression(v)
    refs = iml_refs(e) if e else []
    return bool(e) and len(refs) == 1 and refs[0].module == module and refs[0].field in CALL_ID_FIELDS and refs[0].text == e.strip()


# The Shadow Ledger field a fetch-back lookup keys on (System Logs, fldHf8yjOMGfgyJhc).
LOOKUP_FIELD = "External Call ID"
LOOKUP_TABLE = LEDGER_TABLE
_PIN_WS = re.compile(r"\s+")


def _balanced_formula(s: str) -> bool:
    """Parentheses balance and quotes close, so a remainder cannot end the AND( early."""
    depth, quote, i = 0, "", 0
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
        i += 1
    return depth == 0 and not quote


def _pin_predicate(fid: object) -> str:
    return r"\{" + re.escape(LOOKUP_FIELD) + r"\}\s*=\s*'\{\{\s*" + re.escape(str(fid)) + r"\.call_id\s*\}\}'"


def _pinned_lookup_formula(formula: object, fid: object) -> bool:
    """The lookup formula is exactly {External Call ID} = '{{<fid>.call_id}}', or an AND( ) whose
    first argument is that and whose other arguments hold no {{ }} reference. Anything else (an OR,
    a !=, another field, the request call ID) can match a record the call has nothing to do with."""
    if not isinstance(formula, str) or fid is None:
        return False
    pred = _pin_predicate(fid)
    f = formula.strip()
    if re.fullmatch(pred, f):
        return True
    m = re.fullmatch(r"AND\s*\(\s*" + pred + r"\s*,(.*)\)", f, re.S)
    if not m:
        return False
    rest = m.group(1)
    return bool(rest.strip()) and "{{" not in rest and _balanced_formula(rest)


def _split_top_level(s: str) -> list[str]:
    """Split an Airtable formula argument list at top-level commas (outside quotes, parentheses
    and {field} names)."""
    out, depth, brace, quote, cur, i = [], 0, 0, "", [], 0
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == "{":
            brace += 1
            cur.append(c)
        elif c == "}":
            brace -= 1
            cur.append(c)
        elif c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0 and brace == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


# A top-level AND( ) argument that is true only while a ledger field is blank. The idiom is
# {Field} = BLANK(). The other forms Airtable accepts for "empty" are listed too.
_FIELD = r"\{(?P<f>[^{}]+)\}"
_BLANK_TESTS = tuple(re.compile(p, re.I | re.S) for p in (
    _FIELD + r"\s*=\s*BLANK\(\s*\)",
    r"BLANK\(\s*\)\s*=\s*" + _FIELD,
    _FIELD + r"\s*=\s*(?:''|\"\")",
    r"NOT\(\s*" + _FIELD + r"\s*\)",
    r"LEN\(\s*" + _FIELD + r"\s*\)\s*=\s*0",
))
# Airtable reads a 0 in a number, currency or percent field as blank for every test above. Joining the field
# with an empty text turns 0 into "0", so this is the one form that tells a recorded 0 from a blank cell.
_SAFE_BLANK_TEST = re.compile(r"LEN\(\s*" + _FIELD + r"\s*&\s*(?:''|\"\")\s*\)\s*=\s*0", re.I | re.S)


def _and_rest(formula: object, fid: object) -> list[str] | None:
    """The top-level arguments after the call ID pin of an AND( ) lookup formula, or None."""
    if not isinstance(formula, str) or fid is None:
        return None
    m = re.fullmatch(r"AND\s*\(\s*" + _pin_predicate(fid) + r"\s*,(.*)\)", formula.strip(), re.S)
    return _split_top_level(m.group(1)) if m else None


def _unreconciled_fields(formula: object, fid: object) -> list[tuple[str, bool]]:
    """(ledger field, safe) for the fields the pinned lookup requires to be blank: top-level arguments of the
    AND( ) after the call ID pin that are exactly a blank test. safe is True for LEN({F}&'')=0, the one form
    that does not read a recorded 0 in a number field as blank. A blank test nested in an OR, or joined with
    anything else, restricts nothing and is not listed."""
    out: list[tuple[str, bool]] = []
    for arg in _and_rest(formula, fid) or []:
        a = " ".join(arg.split())
        hit = _SAFE_BLANK_TEST.fullmatch(a)
        if hit:
            out.append((hit.group("f").strip(), True))
            continue
        for rx in _BLANK_TESTS:
            hit = rx.fullmatch(a)
            if hit:
                out.append((hit.group("f").strip(), False))
                break
    return out


LABEL_FIELD_NAME = "Scenario name"


def _label_pinned(formula: object, fid: object, label: str) -> bool:
    """A top-level argument of the AND( ) lookup formula is exactly {Scenario name} = '<label>', so only a row
    that the calling scenario created can match."""
    if not label:
        return False
    rx = re.compile(r"\{\s*" + re.escape(LABEL_FIELD_NAME) + r"\s*\}\s*=\s*(?:'" + re.escape(label) + r"'|\"" + re.escape(label) + r"\")", re.I)
    return any(rx.fullmatch(" ".join(arg.split())) for arg in _and_rest(formula, fid) or [])


def _lookup_shape_problems(lm: dict, fid: object, entry: "WebhookEntry | None") -> list[str]:
    """What a pinned lookup lacks to match exactly the one ledger row of this call: one record at most, and
    the row kind of the calling scenario. Several rows would each run every effect once, and a row another
    scenario wrote with the same call ID and a blank cost field would reopen the replay."""
    out = []
    mr = _mapper(lm).get("maxRecords")
    if str(mr).strip() != "1":
        out.append(f"mapper.maxRecords is {mr!r}, it must be 1 so a second row cannot run every effect again")
    label = entry.lookup_label if entry is not None else ""
    if not label:
        out.append("audit/webhooks.json gives this scenario no lookup_label, so the lookup cannot pin the row kind")
    elif not _label_pinned(_mapper(lm).get("formula"), fid, label):
        out.append(f"the formula does not pin the row kind with a top-level argument {{{LABEL_FIELD_NAME}}} = '{label}' (the label of the scenario "
                   f"that creates the row)")
    return out


def _is_lookup_id_ref(v: object, lid: object) -> bool:
    """Exactly {{<lookup>.id}} with nothing around it."""
    e = _single_expression(v)
    refs = iml_refs(e) if e else []
    return bool(e) and len(refs) == 1 and refs[0].module == lid and refs[0].field == "id" and refs[0].text == e.strip()


def _completion_filter(m: dict, fid: object, ended: tuple = ("completed",)) -> bool:
    """The module's inbound filter requires the call-details output to say the call has ended:
    {{<fid>.status}} equal "completed" (Bland call details, docs.bland.ai/api-v1/get/calls-id) in the one
    AND group. {{<fid>.completed}} is not accepted, because Bland sets it true on calls that failed or were
    not answered. Other conditions may sit in the same group, since they only narrow it. A scenario whose
    registry entry lists more ended_statuses (M1) may have one OR group per status, and every group must
    require one of the listed statuses, so no group lets a call in progress through."""
    groups = _conditions(m)
    if fid is None or not groups or not all(isinstance(g, list) for g in groups):
        return False
    if len(groups) != 1 and tuple(ended) == ("completed",):
        return False
    allowed = {x.lower() for x in ended}

    def group_ok(group: list) -> bool:
        for c in group:
            if not isinstance(c, dict):
                continue
            e = _single_expression(c.get("a"))
            refs = iml_refs(e) if e else []
            if not (e and len(refs) == 1 and refs[0].module == fid and refs[0].text == e.strip()):
                continue
            op, b = str(c.get("o", "")), c.get("b")
            if refs[0].field == "status" and op in ("text:equal", "text:equal:ci") and isinstance(b, str) \
                    and not is_mapping(b) and b.strip().lower() in allowed:
                return True
        return False

    return all(group_ok(g) for g in groups)


def _unreconciled_filter_fields(m: dict, lookup_id: object) -> list[str]:
    """Ledger fields a module's inbound filter requires to be empty on the lookup's record: one AND
    group with a notexist condition on {{<lookup>.<Field>}}."""
    groups = _conditions(m)
    if len(groups) != 1 or not isinstance(groups[0], list):
        return []
    out: list[str] = []
    for c in groups[0]:
        if not isinstance(c, dict) or str(c.get("o", "")) != "notexist":
            continue
        e = _single_expression(c.get("a"))
        refs = iml_refs(e) if e else []
        if e and len(refs) == 1 and refs[0].module == lookup_id and refs[0].text == e.strip():
            out.append(refs[0].field)
    return out


def _call_id_search(m: dict, tid: object, fid: object) -> bool:
    """A search on the ledger or the lead table whose formula carries a call ID reference."""
    if _mtype(m) != "airtable:ActionSearchRecords" or _module_table(m) not in GATE_TABLES:
        return False
    for expr in _value_exprs(_mapper(m).get("formula")):
        if any(r.field in CALL_ID_FIELDS and r.module in (tid, fid) for r in iml_refs(expr)):
            return True
    return False


def _is_lookup(m: dict, tid: object, fid: object) -> bool:
    """A Shadow Ledger (System Logs) search keyed by the call-details output, in the pinned form
    (decision 2: a ledger row the system created)."""
    return (_mtype(m) == "airtable:ActionSearchRecords" and fid is not None and _module_table(m) == LOOKUP_TABLE
            and _pinned_lookup_formula(_mapper(m).get("formula"), fid))


def _found_filter(nxt: dict | None, src: object) -> bool:
    """The next module's inbound filter is exactly [[{a: '{{<src>.id}}', o: 'exist'}]]: the lookup
    found a record, nothing else."""
    groups = _conditions(nxt) if isinstance(nxt, dict) else []
    if len(groups) != 1 or not isinstance(groups[0], list) or len(groups[0]) != 1:
        return False
    c = groups[0][0]
    if not isinstance(c, dict) or str(c.get("o", "")) != "exist" or set(c) - {"a", "o", "b"} or c.get("b") not in (None, ""):
        return False
    e = _single_expression(c.get("a"))
    refs = iml_refs(e) if e else []
    return bool(e) and len(refs) == 1 and refs[0].module == src and refs[0].field == "id" and refs[0].text == e.strip()


def _directive(m: dict) -> str | None:
    for x in reversed(_onerror(m)):
        if isinstance(x, dict) and _mtype(x) in DIRECTIVES:
            return _mtype(x)
    return None


def _handler_directives(m: dict) -> list[str]:
    """Every directive in the module's error handler at any depth (a handler may hold a router)."""
    return [_mtype(x) for x, _e, _c in walk(_onerror(m), True) if _mtype(x) in DIRECTIVES]


def _handler_owner(chain: tuple) -> dict | None:
    """The nearest module on the chain whose error handler (onerror list) holds the module."""
    for k in range(len(chain) - 1, 0, -1):
        pf, pi = chain[k - 1]
        parent = pf[pi] if isinstance(pf[pi], dict) else None
        if parent is not None and chain[k][0] is parent.get("onerror"):
            return parent
    return None


def _bare_reads(m: dict) -> list[str]:
    """Bare names ({{name}} or a name inside an expression) with no module prefix."""
    out: list[str] = []
    for _path, expr in _module_exprs(m):
        bare = _bare_token(expr)
        for w in ([bare] if bare is not None else _bare_words_in_expression(expr)):
            if w not in out:
                out.append(w)
    return out


def check_f(b: Blueprint, allow: Allowlist, webhooks: Webhooks | None = None, hooks: HookInfo | None = None,
            links: AirtableMap | None = None, label: str | None = None) -> list[Finding]:
    """label is the scenario's confirmed ledger label (audit/scenario_labels.json). audit() always passes it, and with it
    F3 (duplicate delivery) runs on api_key scenarios. "" means the scenario has no label entry, an F3 FAIL. None skips F3."""
    flow = b.bp.get("flow") or []
    trig = flow[0] if flow and isinstance(flow[0], dict) else None
    if trig is None or _mtype(trig) != "gateway:CustomWebHook":
        # A scenario the registry lists as a webhook scenario must keep its webhook trigger. Swapping the
        # trigger type would otherwise make every F row disappear.
        sid = None if b.scenario_id is None else str(b.scenario_id)
        if webhooks is not None and sid is not None and sid in webhooks.entries:
            at = trig if trig is not None else {"id": "-", "module": "-"}
            out = [Finding("F", FAIL, _scenario_label(b), at.get("id"), _mtype(at),
                           f"F0 audit/webhooks.json lists scenario {sid} as a webhook scenario (hook {webhooks.entries[sid].hook_id}) but its first module "
                           f"is not a gateway:CustomWebHook trigger, so none of the webhook checks can run. Restore the webhook trigger, "
                           f"or remove the scenario from the registry in a reviewed commit", "F0")]
            return out
        return []
    webhooks = webhooks or Webhooks()
    hooks = hooks or HookInfo()
    scen = _scenario_label(b)
    tid = trig.get("id")
    params = trig.get("parameters") if isinstance(trig.get("parameters"), dict) else {}
    measured = params.get("hook")
    sid = None if b.scenario_id is None else str(b.scenario_id)
    out: list[Finding] = []

    def row(status: str, rule: str, m: dict, detail: str) -> None:
        out.append(Finding("F", status, scen, m.get("id"), _mtype(m), f"{rule} {detail}", rule))

    entry = webhooks.entries.get(sid) if sid else None
    if entry is None:
        row(FAIL, "F0", trig, f"Webhook scenario {sid or '(no scenario ID)'} (hook {measured}) is not in audit/webhooks.json. "
                              f"Add it with the caller and the protection (api_key or fetch_back), so the audit knows what to check")
        return out
    if entry.hook_id != measured:
        row(FAIL, "F0", trig, f"audit/webhooks.json lists hook {entry.hook_id} for this scenario but the trigger uses hook {measured}. "
                              f"Confirm which hook the caller uses, then correct the registry")
        return out
    if entry.protection == "api_key":
        _check_f1(b, entry, hooks, trig, allow, out, row)
        if label is not None and entry.caller != LOGGER_CALLER:
            _check_f3(b, trig, out, row, label, links, entry.caller)
    else:
        _check_f2(b, trig, out, row, links, entry, webhooks.logger)
    return out


def _check_f1(b, entry, hooks, trig, allow, out, row) -> None:
    """F1: the hook requires at least one API key (Make header x-make-apikey). Decision 1 has no
    exception, so F1 cannot be allowlisted. A hook whose key state is unknown is a FAIL (UNCONFIRMED):
    without proof that a key exists, a fresh pull must not pass the audit."""
    hid = entry.hook_id
    info = hooks.by_id.get(hid) if hooks.available else None
    unconfirmed = "UNCONFIRMED, no proof that a key exists: "
    if not hooks.available:
        row(FAIL, "F1", trig, f"{unconfirmed}hook auth state unknown, read token needs Webhooks: View. Hook {hid} cannot be checked for an API key"
                              f" ({hooks.note or 'no hook data'})")
    elif info is None:
        row(FAIL, "F1", trig, f"{unconfirmed}hook auth state unknown, hook {hid} is not in the hook list make_pull recorded")
    elif info.get("scenario_ids") and str(b.scenario_id) not in {str(x) for x in info["scenario_ids"]}:
        row(FAIL, "F1", trig, f"hook {hid} serves scenarios {info['scenario_ids']}, not this scenario. Check which hook the trigger and the caller use")
    elif info.get("apikey_count") is None:
        row(FAIL, "F1", trig, f"{unconfirmed}hook auth state unknown, the hook list has no API key field for hook {hid}. Confirm in the Make UI "
                              f"(Webhooks, the hook, API Key authentication), then pin the field name make_pull reads")
    elif info["apikey_count"] == 0:
        row(FAIL, "F1", trig, f"hook {hid} has no API key configured. Anyone who learns the hook URL can start this scenario. "
                              f"Add an API key with a keychain to the hook (specs/X-23-pending-call-api-key.md)")
    else:
        row(PASS, "F1", trig, f"hook {hid} requires {info['apikey_count']} API key(s)")


def _check_f2(b: Blueprint, trig: dict, out: list, row, links: AirtableMap | None = None, entry: WebhookEntry | None = None,
              logger: "LoggerSpec | None" = None) -> None:
    """F2: statically verify the fetch-back pattern. Each violation is a FAIL row on the module
    that has to change. The call-details module is the only module that reads the request."""
    flow = b.bp.get("flow") or []
    tid = trig.get("id")
    ended = entry.ended_statuses if entry is not None else ("completed",)
    mods = [(m, err, chain) for m, err, chain in walk(flow) if m is not trig]
    top = lambda chain: chain[0][1]  # noqa: E731  index of the module (or its ancestor) in the main flow
    on_trunk = lambda chain: len(chain) == 1  # noqa: E731

    fetch = next((m for m, err, ch in mods if not err and on_trunk(ch) and _mtype(m) in FETCH_MODULES), None)
    fidx = top(next(ch for m, err, ch in mods if m is fetch)) if fetch is not None else None
    fid = fetch.get("id") if fetch is not None else None
    problems = 0

    def bad(m: dict, rule: str, detail: str) -> None:
        nonlocal problems
        problems += 1
        row(FAIL, rule, m, detail)

    # (a) The call-details module.
    if fetch is None:
        stray = next((m for m, err, ch in mods if _mtype(m) in FETCH_MODULES), None)
        first = flow[1] if len(flow) > 1 and isinstance(flow[1], dict) else trig
        if stray is not None:
            bad(stray, "F2a", f"Call-details module {stray.get('id')} sits inside a route or error handler. It must be on the main flow, "
                              f"right after the webhook and before any router, so every request is verified first")
        else:
            bad(first, "F2a", f"No Bland call-details module ({FETCH_MODULES[0]}) fed by {{{{{tid}.call_id}}}} on the main flow. A fetch-back scenario "
                              f"takes only the call ID from the request and re-fetches the call from Bland before anything else reads it")
    else:
        mp = _mapper(fetch)
        refs = _trigger_refs(fetch, tid)
        extra = sorted(f for f in refs if f not in CALL_ID_FIELDS)
        if not _is_call_id_ref(mp.get("call_id"), tid):
            bad(fetch, "F2a", f"Call-details module {fid} is not fed by exactly {{{{{tid}.call_id}}}}. Its call_id input must be that one "
                              f"reference with no function or text around it")
        elif extra:
            bad(fetch, "F2a", f"Call-details module {fid} reads request fields other than the call ID ({', '.join(extra)})")
        if "builtin:Resume" in _handler_directives(fetch):
            bad(fetch, "F2a", f"Call-details module {fid} has an error handler that ends in Resume, so a call ID Bland rejects "
                              f"continues with substituted output and verification is skipped. End the handler with Break or Ignore")

    ref_n = fid if fid is not None else "N"
    pinned = f"{{External Call ID}} = '{{{{{ref_n}.call_id}}}}'"

    # (b) the lookups that tie the call-details output to a ledger row the system created.
    lookups = {m.get("id"): m for m, err, ch in mods if not err and _is_lookup(m, tid, fid)}
    gate_from: dict[int, int] = {}   # id(flow list) -> first index the lookup gates
    lookup_start: dict = {}          # lookup id -> (id(flow list), first index it gates), for lookups that gate
    for m, err, chain in mods:
        if err:
            continue
        if m.get("id") not in lookups:
            if _call_id_search(m, tid, fid):
                bad(m, "F2b", f"Module {m.get('id')} searches by a call ID but is not the pinned lookup, so it gates nothing. It must search "
                              f"System Logs with the formula {pinned} (N is the call-details module, and the formula may be an AND( ) "
                              f"whose other arguments hold no reference) and must not read the request")
            continue
        flow_list, i = chain[-1]
        nxt = flow_list[i + 1] if i + 1 < len(flow_list) and isinstance(flow_list[i + 1], dict) else None
        ok = _found_filter(nxt, m.get("id"))
        if not ok and nxt is not None:
            bad(nxt, "F2b", f"Lookup module {m.get('id')} has no found filter on this module, so a call ID that matches no record still passes. "
                            f"The filter on the link into this module must be exactly: {{{{{m.get('id')}.id}}}} exists")
        if "builtin:Resume" in _handler_directives(m):
            ok = False
            bad(m, "F2b", f"Lookup module {m.get('id')} has an error handler that ends in Resume, so a failed search continues "
                          f"and the gate is skipped. End its handler with Break or Ignore")
        if ok:
            gate_from[id(flow_list)] = min(gate_from.get(id(flow_list), 10 ** 9), i + 1)
            lookup_start[m.get("id")] = (id(flow_list), i + 1)

    def covered(start: dict):
        return lambda chain: any(i >= start[id(fl)] for fl, i in chain if id(fl) in start)

    gated = covered(gate_from)

    def exempt_owner(chain: tuple) -> bool:
        """A module in the error handler of the call-details module or of a lookup, at any depth
        (a router inside the handler counts). Check B requires that handler, and it fires on
        exactly the request that fails verification."""
        owner = _handler_owner(chain)
        return owner is not None and (owner is fetch or owner.get("id") in lookups)

    def uncovered(cov):
        """Modules that write, send or spend outside the cover, and the owners whose error handler does."""
        direct: list[dict] = []
        handler: dict = {}
        for m, err, chain in mods:
            if not _is_effect(m) or cov(chain) or (err and exempt_owner(chain)):
                continue
            if err:
                owner = _handler_owner(chain)
                if owner is None:
                    continue
                if _is_effect(owner) and not cov(chain[:-1]):
                    continue  # the owner's own row covers its handler
                handler.setdefault(owner.get("id"), (owner, []))[1].append(m.get("id"))
                continue
            direct.append(m)
        return direct, handler

    b_direct, b_handler = uncovered(gated)
    for m in b_direct:
        bad(m, "F2b", f"Writes or sends before a ledger lookup by the call-details call ID gates it, so a request for a call the system "
                      f"never created still runs this module. Put a Shadow Ledger (System Logs) lookup with the formula {pinned} and a "
                      f"found filter before it")
    for pid, (parent, ids) in sorted(b_handler.items(), key=lambda kv: str(kv[0])):
        bad(parent, "F2b", f"Error handler modules {sorted(ids, key=str)} write or send before any ledger lookup by call ID gates this module, "
                           f"so a forged request that makes it fail still runs them")

    # (d) F2d, replay. A real call ID plus the hook URL must not re-run a call, and a request that
    # arrives while the call is still in progress must not write state. Two gates in front of every
    # write: the fetched call is complete, and the ledger row is not yet reconciled. The reconciliation
    # itself is the first effect after both gates, so the check-then-act window is as short as it can be,
    # and the scenario runs one execution at a time, so two requests cannot both pass the gate.
    if fid is not None:
        meta = b.bp.get("metadata") if isinstance(b.bp.get("metadata"), dict) else {}
        scen_meta = meta.get("scenario") if isinstance(meta.get("scenario"), dict) else {}
        if scen_meta.get("sequential") is not True:
            bad(trig, "F2d", "Sequential processing is off for this scenario, so two requests for the same call that arrive together run in parallel, "
                             "both pass the unreconciled gate and both write (Voice AI cost double-counted, X-1). In the Make UI open the scenario "
                             "settings and turn on Sequential processing, then re-pull. make_push cannot change scenario settings")
        numeric = {n.strip().lower() for n in ((links.numeric_fields.get(LOOKUP_TABLE) or []) if links is not None else [])}
        lookup_pos: dict = {}   # lookup id -> (flow list, index of the lookup in it)
        for m, err, chain in mods:
            if not err and m.get("id") in lookups:
                lookup_pos[m.get("id")] = chain[-1]

        def gate_filter(x: dict, lid: object) -> bool:
            return _found_filter(x, lid) or _completion_filter(x, fid, ended) or bool(_unreconciled_filter_fields(x, lid))

        def reconcile_problem(lid: object, name: str, fld: str | None) -> str | None:
            """The reconciliation write must really fill the marker on the row the lookup found, run on the
            gated path every effect passes through, and fail loudly."""
            flow_list, li = lookup_pos[lid]
            rid = f"{{{{{lid}.id}}}}"
            for j in range(li + 1, len(flow_list)):
                x = flow_list[j]
                if not isinstance(x, dict):
                    continue
                if _conditions(x) and not gate_filter(x, lid):
                    return (f"module {x.get('id')} between the lookup and the reconciliation update carries a filter that is not one of the gates, "
                            f"so the update can be skipped while the scenario goes on")
                if _mtype(x) == "airtable:ActionUpdateRecords" and _mapper(x).get("table") == LEDGER_TABLE and _is_lookup_id_ref(_mapper(x).get("id"), lid):
                    rec = _record(x)
                    sets = nonempty(rec.get(fld)) or nonempty(rec.get(name)) if fld is not None else any(nonempty(v) for v in rec.values())
                    if not sets:
                        return f"the update {x.get('id')} of the looked-up row does not set {{{name}}} to a value, so the field stays blank after a call is reconciled"
                    dirs = _handler_directives(x)
                    if "builtin:Break" not in dirs or any(d != "builtin:Break" for d in dirs):
                        return (f"the reconciliation update {x.get('id')} has no error handler that ends in Break (it is {sorted(set(dirs)) or 'missing'}). "
                                f"A failed update that continues or is ignored leaves the row blank and the call replayable")
                    return None
                if _mtype(x) == "airtable:ActionUpdateRecords" and _mapper(x).get("table") == LEDGER_TABLE:
                    return (f"the update {x.get('id')} of System Logs does not have the id {rid} exactly, so it does not reconcile the looked-up row "
                            f"and leaves it blank, and the call replayable")
                if x.get("routes"):
                    return (f"router {x.get('id')} sits between the lookup and the reconciliation update, so an effect can run on a route where the update "
                            f"never does. The update must come first, on the main flow")
                if _is_effect(x):
                    return (f"module {x.get('id')} writes, sends or spends before the reconciliation update, so a failure after it leaves the row blank "
                            f"and the call replayable. Move the update of the looked-up row to be the first effect after the gates")
            return (f"no airtable:ActionUpdateRecords on System Logs whose id is exactly {rid} sets {{{name}}} on the flow of lookup {lid}. A new row, "
                    f"another record or a write on a route that may not run leaves the looked-up row blank, so the condition never excludes a replay")

        def marker_problem(name: str, safe: bool, lid: object) -> str | None:
            if name.strip().lower() == LOOKUP_FIELD.lower():
                return f"{{{name}}} is the call ID pin itself"
            fld = None
            if links is not None and LOOKUP_TABLE in links.tables:
                fld = links._field_id(LOOKUP_TABLE, name)
                if fld is None:
                    return f"{{{name}}} is not a System Logs field"
                if links.field_label(LOOKUP_TABLE, fld).strip().lower() in numeric and not safe:
                    return (f"{{{name}}} is a number field and Airtable reads 0 as blank, so a call that costs 0 stays unreconciled and every replay "
                            f"runs the scenario again. Test LEN({{{name}}}&'')=0 instead, or use a text, date or checkbox field such as a Reconciled At timestamp")
            return reconcile_problem(lid, name, fld)

        shape: dict = {}
        for lid in lookup_start:
            shape[lid] = _lookup_shape_problems(lookups[lid], fid, entry)
        done_from: dict[int, int] = {}
        for m, err, chain in mods:
            if not err and m is not fetch and top(chain) > fidx and _completion_filter(m, fid, ended):
                fl, i = chain[-1]
                done_from[id(fl)] = min(done_from.get(id(fl), 10 ** 9), i)
        idem_from: dict[int, int] = {}
        idem_ok: set = set()
        for lid, (flid, start) in lookup_start.items():
            if not shape[lid] and any(marker_problem(f, safe, lid) is None for f, safe in _unreconciled_fields(_mapper(lookups[lid]).get("formula"), fid)):
                idem_from[flid] = min(idem_from.get(flid, 10 ** 9), start)
                idem_ok.add(lid)
        variant_lids: set = set()   # lookups whose unreconciled condition is a filter, not the formula
        variant_why: dict = {}      # lookup id -> why its filter form was rejected
        for m, err, chain in mods:
            if err:
                continue
            for lid, (flid, start) in lookup_start.items():
                if lid in idem_ok or shape[lid]:
                    continue
                probs = [marker_problem(f, False, lid) for f in _unreconciled_filter_fields(m, lid)]
                if probs and not any(p is None for p in probs):
                    variant_why.setdefault(lid, set()).update(probs)
                if not any(p is None for p in probs):
                    continue
                if any(id(fl) == flid and i >= start for fl, i in chain):
                    fl, i = chain[-1]
                    idem_from[id(fl)] = min(idem_from.get(id(fl), 10 ** 9), i)
                    variant_lids.add(lid)
        example = f"AND({pinned}, {{Scenario name}} = '<label>', LEN({{Voice AI cost}}&'') = 0)"
        for lid in sorted(lookup_start, key=str):
            if lid in idem_ok or lid in variant_lids:
                continue
            lm = lookups[lid]
            fields = _unreconciled_fields(_mapper(lm).get("formula"), fid)
            why = "; ".join(shape[lid] + sorted({p for f, safe in fields if (p := marker_problem(f, safe, lid)) is not None}
                                                 | variant_why.get(lid, set())))
            bad(lm, "F2d", f"Lookup module {lid} matches a ledger row that is already reconciled, or more than the one row of this call, so a replay of a real "
                           f"call ID runs this scenario again. It must search with maxRecords 1, pin the row kind with the label of the scenario that creates "
                           f"the row, and require the row to be unreconciled, as top-level AND( ) arguments, with a System Logs field this scenario fills in "
                           f"when it reconciles, for example {example}"
                           + (f". Rejected: {why}" if why else ""))
        c_direct, c_handler = uncovered(covered(done_from))
        i_direct, i_handler = uncovered(covered(idem_from)) if variant_lids else ([], {})
        b_ids = {m.get("id") for m in b_direct} | set(b_handler)
        d_rows: dict = {}
        for m in c_direct:
            d_rows.setdefault(m.get("id"), (m, []))[1].append("completion")
        for pid, (parent, ids) in c_handler.items():
            d_rows.setdefault(pid, (parent, []))[1].append(f"completion (handler modules {sorted(ids, key=str)})")
        for m in i_direct:
            if m.get("id") not in b_ids:
                d_rows.setdefault(m.get("id"), (m, []))[1].append("unreconciled")
        for pid, (parent, ids) in i_handler.items():
            if pid not in b_ids:
                d_rows.setdefault(pid, (parent, []))[1].append(f"unreconciled (handler modules {sorted(ids, key=str)})")
        for did, (dm, missing) in sorted(d_rows.items(), key=lambda kv: str(kv[0])):
            parts = []
            if any(x.startswith("completion") for x in missing):
                parts.append(f"The call may still be in progress. Put a filter before it that requires the fetched call to be complete: "
                             f"{{{{{fid}.status}}}} text equal \"completed\" as the only OR group of the filter. Bland also sets completed true on "
                             f"calls that failed or were not answered, so {{{{{fid}.completed}}}} does not count.")
            if any(x.startswith("unreconciled") for x in missing):
                parts.append("The ledger row may already be reconciled. Put a filter before it that requires the lookup record's "
                             "reconciliation field to be empty.")
            tail = f" ({'; '.join(missing)})" if any("handler" in x for x in missing) else ""
            bad(dm, "F2d", "Writes or sends without the replay gates (a completed call and an unreconciled ledger row), so a replayed "
                           "or early request still runs it. " + " ".join(parts) + tail)

    # (c) No module other than the call-details module reads the request: not the lookups, not any
    # error handler, not a filter. A bare {{name}} could resolve to the request and an aggregator fed
    # by the webhook reads it, so both count. The call ID the lookups use comes from the call-details output.
    src = f"call-details module {fid}" if fid is not None else "the call-details module this scenario still needs (F2a)"
    for m, err, chain in mods:
        if m is fetch:
            continue
        refs = _trigger_refs(m, tid)
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}
        feeder = tid is not None and params.get("feeder") == tid
        bare = _bare_reads(m)
        if not (refs or feeder or bare):
            continue
        early = fetch is not None and top(chain) < fidx
        tail = f" It also runs before call-details module {fid}." if early else ""
        where = " in an error handler" if err else ""
        fields = sorted(refs)
        if is_logger_call(m, logger) and fields:
            # A Logger call body carries the call ID only from the call-details output, or none (the handler of the
            # call-details module itself sends none). The request is unauthenticated free text.
            bad(m, "F2c", f"Logger call body reads request field(s) {', '.join(fields)}{where}. Send call_id as {{{{{fid if fid is not None else 'N'}.call_id}}}} "
                          f"from {src}, or leave it out. Only the call-details module may read the request.{tail}")
        elif fields and all(f in CALL_ID_FIELDS for f in fields):
            bad(m, "F2c", f"Reads the request call ID ({', '.join(fields)}){where}. Only the call-details module may read the request. "
                          f"Read the call ID from the output of {src}. An error handler of the call-details module logs "
                          f"var.scenario.executionId and a constant instead.{tail}")
        elif fields:
            bad(m, "F2c", f"Reads request field(s) {', '.join(fields)} from the webhook{where}. Only the call-details module may read the "
                          f"request, and only the call ID. Read everything else from the output of {src}.{tail}")
        if feeder:
            bad(m, "F2c", f"Takes its source from the webhook (parameters.feeder is module {tid}), so it reads the whole request. "
                          f"Feed it from the output of {src}.{tail}")
        if bare:
            names = ", ".join(f"`{w}`" for w in bare)
            bad(m, "F2c", f"Uses {names} with no module prefix, so in a fetch-back scenario the name may resolve to the request. "
                          f"Write each as N.name, with the module number of {src} or of the module that really outputs it.{tail}")
    if not problems:
        row(PASS, "F2", fetch, f"Fetch-back verified: call-details module {fid} is the only module that reads the request, lookups "
                               f"{sorted(lookups, key=str)} gate every write, every write waits for a completed call and an unreconciled "
                               f"ledger row (F2d), and no handler continues past a failed verification")


# --- F3 --------------------------------------------------------------------
#
# Duplicate delivery on api_key webhooks (X-43, decided 2026-10-29). The hook key proves who sent the request, not that
# it is the first delivery of this call. A Bland pathway webhook node can fire twice for one call, and every delivery
# runs the whole scenario again (measured on Pending Call 3943741: OpenAI, the lead Status write, the SMS and the email
# all repeat). The gate: a System Logs search pinned on exactly AND({External Call ID} = '<call ID>',
# {Scenario name} = "<label>", {Execution Status} = 'Success'), an array aggregator fed by it right after it (a search that finds nothing emits no bundle, the
# aggregator always emits one), and the next module (or the first module of a router route right after it) filtered on
# exactly one OR group holding {{length(<aggregator>.array)}} number equal 0. The search's handler may only Break, since
# an Ignore or a Resume turns an Airtable failure into "found nothing" or a fake row. The gate proves something only if
# processed calls leave the row it looks for: a Success Shadow Ledger create with that label and External Call ID on the
# path of every gated effect. The check then act needs Sequential processing on.

F3_PAID_PREFIXES = ("openai-gpt-3:", "openai:", "anthropic-claude:", "anthropic:", "heygen:", "bland:", "stripe:", "elevenlabs:")


def _f3_kind(m: dict, lead: LeadNames, caller: str = "") -> str | None:
    """Why a module must not run twice for one call: a lead Status write, a client send or a paid call. For the Stripe
    listener also any write to the lead table, since Amount Paid and Payment Status dispatch the AR release (L3). None
    otherwise."""
    if caller == STRIPE_CALLER and is_airtable_write(m):
        t = _mapper(m).get("table") or (m.get("parameters") or {}).get("table")
        if isinstance(t, str) and t.strip().lower() in lead.tables:
            return "lead payment write"
    sval, unknown = lead_status(m, lead)
    if sval is not None or unknown:
        return "lead Status write"
    t = _mtype(m)
    low = t.lower()
    if t in BLAND_CALLS:
        return "client call (paid)"
    if is_email_send(m) or "sms" in low or "whatsapp" in low:
        return "client send"
    if t.startswith(F3_PAID_PREFIXES) and _is_effect(m):
        return "paid call"
    return None


def _f3_call_refs(flow: list, tid: object) -> tuple[set[str], object]:
    """The expressions that name this call's Bland call ID (expr_key form), and the call-details module ID or None.
    With a call-details module: the trigger reference that feeds it and {{<fid>.call_id}}. Without one: {{<trigger>.call_id}}."""
    fetch = next((m for m, err, _c in walk(flow) if not err and _mtype(m) in FETCH_MODULES), None)
    if fetch is None:
        return {f"{tid}.call_id"}, None
    fid = fetch.get("id")
    refs = {f"{fid}.call_id"}
    e = _single_expression(_mapper(fetch).get("call_id"))
    hit = iml_refs(e) if e else []
    if e and len(hit) == 1 and hit[0].module == tid and hit[0].text == e.strip():
        refs.add(hit[0].text)
    return refs, fid


def _f3_quoted(arg: str) -> str | None:
    """The text of a quoted Airtable string literal that is the whole argument, else None."""
    a = arg.strip()
    if len(a) >= 2 and a[0] in "'\"" and a[-1] == a[0] and a[0] not in a[1:-1] and "\\" not in a:
        return a[1:-1]
    return None


F3_OUTCOME_NAME = "Execution Status"
F3_SUCCESS = "Success"


def _f3_pinned(formula: object, call_refs: set, label: str) -> bool:
    """Exactly AND({External Call ID} = '<call ref>', {Scenario name} = "<label>", {Execution Status} = 'Success') in any
    order. The label is quoted with a quote it does not contain (Automating 'Pending Call' Clients needs double quotes).
    The Success clause matters because error rows carry the call ID too (Pending Call 110, 114, 128, 139), so without it
    a run that failed would make a legitimate redelivery look like a duplicate."""
    if not isinstance(formula, str) or not label:
        return False
    m = re.fullmatch(r"\s*AND\s*\((.*)\)\s*", formula, re.S)
    if not m or not _balanced_formula(m.group(1)):
        return False
    args = _split_top_level(m.group(1))
    if len(args) != 3:
        return False
    got_call = got_label = got_ok = False
    for arg in args:
        hit = re.fullmatch(r"\s*\{\s*([^{}]+?)\s*\}\s*=\s*(.+?)\s*", arg, re.S)
        if not hit:
            return False
        name, lit = hit.group(1), _f3_quoted(hit.group(2))
        if lit is None:
            return False
        if name == LOOKUP_FIELD:
            e = _single_expression(lit)
            got_call = got_call or (e is not None and lit.strip().startswith("{{") and lit.strip().endswith("}}") and expr_key(e) in call_refs)
        elif name == LABEL_FIELD_NAME:
            got_label = got_label or lit == label
        elif name == F3_OUTCOME_NAME:
            got_ok = got_ok or lit == F3_SUCCESS
        else:
            return False
    return got_call and got_label and got_ok


def _f3_empty_filter(m: dict | None, agg_id: object) -> bool:
    """Exactly one OR group, holding {{first(map(<agg>.array; "id"))}} does not exist (AGG_EMPTY_HINT). Other conditions in
    the group only narrow it."""
    groups = _norm_groups(m) if isinstance(m, dict) else []
    if len(groups) != 1:
        return False
    return any(_empty_test(c, {agg_id}) for c in groups[0])


def _f3_marker(x: dict, call_refs: set, label: str, links: AirtableMap | None) -> bool:
    """A Shadow Ledger create that records this call as processed: the label literal, External Call ID the call ID and
    Execution Status the literal Success (the lookup only finds Success rows)."""
    if not is_ledger_create(x):
        return False
    rec = _record(x)

    def value(fid: str, name: str) -> object:
        for k, v in rec.items():
            if k == fid or k == name or (links is not None and links._field_id(LEDGER_TABLE, k) == fid):
                return v
        return None

    lab, cid, ok = value(LABEL_FIELD, LABEL_FIELD_NAME), value(CALL_ID_FIELD, LOOKUP_FIELD), value(OUTCOME_FIELD, F3_OUTCOME_NAME)
    e = _single_expression(cid)
    return (isinstance(lab, str) and lab.strip() == label and e is not None and expr_key(e) in call_refs
            and isinstance(ok, str) and ok.strip() == F3_SUCCESS)


def _check_f3(b: Blueprint, trig: dict, out: list, row, label: str, links: AirtableMap | None, caller: str = "") -> None:
    flow = b.bp.get("flow") or []
    tid = trig.get("id")
    lead = lead_names(links)
    call_refs, _fid = _f3_call_refs(flow, tid)
    if caller in F3_DELIVERY_FIELD:
        # No Bland call: the delivery is identified by the caller's own field (the Stripe event ID).
        call_refs = {f"{tid}.{F3_DELIVERY_FIELD[caller]}"}
    mods = [(m, err, ch) for m, err, ch in walk(flow) if m is not trig]
    effects = [(m, ch, k) for m, err, ch in mods if not err and (k := _f3_kind(m, lead, caller))]
    shown = " or ".join(sorted("{{" + r + "}}" for r in call_refs))
    q = '"' if "'" in label else "'"
    example = (f"AND({{{LOOKUP_FIELD}}} = '{{{{{sorted(call_refs)[0]}}}}}', {{{LABEL_FIELD_NAME}}} = {q}{label}{q}, "
               f"{{{F3_OUTCOME_NAME}}} = '{F3_SUCCESS}')")
    problems = 0

    def bad(m: dict, detail: str) -> None:
        nonlocal problems
        problems += 1
        row(FAIL, "F3", m, detail)

    if not label:
        bad(trig, "audit/scenario_labels.json has no label for this scenario, so the duplicate-delivery lookup cannot pin the row kind")
        return
    meta = b.bp.get("metadata") if isinstance(b.bp.get("metadata"), dict) else {}
    scen_meta = meta.get("scenario") if isinstance(meta.get("scenario"), dict) else {}
    if effects and scen_meta.get("sequential") is not True:
        bad(trig, "Sequential processing is off, so two deliveries of the same call that arrive together both pass the duplicate lookup "
                  "and both run. Turn it on in the scenario settings in the Make UI and re-pull (make_push cannot change settings)")
    starts: dict[int, int] = {}
    gates: list = []
    for m, err, chain in mods:
        if err or _mtype(m) != "airtable:ActionSearchRecords" or _module_table(m) != LEDGER_TABLE:
            continue
        formula = _mapper(m).get("formula")
        if not _f3_pinned(formula, call_refs, label):
            if isinstance(formula, str) and LOOKUP_FIELD.lower() in formula.lower():
                bad(m, f"System Logs search by call ID is not the duplicate lookup, so it gates nothing. Its formula must be exactly {example} "
                       f"(the call ID as {shown}, the label in a quote it does not contain, nothing else)")
            continue
        fl, i = chain[-1]
        agg = fl[i + 1] if i + 1 < len(fl) and isinstance(fl[i + 1], dict) else None
        params = agg.get("parameters") if isinstance(agg, dict) and isinstance(agg.get("parameters"), dict) else {}
        if agg is None or _mtype(agg) != "builtin:BasicAggregator" or params.get("feeder") != m.get("id"):
            bad(m, f"Duplicate lookup {m.get('id')} is not followed by an array aggregator (builtin:BasicAggregator) fed by it. A search "
                   f"that finds nothing emits no bundle, so the new-call path never runs, and one that finds the row runs everything "
                   f"after it. Another aggregator has no array, so length(<aggregator>.array) is always 0 and the gate never closes. "
                   f"Put an array aggregator with "
                   f"source module {m.get('id')} right after it, then filter on " + AGG_EMPTY_HINT)
            continue
        dirs = _handler_directives(m)
        if any(d != "builtin:Break" for d in dirs):
            bad(m, f"Duplicate lookup {m.get('id')} has an error handler that ends in {sorted(set(d.split(':')[1] for d in dirs))}. "
                   f"Ignore makes a failed search look like no earlier delivery, so the duplicate runs, and Resume fakes a result. End it in Break")
            continue
        aid = agg.get("id")
        nxt = fl[i + 2] if i + 2 < len(fl) and isinstance(fl[i + 2], dict) else None
        found: list = []
        if _f3_empty_filter(nxt, aid):
            found.append((fl, i + 2))
        elif nxt is not None and nxt.get("routes"):
            for rf in _routes(nxt):
                if rf and isinstance(rf[0], dict) and _f3_empty_filter(rf[0], aid):
                    found.append((rf, 0))
        if not found:
            bad(nxt or agg, f"Duplicate lookup {m.get('id')} and aggregator {aid} do not stop a second delivery: the module after the aggregator "
                            f"(or the first module of a route of a router right after it) needs a filter with one OR group holding "
                            + AGG_EMPTY_HINT.replace("<aggregator>", str(aid)))
            continue
        for gfl, gi in found:
            starts[id(gfl)] = min(starts.get(id(gfl), 10 ** 9), gi)
        gates.append(m.get("id"))

    def gated(chain: tuple) -> bool:
        return any(i >= starts[id(fl)] for fl, i in chain if id(fl) in starts)

    ungated = [(m, k) for m, ch, k in effects if not gated(ch)]
    if ungated:
        first, kind = ungated[0]
        rest = ", ".join(f"{x.get('id')} ({k})" for x, k in ungated[1:])
        bad(first, f"{kind.capitalize()} runs with no duplicate-delivery gate, so a second delivery of the same call runs it again"
                   + (f", and so do modules {rest}" if rest else "")
                   + f". Before it: a System Logs search with the formula {example}, an aggregator fed by that search, and a filter "
                     + AGG_EMPTY_HINT + " on the next module, so the run stops when this call was already processed")
    marker_ids = {x.get("id") for x, err, _c in mods if not err and _f3_marker(x, call_refs, label, links)}
    def has_marker(chain: tuple) -> bool:
        """A marker row runs on this module's path after the gate: in the gate's flow list from the gate on, or in a
        route below it, with no filter between the module (or its ancestor in that list) and the marker. A marker
        before the gate would be found by the first delivery itself."""
        g = next((n for n, (fl, i) in enumerate(chain) if id(fl) in starts and i >= starts[id(fl)]), None)
        if g is None or not marker_ids:
            return False
        for n in range(g, len(chain)):
            fl, i = chain[n]
            for k, x in enumerate(fl):
                if not isinstance(x, dict) or x.get("id") not in marker_ids or (n == g and k < starts[id(fl)]):
                    continue
                if all(not _norm_groups(fl[j]) for j in range(i + 1, k + 1) if isinstance(fl[j], dict)):
                    return True
        return False
    unmarked = [(m, k) for m, ch, k in effects if gated(ch) and not has_marker(ch)]
    if unmarked:
        first, kind = unmarked[0]
        bad(first, f"{kind.capitalize()} is gated by duplicate lookup {sorted(gates, key=str)}, but no Shadow Ledger create with "
                   f"{{{LABEL_FIELD_NAME}}} {label}, {{{LOOKUP_FIELD}}} {shown} and {{{F3_OUTCOME_NAME}}} {F3_SUCCESS} runs on its path after the gate (unfiltered between it and "
                   f"this module), so the lookup never finds the first delivery and a second one passes")
    if not problems:
        what = f"gates {len(effects)} state-changing module(s)" if effects else "has no state-changing module to gate"
        row(PASS, "F3", next((m for m, _e, _c in mods if m.get("id") in gates), trig),
            f"Duplicate delivery: lookup {sorted(gates, key=str)} {what}, and each one's path records the call in the ledger")


# --- L ---------------------------------------------------------------------
#
# The shared Logger (Option C, decided by Rizwan 2026-10-29, replaces the Error Monitor of check G). Every error
# handler calls it, so it must not fail and must not stop. Facts it relies on:
#   help.make.com (Overview of error handling): an error that a module in an error route outputs ends the run
#     with an error. A scenario with an instant trigger (a webhook) is deactivated at once after an error
#     (help.make.com, Scenario settings, quoted in specs/F-E5-v3-shared-logger.md section 3), so every module of the
#     Logger needs a handler that cannot error: exactly one Ignore or Resume. Break is not one, since it needs
#     stored incomplete executions, which are off here.
#   Process data in order off (metadata.scenario.sequential false): the Logger must take parallel calls from
#     every scenario, and with it on a stuck run would queue every later alert.
#   Store incomplete executions off (metadata.scenario.dlq false): nothing parks.
#   Ignore stops the bundle, so when the Slack alert follows the ledger write on the same flow the ledger write's
#     handler is Resume, and the alert reads the row ID (a Resume substitute or ifempty) to say the write failed.


def load_schedule_info(manifest_path: str | None) -> dict:
    """scenario ID (str) -> {type, interval, active, pulled_at} as make_pull recorded them. Never raises: no manifest means no data."""
    if not manifest_path or not os.path.exists(manifest_path):
        return {}
    try:
        data = _read_json(manifest_path)
    except InputError:
        return {}
    out: dict = {}
    pulled_at = data.get("pulled_at") if isinstance(data, dict) else None
    for e in _manifest_entries(data):
        if isinstance(e, dict) and e.get("id") is not None:
            out[str(e["id"])] = {"type": e.get("scheduling_type"), "interval": e.get("scheduling_interval"),
                                 "active": e.get("is_active"), "pulled_at": pulled_at}
    return out


def _is_field_ref(v: object, module: object, name: str) -> bool:
    """Exactly one bare reference {{module.name}} with nothing around it."""
    e = _single_expression(v)
    refs = iml_refs(e) if e else []
    return bool(e) and len(refs) == 1 and refs[0].module == module and refs[0].field == name and refs[0].text == e.strip()


def _path_filtered(chain: tuple) -> bool:
    """A module on the path to the module at chain (the module included) carries a filter, so it may not run."""
    return any(isinstance(x, dict) and _conditions(x) for fl, i in chain for x in fl[:i + 1])


def _logger_mapped_label(m: dict, trigger_id: object) -> bool:
    """A Shadow Ledger write of the Logger whose label is exactly the label the caller sent ({{<trigger>.label}})."""
    return _is_field_ref(_record(m).get(LABEL_FIELD), trigger_id, "label")


def _runs_after(first: tuple, second: tuple) -> bool:
    """The module at chain second runs after the one at chain first for the same bundle: later on the same flow, or on a
    later route of a router whose earlier route holds first (Make runs a router's routes one after the other)."""
    n = 0
    while n < min(len(first), len(second)) and first[n][0] is second[n][0] and first[n][1] == second[n][1]:
        n += 1
    if n >= len(first) or n >= len(second):
        return False
    (fa, ia), (fb, ib) = first[n], second[n]
    if fa is fb:
        return ib > ia
    if n == 0:
        return False
    parent_flow, pi = first[n - 1]
    router = parent_flow[pi]
    routes = [rf for rf in _routes(router)] if isinstance(router, dict) else []
    ra = next((k for k, rf in enumerate(routes) if rf is fa), None)
    rb = next((k for k, rf in enumerate(routes) if rf is fb), None)
    return ra is not None and rb is not None and rb > ra


LOGGER_VAR_INFO_RULE = "L6"


def check_l(blueprints: list[Blueprint], logger: "LoggerSpec | None", schedule: dict, hooks: "HookInfo | None") -> list[Finding]:
    """Check L (the shared Logger). blueprints are the scenarios in scope, schedule the manifest's scenario state,
    hooks the hook list make_pull recorded. Every run ends with one INFO row (L6): the value of the team variable that
    holds the Logger URL is not audited, so the gap shows in every report."""
    out = _check_l_rows(blueprints, logger, schedule, hooks)
    var = (logger.url_variable if logger is not None else None) or "var.team.IMMIOS_LOGGER_URL"
    scen = next((f.scenario for f in out if f.scenario not in ("", "-")), "Logger")
    if logger is not None and logger.url_variable is None and logger.url_sha256:
        out.append(Finding("L", INFO, scen, "-", "-",
                           f"{LOGGER_VAR_INFO_RULE} Literal-URL mode (no team variables below Make Pro): every logger call carries the "
                           f"bare Logger hook URL, and check B accepts it only when its token hashes to url_sha256 in audit/webhooks.json. "
                           f"The URL alone cannot write a row, because the hook requires the x-make-apikey key",
                           LOGGER_VAR_INFO_RULE))
        return out
    out.append(Finding("L", INFO, scen, "-", "-",
                       f"{LOGGER_VAR_INFO_RULE} The value of the team variable {var} is not audited. Check B confirms every logger call "
                       f"reads {{{{{var}}}}}, but the pull never reads the variable's value (the hook URL is a bearer secret and never "
                       f"reaches disk), so nothing here proves the variable holds the Logger hook URL. A wrong value sends every log to "
                       f"another address or fails every call. Rizwan confirms it in the Make UI (Team Variables) after any change, and "
                       f"the test call of specs/F-E5-v3-shared-logger.md section 8 step 7 proves it",
                       LOGGER_VAR_INFO_RULE))
    return out


def _check_l_rows(blueprints: list[Blueprint], logger: "LoggerSpec | None", schedule: dict, hooks: "HookInfo | None") -> list[Finding]:
    def single(detail: str) -> list[Finding]:
        return [Finding("L", FAIL, "Logger", "-", "-", detail, "L0")]

    if logger is None:
        return single("L0 No Logger registered: audit/webhooks.json has no entry with caller make_http. Every error handler calls the Logger, "
                      "so register it (protection api_key, url_variable, connection_id)")
    if logger.scenario_id is None:
        return single("L0 Logger not deployed: the Logger entry of audit/webhooks.json has no scenario_id. Import the Logger blueprint in Make, "
                      "then set scenario_id and hook_id")
    b = next((x for x in blueprints if x.scenario_id == logger.scenario_id), None)
    if b is None:
        return single(f"L0 Logger not deployed: scenario {logger.scenario_id} named in audit/webhooks.json is not in the pull. Pull again, or correct the ID")
    scen = _scenario_label(b)
    flow = b.bp.get("flow") or []
    trig = flow[0] if flow and isinstance(flow[0], dict) else None
    tid = trig.get("id") if trig else None
    hooks = hooks or HookInfo()
    out: list[Finding] = []

    def bad(rule: str, m: dict | None, detail: str) -> None:
        out.append(Finding("L", FAIL, scen, m.get("id") if m else "-", _mtype(m) if m else "-", f"{rule} {detail}", rule))

    # L1 trigger, hook key and state.
    params = trig.get("parameters") if trig and isinstance(trig.get("parameters"), dict) else {}
    if trig is None or _mtype(trig) != "gateway:CustomWebHook":
        bad("L1", trig, "The Logger's first module is not a gateway:CustomWebHook trigger")
    elif params.get("hook") != logger.hook_id:
        bad("L1", trig, f"The trigger uses hook {params.get('hook')} but audit/webhooks.json names hook {logger.hook_id}. Correct the registry")
    unconfirmed = "UNCONFIRMED, no proof that a key exists: "
    info = hooks.by_id.get(logger.hook_id) if hooks.available else None
    if not hooks.available:
        bad("L1", trig, f"{unconfirmed}the read token cannot list hooks ({hooks.note or 'no hook data'}). Hook {logger.hook_id} cannot be checked for an API key")
    elif info is None:
        # The list was read and the hook is not in it: the hook was deleted or the registry names the wrong one. That is known,
        # not unconfirmed (R3).
        bad("L1", trig, f"Hook {logger.hook_id} is not in the hook list make_pull recorded, so the Logger's hook was deleted or "
                        f"audit/webhooks.json names the wrong hook. Every logger call fails until the hook and the registry agree")
    elif info.get("apikey_count") is None:
        bad("L1", trig, f"{unconfirmed}the hook list has no API key field for hook {logger.hook_id}")
    elif info["apikey_count"] == 0:
        bad("L1", trig, f"Hook {logger.hook_id} has no API key, so anyone who learns its URL can write ledger rows and Slack alerts. "
                        f"Add an API key (keychain) to the hook, then give the callers' connection the same key")
    state = (schedule.get(logger.scenario_id) or {}).get("active")
    if state is None:
        bad("L1", trig, "UNCONFIRMED, no scenario state: the pull has no is_active for the Logger (a --dir run has no manifest)")
    elif state is not True:
        bad("L1", trig, "The Logger is not active, so every logger call fails. Rizwan activates it in the Make UI (hard rule 2)")

    # L2 scenario settings.
    md = b.bp.get("metadata") if isinstance(b.bp.get("metadata"), dict) else {}
    sc = md.get("scenario")
    if not isinstance(sc, dict):
        bad("L2", trig, "UNCONFIRMED, no scenario settings in the blueprint (metadata.scenario), so Process data in order and "
                        "Store incomplete executions cannot be checked")
    else:
        if sc.get("sequential") is True:
            bad("L2", trig, "Process data in order is on (metadata.scenario.sequential), so a stuck run queues every later alert. Turn it off "
                            "in the scenario settings in the Make UI")
        if sc.get("dlq") is True:
            bad("L2", trig, "Store incomplete executions is on (metadata.scenario.dlq), so a failed run parks instead of ending. Turn it off "
                            "in the scenario settings in the Make UI")

    main = [(m, chain) for m, err, chain in walk(flow) if not err and m is not trig]
    # L5 every module has a handler that cannot error: exactly one Ignore or Resume.
    for m, _chain in main:
        if _mtype(m) in DIRECTIVES or _mtype(m) == "builtin:BasicRouter":
            continue
        inside = [x for x, _e, _c in walk(_onerror(m), True)]
        if not (len(inside) == 1 and _mtype(inside[0]) in ("builtin:Ignore", "builtin:Resume")):
            bad("L5", m, "Needs an error handler that cannot error: exactly one Ignore or Resume. An unhandled error deactivates a webhook "
                         "scenario at once, and every later logger call then fails")

    # L3 one ledger row, labelled with the caller's label.
    ledgers = [(m, ch) for m, ch in main if is_ledger_create(m)]
    lg = lch = None
    if len(ledgers) != 1:
        bad("L3", ledgers[1][0] if len(ledgers) > 1 else trig, f"The Logger needs exactly one Shadow Ledger create, found {len(ledgers)}")
    else:
        lg, lch = ledgers[0]
        if not _logger_mapped_label(lg, tid):
            bad("L3", lg, f"The ledger row's label must be exactly {{{{{tid}.label}}}}, the label the caller sends")
        rec = _record(lg)
        if not _is_error_row(rec):
            bad("L3", lg, "The ledger row must set Execution Status to the literal Error. The Logger logs errors only, so the caller's outcome is not trusted")
        if nonempty(rec.get(CALL_ID_FIELD)):
            bad("L3", lg, "The ledger row writes External Call ID. A row with a caller's label and a call ID matches the fetch-back replay "
                          "lookup (F2d) next to the real row, which reopens the replay. Put the call ID in the payload field instead")
        if _path_filtered(lch):
            bad("L3", lg, "A filter sits on the ledger row or ahead of it, so some calls write no row")

    # L4 one Slack alert, IDs only, that still goes out when the ledger write fails and says so.
    slacks = [(m, ch) for m, ch in main if is_slack_message(m)]
    if len(slacks) != 1:
        bad("L4", slacks[1][0] if len(slacks) > 1 else trig, f"The Logger needs exactly one Slack alert, found {len(slacks)}")
    else:
        sm, sch = slacks[0]
        if _path_filtered(sch):
            bad("L4", sm, "A filter sits on the Slack alert or ahead of it, so some calls send no alert")
        refs = [r for _p, e in _module_exprs(sm) for r in iml_refs(e)]
        extra = sorted({r.text for r in refs if not ((r.module == tid and r.field in LOGGER_SLACK_FIELDS)
                                                     or (lg is not None and r.module == lg.get("id") and r.field == "id"))})
        if extra:
            bad("L4", sm, f"The Slack alert carries {', '.join(extra)}. It may carry IDs only (label, outcome, module ID, error type, execution, "
                          f"lead record and call IDs, the ledger row ID). An error message can hold client data (E6)")
        if lg is not None:
            if not _runs_after(lch, sch):
                bad("L4", sm, "The Slack alert does not run after the ledger write, so it cannot name the row or say the write failed")
            elif lch[-1][0] is sch[-1][0] or any(fl is lch[-1][0] for fl, _i in sch):
                handler = [x for x, _e, _c in walk(_onerror(lg), True)]
                if not (len(handler) == 1 and _mtype(handler[0]) == "builtin:Resume"):
                    bad("L4", lg, "The Slack alert follows the ledger write on the same flow, so the write's handler must be Resume. Ignore or no "
                                  "handler stops the bundle and no alert goes out when the write fails")
            lid = lg.get("id")
            if not any(r.module == lid and r.field == "id" for r in refs):
                bad("L4", sm, f"The Slack alert does not name the ledger row ({{{{{lid}.id}}}}), so it cannot say whether the write failed")
            else:
                handler = [x for x, _e, _c in walk(_onerror(lg), True)]
                substitute = len(handler) == 1 and _mtype(handler[0]) == "builtin:Resume" and _is_literal(_mapper(handler[0]).get("id"))
                fallback = any("ifempty(" in e.replace(" ", "") and any(r.module == lid and r.field == "id" for r in iml_refs(e))
                               for _p, e in _module_exprs(sm))
                if not (substitute or fallback):
                    bad("L4", sm, f"When the ledger write fails the alert shows an empty row ID instead of saying so. Map "
                                  f"{{{{ifempty({lid}.id; \"LEDGER WRITE FAILED\")}}}}, or give the Resume a literal substitute id")

    if not any(f.status == FAIL for f in out):
        out.append(Finding("L", PASS, scen, "-", "-",
                           "Logger verified: webhook with an API key, active, Process data in order and Store incomplete executions off, one "
                           "ledger row under the caller's label, one Slack alert with IDs only that still goes out and says so when the "
                           "ledger write fails, and a handler that cannot error on every module", "L"))
    return out



# ---------------------------------------------------------------------------
# Check R: the prompts registry (X-36.1, decided by Rizwan 2026-11-13)
# ---------------------------------------------------------------------------

PROMPTS_CHECK = "R"


def load_prompts(prompts_path: str = DEFAULT_PROMPTS, bindings_path: str = DEFAULT_PROMPT_BINDINGS) -> "prompt_registry.Registry":
    """The registry is required: a missing or emptied file would hide every R row, so it is an InputError, like the Bland
    agent registry of E28."""
    try:
        return prompt_registry.load(prompts_path, bindings_path)
    except prompt_registry.RegistryError as exc:
        raise InputError(str(exc)) from None


def check_r(b: Blueprint, prompts: "prompt_registry.Registry") -> list[Finding]:
    """R1 every Claude module (routes and error routes included) has a binding in ref/prompt_bindings.json. R2 its mapper
    hashes to the template_sha256 of the version the binding names, so a prompt or setting edited in Make without a new
    registered version FAILs. R3 every binding of this scenario names a Claude module that exists. Each FAIL sits on the
    module to change, and fix ID X-36 closes it."""
    out: list[Finding] = []
    scen = _scenario_label(b)
    sid = str(b.scenario_id) if b.scenario_id is not None else None
    seen: set = set()
    for m, _in_err, _chain in walk(b.bp.get("flow") or []):
        if _mtype(m) != prompt_registry.CLAUDE_MODULE:
            continue
        mid = m.get("id")
        seen.add(mid)
        bound = prompts.bindings.get((sid, mid)) if sid is not None else None
        if bound is None:
            out.append(Finding(PROMPTS_CHECK, FAIL, scen, mid, _mtype(m),
                               "R1 Claude module with no registered prompt. Register it (scripts/prompt_registry.py register) "
                               "and commit ref/prompts.json and ref/prompt_bindings.json", "R1"))
            continue
        stage, version = bound
        reg = prompts.versions[(stage, version)]
        live = prompt_registry.template_sha256(m.get("mapper") if isinstance(m.get("mapper"), dict) else {})
        tag = prompt_registry.stamp(stage, version)
        if live != reg["template_sha256"]:
            out.append(Finding(PROMPTS_CHECK, FAIL, scen, mid, _mtype(m),
                               f"R2 template differs from {tag} (registered sha256 {reg['template_sha256'][:16]}, live "
                               f"{live[:16]}). An edit is a new version: register it and bind the module to it", "R2"))
        else:
            out.append(Finding(PROMPTS_CHECK, PASS, scen, mid, _mtype(m), f"R matches {tag}", "R"))
    if sid is not None:
        for (bsid, bmid), (stage, version) in sorted(prompts.bindings.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            if bsid == sid and bmid not in seen:
                out.append(Finding(PROMPTS_CHECK, FAIL, scen, bmid, "-",
                                   f"R3 ref/prompt_bindings.json binds {prompt_registry.stamp(stage, version)} to module {bmid}, "
                                   f"which is not a Claude module of this scenario. Remove or move the binding", "R3"))
    return out


def check_r_pull(prompts: "prompt_registry.Registry", known: set) -> list[Finding]:
    """R3 over the whole pull: a binding whose scenario is not in it (a deleted scenario or a wrong ID) would still load
    into ref.prompt_bindings as a module that runs that version. Runs only on a full audit."""
    out: list[Finding] = []
    for (bsid, bmid), (stage, version) in sorted(prompts.bindings.items(), key=lambda kv: (int(kv[0][0]), kv[0][1])):
        if bsid not in known:
            out.append(Finding(PROMPTS_CHECK, FAIL, f"scenario {bsid}", bmid, "-",
                               f"R3 ref/prompt_bindings.json binds {prompt_registry.stamp(stage, version)} to scenario {bsid} "
                               f"module {bmid}, which is not in the pull. Remove the binding (the version stays registered), "
                               f"or correct the ID", "R3"))
    return out



# ---------------------------------------------------------------------------
# Check R, rules R4 to R6: run-time prompt stamps on call rows (X-36.2, decided by Rizwan 2026-11-13,
# specs/X-36.2-call-rows.md). Every Claude module outside an error route writes one call row: the System Logs create at
# index i+1 of its own flow list, unfiltered, carrying the stamps of its bound version and that call's tokens. A call is
# priced and stamped once, whether it ended in end_turn, max_tokens or refusal, because no gate stands between the call
# and its row. None of these rules can be allowlisted, and fix ID X-36.2 (prefix-mapped to R) closes them.
# ---------------------------------------------------------------------------

# Stamp roles pinned in audit/airtable_links.json under the System Logs table's stamp_fields (role -> field ID).
STAMP_ROLES = ("prompt_version", "prompt_sha256", "model_requested", "model_served", "stop_reason", "message_id",
               "execution_id", "inference_geo", "cache_write_tokens", "cache_read_tokens")
# Existing System Logs fields a call row writes (schema read 2026-10-28, audit/airtable_links.json).
TOKEN_IN_FIELD = "fldzWonoDyQIVi5pp"
TOKEN_OUT_FIELD = "fldH27E3yx8cwGkGv"
# R6: the shortest literal run of a registered system prompt that counts as a hand copy.
R6_MIN_RUN = 80


def _stamp_map_problem(table: dict) -> str | None:
    """Why the System Logs entry's stamp_fields cannot be used, or None. The map is a required audit input: without it
    rule R4c could not see a stamp written outside a call row, and R4b could not check a call row's keys."""
    sf = table.get("stamp_fields")
    if not isinstance(sf, dict):
        return "has no stamp_fields map (X-36.2 role -> field ID)"
    if sorted(sf) != sorted(STAMP_ROLES):
        return f"stamp_fields must name exactly the roles {', '.join(STAMP_ROLES)}"
    fields = table.get("fields") if isinstance(table.get("fields"), dict) else {}
    ids = list(sf.values())
    if any(not isinstance(v, str) or v not in fields for v in ids):
        return "stamp_fields names a field ID that is not in the System Logs fields map"
    if len(set(ids)) != len(ids) or {TOKEN_IN_FIELD, TOKEN_OUT_FIELD, LABEL_FIELD, OUTCOME_FIELD, LEAD_LINK_FIELD} & set(ids):
        return "stamp_fields must name ten distinct new fields, none of the label, status, token or link fields"
    return None


def _stamp_map(links: "AirtableMap | None") -> dict | None:
    """role -> field ID, or None when the map has no usable System Logs stamp_fields (a synthetic map)."""
    t = (links.tables.get(LEDGER_TABLE) if links is not None else None) or {}
    return dict(t["stamp_fields"]) if isinstance(t, dict) and _stamp_map_problem(t) is None else None


def _ledger_key(links: "AirtableMap | None", key: object) -> object:
    """A System Logs record key as its field ID (a module with useColumnId false maps field names)."""
    fid = links._field_id(LEDGER_TABLE, key) if links is not None else None
    return fid if fid is not None else key


def _norm_iml(v: object) -> object:
    """A mapped value with the whitespace inside {{ }} next to a delimiter removed, so {{ 81.model }} reads as {{81.model}}
    and ifempty(2.stop_reason; "x") as ifempty(2.stop_reason;"x"). Whitespace inside "strings", around a dot and between
    two name characters is kept, so {{2.mod el}} or {{2 . id}} never match a form. Text outside the braces is kept, so a
    value with text around its mapping never matches a form either."""
    if not isinstance(v, str):
        return v
    out: list[str] = []
    i, n, depth, in_str = 0, len(v), 0, False
    while i < n:
        c = v[i]
        if depth == 0:
            if v.startswith("{{", i):
                depth, in_str = 1, False
                out.append("{{")
                i += 2
                continue
            out.append(c)
        elif in_str:
            out.append(c)
            if c == '"':
                if i + 1 < n and v[i + 1] == '"':
                    out.append('"')
                    i += 1
                else:
                    in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif v.startswith("}}", i):
            while out and out[-1].isspace():
                out.pop()
            depth = 0
            out.append("}}")
            i += 2
            continue
        elif c.isspace():
            j = i
            while j < n and v[j].isspace():
                j += 1
            prev = out[-1] if out else ""
            nxt = v[j] if j < n else ""
            if not (prev in _IML_DELIMS or prev.endswith("{") or nxt in _IML_DELIMS or v.startswith("}}", j)):
                out.append(" ")
            i = j
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


_IML_DELIMS = set("();,+-*/<>=!&|")


def _uses_usage(m: dict, n: object) -> bool:
    """True when a module maps the usage of Claude module n anywhere (mapper, filter, parameters)."""
    return any(r.module == n and r.field == "usage" for _p, e in _module_exprs(m) for r in iml_refs(e))


def _is_ledger_write_any(m: dict, links: "AirtableMap | None" = None) -> bool:
    """A System Logs create, update or upsert, the table given by ID or by its name in audit/airtable_links.json."""
    return is_airtable_write(m) and (_module_table(m) == LEDGER_TABLE
                                     or (links is not None and _e25_table(m, links) == LEDGER_TABLE))


def _api_write(m: dict) -> bool:
    """An Airtable API call or an HTTP call to the Airtable API that can write: a GET (or an HTTP module with no method,
    which Make sends as a GET) only reads, the test alias_status_write uses."""
    if not _airtable_api_module(m):
        return False
    method = str(_mapper(m).get("method") or "").strip().lower()
    return not (method == "get" or (not method and _mtype(m).startswith("http:")))


def _api_ledger_write(m: dict, links: "AirtableMap | None") -> bool:
    """An API write whose request names System Logs, by ID or by name."""
    if not _api_write(m):
        return False
    text = " ".join(_strings(_mapper(m))).replace("%20", " ")
    name = str(((links.tables.get(LEDGER_TABLE) or {}).get("name") if links is not None else "") or "System Logs")
    return LEDGER_TABLE in text or re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text, re.I) is not None


def _ledger_writes(order: list, links: "AirtableMap | None") -> list:
    """Every module that writes System Logs: native writes (by ID or name) and API writes that name the table."""
    return [m for m, _err, _c in order if _is_ledger_write_any(m, links) or _api_ledger_write(m, links)]


def _token_keys(m: dict, links: "AirtableMap | None") -> list[str]:
    """Input Tokens or Output Tokens written by a System Logs module, by record key or, for an API write, by field ID or name."""
    fields = ((links.tables.get(LEDGER_TABLE) or {}).get("fields") or {}) if links is not None else {}
    out = []
    for fid in (TOKEN_IN_FIELD, TOKEN_OUT_FIELD):
        name = fields.get(fid, {TOKEN_IN_FIELD: "Input Tokens", TOKEN_OUT_FIELD: "Output Tokens"}[fid])
        if is_airtable_write(m):
            keys = {_ledger_key(links, k) for k in _record(m)} | {str(k).strip().lower() for k in _record(m)}
            hit = fid in keys or name.lower() in keys
        else:
            text = " ".join(_strings(_mapper(m))).replace("%20", " ")
            hit = fid in text or re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text, re.I) is not None
        if hit:
            out.append(name)
    return out


def _before_ids(chain: tuple) -> set:
    """IDs of the modules that run before the module at the end of chain on its path: the earlier modules of each flow
    list on the way down, and the routers that contain it."""
    out: set = set()
    for depth, (flow, idx) in enumerate(chain):
        for j in range(idx):
            if isinstance(flow[j], dict):
                out.add(flow[j].get("id"))
        if depth < len(chain) - 1 and isinstance(flow[idx], dict):
            out.add(flow[idx].get("id"))
    return out


def _r_registered(b: Blueprint, prompts: "prompt_registry.Registry", m: dict) -> tuple[str | None, dict | None, bool]:
    """(stamp, registered version, live mapper equals it) of a Claude module. (None, None, False) when unbound (R1)."""
    sid = str(b.scenario_id) if b.scenario_id is not None else None
    bound = prompts.bindings.get((sid, m.get("id"))) if sid is not None else None
    if bound is None:
        return None, None, False
    reg = prompts.versions[bound]
    live = prompt_registry.template_sha256(m.get("mapper") if isinstance(m.get("mapper"), dict) else {})
    return prompt_registry.stamp(*bound), reg, live == reg["template_sha256"]


def _call_row_forms(n: object, resume: bool, stamps: dict) -> dict:
    """field ID -> the exact mapped form a call row of Claude module n writes (normalised by _norm_iml)."""
    return {
        stamps["model_served"]: f"{{{{{n}.model}}}}",
        stamps["stop_reason"]: (f'{{{{ifempty({n}.stop_reason;"no response")}}}}' if resume else f"{{{{{n}.stop_reason}}}}"),
        stamps["message_id"]: f"{{{{{n}.id}}}}",
        stamps["execution_id"]: "{{var.scenario.executionId}}",
        stamps["inference_geo"]: f"{{{{{n}.usage.inference_geo}}}}",
        stamps["cache_write_tokens"]: f"{{{{{n}.usage.cache_creation_input_tokens}}}}",
        stamps["cache_read_tokens"]: f"{{{{{n}.usage.cache_read_input_tokens}}}}",
        TOKEN_IN_FIELD: f"{{{{{n}.usage.input_tokens}}}}",
        TOKEN_OUT_FIELD: f"{{{{{n}.usage.output_tokens}}}}",
        OUTCOME_FIELD: (f'{{{{if({n}.id;"Success";"Error")}}}}' if resume else "Success"),
    }


# Functions an Applicant Link on a call row may use: the forms the outcome rows already use (a record ID, a one-item list,
# first() of a link and the empty-safe remove(add(emptyarray; ifempty(first(...); emptystring)); emptystring)).
_LINK_FUNCS = {"first", "remove", "add", "ifempty", "emptyarray", "emptystring"}


def _link_value_problem(v: object, by_id: dict, before: set, n: object, links: "AirtableMap | None") -> str | None:
    """Why a call row's Applicant Link is not an Applicants record ID mapped from a module that runs before Claude module n."""
    item = v[0] if isinstance(v, list) and len(v) == 1 else v
    wrapped = re.fullmatch(r'\s*\[\s*"(\{\{.*\}\})"\s*\]\s*', item, re.S) if isinstance(item, str) else None
    e = _single_expression(wrapped.group(1) if wrapped else item)
    if e is None:
        return ("Applicant Link must be one mapping of an Applicants record ID ({{K.id}}, [\"{{K.id}}\"] or first() of an "
                "Applicants link), never a literal or text")
    if secret_scan._quoted_literals(e):
        return "Applicant Link holds a quoted literal, so it is not a record ID mapping"
    used = set(re.findall(r"[A-Za-z_]\w*", _REF_RX.sub(" ", _blank_strings(e))))
    if used - _LINK_FUNCS:
        return f"Applicant Link uses {', '.join(sorted(used - _LINK_FUNCS))}, which no record ID form needs"
    refs = iml_refs(e)
    if not refs:
        return "Applicant Link maps no module's record ID"
    late = sorted({str(r.module) for r in refs if r.module not in before})
    if late:
        return f"Applicant Link references module {', '.join(late)}, which does not run before module {n}"
    for r in refs:
        k = by_id.get(r.module)
        table = _e25_table(k, links) if (k is not None and links is not None) else (_module_table(k) if k is not None else None)
        if r.field == "id":
            if table != LEAD_TABLE:
                return f"Applicant Link maps {r.text}, which is not the ID of an Applicants record"
        elif links is None or table is None or links.link_target(table, r.field) != LEAD_TABLE:
            return f"Applicant Link maps {r.text}, which is not a link to Applicants"
    return None


def _call_row_problems(c: dict, n_mod: dict, chain: tuple, b: Blueprint, prompts: "prompt_registry.Registry",
                       links: "AirtableMap | None", stamps: dict | None, logger: "LoggerSpec | None",
                       by_id: dict | None = None) -> list[str]:
    n = n_mod.get("id")
    tag, reg, same = _r_registered(b, prompts, n_mod)
    problems: list[str] = []
    if tag is None:
        problems.append(f"stamp unverifiable, module {n} has no registered prompt (R1)")
    elif not same:
        problems.append(f"stamp unverifiable, module {n} runs a template the registry does not hold for {tag} (R2), so this "
                        f"row would record a false version")
    if _conditions(c):
        problems.append("it has a filter, so a refusal, a cutoff or a failed parse would go unstamped and unpriced")
    if _mtype(c) != "airtable:ActionCreateRecord":
        problems.append(f"it is a {_mtype(c)}, a call row is an airtable:ActionCreateRecord")
    handler = [x for x in _onerror(c) if isinstance(x, dict)]
    if not (len(handler) == 2 and is_logger_call(handler[0], logger) and _mtype(handler[1]) == "builtin:Resume"
            and not any(_conditions(x) or _routes(x) or _onerror(x) for x in handler)):
        problems.append("its handler is not exactly one Logger call followed by Resume, so a failed stamp write could stop the "
                        "business flow or park the queue")
    if stamps is None:
        problems.append("the Airtable map pins no System Logs stamp_fields, so the stamps cannot be verified")
        return problems
    resume = _handler_parts(_onerror(n_mod))[2] == ["Resume"]
    if resume:
        subs = [x for x in _handler_modules(_onerror(n_mod)) if _mtype(x) == "builtin:Resume"]
        if any(_strings_nonempty(_mapper(x)) for x in subs):
            problems.append(f"the Resume handler of module {n} substitutes an output, so a failed call would be stamped as a "
                            f"response. Leave every Resume field empty")
    rec = {_ledger_key(links, k): v for k, v in _record(c).items()}
    forms = _call_row_forms(n, resume, stamps)
    literals = {stamps["prompt_version"]: tag, stamps["prompt_sha256"]: reg["template_sha256"] if reg else None,
                stamps["model_requested"]: reg["model"] if reg else None}

    def name(fid: object) -> str:
        return links.field_label(LEDGER_TABLE, fid) if links is not None else str(fid)

    required = set(forms) | set(literals) | {LABEL_FIELD}
    missing = sorted(name(f) for f in required if f not in rec)
    extra = sorted(name(f) for f in rec if f not in required and f != LEAD_LINK_FIELD)
    if missing:
        problems.append(f"it does not write {', '.join(missing)}")
    if extra:
        problems.append(f"it also writes {', '.join(extra)}, which a call row never holds (no content, payload, call ID or cost)")
    for fid, want in forms.items():
        if fid in rec and _norm_iml(rec[fid]) != want:
            problems.append(f"{name(fid)} must be exactly {want}")
    for fid, want in literals.items():
        if fid in rec and want is not None and rec[fid] != want:
            problems.append(f"{name(fid)} must be the literal {want} of the bound version")
    if LABEL_FIELD in rec and not _is_literal(rec[LABEL_FIELD]):
        problems.append("Scenario name must be the scenario's confirmed label as a literal")
    if LEAD_LINK_FIELD in rec:
        why = _link_value_problem(rec[LEAD_LINK_FIELD], by_id or {}, _before_ids(chain), n, links)
        if why:
            problems.append(why)
    return problems


def _strings_nonempty(v: object) -> bool:
    """True when a value holds any non-blank text or number (a Resume mapper of empty keys holds none)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        return v.strip() != ""
    if isinstance(v, (list, tuple)):
        return any(_strings_nonempty(x) for x in v)
    if isinstance(v, dict):
        return any(_strings_nonempty(x) for x in v.values())
    return False


def _literal_pieces(v: object) -> list[str]:
    """The literal text of a value: the text between {{ }} mappings (never joined across one), plus the quoted literals
    inside the mappings, with whitespace runs collapsed to one space."""
    out: list[str] = []
    for s in _strings(v):
        exprs, _outside = secret_scan._iml_segments(s)
        rest = s
        for e in exprs:
            rest = rest.replace("{{" + e + "}}", "\x00", 1)
            out.extend(secret_scan._quoted_literals(e))
        out.extend(rest.split("\x00"))
    return [" ".join(p.split()) for p in out if p and p.strip()]


_WINDOWS_CACHE: list = []   # [(registry, windows)]: the registry is immutable for a run, so one build serves every blueprint


def _system_windows(prompts: "prompt_registry.Registry") -> dict:
    """Every R6_MIN_RUN-character window of the literal system text of every registered version -> its stages."""
    if _WINDOWS_CACHE and _WINDOWS_CACHE[0][0] is prompts:
        return _WINDOWS_CACHE[0][1]
    wins: dict = {}
    for (stage, _version), reg in prompts.versions.items():
        system = (reg.get("template") or {}).get("system")
        texts = [system] if isinstance(system, str) else [x.get("text") for x in system or [] if isinstance(x, dict)]
        for piece in _literal_pieces([t for t in texts if isinstance(t, str)]):
            for i in range(0, len(piece) - R6_MIN_RUN + 1):
                wins.setdefault(piece[i:i + R6_MIN_RUN], set()).add(stage)
    _WINDOWS_CACHE[:] = [(prompts, wins)]
    return wins


def _stamp_hits(m: dict, links: "AirtableMap | None", stamps: dict) -> list[str]:
    """Names of the stamp fields a module writes: a System Logs record key, or a stamp field ID or name in an Airtable API
    call or an HTTP call to the Airtable API."""
    ids = set(stamps.values())
    fields = ((links.tables.get(LEDGER_TABLE) or {}).get("fields") or {}) if links is not None else {}
    names = {fid: fields.get(fid, fid) for fid in ids}
    hit: set = set()
    if _is_ledger_write_any(m, links):
        lower = {str(n).strip().lower(): f for f, n in names.items()}
        for k in _record(m):
            key = _ledger_key(links, k)
            if key in ids:
                hit.add(key)
            elif str(k).strip().lower() in lower:
                hit.add(lower[str(k).strip().lower()])
    elif is_airtable_write(m):
        # A table the audit cannot resolve (mapped, or a name not in the map): the stamp field IDs are unique to System Logs.
        tid = _e25_table(m, links) if links is not None else _module_table(m)
        if tid is None:
            hit |= {k for k in _record(m) if k in ids}
    elif _api_write(m):
        text = " ".join(_strings(_mapper(m))).replace("%20", " ")
        for fid in ids:
            if fid in text or (_api_ledger_write(m, links)
                               and re.search(r"(?<![\w])" + re.escape(names[fid]) + r"(?![\w])", text, re.I)):
                hit.add(fid)
    return sorted(names[f] for f in hit)


def check_r_stamps(b: Blueprint, prompts: "prompt_registry.Registry", links: "AirtableMap | None" = None,
                   logger: "LoggerSpec | None" = None) -> list[Finding]:
    """R4a a System Logs write (error routes included) that maps the usage of Claude module N and is not N's call row.
    R4b N's call row breaks the contract (filter, keys, literals, exact forms, Applicant Link, handler, or N fails R1/R2).
    R4c a module that writes a stamp field and is not a call row (the Logger, error routes, Airtable API and HTTP calls).
    R5 a Claude module outside error routes whose usage no System Logs write maps. R6 a System Logs write holding a literal
    run of R6_MIN_RUN or more characters of the system text of any registered version. Each FAIL sits on the module to
    change. Fix ID X-36.2 closes them (prefix-mapped to R)."""
    out: list[Finding] = []
    scen = _scenario_label(b)
    stamps = _stamp_map(links)
    order = list(walk(b.bp.get("flow") or []))
    by_id = {m.get("id"): m for m, _e, _c in order}
    claude = [(m, err, chain) for m, err, chain in order if _mtype(m) == prompt_registry.CLAUDE_MODULE]
    call_rows: dict = {}   # id(call row module) -> (call row, Claude module, chain of the Claude module)
    for m, err, chain in claude:
        if err:
            continue
        flow, i = chain[-1]
        c = flow[i + 1] if i + 1 < len(flow) else None
        if isinstance(c, dict) and _is_ledger_write_any(c, links) and _uses_usage(c, m.get("id")):
            call_rows[id(c)] = (c, m, chain)
    writes = _ledger_writes(order, links)
    for m, err, _chain in claude:
        n = m.get("id")
        if not err and not any(_uses_usage(w, n) for w in writes):
            out.append(Finding(PROMPTS_CHECK, FAIL, scen, n, _mtype(m),
                               f"R5 Claude module {n} has no call row and no System Logs write maps its usage, so the call is "
                               f"neither priced nor stamped. Add its call row, the System Logs create right after it (X-36.2)", "R5"))
    for w in writes:
        own = call_rows.get(id(w))
        direct = False
        for m, _e, _c in claude:
            n = m.get("id")
            if (own is None or own[1] is not m) and _uses_usage(w, n):
                direct = True
                out.append(Finding(PROMPTS_CHECK, FAIL, scen, w.get("id"), _mtype(w),
                                   f"R4a System Logs row maps the usage of Claude module {n}. A call's tokens go only on its call "
                                   f"row, the System Logs create right after module {n} (X-36.2)", "R4a"))
        tokens = _token_keys(w, links)
        if own is None and not direct and tokens:
            # Tokens copied through a variable, a parser, an aggregator or the call row's own output still price the call
            # twice, because the cost formula prices any row without Model Served by its label.
            out.append(Finding(PROMPTS_CHECK, FAIL, scen, w.get("id"), _mtype(w),
                               f"R4a System Logs row writes {' and '.join(tokens)} but is not a call row. A call's tokens go only "
                               f"on its call row, so this row prices a call a second time (X-36.2)", "R4a"))
    for c, m, chain in call_rows.values():
        problems = _call_row_problems(c, m, chain, b, prompts, links, stamps, logger, by_id)
        if problems:
            clauses = ". ".join(p[0].upper() + p[1:] for p in problems)
            out.append(Finding(PROMPTS_CHECK, FAIL, scen, c.get("id"), _mtype(c),
                               f"R4b call row of Claude module {m.get('id')} breaks the X-36.2 contract. {clauses}", "R4b"))
        else:
            out.append(Finding(PROMPTS_CHECK, PASS, scen, c.get("id"), _mtype(c),
                               f"R4 call row of Claude module {m.get('id')} stamps {_r_registered(b, prompts, m)[0]}", "R"))
    if stamps is not None:
        for m, _err, _chain in order:
            if id(m) in call_rows:
                continue
            hits = _stamp_hits(m, links, stamps)
            if hits:
                out.append(Finding(PROMPTS_CHECK, FAIL, scen, m.get("id"), _mtype(m),
                                   f"R4c writes the X-36.2 stamp field {', '.join(hits)} but is not a call row. Only the System "
                                   f"Logs create right after a Claude module writes a stamp", "R4c"))
    wins = _system_windows(prompts)
    for w in writes:
        stages: set = set()
        for piece in _literal_pieces(_record(w) if is_airtable_write(w) else _mapper(w)):
            for i in range(0, len(piece) - R6_MIN_RUN + 1):
                stages |= wins.get(piece[i:i + R6_MIN_RUN], set())
        if stages:
            out.append(Finding(PROMPTS_CHECK, FAIL, scen, w.get("id"), _mtype(w),
                               f"R6 System Logs row holds a copy of the system prompt of {', '.join(sorted(stages))} (a literal run "
                               f"of {R6_MIN_RUN} or more characters). The call row's Prompt Version and Prompt SHA256 name the "
                               f"template, so remove the copy (X-36.2)", "R6"))
    return out

# ---------------------------------------------------------------------------
# Check R, rule R7: totals over System Logs once call rows exist (X-36.2.1, decision 8 of X-36.2, Rizwan 2026-11-13 and
# 2026-11-14). A call row is one System Logs row per Claude call, so a count of System Logs rows now counts the calls too,
# while the spend total must keep them, since the call rows carry all Claude cost. Make returns at most 3,200 objects per
# search run (help.make.com, Types of modules, Module limits, read 2026-11-14), so a lower limit cuts a busy day short.
# Not allowlistable. Fix ID X-36.2.1 closes it (prefix-mapped to R).
# ---------------------------------------------------------------------------

MAKE_SEARCH_MAX = 3200
# Call rows always write these two as literals of the bound version (R4b), so a blank test on either drops every call row
# for certain. A blank test on any stamp field drops the call rows that carry cost.
CALL_ROW_KEYS = ("Prompt Version", "Prompt SHA256")
DEFAULT_STAMP_NAMES = ("Prompt Version", "Prompt SHA256", "Model Requested", "Model Served", "Stop Reason", "Message ID",
                       "Execution ID", "Inference Geo", "Cache Write Tokens", "Cache Read Tokens")
TIMESTAMP_NAME = "Timestamp"   # System Logs created time (fldc7vZ8hLX6nyL3A, schema read 2026-11-14)
R7_AGGREGATORS = ("builtin:BasicAggregator", "util:FunctionAggregator2", "builtin:NumericAggregator")


def _top_args(formula: object) -> list[str]:
    """The top-level arguments of an AND( ) formula, or the formula itself, whitespace collapsed."""
    if not isinstance(formula, str) or not formula.strip():
        return []
    f = formula.strip()
    m = re.fullmatch(r"AND\s*\((.*)\)", f, re.S | re.I)
    return [" ".join(a.split()) for a in (_split_top_level(m.group(1)) if m else [f])]


def _blank_fields(formula: object) -> set[str]:
    """Lower-cased names of the fields a top-level argument requires to be blank."""
    out: set[str] = set()
    for a in _top_args(formula):
        for rx in (_SAFE_BLANK_TEST,) + _BLANK_TESTS:
            hit = rx.fullmatch(a)
            if hit:
                out.add(hit.group("f").strip().lower())
                break
    return out


def _excludes_call_rows(formula: object) -> bool:
    """The search drops every call row: a top-level blank test of Prompt Version or Prompt SHA256."""
    return bool(_blank_fields(formula) & {k.lower() for k in CALL_ROW_KEYS})


def _drops_costed_call_rows(formula: object, stamp_names: tuple) -> bool:
    """The search drops the call rows that carry cost: a top-level blank test of any stamp field."""
    return bool(_blank_fields(formula) & {k.lower() for k in stamp_names})


def _limit_ok(v: object) -> bool:
    try:
        return int(str(v).strip()) >= MAKE_SEARCH_MAX
    except (TypeError, ValueError):
        return False


_TS = r"\{\s*" + re.escape(TIMESTAMP_NAME) + r"\s*\}"
_WINDOW_FORMS = (
    # one calendar day of the created time, against a quoted date (a literal or a mapping inside the quotes)
    re.compile(r"DATETIME_FORMAT\(\s*(?:SET_TIMEZONE\(\s*" + _TS + r"\s*,\s*'[^']*'\s*\)|" + _TS + r")\s*,\s*'[^']*'\s*\)\s*=\s*'[^']*'", re.I),
    re.compile(r"IS_SAME\(\s*" + _TS + r"\s*,\s*[^,()]+(?:\([^()]*\))?\s*,\s*'(?:day|days|week|month|year)'\s*\)", re.I),
)


def _dated(formula: object) -> bool:
    """The search formula keeps one window of created time: a top-level argument of AND( ) (or the whole formula) is a
    DATETIME_FORMAT of {Timestamp} equal to a quoted date, or IS_SAME({Timestamp}, <date>, '<unit>'), or the pair
    IS_AFTER({Timestamp}, ...) and IS_BEFORE({Timestamp}, ...). A test under NOT, IF or OR, a blank test or a single bound
    sets no window. A view cannot count, because the blueprint does not show its filter (measured 2026-11-14: the Daily
    API Cost Audit's Grid view has none)."""
    args = _top_args(formula)
    if any(rx.fullmatch(a) for a in args for rx in _WINDOW_FORMS):
        return True
    after = any(re.fullmatch(r"IS_AFTER\(\s*" + _TS + r"\s*,.*\)", a, re.I) for a in args)
    before = any(re.fullmatch(r"IS_BEFORE\(\s*" + _TS + r"\s*,.*\)", a, re.I) for a in args)
    return after and before


def _enclosing_calls(expr: str, pos: int) -> list[str]:
    """Names of the function calls whose parentheses enclose position pos of expr (strings blanked), innermost first."""
    out, depth, i = [], 0, pos - 1
    while i >= 0:
        c = expr[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                m = re.search(r"([A-Za-z_]\w*)\s*$", expr[:i])
                out.append(m.group(1).lower() if m else "")
            else:
                depth -= 1
        i -= 1
    return out


def _value_exprs_only(m: dict):
    """Expressions in the mapper and parameters (a filter only tests, it never reports a total)."""
    for path, e in _module_exprs(m):
        if not path.startswith("filter"):
            yield e


def check_r_totals(b: Blueprint, links: "AirtableMap | None" = None) -> list[Finding]:
    """R7 over every aggregator (array, function or numeric) fed by a System Logs search, and every reference to such a
    search's own bundle count. R7a a count: of rows that keep the call rows, or in a form other than
    length(map(<array aggregator>.array; "id")) over an aggregator that collects {{<search>.id}} (a search that finds
    nothing can emit one empty bundle, so any other form reads 1 on an empty day). A test that the search reached 3,200
    rows is not a count. R7b a search that feeds a total with a limit below 3,200. R7c a sum over a search that drops the
    call rows that carry cost. R7d a search that feeds a total with no window of created time. Mapper and parameter
    values only: a filter tests, it reports nothing. Each FAIL sits on the module to change."""
    out: list[Finding] = []
    scen = _scenario_label(b)
    stamp_names = DEFAULT_STAMP_NAMES
    sm = _stamp_map(links)
    if sm is not None:
        fields = (links.tables.get(LEDGER_TABLE) or {}).get("fields") or {}
        stamp_names = tuple(fields.get(fid, fid) for fid in sm.values())
    order = list(walk(b.bp.get("flow") or []))
    by_id = {m.get("id"): m for m, _e, _c in order}
    searches = {m.get("id"): m for m, _e, _c in order
                if _mtype(m) == "airtable:ActionSearchRecords" and _module_table(m) == LEDGER_TABLE}
    feeds: dict = {}   # search id -> set of kinds ("count", "sum")

    def fail(rule: str, m: dict, text: str) -> None:
        out.append(Finding(PROMPTS_CHECK, FAIL, scen, m.get("id"), _mtype(m), f"{rule} {text} (X-36.2.1)", rule))

    for agg, _err, _chain in order:
        if _mtype(agg) not in R7_AGGREGATORS:
            continue
        params = agg.get("parameters") if isinstance(agg.get("parameters"), dict) else {}
        src = searches.get(params.get("feeder"))
        if src is None:
            continue
        a, s = agg.get("id"), src.get("id")
        formula = _mapper(src).get("formula")
        excl = _excludes_call_rows(formula)
        if _mtype(agg) != "builtin:BasicAggregator":
            fn = str(params.get("fn") or "").strip().lower()
            kind = "count" if fn == "count" else "sum"
            feeds.setdefault(s, set()).add(kind)
            if kind == "count":
                fail("R7a", agg, f"counts the System Logs rows of search {s} with a {_mtype(agg)}, which counts the one empty "
                                 f"bundle a search emits when it finds nothing. Count with an array aggregator that collects "
                                 f"{{{{{s}.id}}}} and length(map({a}.array; \"id\")) over a search without call rows")
            elif _drops_costed_call_rows(formula, stamp_names):
                fail("R7c", agg, f"sums over search {s}, which drops the X-36.2 call rows, so the total leaves out every "
                                 f"Claude call's cost. Sum over a search that keeps every row of the day")
            continue
        collects_id = re.sub(r"\s", "", str(_mapper(agg).get("id") or "")) == f"{{{{{s}.id}}}}"
        for m, _e, _c in order:
            for e in _value_exprs_only(m):
                blank = _blank_strings(e)
                for hit in re.finditer(r"(?<![\w.])%d\.array\b" % a, blank):
                    calls = _enclosing_calls(blank, hit.start())
                    if "length" in calls:
                        li = calls.index("length")
                        # a test that the search reached Make's limit: length(...) followed by >= 3200 or > 3199
                        rest = blank[hit.end():]
                        depth = li + 1
                        j = 0
                        while j < len(rest) and depth > 0:
                            if rest[j] == "(":
                                depth += 1
                            elif rest[j] == ")":
                                depth -= 1
                            j += 1
                        if re.match(r"\s*(?:>=\s*%d|>\s*%d)(?!\d)" % (MAKE_SEARCH_MAX, MAKE_SEARCH_MAX - 1), rest[j:]):
                            feeds.setdefault(s, set()).add("count")
                            continue
                        feeds.setdefault(s, set()).add("count")
                        exact = (calls[:2] == ["map", "length"] and re.match(r'\s*;\s*"id"\s*\)\s*\)', e[hit.end():])
                                 and collects_id)
                        if not excl:
                            fail("R7a", m, f"counts the System Logs rows of search {s} (aggregator {a}), which holds the "
                                           f"X-36.2 call rows too, so every Claude call counts as a task. Count from a search "
                                           f"whose formula requires {{Prompt Version}} = BLANK() at the top level")
                        elif not exact:
                            fail("R7a", m, f"counts aggregator {a} in a form other than length(map({a}.array; \"id\")) over "
                                           f"an aggregator that collects {{{{{s}.id}}}}. A search that finds nothing can emit "
                                           f"one empty bundle, so another form reads 1 on an empty day")
                    elif "sum" in calls:
                        feeds.setdefault(s, set()).add("sum")
                        if _drops_costed_call_rows(formula, stamp_names):
                            fail("R7c", m, f"sums over search {s} (aggregator {a}), which drops the X-36.2 call rows, so the "
                                           f"total leaves out every Claude call's cost. Sum over a search that keeps every row "
                                           f"of the day")
    for m, _e, _c in order:
        for e in _value_exprs_only(m):
            for r in iml_refs(e):
                if r.module in searches and r.field == "__IMTLENGTH__":
                    feeds.setdefault(r.module, set()).add("count")
                    fail("R7a", m, f"counts System Logs rows through the bundle count of search {r.module}, which counts the "
                                   f"empty bundle and the call rows. Count with an array aggregator and length(map(<aggregator>"
                                   f".array; \"id\")) over a search without call rows")
    for s, kinds in sorted(feeds.items(), key=lambda kv: str(kv[0])):
        src = searches[s]
        if not _limit_ok(_mapper(src).get("maxRecords")):
            fail("R7b", src, f"search {s} feeds a System Logs total with a limit below {MAKE_SEARCH_MAX}, the most Make returns "
                             f"per run, so a busy day is cut short. Set Limit to {MAKE_SEARCH_MAX}")
        if not _dated(_mapper(src).get("formula")):
            fail("R7d", src, f"search {s} feeds a System Logs total with no window of created time, so the total covers "
                             f"whatever rows come first in the table, not one day. Give the formula a top-level day test of "
                             f"{{Timestamp}}, such as DATETIME_FORMAT(SET_TIMEZONE({{Timestamp}}, 'America/Toronto'), "
                             f"'YYYY-MM-DD') = '<date>'")
    return out

def audit(blueprints: list[Blueprint], labels: Labels, schema: Schema, by_id: bool,
          coverage: list[Finding] | None = None, links: AirtableMap | None = None,
          allowlist: Allowlist | None = None, webhooks: Webhooks | None = None,
          hooks: HookInfo | None = None, secret_allowlist: list[dict] | None = None,
          partial: bool = False, status_designs: StatusDesigns | None = None,
          schedule: dict | None = None, bland_agents: BlandAgents | None = None,
          prompts: "prompt_registry.Registry | None" = None, manifest_ids: set | None = None,
          ff10: FF10Pin | None = None, x32: "X32Pin | None" = None, x16: "X16Pin | None" = None) -> AuditResult:
    """partial=True marks a run on part of the scenarios (make_push audits one). Check D then cannot
    evaluate the fetch-back state of the scenario an allowlisted URL targets and reports INFO, and check L
    (the Logger, a property of the whole pull) does not run. The Logger entry of webhooks identifies the
    logger calls for checks B, C, E6 and F2c. schedule is the scenario state the manifest recorded, by scenario ID.
    bland_agents is the E28 registry (None reads audit/bland_agents.json, and a missing file is an InputError)."""
    if links is None:
        links = load_links(DEFAULT_LINKS)
    if allowlist is None:
        allowlist = Allowlist()
    if webhooks is None:
        webhooks = load_webhooks(DEFAULT_WEBHOOKS)
    if hooks is None:
        hooks = HookInfo(note="no hook data supplied")
    if status_designs is None:
        status_designs = load_status_designs(DEFAULT_STATUS_ALLOW)
    if bland_agents is None:
        bland_agents = load_bland_agents(DEFAULT_BLAND_AGENTS)
    if prompts is None:
        prompts = load_prompts()
    if ff10 is None:
        ff10 = load_ff10(DEFAULT_FF10)
    if x32 is None:
        x32 = load_x32(DEFAULT_X32)
    if x16 is None:
        x16 = load_x16(DEFAULT_X16)
    if secret_allowlist is None:
        try:
            secret_allowlist = secret_scan.load_secret_allowlist(DEFAULT_SECRET_ALLOWLIST)
        except secret_scan.SecretAllowlistError as exc:
            raise InputError(str(exc)) from None
    logger = webhooks.logger
    res = AuditResult(blueprints=blueprints, labels_confirmed=labels.confirmed)
    res.findings.extend(coverage or [])
    in_scope: list[Blueprint] = []
    for b in blueprints:
        _sid, entry = _labels_entry(b, labels, by_id)
        if isinstance(entry, dict) and entry.get("out_of_scope") is True:
            reason = entry.get("note") or "marked out_of_scope in scenario_labels.json"
            res.findings.append(Finding("M", INFO, _scenario_label(b), "-", "-", f"Skipped, out of scope: {reason}"))
            continue
        in_scope.append(b)
    # Check F first for every scenario, because check D depends on whether the scenario an
    # allowlisted URL targets passes F2.
    f_by_sid: dict[str, list[Finding]] = {}
    for b in in_scope:
        _lsid, lentry = _labels_entry(b, labels, by_id)
        f_label = str(lentry.get("expected_label") or "").strip() if isinstance(lentry, dict) else ""
        f_by_sid[id(b)] = check_f(b, allowlist, webhooks, hooks, links, f_label)
    f2_state: dict[str, bool] | None = None
    if not partial:
        f2_state = {}
        for b in in_scope:
            reg = webhooks.entries.get(str(b.scenario_id)) if b.scenario_id is not None else None
            if reg is not None and reg.protection == "fetch_back":
                rows = f_by_sid[id(b)]
                f2_state[str(b.scenario_id)] = bool(rows) and not any(r.status == FAIL for r in rows)
    used_secret: set = set()
    for b in in_scope:
        res.findings.extend(check_a(b, schema, links, status_designs))
        res.findings.extend(check_b(b, logger, links, webhooks))
        res.findings.extend(check_c(b, labels, schema, by_id, logger))
        res.findings.extend(check_d(b, secret_allowlist, f2_state, used_secret))
        state = (schedule or {}).get(str(b.scenario_id)) if b.scenario_id is not None else None
        active = state.get("active") if isinstance(state, dict) and isinstance(state.get("active"), bool) else None
        res.findings.extend(check_e(b, links, allowlist, logger, webhooks, bland_agents, ff10, x32, x16, active))
        res.findings.extend(check_p(b, logger))
        res.findings.extend(check_r(b, prompts))
        res.findings.extend(check_r_stamps(b, prompts, links, logger))
        res.findings.extend(check_r_totals(b, links))
        res.findings.extend(check_s(b, links))
        res.findings.extend(f_by_sid[id(b)])
    if not partial:
        res.findings.extend(check_l(in_scope, logger, schedule or {}, hooks))
    audited = {b.scenario_id for b in blueprints if b.scenario_id is not None}
    if not partial and manifest_ids is not None:
        res.findings.extend(check_r_pull(prompts, {str(x) for x in manifest_ids} | {str(x) for x in audited}))
    res.unused_allowlist = allowlist.unused(audited)
    res.unused_secret_allowlist = [e for e in secret_allowlist
                                   if e["scenario_id"] in audited
                                   and (e["scenario_id"], e["module_id"], e["pattern_type"]) not in used_secret]
    return res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _cell(v: object) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


SECTION_INTRO = {
    "A": "Every point where a lead can become Disqualified needs a Shadow Ledger create at the decision point with the lead link, the decision value, evidence and the Bland call ID. Routers that branch on a decision value need a fallback route. VIP tiering is listed as INFO. A-3 (bug sweep H2) a lead Status write whose record ID is {{N.id}} of a search needs a filter {{N.id}} exists after the search on its path (on the write or a module between), because a search that finds nothing can emit one empty bundle (measured 2026-10-30) and the update then fails on an empty ID. A re-lookup is credited: the search, or a module before it on its path, is gated on the first record ID of an aggregator fed by an identical search (same table and formula). A-4 (bug sweep M3) no filter on the path of a lead Status write outside an error route waits for a lead-table search to find the lead, since a miss stops the bundle with no trace. A found test on the first record ID of an aggregator fed by the lead search passes only on the first module of a router route whose fallback leaves a trace or whose sibling route tests the empty result and holds an unfiltered Error ledger row and a Slack alert. Does-not-exist gates (dedupe stops) and a search that is the scenario's first module (a scheduled poll, where empty is idle) are out of scope. A-5 (D5, 2026-11-01) for a scenario in audit/status_allow_list.json every allowed value passes the allow-list filter of the dynamic lead Status write, and when the first router after the write on its flow branches on the same mapping, every allowed value has a route of its own that is not the fallback, whose first module's filter is one OR group that tests the value with text equal (case-insensitive equal is fine). The fallback alone does not count, since it logs the value as unmatched.",
    "B": "F-E5 v3 (Option C, decided by Rizwan 2026-10-29). Every external-call module outside an error route, except the trigger, needs a complete error handler. Complete is one call to the shared Logger and then exactly one directive, which is a PASS whose row says what the directive means for the trace (Ignore and Resume make Make mark the run a Success, so the Logger row is the only trace, Break retries log again). The legacy handler, a Shadow Ledger write, a Slack message and one directive, is a REVIEW until F-E5.3 converts it. A module that is itself a Shadow Ledger write needs a logger call (or the legacy Slack message) and one directive. A missing or partial handler is a FAIL. A logger call is an HTTP module whose URL is the Logger URL variable or whose keychain connection is the Logger connection (audit/webhooks.json), and it must be http:MakeRequest, POST, keychain-authenticated with no hand-set key header, with Return error if HTTP request fails off, no filter and no handler of its own, and a urlencoded body of exactly label, outcome Error, module_id (the owner), module_name, error_type and error_message from the owner, execution_id {{var.scenario.executionId}}, and optionally lead_record_id and call_id. What remains with the error setting off: a failure below HTTP (DNS, TLS, refused connection, a 40-second timeout, a missing team variable) is still an error inside the error route, which ends the run with an error and, for a webhook-triggered scenario, deactivates it. A 4xx or 5xx reply from the Logger is silent and that log entry is lost. The Logger scenario itself is judged by check L. B1 (bug sweep L3, 2026-10-31) a Logger call whose lead_record_id is one bare reference to an Airtable link field sends the whole link list. Two links reach the Logger as one text, its Applicant Link write gets a 422 and the Error row is lost. The row sits on the call and closes with {{first(<link>)}} (F-E5.4). The payload contract accepts lead_record_id as one bare Applicants record ID reference or as first() of an Applicants link field, and first() of a record ID or of any other field is a FAIL.",
    "C": "Every Shadow Ledger write and every Logger call (its body label) uses the label mapped to its scenario, every scenario that writes the ledger or calls the Logger has an entry, and every label is a Single Select option. The Logger's own ledger row maps the caller's label ({{trigger.label}}) and is exempt.",
    "D": "Credential literals found by scripts/secret_scan.py, including blueprints make_pull.py withheld for one. Values are never shown. The one allowance is audit/secret_allowlist.json: a Make webhook URL in the mapper.webhook of a Bland call module (Send a Call or Create a Call) is INFO (allowlisted) while the scenario its entry names (requires_fetch_back_hook) passes F2, and FAIL when it does not.",
    "E": "Static mapping integrity, read from the blueprint and each module's metadata.interface. E1 a reference to a field the referenced module does not output. E2 a bare {{name}} with no module prefix. E3 a record ID that links or addresses the wrong Airtable table, or comes from a non-Airtable module. E4 a literal record ID in a get, update or delete (intended singletons go in audit/allowlist.json with a reason). E5 a filter waiting for a search to return 0 bundles, which never fires. E6 client PII in a Slack message or in a Logger call body. E7 (REVIEW) a router whose routes all have filters, with no fallback, where a route writes state (two exactly opposite filters are not flagged). E8 an Airtable formula that names a field the table does not have, or compares with an unquoted {{...}} value. E9 (X-44) a router where two routes can both run for one bundle (a route with no filter that is not the fallback, or filters that do not exclude each other) and both update the same Applicants field, so the later write wins. E10 (X-45) a Voice AI Ledger create whose mappings do not make Total Cost, the formula ({Call_Length}/60) * {Rate per minute}, equal the Bland price: Call_Length is a duration in whole seconds and Bland call_length is minutes, so Call_Length is round(call_length * 60) and Rate per minute is price * 60 divided by those seconds, guarded for a zero length. The audit evaluates both mappings on sample calls. E11 a literal empty value in an Airtable record list field (a link written as [\"\"]), which Airtable rejects with 422, and (a, bug sweep L2) a list item, error routes included, that maps a module field other than id, since it is empty when the source has no value. Map one string with the remove of add over emptyarray with ifempty form instead (the IML is in CLAUDE.md check E). E5 also FAILs any number comparison of {{length(<aggregator>.array)}} or a search bundle count, because a search that finds nothing emits one empty bundle (measured 2026-10-30): test the first aggregated record ID (first of map over <aggregator>.array with the key id, the IML is in CLAUDE.md check E) or {{<search>.id}} with exists or does not exist. E12 (bug sweep B3) an Airtable Watch Records trigger whose scenario updates the record it returned on the same table while the trigger formula, evaluated with the written values, can still match, so the next poll runs the scenario again (a Created Time trigger field is exempt). E13 (bug sweep B2) a reference to a HeyGen Get a Video or Create an Avatar Video output path the module does not output, checked against output lists read with app-module_get on 2026-10-30. E9, E10, E11, E12 and E13 cannot be allowlisted. E6 also covers client PII that comes from outside Airtable (an inbound email, a webhook body, a Drive link), listed under non_airtable_pii in audit/airtable_links.json. Allowlisted rows show as INFO. Modules with no interface are skipped and counted as INFO. E19 (bug sweep H3) IML written as text: a known IML function written outside {{ }} with a mapping as an argument (Make sends the call as literal text), or a string literal inside {{ }} wrapped in quote characters (\"\"\"X\"\"\"), so the value carries the quotes. E20 (bug sweep H4) a text value mapped into an Airtable attachment field (an array of url and filename items in metadata.expect). Only an expression that makes an array, or a bare reference to an array field, passes. E21 (bug sweep M4) a Gmail search watch trigger whose query does not exclude the account's own mail with -from:me (or -in:sent, -label:sent), so an outgoing email that fits the query runs the scenario. E19, E20 and E21 cannot be allowlisted. E22 (bug sweep M8) a client send that maps HeyGen Get a Video output with no filter, on it or an earlier module after the video, of one OR group requiring {{G.data.status}} text equal completed and {{G.data.video_url}} exists, so a render still processing after the wait never emails a dead link. E23 (bug sweep L5) a Voice AI Ledger create not linked to its System Logs row, either by System Log Link mapped to the id of a System Logs module that runs before it, or by a later System Logs write on its path that maps Voice AI Ledger to its id (the link is reciprocal, so one side fills both). E22 and E23 cannot be allowlisted. E24 (bug sweep M7) an Ignore handler that ends a path which still holds independent work. A later module on the same flow (routes included) that does not reference the module, directly or through a module that does, and does not read its table, never runs when the module fails. It FAILs on an Airtable create, or when every such module is a Shadow Ledger create (the run's Success or cost row). The last module on a flow drops nothing. The fix is Resume, or moving the independent modules ahead. E25 (bug sweep L9) one owner for voice cost: only a fetch_back scenario in audit/webhooks.json may create a Voice AI Ledger row or write System Logs Voice AI cost, since its F2d gate runs the write once for an ended call. Any other scenario's write can run while the call is in progress and counts the call twice in Grand Total. E24 and E25 cannot be allowlisted. E26 (bug sweep L8a) a search that can return several records (maxRecords not 1) reaches a module that writes, sends or spends with no filter that is false on its empty bundle, one row on the module right after the search (fix: {{<search>.id}} exists there). E26 cannot be allowlisted. E28 (X-46) a Bland call to a migrated pathway, error routes included: a Send a Call or Create a Call whose pathway_id is a pathway audit/bland_agents.json registers as migrated to an agent, a Send a Call that sets agent_id (the module has no such field, so the call dials by pathway or task), a Create a Call whose agent_id is empty, missing, a mapping, padded with spaces, not a Bland UUID or not a registered agent (the module type is used only for migrated agents, so one that dials by pathway_id or persona_id alone FAILs too), a Create a Call that sets pathway_id or persona_id beside agent_id (Make takes only one of the three), a Create a Call with no connection, or one with an agent_id whose agent_version is not exactly the literal production. A Send a Call that maps pathway_id is a REVIEW while the registry lists a pathway. The audit refuses a missing registry. E14, E17, E18 and F3 treat Send a Call and Create a Call the same, and E1 checks a reference to either against their pinned outputs (status, message, call_id), since neither carries a metadata.interface. E28 cannot be allowlisted. F-F10 (specs/F-F10-drafting-chain.md, owner pinned in audit/ff10.json): E29 no module writes Applicants Synthetic Test Case (a record key by ID or name, an Airtable API or HTTP write, error routes included), since Rizwan ticks it by hand. E30 only the owner writes Applicants Drafting Status, and every write there is an Airtable update keyed exactly {{1.id}} of its Applicants Watch Records trigger. E31 ff13.drafting_context and ff13.validate_draft run only from the owner, through postgres:StoredProcedure v2 on the pinned ff13_make connection with isToManageDataInSharedTransaction false and the literal function name, and every argument holds its pinned form (matched by value, and by key when the keys are the measured positional @NN:text keys, so a swap FAILs, otherwise a REVIEW): record ID {{1.id}}, execution ID, codes, name and facts from module 1, the flag as an if over Synthetic Test Case that gives the text true or false, the draft in the P5 form and the stamps from the drafter's call row (by field name, or by field ID only when the call row has useColumnId true). Any module on the ff13_make connection is an ff13 call, and one that names no ff13 function as a literal, or SQL with a mapping in a name position, FAILs anywhere. E29 and E30 also FAIL a write that may reach Applicants and hides which fields it writes (a mapped bulk records list, a mapped record, an API or HTTP body built in another module). While owner_scenario_id is null, a scenario named like the owner is checked in full and each write and call also gets an owner pending FAIL. E6 also treats the PostgreSQL outputs review_note, detail and provisions and Claude content as client data. E32 every Google Docs create of the owner runs after the validator, maps exactly the drafter's text in the P5 form, and sits behind filters that require the verdict pass or pass_with_flags, the drafter's stop_reason end_turn and one grounding mode. A test Doc also requires the TEST MODE review note, a literal folder with no mapping or placeholder (since X-16 exactly the pinned test folder of audit/x16.json) and the TEST title. A production Doc requires a review note without that prefix and, since X-16, the review folder below. Any other owner module that maps the drafter's text FAILs. None of E29 to E32 and none of these E6 rows can be allowlisted. X-32 (specs/X-32-exemplars.md, pin audit/x32.json): E35 no module of any scenario writes the Exemplars table (a native write by ID or name, an Airtable API or HTTP write that names it), only the F-F10 owner reads it, through Search Records only, and any Airtable module with a mapped table or base, or Airtable API or HTTP call with a mapped base or table in its URL, reads included, FAILs in every scenario. E36 the owner holds one Exemplars search on the drafter's flow before the drafter, behind the outline's end_turn filter, after one ff13.drafting_context call, with the pinned formula (firm literal, the codes from module 1, Status from the grounding gate_mode), the pinned Limit, Exemplar Code ascending, no view, the four output fields, useColumnId false and the trigger's base, followed by an array aggregator of exactly id, rank_key, skeleton and terms and then the ff13.rank_exemplars call, neither filtered, and no second search, aggregator or ranker. The search's and the ranker's handlers are each exactly [Logger call, the pinned selection_directive] (Ignore or Break), and a Resume FAILs. E37 only the drafter maps the aggregator's skeleton (once, inside its exemplar tag), only the validator's @08 its terms and only the ranker its Rank Key lines, nothing else maps the search, and a skeleton without terms or the reverse FAILs. E31 covers ff13.rank_exemplars and E6 the aggregator and the Exemplars text fields. None of E35 to E37 can be allowlisted. X-16 Phase A (specs/X-16-options.md, pin audit/x16.json, decided 2026-11-16): E38 the drafting chain holds a ParseJSON of the outline's text right after the outline's call row and before the outline router, and each of its seven outcome routes (pinned by the module ID and route of its Applicants update) creates exactly one Draft Reviews row right after that update (on the two Draft Ready routes with only a Get a Document of the route's new Doc between, select map, includeTabsContent false, filter image) with the pinned record (execution ID, Applicant as a list of {{1.id}}, the route's Outcome, Gate Mode and Grounding ID, the validator fields where the route runs after the validator, Risk Flags and Weak Grounds from the ParseJSON, the outline text, Assigned RCIC, Sign-off State Pending on the two Draft Ready routes and Not approvable elsewhere, and on the Draft Ready routes Doc ID, Doc Link and a guarded hash of the Doc's text), every new module unfiltered with the handler Logger call then Resume. The owner writes Draft Reviews nowhere else (no other create, update, upsert, API or HTTP write), and an Applicants Drafting Status write after the outline outside the seven routes FAILs. E39 only the owner writes Draft Reviews, no module deletes a row and none writes the Applicants inverse link. E40 no client send, Drive share, access change, copy, move, template copy, Doc write, upload, file content update or HTTP call to the Drive or Docs API that is not a GET maps the working Doc (Draft Doc Link, a Draft Reviews Doc ID or Doc Link, the owner's Doc creates or anything fed by them, a download or export included), and no scenario but the owner writes Claude text into a Doc or an upload: a FAIL when the scenario is active or its state is unknown, a REVIEW while the pull shows it inactive (the fallback Submission Letter). E32 moves the production Doc to the pinned staff-only review folder with {{1.id}} in its name (owner pending while the folder is not pinned) and keeps test Docs in the pinned test folder, E30 covers Draft Doc Link and Drafting Review Note (a field name counts in an HTTP request only when it can reach Airtable), E6 covers the Draft Reviews PII fields (Doc Link included), Applicants RCIC of Record and Draft Doc Link, a Google Docs create's webViewLink, a ParseJSON of Claude content, a Google Doc's text and title, an export or download's data and a Docs or Drive API call's body, directly or through a variable, parser, aggregator or text step, and E12 reads the erase keyword as blank. None of these rows can be allowlisted.",
    "F": "Every scenario triggered by a custom webhook is listed in audit/webhooks.json (F0). api_key scenarios are called by a Bland pathway webhook node that can send headers, so F1 needs the hook to require at least one Make API key (header x-make-apikey), read from the hook list in manifest.json. Missing hook data is a FAIL marked UNCONFIRMED (no proof that a key exists), and F1 cannot be allowlisted. fetch_back scenarios are called by a Bland post-call webhook that cannot send a header, so F2 verifies in the blueprint that (a) a Bland call-details module on the main flow takes only the call ID from the request and its error handler ends in Break or Ignore, never Resume, (b) a Shadow Ledger (System Logs) lookup in the pinned form {External Call ID} = '{{call-details.call_id}}' (optionally inside an AND with reference-free arguments), on a search whose error handler does not Resume and whose next module has exactly the found filter, gates every module that writes or sends (error handlers of the call-details module and of the lookups are exempt from the gate), and (c) no module other than the call-details module reads the request, handlers and Logger call bodies included (a Logger call sends call_id from the call-details output or none), and no bare name or aggregator source can resolve to it. (d) F2d, replay: every module that writes, sends or spends also waits for the fetched call to be complete (a filter on the call-details output, {{N.status}} equal \"completed\" as the only OR group, since Bland also sets completed true on failed calls) and for a ledger row that is not yet reconciled. The lookup searches with maxRecords 1, pins the row kind with {Scenario name} = '<label of the calling scenario>' (lookup_label in audit/webhooks.json) and carries a top-level blank test such as {Voice AI cost} = BLANK() on a System Logs field the scenario fills in when it reconciles (for a number field Airtable reads 0 as blank, so only LEN({F}&'')=0 counts), or a later filter requires that field to be empty on the lookup record. The reconciliation is an airtable:ActionUpdateRecords on System Logs whose id is exactly {{lookup.id}} and that sets the field, the first effect after the gates on the main flow (no router and no other effect before it, no filter between the gates and it), with an error handler that ends in Break. The scenario must run with Sequential processing on, because the check and the update are two steps. Each F2 violation is a FAIL on the module that has to change. F3 (X-43, api_key scenarios except the Logger) duplicate delivery: every lead Status write, client send and paid call runs only behind a System Logs search whose formula is exactly AND({External Call ID} = '<call ID>', {Scenario name} = \"<label>\", {Execution Status} = 'Success') with an error handler that only Breaks, an array aggregator (builtin:BasicAggregator) fed by it right after it, and a filter of one OR group whose condition is that the first record ID the aggregator collected does not exist, on the next module (a search that finds nothing can still emit one empty bundle, measured 2026-10-30, so a length test never reads 0) (or on the first module of a router route right after it). Each gated module's path must also write the marker row after the gate (a Shadow Ledger create with that label, External Call ID and Execution Status Success), and Sequential processing must be on. The first ungated module gets the FAIL. Hook-level IP restrictions are not visible in the blueprint.",
    "L": "The shared Logger (the entry of audit/webhooks.json with caller make_http, specs/F-E5-v3-shared-logger.md). Until it is registered, deployed and in the pull this is a single FAIL. Then L1 its trigger is a custom webhook on the registered hook, the hook has an API key (manifest hook list, UNCONFIRMED when unreadable) and the scenario is active, L2 Process data in order and Store incomplete executions are off, L3 exactly one Shadow Ledger create labelled {{trigger.label}}, Execution Status Error, no External Call ID (it would match the fetch-back replay lookup), with no filter ahead of it, L4 exactly one Slack alert after it with IDs only that names the ledger row and says when the write failed (a Resume with a literal substitute id, or ifempty), with the ledger write's handler a Resume when the alert follows it on the same flow, and L5 every module has a handler that cannot error, exactly one Ignore or Resume, because an unhandled error deactivates a webhook scenario at once.",
    "S": "Stripe money calls (F-H1, F-H2, F-H9-prep). S1 every Stripe call that creates or moves money carries an idempotency key built from a record ID mapping and nothing that changes per run (the native Create a Payment Intent field, or an Idempotency-Key header on a Make an API Call POST). Native create modules without a key field FAIL. S2 every Invoice or PaymentIntent create carries metadata airtable_record_id (exactly a record ID mapping) and milestone, so the F-H9 listener finds the lead. S3 no module maps {{N.charges...}} of a Stripe module, since a PaymentIntent has no payable URL. S4 the lead Status write Payment Verified - Ready runs only behind a filter that requires Payment Status = Paid in Full (F-H4). S5 the Status write LOCKED - Payment Required runs only behind a filter that requires Payment Status not Paid in Full, so the widened AR trigger (L3) never re-locks a paid lead. S6 no router holds Stripe money calls on two routes where one runs unfiltered, since Make keeps running sibling routes after a Break. S7 paid_out_of_band (removed in Stripe API 2025-03-31.basil) is read only from a Stripe call pinned with a Stripe-Version header before that version. S8 no Stripe POST takes its customer straight from a search or list module, since Make's Stripe search emits an empty bundle when it finds nothing. S9 a Stripe module that sends an email (mapper email, or the email= pair of a POST /v1/customers body) has a text:pattern filter holding @ on that mapping, on the first module of a router route whose fallback leaves an unfiltered Shadow Ledger row and Slack alert, since an empty email lists another client's customer and a malformed one gets email_invalid. S10 an update or upsert on the lead table never writes Payment Status as a fixed Partial or Unpaid unless the same record writes Amount Paid, since the value must follow the amount paid (derive it from the trigger's Amount Paid).",
    "R": "The prompts registry (X-36.1, decided by Rizwan 2026-11-13). ref/prompts.json holds every Claude prompt as immutable versions, each the module mapper (model, settings, system and messages, mappings unfilled) with the SHA-256 of its canonical JSON, and ref/prompt_bindings.json names the version each module runs. R1 every Claude module, routes and error routes included, has a binding. R2 its mapper hashes to the registered version, so an edit made in Make without a new registered version FAILs. R3 every binding of a scenario names a Claude module that exists, and in a full audit every binding names a scenario in the pull. An edit is a new version (scripts/prompt_registry.py register), never a change to an old one. Fix ID X-36 closes check R.",
    "P": "AI model pinning (X-15, X-18, decided by Rizwan 2026-10-30: Anthropic only, no OpenAI, no mini models, no Sonnet). P1 no OpenAI or other LLM module and no HTTP or API-call module to an LLM API host anywhere in the scenario, error routes included. Every LLM call is anthropic-claude:createAMessage v1. P2 model is a literal, claude-opus-5-5 or claude-haiku-5-5. P3 the mapper sets none of temperature, top_p and top_k (also not through additionalParameters), thinking is never type enabled and never carries budget_tokens, and on claude-opus-5-5 it is never type disabled. P4 max_tokens is a literal integer, at least 16000 on claude-opus-5-5 and 2048 on claude-haiku-5-5, so thinking cannot use the whole budget. P5 every reference to a Claude module's content in another module (mapper, filter, parameters, error routes) is exactly the first-text-block form, first of map over N.content taking text where type is text (the IML is in CLAUDE.md check P), since thinking blocks come first on Opus, and no module reads an OpenAI-only output (choices, usage.prompt_tokens, usage.completion_tokens) of a Claude module, which check E1 cannot see because the module has no interface. P6 a client send (email, SMS, HeyGen video, Bland call) that maps Claude text runs behind a filter, on itself or an earlier module after the Claude module, of one OR group requiring {{N.stop_reason}} text equal end_turn, since a refusal or a max_tokens stop leaves no text. Each FAIL sits on the module that has to change.",
    "M": "Every scenario in manifest.json has a blueprint the audit read. A missing file is FAIL. A scenario with no live version is REVIEW.",
}


def render_report(res: AuditResult, report_date: str, source: str) -> str:
    lines = [f"# Blueprint audit {report_date}", ""]
    lines.append(f"Source: `{source}`. Blueprints audited: {len(res.blueprints)}.")
    lines.append("")
    if res.labels_confirmed:
        lines.append("Scenario labels file: confirmed. Check C counts toward the result.")
    else:
        lines.append("Scenario labels file: not confirmed. Check C findings are UNCONFIRMED and do not count as FAIL.")
    lines.append("")
    lines.append(f"Result: **{'FAIL' if res.failed else 'PASS'}**")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Check | " + " | ".join(STATUS_ORDER) + " |")
    lines.append("|---|" + "---:|" * len(STATUS_ORDER))
    for c in CHECKS:
        counts = " | ".join(str(res.count(c, s)) for s in STATUS_ORDER)
        lines.append(f"| {c}. {CHECK_TITLES[c]} | {counts} |")
    for c in CHECKS:
        lines += ["", f"## {c}. {CHECK_TITLES[c]}", "", SECTION_INTRO[c], ""]
        rows = [f for f in res.findings if f.check == c]
        if not rows:
            lines.append("No findings.")
            continue
        rows.sort(key=lambda f: (STATUS_ORDER.index(f.status), f.scenario, str(f.module_id)))
        lines.append("| Status | Scenario | Module | Type | Detail |")
        lines.append("|---|---|---|---|---|")
        for f in rows:
            lines.append(f"| {f.status} | {_cell(f.scenario)} | {_cell(f.module_id)} | `{_cell(f.module_type)}` | {_cell(f.detail)} |")
    lines.append("")
    return "\n".join(lines)


def render_summary(res: AuditResult, report_note: str) -> str:
    lines = [f"Audited {len(res.blueprints)} blueprints. Labels confirmed: {'yes' if res.labels_confirmed else 'no'}."]
    for c in CHECKS:
        counts = "  ".join(f"{s} {res.count(c, s)}" for s in STATUS_ORDER)
        lines.append(f"{c}  {CHECK_TITLES[c]:<30} {counts}")
    allowed = Counter(f.check for f in res.findings if f.allowlisted)
    if allowed:
        lines.append("Allowlisted (shown as INFO): " + ", ".join(f"{c} {n}" for c, n in sorted(allowed.items())))
    for e in res.unused_allowlist:
        lines.append(f"Allowlist entry matched nothing: {e['check']} scenario {e['scenario']} module {e['module']}. "
                     f"Remove it, or check that the finding it excuses still exists")
    for e in res.unused_secret_allowlist:
        lines.append(f"Secret allowlist entry matched nothing: scenario {e['scenario_id']} module {e['module_id']}. "
                     f"Remove it, or check that the URL it excuses is still in the blueprint")
    lines.append(f"Result: {'FAIL' if res.failed else 'PASS'}. {report_note}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_date(s: str) -> str:
    try:
        return _dt.date.fromisoformat(s).isoformat()
    except ValueError:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Audit Make blueprints for Immi-OS checks A to F, L and M.")
    p.add_argument("--dir", help="audit any folder of blueprint JSON files instead of blueprints/ + manifest")
    p.add_argument("--blueprints", default=os.path.join(REPO_ROOT, "blueprints"), help="blueprints folder (manifest mode)")
    p.add_argument("--manifest", default=None, help="manifest path (default <blueprints>/manifest.json)")
    p.add_argument("--labels", default=os.path.join(REPO_ROOT, "audit", "scenario_labels.json"))
    p.add_argument("--schema", default=os.path.join(REPO_ROOT, "audit", "airtable_ledger_schema.json"))
    p.add_argument("--links", default=DEFAULT_LINKS, help="Airtable table and link map (checks E1, E3, E4, E6)")
    p.add_argument("--allowlist", default=DEFAULT_ALLOWLIST, help="intended exceptions to checks E and F")
    p.add_argument("--webhooks", default=DEFAULT_WEBHOOKS, help="webhook registry and the Logger entry (checks B, C, E6, F and L)")
    p.add_argument("--secret-allowlist", default=DEFAULT_SECRET_ALLOWLIST, help="pinned secret allowlist (check D)")
    p.add_argument("--status-allow", default=DEFAULT_STATUS_ALLOW, help="Status allow-list for the F-31 design (check A)")
    p.add_argument("--bland-agents", default=DEFAULT_BLAND_AGENTS, help="migrated Bland pathways and their agents (check E28)")
    p.add_argument("--prompts", default=DEFAULT_PROMPTS, help="prompts registry versions (check R, ref/prompts.json)")
    p.add_argument("--prompt-bindings", default=DEFAULT_PROMPT_BINDINGS, help="prompts registry bindings (check R, ref/prompt_bindings.json)")
    p.add_argument("--ff10", default=DEFAULT_FF10, help="F-F10 owner pin (checks E30 and E31, audit/ff10.json)")
    p.add_argument("--x32", default=DEFAULT_X32, help="X-32 exemplar pin (checks E35 to E37, audit/x32.json)")
    p.add_argument("--x16", default=DEFAULT_X16, help="X-16 review pin (checks E38 to E40 and the E32 production folder, audit/x16.json)")
    p.add_argument("--reports-dir", default=os.path.join(REPO_ROOT, "audit", "reports"))
    p.add_argument("--report-date", type=_parse_date, default=None, help="report date YYYY-MM-DD (default today)")
    p.add_argument("--no-report", action="store_true", help="dry run, print the summary only")
    return p


def main(argv: list[str] | None = None, today: _dt.date | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        labels = load_labels(args.labels)
        schema = load_schema(args.schema)
        links = load_links(args.links)
        allowlist = load_allowlist(args.allowlist)
        webhooks = load_webhooks(args.webhooks)
        status_designs = load_status_designs(args.status_allow)
        bland_agents = load_bland_agents(args.bland_agents)
        prompts = load_prompts(args.prompts, args.prompt_bindings)
        ff10 = load_ff10(args.ff10)
        x32 = load_x32(args.x32)
        x16 = load_x16(args.x16)
        check_pins_agree(ff10, x16)
        try:
            secret_allow = secret_scan.load_secret_allowlist(args.secret_allowlist)
        except secret_scan.SecretAllowlistError as exc:
            raise InputError(str(exc)) from None
        hooks = HookInfo(note="--dir mode has no manifest")
        manifest_ids = None
        if args.dir:
            blueprints = load_dir(args.dir)
            if args.manifest:
                hooks = load_hooks_info(args.manifest)  # --dir reads hook state only from an explicit --manifest
            source = args.dir
            by_id = False
            coverage = []
        else:
            manifest = args.manifest or os.path.join(args.blueprints, "manifest.json")
            blueprints, coverage = load_manifest_mode(args.blueprints, manifest)
            manifest_ids = {str(e.get("id", e.get("scenarioId"))) for e in _manifest_entries(_read_json(manifest))
                            if e.get("id", e.get("scenarioId")) is not None}
            hooks = load_hooks_info(manifest)
            source = os.path.relpath(args.blueprints, REPO_ROOT) if os.path.isabs(args.blueprints) else args.blueprints
            by_id = True
    except InputError as exc:
        print(f"audit_blueprints: {exc}", file=sys.stderr)
        return 2
    res = audit(blueprints, labels, schema, by_id, coverage, links, allowlist, webhooks, hooks, secret_allow,
                status_designs=status_designs, bland_agents=bland_agents, prompts=prompts, manifest_ids=manifest_ids, ff10=ff10, x32=x32, x16=x16,
                schedule=load_schedule_info(args.manifest or (None if args.dir else os.path.join(args.blueprints, "manifest.json"))))
    report_date = args.report_date or (today or _dt.date.today()).isoformat()
    if args.no_report:
        note = "Report not written (--no-report)."
    else:
        os.makedirs(args.reports_dir, exist_ok=True)
        path = os.path.join(args.reports_dir, f"{report_date}.md")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_report(res, report_date, source.replace(os.sep, "/")))
        note = f"Report: {path}"
    print(render_summary(res, note))
    return 1 if res.failed else 0


if __name__ == "__main__":
    sys.exit(main())
