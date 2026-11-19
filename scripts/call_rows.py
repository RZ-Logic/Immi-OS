"""X-36.2 call rows: build the push candidate of one AI scenario, check it with make_push's local guards, and write its spec.

Usage (from the repo root):
    python scripts/call_rows.py --scenario 3920821 --id-sequence 106 --base-version 35 --out <folder outside the repo>
                                [--write-spec]

The design is specs/X-36.2-call-rows.md (decided by Rizwan 2026-11-13). For each Claude module N outside error routes the
candidate inserts one call row at index i+1 of N's flow list: an unfiltered airtable:ActionCreateRecord on System Logs
whose record is the call-row contract of audit rule R4b (label literal, Execution Status, the call's tokens, the ten stamps
of N's bound version, and Applicant Link where an outcome row already maps one from a module that runs before N), with the
handler [a copy of N's own Logger call, Resume]. Every other System Logs write drops its Input Tokens and Output Tokens
(R4a), and a write that holds a hand copy of a registered system prompt (R6) gets its AI prompt / Payload rewritten to the
call's inputs only: the registered template's user message and the mappings inside a templated system text, mappings
intact, no prompt text.

--id-sequence is the scenario's live idSequence (GET /scenarios/{id}/blueprint, read token), so the new module IDs sit
above it as make_push requires. Nothing here writes to Make: the candidate and plan go to --out (refused inside the repo),
and --write-spec writes specs/X-36.2-<slug>.md. The push itself is scripts/make_push.py with the command the spec prints.
Reads the committed snapshot, never live state, so pull first (CLAUDE.md, session start).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import audit_blueprints as ab  # noqa: E402
import make_push as mp  # noqa: E402
import prompt_registry as pr  # noqa: E402
import secret_scan  # noqa: E402

REPO = os.path.dirname(HERE)
PAYLOAD_FIELD = "fldeAVW2SAkT6KpZw"
FIX = "X-36.2"
NUMBER_ROLES = ("cache_write_tokens", "cache_read_tokens")

# Per scenario: spec slug, the test checklist lines whose expectations this push changes, and the runtime test plan (test
# records only, hard rule 3, with the guards docs/IMMIOS_TEST_CHECKLIST.md already sets). Triggers measured 2026-11-14.
SCENARIOS = {
    3920821: ("vip-intake", [44], (
        "Pilot [STATUS], after the item 44 probe. The dedupe stops a second email from a known sender before the call: the "
        "filter on Claude 81 tests aggregator 70 (Files search 11) and aggregator 88 (Applicants search 85) on the sender's "
        "address, and item 44 leaves TEST Gate 5 behind. So use a TEST sender address with no Applicant and no Files row, or "
        "clear TEST Gate 5's Email first. Then run line 44's steps (route 1 with a phone, Run once, "
        "Choose where to start on that email only). Expected: call row {row81} right after Claude 81 holds Prompt Version {tag81}, "
        "Prompt SHA256, Model Requested claude-haiku-5-5, Model Served, Stop Reason end_turn, Message ID, Execution ID, Inference "
        "Geo, both cache counts (0 is fine) and both token counts, and Pricing Check reads ok. Ledger 18 holds AI Response, the "
        "inputs and `Call row:` with the call row's record ID, and no token counts. Route 1 creates the lead at Pending Call with "
        "an E.164 phone, so Batch Outbound Caller 3953105 must stay inactive (checklist A.5 guard), or it would dial the lead. "
        "Set the lead neutral afterwards. If the stamps come back blank, Rizwan opens call row {row81} "
        "in the Make UI, saves it with no mapping change, and Claude re-pulls.")),
    3974513: ("submission-letter", [], (
        "[STATUS] On a TEST Applicant only, with synthetic Case Facts and Name (never a real lead): set Status Generate "
        "Submission (trigger 1 watches `{{Status}} = 'Generate Submission'`, see specs/X-15-submission-letter.md), then Run once "
        "with Choose where to start on that record. Expected: call row {row25} right after Claude 25 with Prompt Version {tag25}, "
        "Model Served claude-opus-5-5, Stop Reason end_turn, both token counts and Pricing Check ok. Ledger 5 has no token "
        "counts. Submission Letter writes no Status, so reset the TEST Applicant's Status to a neutral value afterwards, or the "
        "next poll picks it up again.")),
    3921613: ("market-watchdog", [56], (
        "Guards as in checklist A.5: Campaign Launcher 3961751 stays inactive, save no edit in the editor, delete the test Intel "
        "and Campaigns Draft rows afterwards and never set a Draft row to Active. On the RSS module, Choose where to start, the "
        "newest article, Run once (no client data). Expected: call row {row79} right after Claude 79 with Prompt Version {tag79} "
        "and both token counts. The route's row 16, 23 or 24 keeps AI Response, the inputs and `Call row:`, with no token counts.")),
    5091060: ("auto-celebrate", [58], (
        "[PAID] HeyGen render, with line 58's guard, never Run once on the live trigger (it renders and emails every real "
        "Approved Files row). Prereq: the TEST Files record with Client Name `TEST-B6`, File Status Approved, Approval Video Sent "
        "unchecked, Related Applicant a TEST Applicant whose Email is your inbox. As a draft, set trigger 1 to "
        "`AND({{File Status}} = \"Approved\", NOT({{Approval Video Sent}}), FIND(\"TEST-B6\", {{Client Name}}))`, Run once, then "
        "discard the draft and Claude re-pulls. Expected: call row {row119} right after Claude 119 with Prompt Version {tag119} "
        "and both token counts. Row 32 (or 124 if the render is not ready) has no token counts and carries `Call row:`. Waits "
        "for Rizwan's go-ahead on the render cost.")),
    3975156: ("grader", [100], (
        "[BLAND][PAID] Waits for Bland credit (the grader runs on a Bland post-call webhook). Expected on the TEST mock interview "
        "of line 100: call row {row82} right after Claude 82 with Prompt Version {tag82}, Model Served claude-opus-5-5 and both "
        "token counts. Row 9 has no token counts and carries `Call row:`.")),
    3954492: ("support-bot", [53, 54], (
        "Guards G1 to G3 of the checklist: draft query `subject:(\"TEST-X41.16\") -from:me`, Choose where to start From now "
        "on before each send, delete the test entry in Incomplete executions after every run, and restore the query and start "
        "point (discard the draft) before the re-pull. Subject for both emails: `TEST-X41.16 any update on my application`. "
        "Run 1, status: the TEST Files record at File Status Processing (so route 0 and Claude 135 run, never the paid HeyGen "
        "route 1 with Claude 138), Client Email your test inbox, Related Applicant the TEST lead, no other Files row on that "
        "address. Expected: call row {row132} after Claude 132 and call row {row135} after Claude 135, each with its own Prompt "
        "Version ({tag132}, {tag135}), and ledger 18 with no token counts and `Call rows:`. Run 2, a sales pitch from the same "
        "inbox with the subject `TEST-X41.16 partnership proposal` (it still matches G1, and nothing in it asks for a status): only call row {row132} is written (this call went unpriced before), no reply, no other ledger row. Route 1 "
        "and call row {row138} need a [PAID] HeyGen run (line 61) and wait for Rizwan's go-ahead.")),
    3943741: ("pending-call", [70, 81], (
        "[BLAND][PAID][STATUS] Waits for Bland credit (Pending Call runs on the Bland pathway webhook). Expected on the TEST lead "
        "of lines 70 and 81: call row {row172} right after Claude 172, then marker 125 unchanged, and call row {row176} right after "
        "Claude 176. If 176 fails under its Resume, its call row still runs with Execution Status Error and Stop Reason no "
        "response, and email 180 still goes out. Rows 81, 83, 136 and 184 have no token counts and carry `Call row:`. Routers "
        "10 and 146 behave as before.")),
}


class BuildError(Exception):
    pass


def _walk(flow: list):
    """(module, flow list, index, in_error) for every module."""
    for i, m in enumerate(flow if isinstance(flow, list) else []):
        if not isinstance(m, dict):
            continue
        yield m, flow, i, False
        for r in m.get("routes") or []:
            for x in _walk(r.get("flow") if isinstance(r, dict) else []):
                yield x
        for x, f, j, _e in _walk(m.get("onerror") or []):
            yield x, f, j, True


def _ledger_template(bp: dict, links: ab.AirtableMap) -> dict:
    """The scenario's first System Logs create outside error routes: base, connection, module version, expect and restore."""
    for m, _f, _i, err in _walk(bp.get("flow")):
        if not err and m.get("module") == "airtable:ActionCreateRecord" and ab._is_ledger_write_any(m, links):
            return m
    raise BuildError("the scenario has no System Logs create to copy the connection and metadata from")


def _field_spec(links: ab.AirtableMap, stamps: dict) -> list[dict]:
    names = links.tables[ab.LEDGER_TABLE]["fields"]
    return [{"name": fid, "type": "number" if role in NUMBER_ROLES else "text", "label": names[fid]}
            for role, fid in stamps.items()]


def _with_stamp_spec(meta: dict, extra: list[dict]) -> dict:
    """metadata of the template with the stamp fields added to the record spec of expect and restore, interface dropped
    (Make fills a new module's interface when the module is next opened)."""
    meta = copy.deepcopy(meta)
    meta.pop("interface", None)
    for e in meta.get("expect") or []:
        if isinstance(e, dict) and e.get("name") == "record" and isinstance(e.get("spec"), list):
            have = {s.get("name") for s in e["spec"] if isinstance(s, dict)}
            e["spec"].extend(copy.deepcopy(s) for s in extra if s["name"] not in have)
    nested = (((meta.get("restore") or {}).get("expect") or {}).get("table") or {}).get("nested")
    for e in nested or []:
        if isinstance(e, dict) and e.get("name") == "record" and isinstance(e.get("spec"), list):
            have = {s.get("name") for s in e["spec"] if isinstance(s, dict)}
            e["spec"].extend(copy.deepcopy(s) for s in extra if s["name"] not in have)
    return meta


def _logger_copy(n_mod: dict, logger: ab.LoggerSpec, row_id: int, new_id: int) -> dict:
    calls = [x for x in n_mod.get("onerror") or [] if isinstance(x, dict) and ab.is_logger_call(x, logger)]
    if len(calls) != 1:
        raise BuildError(f"Claude module {n_mod.get('id')} has no single Logger call in its handler to copy")
    lg = copy.deepcopy(calls[0])
    lg["id"] = new_id
    for kv in (lg.get("mapper") or {}).get("urlEncodedBodyContent") or []:
        name = kv.get("name")
        if name == "module_id":
            kv["value"] = str(row_id)
        elif name == "module_name":
            kv["value"] = f"Call row of Claude {n_mod.get('id')}"
        elif name == "error_type":
            kv["value"] = "{{%d.error.type}}" % row_id
        elif name == "error_message":
            kv["value"] = "{{%d.error.message}}" % row_id
    return lg


def _designer(m: dict, dx: int, dy: int) -> dict:
    d = ((m.get("metadata") or {}).get("designer") or {})
    return {"x": int(d.get("x", 0)) + dx, "y": int(d.get("y", 0)) + dy}


def _link_for(bp: dict, n: int, chain: tuple, links: ab.AirtableMap, by_id: dict) -> object | None:
    """The Applicant Link an outcome row of N already maps, when it is a record ID form R4b accepts from modules before N."""
    before = ab._before_ids(chain)
    for m, _f, _i, _err in _walk(bp.get("flow")):
        if ab._is_ledger_write_any(m, links) and ab.LEAD_LINK_FIELD in ab._record(m) and ab._uses_usage(m, n):
            v = ab._record(m)[ab.LEAD_LINK_FIELD]
            if ab._link_value_problem(v, by_id, before, n, links) is None:
                return copy.deepcopy(v)
    return None


_COPY_START = re.compile(r"\s*(system|prompt\s*1)\s*:", re.I)
_MAPPING = re.compile(r"\{\{.*?\}\}", re.S)


def _mappings(v: object) -> list[str]:
    """The {{...}} mappings of a value, in order, without repeats."""
    return list(dict.fromkeys(m for s in ab._strings(v) for m in _MAPPING.findall(s)))


def _inputs_payload(calls: list[tuple[int, dict]], kept: list[str]) -> str:
    """AI prompt / Payload with the prompt text removed: only mappings the old payload already held (kept), laid out as the
    registered template's user message where every mapping of it was held, and as plain inputs otherwise. Never adds a
    mapping the row did not map before, so no client field reaches a row that did not hold it (hard rule 5)."""
    left = list(kept)
    parts = []
    for n, reg in calls:
        t = reg["template"]
        users = " ".join(m.get("content") for m in t.get("messages") or []
                         if isinstance(m, dict) and m.get("role") == "user" and isinstance(m.get("content"), str))
        system = t.get("system") if isinstance(t.get("system"), str) else ""
        piece = []
        user_maps = _mappings(users)
        if user_maps and all(x in left for x in user_maps):
            piece.append(f"User: [{users}]")
            left = [x for x in left if x not in user_maps]
        sys_maps = [x for x in _mappings(system) if x in left]
        if sys_maps:
            piece.append(f"System inputs: [{' | '.join(sys_maps)}]")
            left = [x for x in left if x not in sys_maps]
        if piece:
            parts.append(" ".join(piece) if len(calls) == 1 else f"Call {n} " + " ".join(piece))
    if left:
        parts.append(f"Inputs: [{' | '.join(left)}]")
    return "  ".join(parts)


def _free_spot(taken: list[tuple[int, int]], x: int, y: int) -> tuple[int, int]:
    """The first position at or below (x, y), in 150 px steps, at least 120 px from every placed module."""
    while any(abs(x - a) < 120 and abs(y - b) < 120 for a, b in taken):
        y += 150
    taken.append((x, y))
    return x, y


def build(bp: dict, sid: int, id_sequence: int, prompts: pr.Registry, labels: ab.Labels, links: ab.AirtableMap,
          logger: ab.LoggerSpec) -> tuple[dict, dict]:
    cand = copy.deepcopy(bp)
    stamps = ab._stamp_map(links)
    if stamps is None:
        raise BuildError("audit/airtable_links.json pins no System Logs stamp_fields")
    entry = labels.scenarios.get(str(sid)) or {}
    label = str(entry.get("expected_label") or "").strip()
    if not label:
        raise BuildError(f"scenario {sid} has no confirmed label in audit/scenario_labels.json")
    tmpl = _ledger_template(cand, links)
    extra = _field_spec(links, stamps)
    # Pass 1 on the unchanged candidate: every decision that reads positions (chains, links) is made before any insert.
    order = list(ab.walk(cand.get("flow") or []))
    by_id = {m.get("id"): m for m, _e, _c in order}
    taken = [(int(((m.get("metadata") or {}).get("designer") or {}).get("x", 0)),
              int(((m.get("metadata") or {}).get("designer") or {}).get("y", 0))) for m, _e, _c in order]
    plans = []
    nxt = id_sequence + 1
    for n_mod, err, chain in order:
        if n_mod.get("module") != pr.CLAUDE_MODULE or err:
            continue
        n = n_mod.get("id")
        bound = prompts.bindings.get((str(sid), n))
        if bound is None:
            raise BuildError(f"Claude module {n} has no binding in ref/prompt_bindings.json (check R1)")
        reg = prompts.versions[bound]
        if pr.template_sha256(n_mod.get("mapper") or {}) != reg["template_sha256"]:
            raise BuildError(f"Claude module {n} does not match {pr.stamp(*bound)} (check R2). Register the template first")
        flow, i = chain[-1]
        nxt_mod = flow[i + 1] if i + 1 < len(flow) else None
        if isinstance(nxt_mod, dict) and ab._is_ledger_write_any(nxt_mod, links) \
                and any(ab._ledger_key(links, k) in set(stamps.values()) for k in ab._record(nxt_mod)):
            raise BuildError(f"Claude module {n} already has a call row ({nxt_mod.get('id')}). Build from a snapshot without one")
        plans.append((n_mod, flow, bound, reg, _link_for(bp, n, chain, links, by_id), nxt))
        nxt += 3
    rows = []
    for n_mod, flow, bound, reg, link, row_id in plans:
        n = n_mod.get("id")
        directives = ab._handler_parts(n_mod.get("onerror") or [])[2]
        resume = directives == ["Resume"]
        lg_id, rs_id = row_id + 1, row_id + 2
        rec = {
            ab.LABEL_FIELD: label,
            ab.OUTCOME_FIELD: '{{if(%d.id; "Success"; "Error")}}' % n if resume else "Success",
            ab.TOKEN_IN_FIELD: "{{%d.usage.input_tokens}}" % n,
            ab.TOKEN_OUT_FIELD: "{{%d.usage.output_tokens}}" % n,
            stamps["prompt_version"]: pr.stamp(*bound),
            stamps["prompt_sha256"]: reg["template_sha256"],
            stamps["model_requested"]: reg["model"],
            stamps["model_served"]: "{{%d.model}}" % n,
            stamps["stop_reason"]: '{{ifempty(%d.stop_reason; "no response")}}' % n if resume else "{{%d.stop_reason}}" % n,
            stamps["message_id"]: "{{%d.id}}" % n,
            stamps["execution_id"]: "{{var.scenario.executionId}}",
            stamps["inference_geo"]: "{{%d.usage.inference_geo}}" % n,
            stamps["cache_write_tokens"]: "{{%d.usage.cache_creation_input_tokens}}" % n,
            stamps["cache_read_tokens"]: "{{%d.usage.cache_read_input_tokens}}" % n,
        }
        if link is not None:
            rec[ab.LEAD_LINK_FIELD] = link
        d = ((n_mod.get("metadata") or {}).get("designer") or {})
        nx, ny = int(d.get("x", 0)), int(d.get("y", 0))
        rx, ry = _free_spot(taken, nx + 150, ny + 150)
        lg = _logger_copy(n_mod, logger, row_id, lg_id)
        lx, ly = _free_spot(taken, rx, ry + 300)
        lg.setdefault("metadata", {})["designer"] = {"x": lx, "y": ly}
        sx, sy = _free_spot(taken, lx + 300, ly)
        resume_mod = {"id": rs_id, "module": "builtin:Resume", "version": 1, "mapper": {},
                      "metadata": {"designer": {"x": sx, "y": sy}}}
        meta = _with_stamp_spec(tmpl.get("metadata") or {}, extra)
        meta["designer"] = {"x": rx, "y": ry}
        row = {"id": row_id, "module": "airtable:ActionCreateRecord", "version": tmpl.get("version", 3),
               "parameters": copy.deepcopy(tmpl.get("parameters") or {}),
               "mapper": {"base": tmpl["mapper"]["base"], "table": ab.LEDGER_TABLE, "record": rec, "typecast": False,
                          "useColumnId": tmpl["mapper"].get("useColumnId", True)},
               "metadata": meta, "onerror": [lg, resume_mod]}
        flow.insert(flow.index(n_mod) + 1, row)   # the index now, after any earlier insert in the same flow list
        rows.append({"claude": n, "call_row": row_id, "logger": lg_id, "resume": rs_id, "stamp": pr.stamp(*bound),
                     "sha256": reg["template_sha256"], "model": reg["model"], "resume_owner": resume,
                     "directive": "/".join(directives) or "none", "applicant_link": link})
    row_of = {r["claude"]: r["call_row"] for r in rows}
    wins = ab._system_windows(prompts)
    by_stage: dict = {}
    for (bsid, bmid), b in prompts.bindings.items():
        if bsid == str(sid):
            by_stage.setdefault(b[0], []).append((bmid, prompts.versions[b]))
    outcome = []
    for m, _f, _i, _err in _walk(cand.get("flow")):
        if m.get("id") in row_of.values() or not ab._is_ledger_write_any(m, links):
            continue
        rec = (m.get("mapper") or {}).get("record")
        if not isinstance(rec, dict):
            continue
        calls_used = [n for n in row_of if ab._uses_usage(m, n)]
        dropped = []
        for k in list(rec):
            if ab._ledger_key(links, k) in (ab.TOKEN_IN_FIELD, ab.TOKEN_OUT_FIELD):
                dropped.append(links.field_label(ab.LEDGER_TABLE, ab._ledger_key(links, k)))
                del rec[k]
        copied, old = None, None
        for k in list(rec):
            v = rec[k]
            hit = set()
            for piece in ab._literal_pieces(v):
                for j in range(0, len(piece) - ab.R6_MIN_RUN + 1):
                    hit |= wins.get(piece[j:j + ab.R6_MIN_RUN], set())
            stale = (ab._ledger_key(links, k) == PAYLOAD_FIELD and dropped and isinstance(v, str) and _COPY_START.match(v)
                     and any(len(p) >= ab.R6_MIN_RUN for p in ab._literal_pieces(v)))
            if hit and ab._ledger_key(links, k) != PAYLOAD_FIELD:
                raise BuildError(f"module {m.get('id')} holds a prompt copy in {k}, not in AI prompt / Payload. Edit it by hand")
            if hit or stale:
                calls = sorted({c[0]: c for st in hit for c in by_stage.get(st, [])}.values(), key=lambda c: c[0])
                old = v
                rec[k] = _inputs_payload(calls, _mappings(v))
                copied = sorted(hit) or ["an unregistered prompt"]
        if not (dropped or copied):
            continue
        if dropped and not calls_used:
            raise BuildError(f"module {m.get('id')} writes tokens that reach it through another module, so its call row cannot "
                             f"be named. Edit it by hand")
        if dropped:
            # Joins the outcome row to the call row that now carries its call's tokens and stamps.
            pointer = ("Call row: " if len(calls_used) == 1 else "Call rows: ") + " ".join("{{%d.id}}" % row_of[n] for n in calls_used)
            key = next((k for k in rec if ab._ledger_key(links, k) == PAYLOAD_FIELD), PAYLOAD_FIELD)
            cur = rec.get(key)
            if old is None:
                old = cur
            rec[key] = (cur.rstrip() + " " + pointer) if isinstance(cur, str) and cur.strip() else pointer
        outcome.append({"module": m.get("id"), "dropped": dropped, "payload_rewritten_from": copied,
                        "old_mappings": _mappings(old) if old is not None else [],
                        "payload": rec.get(next((k for k in rec if ab._ledger_key(links, k) == PAYLOAD_FIELD), PAYLOAD_FIELD))})
        added_maps = [x for x in _mappings(outcome[-1]["payload"]) if x not in outcome[-1]["old_mappings"]
                      and not re.fullmatch(r"\{\{(%s)\.id\}\}" % "|".join(str(r) for r in row_of.values()), x)]
        if added_maps:
            raise BuildError(f"module {m.get('id')}: the payload would gain {added_maps}, which it did not map before")
    return cand, {"scenario": sid, "name": bp.get("name"), "label": label, "id_sequence": id_sequence, "call_rows": rows,
                  "outcome_rows": outcome}


def check(live: dict, cand: dict, sid: int, plan: dict, links: ab.AirtableMap) -> dict:
    """make_push's local guards and audit comparison, the checks a dry run makes before it reads Make."""
    labels = ab.load_labels(os.path.join(REPO, "audit", "scenario_labels.json"))
    schema = ab.load_schema(os.path.join(REPO, "audit", "airtable_ledger_schema.json"))
    allowlist = ab.load_allowlist(os.path.join(REPO, "audit", "allowlist.json"))
    webhooks = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True)
    sal = secret_scan.load_secret_allowlist(secret_scan.DEFAULT_SECRET_ALLOWLIST, ab.DEFAULT_WEBHOOKS)
    hooks = ab.load_hooks_info(os.path.join(REPO, "blueprints", "manifest.json"))
    sd = ab.load_status_designs(os.path.join(REPO, "audit", "status_allow_list.json"))
    bland = ab.load_bland_agents(os.path.join(REPO, "audit", "bland_agents.json"), required=True)
    prompts = ab.load_prompts()
    diff = mp.diff_modules(live, cand)
    status_touched = mp.check_status_writes(FIX, cand, diff, links, live)
    mp.check_interfaces_unchanged(live, cand)
    mp.check_trigger_type(live, cand)
    mp.check_top_level(live, cand)
    blocking, _allowed = secret_scan.split_findings(cand, sid, sal)
    if blocking:
        raise BuildError(f"the candidate has {len(blocking)} secret finding(s), so it is not written")
    low = [i for i in diff.added if i <= plan["id_sequence"]]
    if low:
        raise BuildError(f"new module IDs {low} are at or below idSequence {plan['id_sequence']}")
    d = mp.compare_audits(live, cand, sid, live.get("name", ""), labels, schema, None, links, allowlist, webhooks, hooks, sal,
                          touched=diff.touched, status_designs=sd, bland_agents=bland, prompts=prompts)
    targets = sorted({("R", k[1]) for k in d.closed if k[0] == "R" and k[2] == ab.FAIL}, key=lambda t: int(t[1]))
    mp.check_targets(FIX, targets, d, set(diff.touched))
    if d.new_fails:
        raise BuildError("the candidate adds FAILs: " + "; ".join(f"{k[0]} {k[1]} {k[3][:160]}" for k in d.new_fails))
    if any(k[0] == "R" for k in d.remaining_fails):
        raise BuildError("check R still FAILs on the candidate: " + ", ".join(f"R:{k[1]}" for k in sorted(d.remaining_fails)))
    return {"added": sorted(diff.added), "changed": sorted(diff.changed), "removed": sorted(diff.removed),
            "status_touched": sorted(status_touched or []), "fails_before": d.fails_before, "fails_after": d.fails_after,
            "closes": [f"{t[0]}:{t[1]}" for t in targets],
            "closed_other": sorted(f"{k[2]} {k[0]}:{k[1]}" for k in d.closed if k[0] != "R" and k[2] != ab.PASS),
            "new_other": sorted(f"{k[2]} {k[0]}:{k[1]} {_cut(k[3])}" for k in d.new_other)}


def _cut(text: str, n: int = 200) -> str:
    """text cut at a word boundary near n characters."""
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " (cut)"


def _fence(value: object) -> list[str]:
    """A value in a fenced block, so pipes, backticks and newlines in a mapping cannot break the markdown."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return ["```text", text, "```"]


def spec_text(plan: dict, result: dict, base_version: int, slug: str, checklist: list[int], test_plan: str) -> str:
    sid, rows = plan["scenario"], plan["call_rows"]
    fmt = {f"row{r['claude']}": r["call_row"] for r in rows} | {f"tag{r['claude']}": r["stamp"] for r in rows}
    modules = ",".join(str(i) for i in sorted(set(result["added"]) | set(result["changed"])))
    lines = [f"# X-36.2 call rows: {plan['name']} ({sid})", "",
             f"Fix ID X-36.2, check R (rules R4a, R4b, R6). Design: `specs/X-36.2-call-rows.md` (decided by Rizwan 2026-11-13). "
             f"Built by `scripts/call_rows.py` from the snapshot pulled 2026-11-14 (live version {base_version}, idSequence "
             f"{plan['id_sequence']}). Rebuild it if either has moved by push time.", "",
             "## Call rows", "",
             "Each is an `airtable:ActionCreateRecord` on System Logs (`tblf73Cdii3CsLKfL`), inserted right after its Claude module "
             "in the same flow list, with no filter, typecast off and the scenario's own Airtable connection. Its handler is a copy "
             "of the Claude module's own Logger call (module_id and module_name name the call row) followed by Resume, so a failed "
             "stamp write logs one Error row and the flow continues.", "",
             "| Claude module | Call row | Logger call | Resume | Prompt Version | Model Requested | Owner directive | Applicant Link |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['claude']} | {r['call_row']} | {r['logger']} | {r['resume']} | `{r['stamp']}` | `{r['model']}` | "
                     f"{r['directive']} | {'below' if r['applicant_link'] is not None else 'not written'} |")
    lines += [""]
    for r in rows:
        lines += [f"Call row {r['call_row']}: Prompt SHA256 `{r['sha256']}`."]
        if r["applicant_link"] is not None:
            lines += ["", f"Applicant Link of call row {r['call_row']} (the form its outcome rows already map):", ""]
            lines += _fence(r["applicant_link"])
        lines += [""]
    lines += [f"Record of every call row (label literal `{plan['label']}`). N is the Claude module:", "",
              "| Field | Value |", "|---|---|",
              "| Scenario name | the label above, literal |",
              "| Execution Status | `Success`, or `{{if(N.id; \"Success\"; \"Error\")}}` when the Claude module's directive is Resume |",
              "| Input Tokens, Output Tokens | `{{N.usage.input_tokens}}`, `{{N.usage.output_tokens}}` |",
              "| Prompt Version, Prompt SHA256, Model Requested | the literals above |",
              "| Model Served | `{{N.model}}` |",
              "| Stop Reason | `{{N.stop_reason}}`, or `{{ifempty(N.stop_reason; \"no response\")}}` when the directive is Resume |",
              "| Message ID | `{{N.id}}` |",
              "| Execution ID | `{{var.scenario.executionId}}` |",
              "| Inference Geo | `{{N.usage.inference_geo}}` |",
              "| Cache Write Tokens, Cache Read Tokens | `{{N.usage.cache_creation_input_tokens}}`, `{{N.usage.cache_read_input_tokens}}` |",
              "", "Its `metadata.expect` and `metadata.restore` are copied from the scenario's first System Logs create with the "
              "ten stamp fields added to the record spec (text, the two cache counts number), and no interface. Designer positions "
              "are free spots below the Claude module.", "",
              "## Outcome rows", ""]
    if plan["outcome_rows"]:
        lines += ["Each drops Input Tokens and Output Tokens and gains `Call row:` with its call row's record ID in AI prompt / "
                  "Payload, so the outcome joins its call. A row that held a hand copy of a prompt keeps only the mappings it "
                  "already held, without the prompt text (decision 5). No row gains a client field it did not map before, which "
                  "the builder refuses. Every other key, the filter, the handler and the position stay as they are.", "",
                  "| Module | Drops | Prompt copy removed |", "|---|---|---|"]
        for o in plan["outcome_rows"]:
            lines.append(f"| {o['module']} | {', '.join(o['dropped']) or 'nothing'} | "
                         f"{', '.join(o['payload_rewritten_from']) if o['payload_rewritten_from'] else 'none'} |")
        lines += ["", "AI prompt / Payload after the push:", ""]
        for o in plan["outcome_rows"]:
            lines += [f"Module {o['module']}:", ""] + _fence(o["payload"]) + [""]
    else:
        lines.append("None.")
        lines.append("")
    routers = [i for i in result["changed"] if i not in {o["module"] for o in plan["outcome_rows"]}]
    if routers:
        lines += [f"Also changed: {', '.join(str(i) for i in routers)}, only because a call row now sits in their route "
                  "(their child lists change, nothing else).", ""]
    lines += ["## Push", "", "```bash",
              f"python scripts/make_push.py --scenario {sid} --candidate <candidate outside the repo> --fix X-36.2 --modules {modules} "
              f"--base-version {base_version} --closes {','.join(result['closes'])}", "```", "",
              f"Dry run first, then `--apply`. Expected: check R FAIL {result['fails_before']} to {result['fails_after']} on this "
              f"scenario, no new FAIL, no lead Status write touched, the scenario stays inactive. Added modules: "
              f"{', '.join(str(i) for i in result['added'])}. Changed: {', '.join(str(i) for i in result['changed'])}."]
    if result["new_other"]:
        lines += ["", "New non-FAIL rows on the candidate (text changes only):", ""] + [f"- {x}" for x in result["new_other"]]
    lines += ["", "## Test plan (test records only, Rizwan in the Make UI)", "", test_plan.format(**fmt), ""]
    if checklist:
        word = "line" if len(checklist) == 1 else "lines"
        lines += [f"The push changes the expected results of `docs/IMMIOS_TEST_CHECKLIST.md` {word} {', '.join(str(c) for c in checklist)} "
                  "(token counts move from the outcome rows to the call rows). Those lines are updated in the push commit.", ""]
    lines += ["Claude reads back only the stamp fields, Execution Status and token counts of the new call rows, by record ID with "
              "fields[] (hard rule 5). The fix is done when a fresh pull shows R FAIL 0 on this scenario (hard rule 6).", ""]
    return "\n".join(lines)


def _inside_repo(path: str) -> bool:
    """True when path is the repo or under it, in any letter case, through a link or an extended-length prefix. A path whose
    place the check cannot tell (a UNC share) counts as inside, so the candidate is never written into the repo by accident."""
    def norm(x: str) -> str:
        x = os.path.normcase(os.path.realpath(x))
        return x[4:] if x.startswith(EXTENDED_PREFIX) else x
    o, r = norm(path), norm(REPO)
    try:
        return os.path.commonpath([o, r]) == r
    except ValueError:
        return o.startswith(UNC_PREFIX)


EXTENDED_PREFIX = "\\\\?\\"   # the four characters backslash backslash ? backslash
UNC_PREFIX = "\\\\"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scenario", type=int, required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--id-sequence", type=int, required=True, help="live idSequence of the scenario")
    ap.add_argument("--base-version", type=int, required=True, help="live version the candidate is based on")
    ap.add_argument("--out", required=True, help="folder for the candidate and plan, outside the repo")
    ap.add_argument("--write-spec", action="store_true", help="write specs/X-36.2-<slug>.md")
    args = ap.parse_args(argv)
    out = os.path.abspath(args.out)
    if _inside_repo(out):
        print("--out must be outside the repo (a candidate is never committed)", file=sys.stderr)
        return 2
    try:
        links = ab.load_links(ab.DEFAULT_LINKS, required=True)
        prompts = ab.load_prompts()
        labels = ab.load_labels(os.path.join(REPO, "audit", "scenario_labels.json"))
        logger = ab.load_webhooks(ab.DEFAULT_WEBHOOKS, required=True).logger
        snap = mp.find_snapshot(os.path.join(REPO, "blueprints"), args.scenario)
        live = json.load(open(snap, encoding="utf-8"))
        cand, plan = build(live, args.scenario, args.id_sequence, prompts, labels, links, logger)
        result = check(live, cand, args.scenario, plan, links)
    except (BuildError, mp.Abort, ab.InputError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    os.makedirs(out, exist_ok=True)
    slug, checklist, test_plan = SCENARIOS[args.scenario]
    with open(os.path.join(out, f"X-36.2-{slug}.candidate.json"), "w", encoding="utf-8") as f:
        json.dump(cand, f, indent=2, ensure_ascii=False)
    with open(os.path.join(out, f"X-36.2-{slug}.plan.json"), "w", encoding="utf-8") as f:
        json.dump({"plan": plan, "check": result, "base_version": args.base_version}, f, indent=2, ensure_ascii=False)
    if args.write_spec:
        with open(os.path.join(REPO, "specs", f"X-36.2-{slug}.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(spec_text(plan, result, args.base_version, slug, checklist, test_plan))
    print(f"{args.scenario} {plan['name']}: call rows {[(r['claude'], r['call_row']) for r in plan['call_rows']]}, "
          f"R FAIL {result['fails_before']} -> {result['fails_after']}, --modules "
          f"{','.join(str(i) for i in sorted(set(result['added']) | set(result['changed'])))} --closes {','.join(result['closes'])}")
    for x in result["new_other"]:
        print("  new", x[:160])
    return 0


if __name__ == "__main__":
    sys.exit(main())
