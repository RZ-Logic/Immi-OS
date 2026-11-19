#!/usr/bin/env python3
"""Create one inactive Make scenario from a committed blueprint (hard rule 2).

Usage:
  python scripts/make_create.py --blueprint specs/logger.blueprint.json --name Logger \
      --scheduling immediately [--folder-id 199043] [--apply]

Without --apply it is a dry run: every check runs and nothing is sent.

Guards, each a hard abort:
  - the blueprint is under specs/, ends in .blueprint.json, is tracked by git and equals HEAD
  - it scans clean for secrets (scripts/secret_scan.py). A Logger call's URL is written as the placeholder
    __IMMIOS_LOGGER_URL__ in the spec (so the hook URL never sits in specs/), and is filled in memory from a committed
    snapshot whose Logger call URL hashes to the pinned Logger token (audit/secret_allowlist.json logger_hook). After that
    the only finding allowed is that URL as the bare mapper.url of a Logger call (secret_scan.split_findings)
  - no build placeholder (__NAME__, Make's own __IMT...__ names aside) is left in it after the Logger URL fill, except a
    call row's Prompt SHA256 (System Logs create, audit/airtable_links.json stamp_fields), which check R4b FAILs until the
    registered literal is pushed. A placeholder anywhere else (a test folder ID, say) would run as literal text and no
    audit row would name it
  - its first module is not a polling watch trigger (an active copy of an Airtable watch
    fires twice), unless --allow-watch-trigger is passed on Rizwan's say-so
  - no scenario in the team already has that name (never a copy)
  - the only write is POST /scenarios (write token), never confirmed=true, never activate or run
  - after the create, GET /scenarios/{id} must show isActive false, else an alarm
Reads use MAKE_API_TOKEN, the create uses MAKE_WRITE_TOKEN. Tokens are never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Callable

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import make_pull  # noqa: E402
import make_push  # noqa: E402
import secret_scan  # noqa: E402

ROOT = os.path.dirname(SCRIPT_DIR)
SPECS = os.path.join(ROOT, "specs")
DEFAULT_ENV = os.path.join(ROOT, ".env")
DEFAULT_RECORDS = os.path.join(ROOT, "audit", "pushes")

EXIT_OK, EXIT_ABORT, EXIT_CONFIG, EXIT_READ, EXIT_REJECTED, EXIT_ACTIVE = 0, 1, 2, 3, 4, 6
LOGGER_URL_PLACEHOLDER = "__IMMIOS_LOGGER_URL__"
BLUEPRINTS = os.path.join(ROOT, "blueprints")


class Abort(Exception):
    pass


def parse_scheduling(text: str) -> dict:
    if text == "immediately":
        return {"type": "immediately"}
    if text == "on-demand":
        return {"type": "on-demand"}
    if text.startswith("indefinitely:"):
        sec = text.split(":", 1)[1]
        if sec.isdigit() and 60 <= int(sec) <= 86400:
            return {"type": "indefinitely", "interval": int(sec)}
    raise argparse.ArgumentTypeError("scheduling is immediately, on-demand or indefinitely:<60-86400 seconds>")


def first_module(bp: dict) -> dict:
    flow = bp.get("flow")
    if not isinstance(flow, list) or not flow or not isinstance(flow[0], dict):
        raise Abort("the blueprint has no flow")
    return flow[0]


def _modules(flow: object):
    for m in flow if isinstance(flow, list) else []:
        if isinstance(m, dict):
            yield m
            for r in m.get("routes") or []:
                if isinstance(r, dict):
                    yield from _modules(r.get("flow"))
            yield from _modules(m.get("onerror"))


def resolve_logger_url(bp: dict, logger: "secret_scan.LoggerAllowance | None", snapshots: str) -> int:
    """Replace the placeholder URL of every Logger call in bp, in place, with the pinned Logger hook URL taken from a
    committed snapshot. Returns how many calls were filled. The URL is never returned, printed or written here."""
    calls = [m for m in _modules(bp.get("flow")) if (m.get("mapper") or {}).get("url") == LOGGER_URL_PLACEHOLDER]
    if not calls:
        return 0
    if logger is None or not logger.active:
        raise Abort("the blueprint has Logger calls but the Logger hook is not pinned and active "
                    "(audit/secret_allowlist.json logger_hook, audit/webhooks.json)")
    if any(not secret_scan.is_logger_call_module(m) for m in calls):
        raise Abort("the Logger URL placeholder may only sit in the url of a Logger call (http:MakeRequest, POST, API key keychain)")
    url = None
    for name in sorted(os.listdir(snapshots)) if os.path.isdir(snapshots) else []:
        if not name.endswith(".json") or name == "manifest.json":
            continue
        try:
            with open(os.path.join(snapshots, name), encoding="utf-8") as fh:
                snap = json.load(fh)
        except (OSError, ValueError):
            continue
        for m in _modules(snap.get("flow") if isinstance(snap, dict) else None):
            value = (m.get("mapper") or {}).get("url")
            if secret_scan.is_logger_call_module(m) and secret_scan.logger_url_matches(value, logger):
                url = value
                break
        if url:
            break
    if not url:
        raise Abort("no committed snapshot holds a Logger call whose URL matches the pinned Logger token")
    for m in calls:
        m["mapper"]["url"] = url
    return len(calls)


PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*__")
LEDGER_TABLE = "tblf73Cdii3CsLKfL"


def _outside_mappings(text: str) -> str:
    """text with every {{ ... }} cut out, so a Make name such as {{3.__IMTLENGTH__}} is not read as a placeholder."""
    return re.sub(r"\{\{.*?\}\}", " ", text, flags=re.S)


def sha_stamp_keys(links_path: str) -> set:
    """The record keys of the Prompt SHA256 stamp of a System Logs call row: its field ID and name from the links map."""
    try:
        with open(links_path, encoding="utf-8") as fh:
            table = (json.load(fh).get("tables") or {}).get(LEDGER_TABLE) or {}
    except (OSError, ValueError) as exc:
        raise Abort(f"cannot read the Airtable field map {links_path}: {exc}")
    fid = (table.get("stamp_fields") or {}).get("prompt_sha256")
    if not isinstance(fid, str) or not fid:
        raise Abort("the Airtable field map names no System Logs prompt_sha256 stamp field")
    name = (table.get("fields") or {}).get(fid)
    return {fid} | ({name.strip().casefold()} if isinstance(name, str) else set())


def leftover_placeholders(bp: dict, sha_keys: set) -> list[str]:
    """Where a build placeholder is left in bp (module ID and path), skipping Make's __IMT names and the one allowed
    place, the whole value of a call row's Prompt SHA256 stamp."""
    out: list[str] = []

    def scan(v: object, path: str, mid: object) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                if k in ("routes", "onerror") and path == "":
                    continue
                scan(x, f"{path}.{k}" if path else str(k), mid)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                scan(x, f"{path}[{i}]", mid)
        elif isinstance(v, str):
            names = [n for n in PLACEHOLDER.findall(_outside_mappings(v)) if not n.startswith("__IMT")]
            if names:
                out.append(f"module {mid} {path} ({', '.join(sorted(set(names)))})")

    for m in _modules(bp.get("flow")):
        mapper = m.get("mapper") if isinstance(m.get("mapper"), dict) else {}
        record = mapper.get("record") if isinstance(mapper.get("record"), dict) else {}
        allowed = None
        if (m.get("module") == "airtable:ActionCreateRecord" and str(mapper.get("table", "")).strip() == LEDGER_TABLE):
            allowed = {k for k, v in record.items() if isinstance(v, str) and PLACEHOLDER.fullmatch(v.strip())
                       and (k in sha_keys or str(k).strip().casefold() in sha_keys)}
        rest = {k: v for k, v in m.items() if k not in ("routes", "onerror")}
        if allowed:
            rest = dict(rest, mapper=dict(mapper, record={k: v for k, v in record.items() if k not in allowed}))
        scan(rest, "", m.get("id"))
    return out


def is_watch_trigger(module: dict) -> bool:
    name = str(module.get("module", ""))
    app_module = name.split(":", 1)[-1].lower()
    return app_module.startswith("triggerwatch") or app_module.startswith("watch")


class CreateTransport:
    """Allows GET /scenarios?teamId... (list, read token), GET /scenarios/{id} (post-check)
    and exactly one POST /scenarios with a body and no query. Refuses everything else."""

    def __init__(self, inner: Callable, base_url: str):
        parts = urllib.parse.urlsplit(base_url)
        self._inner, self._host = inner, parts.netloc
        self._root = f"{parts.path.rstrip('/')}/scenarios"
        self.posts = 0

    def check(self, method: str, url: str, body: bytes | None) -> None:
        p = urllib.parse.urlsplit(url)
        if p.scheme != "https" or p.netloc != self._host or p.fragment or "@" in p.netloc:
            raise make_push.TransportRefused(f"refused {method} {p.path}: wrong scheme or host")
        if method == "GET" and body is None:
            if p.path == self._root:
                return
            rest = p.path[len(self._root) + 1:] if p.path.startswith(self._root + "/") else ""
            if rest.isdigit() and not p.query:
                return
        if method == "POST" and body is not None and p.path == self._root and not p.query and self.posts == 0:
            self.posts += 1
            return
        raise make_push.TransportRefused(f"refused {method} {p.path}: only list, GET /scenarios/{{id}} and one "
                                         f"POST /scenarios are allowed")

    def __call__(self, method, url, headers, timeout, body=None):
        self.check(method, url, body)
        return self._inner(method, url, headers, timeout) if body is None else self._inner(method, url, headers, timeout, body)


def post_transport(method, url, headers, timeout, body=None):
    """POST through the no-redirect opener, reusing make_push's PATCH plumbing shape."""
    if method == "GET":
        return make_pull.urllib_transport(method, url, headers, timeout)
    if method != "POST":
        raise ValueError("make_create only issues GET and one POST")
    import urllib.request, urllib.error, http.client  # noqa: E401
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with make_pull._OPENER.open(req, timeout=timeout) as resp:
            return make_pull.Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read())
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read()
        except Exception:  # noqa: BLE001
            data = b""
        return make_pull.Response(exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, data)
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
        raise make_pull.TransientError(type(getattr(exc, "reason", exc)).__name__) from None


def main(argv: list[str] | None = None, transport: Callable | None = None, environ: dict | None = None,
         now: Callable[[], datetime] | None = None, git_state: Callable[[str], str | None] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Create one inactive Make scenario from a committed blueprint.")
    ap.add_argument("--blueprint", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--scheduling", required=True, type=parse_scheduling)
    ap.add_argument("--folder-id", type=int, default=None)
    ap.add_argument("--allow-watch-trigger", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--env", default=DEFAULT_ENV)
    ap.add_argument("--specs", default=SPECS)
    ap.add_argument("--records", default=DEFAULT_RECORDS)
    ap.add_argument("--secret-allowlist", default=os.path.join(ROOT, "audit", "secret_allowlist.json"))
    ap.add_argument("--snapshots", default=BLUEPRINTS)
    ap.add_argument("--links", default=os.path.join(ROOT, "audit", "airtable_links.json"))
    args = ap.parse_args(argv)
    now = now or (lambda: datetime.now(timezone.utc))
    git_state = git_state or make_push.git_snapshot_state
    out = lambda s: print(s)  # noqa: E731
    try:
        cfg = make_push.load_push_config(args.env, environ if environ is not None else dict(os.environ))
    except make_pull.ConfigError as exc:
        print(f"make_create: config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    tokens = (cfg.read.token, cfg.write.token)
    try:
        path = os.path.abspath(args.blueprint)
        if not (path.startswith(os.path.abspath(args.specs) + os.sep) and path.endswith(".blueprint.json")):
            raise Abort("the blueprint must be a specs/*.blueprint.json file")
        state = git_state(path)
        if state:
            raise Abort(f"the blueprint is not committed: {state}")
        with open(path, encoding="utf-8") as fh:
            bp = json.load(fh)
        if not isinstance(bp, dict) or set(bp) - {"name", "flow", "metadata"}:
            raise Abort("the blueprint must be export format (name, flow, metadata)")
        if secret_scan.scan_obj(bp):
            raise Abort("the committed blueprint holds secret-shaped values. Write a Logger call URL as "
                        f"{LOGGER_URL_PLACEHOLDER} and never commit a hook URL to specs/")
        allow = secret_scan.load_secret_allowlist(args.secret_allowlist) if args.secret_allowlist else secret_scan.SecretAllowlist()
        filled = resolve_logger_url(bp, allow.logger, args.snapshots)
        blocking, _allowed = secret_scan.split_findings(bp, None, [], allow.logger)
        if blocking:
            raise Abort("the blueprint holds secret-shaped values: " + ", ".join(sorted({f["pattern_type"] for f in blocking})))
        left = leftover_placeholders(bp, sha_stamp_keys(args.links))
        if left:
            raise Abort("the blueprint still holds build placeholders, which Make would run as literal text: " + "; ".join(left)
                        + ". Replace them in the committed blueprint (only a call row's Prompt SHA256 may wait for its push)")
        trig = first_module(bp)
        if is_watch_trigger(trig) and not args.allow_watch_trigger:
            raise Abort(f"the first module is a polling watch trigger ({trig.get('module')}). Pass --allow-watch-trigger "
                        f"only on Rizwan's say-so for this scenario")
        bp = dict(bp, name=args.name)
        inner = transport or post_transport
        guarded = CreateTransport(inner, cfg.read.base_url)
        reader = make_pull.MakeClient(cfg.read, guarded)
        existing = make_pull.list_scenarios(reader, cfg.read.team_id)
        if any(str(s.get("name", "")).strip().casefold() == args.name.strip().casefold() for s in existing):
            raise Abort(f"a scenario named {args.name!r} already exists in the team. make_create never makes copies")
        out(f"make_create: {'APPLY' if args.apply else 'DRY RUN'} create {args.name!r} from {os.path.relpath(path, ROOT)}")
        out(f"Checks passed: committed, secret scan clean ({filled} Logger call URL(s) filled from the pinned hook), "
            f"no build placeholder left, trigger {trig.get('module')}, name unused "
            f"({len(existing)} scenarios in the team), scheduling {json.dumps(args.scheduling)}.")
        if not args.apply:
            out("Dry run: nothing sent. Re-run with --apply to create the scenario inactive.")
            return EXIT_OK
        body = {"blueprint": json.dumps(bp, ensure_ascii=False), "teamId": int(cfg.read.team_id),
                "scheduling": json.dumps(args.scheduling)}
        if args.folder_id is not None:
            body["folderId"] = args.folder_id
        headers = {"Authorization": f"Token {cfg.write.token}", "Content-Type": "application/json",
                   "Accept": "application/json", "User-Agent": "immi-os-make-create/1.0"}
        resp = guarded("POST", f"{cfg.write.base_url}/scenarios", headers, 60, json.dumps(body).encode("utf-8"))
        if resp.status != 200:
            code = make_push.error_code(resp.body, tokens) or "none"
            detail = make_push.validation_detail(resp.body, tokens) if resp.status in (400, 422) else None
            print(f"make_create: create rejected, HTTP {resp.status} [{code}]. Nothing was created."
                  + (f" Make says: {detail}" if detail else ""), file=sys.stderr)
            return EXIT_REJECTED
        data = json.loads(resp.body.decode("utf-8"))
        sid = int(data["scenario"]["id"])
        st = reader.get_json(f"/scenarios/{sid}", [])
        active = (st.get("scenario") or {}).get("isActive")
        record = {"action": "create", "scenario_id": sid, "name": args.name, "blueprint": os.path.relpath(path, ROOT),
                  "scheduling": args.scheduling, "folder_id": args.folder_id, "is_active_after": active,
                  "created_at": now().isoformat(timespec="seconds")}
        os.makedirs(args.records, exist_ok=True)
        rec = os.path.join(args.records, f"{now().date().isoformat()}__CREATE__{sid}.json")
        with open(rec, "w", encoding="utf-8") as fh:
            fh.write(make_pull.render_json(record))
        if active is not False:
            print(f"make_create: ALARM scenario {sid} reports isActive={active}. Deactivate it in the Make UI now.", file=sys.stderr)
            return EXIT_ACTIVE
        out(f"Created scenario {sid} {args.name!r}, inactive. Record: {rec}")
        out("Next: pull, then Rizwan finishes the credential steps and activates it in the Make UI.")
        return EXIT_OK
    except Abort as exc:
        print(f"make_create: ABORT, nothing sent: {exc}", file=sys.stderr)
        return EXIT_ABORT
    except (make_pull.PullError, make_push.TransportRefused) as exc:
        print(f"make_create: {make_pull.redact(str(exc), cfg.read.token)}", file=sys.stderr)
        return EXIT_READ


if __name__ == "__main__":
    sys.exit(main())
