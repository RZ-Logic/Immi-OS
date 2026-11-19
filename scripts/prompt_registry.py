#!/usr/bin/env python3
"""The prompts registry (X-36.1): every Claude prompt Immi-OS runs, as immutable versions with a SHA-256.

Decided by Rizwan 2026-11-13:
  - The repo and a Supabase registry are the record of each prompt. Make keeps the text in its Claude module, and audit
    check R fails a module whose template is not the registered version its binding names. No scenario calls Supabase
    for a prompt at run time.
  - A version's hash covers the whole module mapper (model, max_tokens, thinking, output format, system and messages)
    exactly as written in the blueprint, mappings unfilled. It never hashes client data.
  - A registered version never changes or disappears. An edit is a new version.
  - Run-time stamps (requested and served model, stop reason, prompt version and hash, message ID) go to System Logs as
    X-36.2, and to the ff13 ledger for Module F.

Files, loaded into ref.prompts and ref.prompt_bindings by scripts/law_load:
  ref/prompts.json          {"prompts": [{stage, version, description, model, template, template_sha256, registered_on}]}
  ref/prompt_bindings.json  {"prompt_bindings": [{scenario_id, module_id, stage, version}]}

The run-time stamp for a version is "<stage>@<version>" (the ff13 ledger's prompt_version shape).

  python scripts/prompt_registry.py check              files, then every version against the commit that registered it
  python scripts/prompt_registry.py check --staged     the same history check on the staged file (the pre-commit hook)
  python scripts/prompt_registry.py register --scenario 3974513 --module 25 --stage submission-letter.draft \\
      --description "One sentence on what the prompt does" [--candidate <blueprint make_push will send>] [--no-bind]

register reads the committed snapshot blueprints/<slug>__<scenario>.json, or with --candidate the edited blueprint a
push will send. It reuses the stage's version that has this template (a revert included), or adds the next version,
and binds the module to it (with --no-bind it only registers or reuses, X-32). It never edits a version, and it writes
nothing that load() would refuse.

Standard library only.
"""

import argparse
import datetime as _dt
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PROMPTS = os.path.join(REPO_ROOT, "ref", "prompts.json")
DEFAULT_BINDINGS = os.path.join(REPO_ROOT, "ref", "prompt_bindings.json")
DEFAULT_BLUEPRINTS = os.path.join(REPO_ROOT, "blueprints")
CLAUDE_MODULE = "anthropic-claude:createAMessage"
STAGE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
JS_SAFE_INT = 2 ** 53 - 1
PROMPT_COLS = ("stage", "version", "description", "model", "template", "template_sha256", "registered_on")
BINDING_COLS = ("scenario_id", "module_id", "stage", "version")


class RegistryError(Exception):
    pass


def canonical(obj) -> str:
    """Sorted keys, no whitespace, UTF-8 text as is. scripts/law_load/load.mjs canonicalJson builds the same string for
    every template portable_problem() accepts."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def template_sha256(template: dict) -> str:
    # surrogatepass: a live mapper with a lone surrogate still hashes (check R then reports drift, since load() refuses to
    # register such a template) instead of crashing the audit.
    return hashlib.sha256(canonical(template).encode("utf-8", "surrogatepass")).hexdigest()


def stamp(stage: str, version: int) -> str:
    return f"{stage}@{version}"


def portable_problem(obj, path: str = "template") -> str | None:
    """Why scripts/law_load/load.mjs would hash this template differently, or None. JSON.parse turns 2048.0 into 2048 and
    rounds integers past 2^53, JS writes 1e-7 where Python writes 1e-07, and JS sorts keys by UTF-16 unit where Python sorts
    by code point (they differ only above U+FFFF). So a template holds no float, no integer beyond 2^53 - 1, no key above
    U+FFFF and no lone surrogate (review 2026-11-13, measured)."""
    if obj is None or isinstance(obj, bool):
        return None
    if isinstance(obj, float):
        return f"{path} holds the number {obj!r}, and a template may hold integers only"
    if isinstance(obj, int):
        return None if abs(obj) <= JS_SAFE_INT else f"{path} holds an integer beyond 2^53 - 1"
    if isinstance(obj, str):
        return f"{path} holds a lone surrogate" if any(0xD800 <= ord(ch) <= 0xDFFF for ch in obj) else None
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            why = portable_problem(v, f"{path}[{i}]")
            if why:
                return why
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str) or any(ord(ch) > 0xFFFF or 0xD800 <= ord(ch) <= 0xDFFF for ch in k):
                return f"{path} holds a key above U+FFFF or a lone surrogate"
            why = portable_problem(v, f"{path}.{k}")
            if why:
                return why
        return None
    return f"{path} holds a {type(obj).__name__}"


class Registry:
    def __init__(self):
        self.versions: dict[tuple[str, int], dict] = {}
        self.bindings: dict[tuple[str, int], tuple[str, int]] = {}

    def latest(self, stage: str) -> dict | None:
        rows = [r for (s, _v), r in self.versions.items() if s == stage]
        return max(rows, key=lambda r: r["version"]) if rows else None


def _read(path: str, key: str) -> list:
    if not os.path.exists(path):
        raise RegistryError(f"no prompts registry file at {path}")
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"{os.path.basename(path)} is not valid JSON: {exc}") from None
    rows = data.get(key) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise RegistryError(f"{os.path.basename(path)} has no {key} list")
    return rows


def _check_prompts(reg: Registry, rows: list, pname: str) -> None:
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or sorted(r) != sorted(PROMPT_COLS):
            raise RegistryError(f"{pname} entry {i} must have exactly {', '.join(PROMPT_COLS)}")
        stage, version = r["stage"], r["version"]
        if not isinstance(stage, str) or not STAGE_RE.fullmatch(stage) or len(stage) > 60:
            raise RegistryError(f"{pname} entry {i}: stage must be lowercase words joined by dots, such as submission-letter.draft")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise RegistryError(f"{pname} {stage}: version must be a positive integer")
        if (stage, version) in reg.versions:
            raise RegistryError(f"{pname} lists {stamp(stage, version)} twice")
        t = r["template"]
        if not isinstance(t, dict) or not t:
            raise RegistryError(f"{pname} {stamp(stage, version)}: template must be the module mapper object")
        why = portable_problem(t)
        if why:
            raise RegistryError(f"{pname} {stamp(stage, version)}: {why}, so scripts/law_load could not reproduce its hash")
        if not isinstance(r["model"], str) or r["model"] != t.get("model"):
            raise RegistryError(f"{pname} {stamp(stage, version)}: model must equal template.model")
        if r["template_sha256"] != template_sha256(t):
            raise RegistryError(f"{pname} {stamp(stage, version)}: template_sha256 is not the SHA-256 of the canonical template")
        if not isinstance(r["description"], str) or len(r["description"].strip()) < 12:
            raise RegistryError(f"{pname} {stamp(stage, version)}: description must be a sentence")
        try:
            if not isinstance(r["registered_on"], str) or not DATE_RE.fullmatch(r["registered_on"]):
                raise ValueError
            _dt.date.fromisoformat(r["registered_on"])
        except ValueError:
            raise RegistryError(f"{pname} {stamp(stage, version)}: registered_on must be YYYY-MM-DD") from None
        reg.versions[(stage, version)] = r
    for stage in sorted({s for s, _v in reg.versions}):
        have = sorted(v for s, v in reg.versions if s == stage)
        if have != list(range(1, len(have) + 1)):
            raise RegistryError(f"{pname} {stage}: versions must run 1, 2, 3 with no gap, found {have}")
        # ref.prompts holds UNIQUE (template_sha256, stage): one template is one version of its stage.
        first: dict[str, int] = {}
        for v in have:
            prior = first.setdefault(reg.versions[(stage, v)]["template_sha256"], v)
            if prior != v:
                raise RegistryError(f"{pname} {stamp(stage, v)} has the template of {stamp(stage, prior)}. One template is one "
                                    f"version of a stage: bind the module to {stamp(stage, prior)}")


def _check_bindings(reg: Registry, rows: list, bname: str) -> None:
    for i, b in enumerate(rows):
        if not isinstance(b, dict) or sorted(b) != sorted(BINDING_COLS):
            raise RegistryError(f"{bname} entry {i} must have exactly {', '.join(BINDING_COLS)}")
        sid, mid = b["scenario_id"], b["module_id"]
        if not all(isinstance(x, int) and not isinstance(x, bool) and 0 < x <= JS_SAFE_INT for x in (sid, mid)):
            raise RegistryError(f"{bname} entry {i}: scenario_id and module_id must be positive integers")
        key = (str(sid), mid)
        if key in reg.bindings:
            raise RegistryError(f"{bname} binds scenario {sid} module {mid} twice")
        if (b["stage"], b["version"]) not in reg.versions:
            raise RegistryError(f"{bname} entry {i}: {stamp(b['stage'], b['version'])} is not a registered version")
        reg.bindings[key] = (b["stage"], b["version"])


def load(prompts_path: str = DEFAULT_PROMPTS, bindings_path: str = DEFAULT_BINDINGS) -> Registry:
    reg = Registry()
    _check_prompts(reg, _read(prompts_path, "prompts"), os.path.basename(prompts_path))
    _check_bindings(reg, _read(bindings_path, "prompt_bindings"), os.path.basename(bindings_path))
    return reg


def _walk(flow):
    for m in flow if isinstance(flow, list) else []:
        if not isinstance(m, dict):
            continue
        yield m
        for r in m.get("routes") or []:
            if isinstance(r, dict):
                yield from _walk(r.get("flow"))
        yield from _walk(m.get("onerror"))


def claude_modules(bp: dict):
    """Every Claude module of a blueprint (the snapshot or its blueprint object), routes and error routes included."""
    bp = bp.get("blueprint", bp) if isinstance(bp, dict) else {}
    for m in _walk(bp.get("flow")):
        if m.get("module") == CLAUDE_MODULE:
            yield m


def _snapshot(blueprints: str, scenario_id: int) -> dict:
    hits = glob.glob(os.path.join(blueprints, f"*__{scenario_id}.json"))
    if len(hits) != 1:
        raise RegistryError(f"expected one snapshot blueprints/*__{scenario_id}.json, found {len(hits)}")
    with open(hits[0], encoding="utf-8") as f:
        return json.load(f)


def _candidate(path: str) -> dict:
    """The export-format blueprint a make_push sends (top-level name, flow, metadata), the shape make_push --candidate takes."""
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except OSError as exc:
        raise RegistryError(f"cannot read candidate {path}: {exc.strerror}") from None
    except json.JSONDecodeError as exc:
        raise RegistryError(f"candidate {os.path.basename(path)} is not valid JSON: {exc}") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("flow"), list) or not isinstance(obj.get("name"), str) \
            or not isinstance(obj.get("metadata"), dict):
        raise RegistryError("candidate is not an export-format blueprint (top-level name, flow, metadata)")
    return obj


def _write(path: str, key: str, rows: list, source: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"source": source, key: rows}, indent=2, ensure_ascii=False) + "\n")


SOURCE_PROMPTS = ("X-36.1, decided by Rizwan 2026-11-13. Every Claude prompt Immi-OS runs, as immutable versions. template is "
                  "the module mapper exactly as in the committed snapshot, mappings unfilled, and template_sha256 is the SHA-256 "
                  "of its canonical JSON (scripts/prompt_registry.py canonical). Never edit a version: register a new one.")
SOURCE_BINDINGS = "X-36.1. The registered version each Claude module runs, by scenario and module. Audit check R holds the live template to it."


def register(scenario_id: int, module_id: int, stage: str, description: str, blueprints: str = DEFAULT_BLUEPRINTS,
             prompts_path: str = DEFAULT_PROMPTS, bindings_path: str = DEFAULT_BINDINGS, today: str | None = None,
             candidate: str | None = None, bind: bool = True) -> str:
    """bind False (X-32, --no-bind) registers or reuses the version insert-only and leaves every binding as it is, so a new
    version can be evaluated (F-F14) before the module runs it. The same call with bind True then reuses it and binds."""
    reg = load(prompts_path, bindings_path) if os.path.exists(prompts_path) else Registry()
    source = _snapshot(blueprints, scenario_id)   # also with a candidate, so a mistyped scenario ID is refused
    where = "committed snapshot"
    if candidate is not None:
        source, where = _candidate(candidate), "candidate"
    mods = [m for m in claude_modules(source) if m.get("id") == module_id]
    if len(mods) != 1:
        raise RegistryError(f"scenario {scenario_id} has no Claude module {module_id} in its {where}")
    template = mods[0].get("mapper")
    if not isinstance(template, dict) or not template:
        raise RegistryError(f"scenario {scenario_id} module {module_id} has no mapper")
    if not STAGE_RE.fullmatch(stage) or len(stage) > 60:
        raise RegistryError("stage must be lowercase words joined by dots, such as submission-letter.draft")
    why = portable_problem(template)
    if why:
        raise RegistryError(f"scenario {scenario_id} module {module_id}: {why}. Change the value in the module and pull again")
    sha = template_sha256(template)
    # Any version of the stage with this template, so a revert binds back to it (ref.prompts holds (template_sha256, stage)
    # unique, review 2026-11-13).
    same = [r for (s, _v), r in reg.versions.items() if s == stage and r["template_sha256"] == sha]
    if same:
        version, note = same[0]["version"], "reused"
    else:
        last = reg.latest(stage)
        version, note = (last["version"] + 1 if last else 1), "registered"
        reg.versions[(stage, version)] = {"stage": stage, "version": version, "description": description.strip(),
                                          "model": template.get("model"), "template": template, "template_sha256": sha,
                                          "registered_on": today or _dt.date.today().isoformat()}
    if bind:
        reg.bindings[(str(scenario_id), module_id)] = (stage, version)
    prompt_rows = [{c: reg.versions[k][c] for c in PROMPT_COLS} for k in sorted(reg.versions)]
    binding_rows = [{"scenario_id": int(s), "module_id": m, "stage": st, "version": v}
                    for (s, m), (st, v) in sorted(reg.bindings.items(), key=lambda kv: (int(kv[0][0]), kv[0][1]))]
    # Write the pair beside the real files and load() it first, so a version load() refuses (no model, a short description)
    # never reaches the files. Only then replace the real pair.
    tmp = tempfile.mkdtemp(dir=os.path.dirname(os.path.abspath(prompts_path)))
    try:
        tp, tb = os.path.join(tmp, os.path.basename(prompts_path)), os.path.join(tmp, os.path.basename(bindings_path))
        _write(tp, "prompts", prompt_rows, SOURCE_PROMPTS)
        _write(tb, "prompt_bindings", binding_rows, SOURCE_BINDINGS)
        load(tp, tb)
        os.replace(tp, prompts_path)
        os.replace(tb, bindings_path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    how = "" if bind else ", not bound (--no-bind)"
    return f"{note} {stamp(stage, version)} for scenario {scenario_id} module {module_id} ({where}){how}, sha256 {sha[:16]}"


# ---------------------------------------------------------------------------
# Immutability against git history (review 2026-11-13). The database refuses an edited version only once it holds one,
# so a version committed but not yet loaded could be rewritten. Every commit that ever held ref/prompts.json is read, and a
# version must stay equal to the row of the first commit that registered it.
# ---------------------------------------------------------------------------

def _git(folder: str, *args: str) -> str:
    r = subprocess.run(["git", *args], cwd=folder, capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RegistryError(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:200]}")
    return r.stdout


def _rows_of(text: str) -> list:
    try:
        rows = json.loads(text).get("prompts")
    except (json.JSONDecodeError, AttributeError):
        return []
    return rows if isinstance(rows, list) else []


def history_problems(prompts_path: str = DEFAULT_PROMPTS, staged: bool = False) -> list[str]:
    folder = os.path.dirname(os.path.abspath(prompts_path))
    top = _git(folder, "rev-parse", "--show-toplevel").strip()
    rel = os.path.relpath(os.path.abspath(prompts_path), top).replace(os.sep, "/")
    try:
        _git(top, "rev-parse", "--verify", "--quiet", "HEAD")
    except RegistryError:
        return []
    commits = [c for c in _git(top, "rev-list", "--reverse", "--full-history", "HEAD", "--", rel).split() if c]
    first: dict[tuple, tuple[str, str]] = {}
    for c in commits:
        try:
            text = _git(top, "show", f"{c}:{rel}")
        except RegistryError:
            continue
        for r in _rows_of(text):
            if isinstance(r, dict) and "stage" in r and "version" in r:
                first.setdefault((r["stage"], r["version"]), (c, canonical({k: r.get(k) for k in PROMPT_COLS})))
    if staged:
        try:
            now_text = _git(top, "show", f":{rel}")
        except RegistryError:
            now_text = ""
    else:
        if not os.path.exists(prompts_path):
            now_text = ""
        else:
            with open(prompts_path, encoding="utf-8") as f:
                now_text = f.read()
    now = {(r["stage"], r["version"]): canonical({k: r.get(k) for k in PROMPT_COLS})
           for r in _rows_of(now_text) if isinstance(r, dict) and "stage" in r and "version" in r}
    out = []
    for key, (commit, row) in sorted(first.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        tag = stamp(*key)
        if key not in now:
            out.append(f"{tag} was registered in commit {commit[:12]} and is gone. A version never disappears")
        elif now[key] != row:
            out.append(f"{tag} differs from commit {commit[:12]}, which registered it. Restore it and register the edit as a new version")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="validate the files, then every version against the commit that registered it")
    c.add_argument("--staged", action="store_true", help="check the staged ref/prompts.json against history only (pre-commit)")
    r = sub.add_parser("register", help="register or reuse a version for one Claude module and bind it")
    r.add_argument("--scenario", type=int, required=True)
    r.add_argument("--module", type=int, required=True)
    r.add_argument("--stage", required=True)
    r.add_argument("--description", required=True)
    r.add_argument("--candidate", default=None, help="export-format blueprint a make_push will send (default: the committed snapshot)")
    r.add_argument("--no-bind", action="store_true", help="register or reuse the version without binding the module to it (X-32: "
                                                          "evaluate a new version in F-F14 before the module runs it)")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "check":
            if not args.staged:
                reg = load()
                print(f"prompts registry: {len(reg.versions)} versions, {len(reg.bindings)} bindings, every hash recomputed")
            problems = history_problems(staged=args.staged)
            for p in problems:
                print(f"prompt_registry: {p}", file=sys.stderr)
            if problems:
                return 2
            print("prompts registry: every version equals the commit that registered it")
        else:
            print(register(args.scenario, args.module, args.stage, args.description, candidate=args.candidate,
                           bind=not args.no_bind))
    except RegistryError as exc:
        print(f"prompt_registry: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
