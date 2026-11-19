#!/usr/bin/env python3
"""F-F14 tier A grading sheet: a standalone HTML file in the run folder (the Finance-Agent-Evals labeling-sheet pattern).

  python scripts/ff14_grading_sheet.py build eval/ff14/runs/<run id>
      writes <run>/grading.html from the run's handgrade.json, case files and the golden set. Open it in a browser:
      grades autosave in that browser, Export writes handgrade-export.json.
  python scripts/ff14_grading_sheet.py merge eval/ff14/runs/<run id> [<export.json>]
      fills <run>/handgrade.json (tier A rows, hand checks, grader, graded_at) from the export, default
      <run>/handgrade-export.json. Then: node scripts/ff14/grade.mjs --summarize eval/ff14/runs/<run id>

Everything in a run is synthetic (golden cases, drafted letters, public law text). Standard library only.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, "scripts", "ff14", "grading_template.html")
A1 = {"agree", "too_generous", "too_strict", "unsure", None}
A2 = {"as_label_allows", "overstated", "omitted_supported", "unsure", None}
A3 = {"true", "partly", "wrong", "unsure", None}


def _load(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build(run: str) -> str:
    sheet = _load(os.path.join(run, "handgrade.json"))
    ids = sorted({r["case_id"] for r in sheet["tier_a"]} | {c["case_id"] for c in sheet["hand_checks"]})
    cases = {}
    for cid in ids:
        c = _load(os.path.join(run, "cases", f"{cid}.json"))
        g = _load(os.path.join(ROOT, "eval", "ff14", "golden", sheet.get("golden_version", "v1"), f"{cid}.json"))
        outline = json.loads(c["outline"]["text"]) if c.get("outline") and c["outline"].get("text") else {}
        prov = {p["key"]: p["text"] for p in json.loads(c["grounding"]["provisions"])} if c.get("grounding", {}).get("provisions") else {}
        cases[cid] = {
            "kind": c.get("kind"), "visa": g["inputs"]["visa_code"], "name": g["inputs"]["name"],
            "facts": g["inputs"]["case_facts_lines"], "provisions": prov,
            "grounds": {gr["provision_key"]: gr for gr in outline.get("grounds", [])},
            "thesis": outline.get("thesis", ""), "risk": outline.get("risk_flags", []),
            "letter": (c.get("draft") or {}).get("text", ""),
            "verdict": (c.get("validation") or {}).get("verdict", ""),
        }
    data = {"run": sheet["run_id"], "cases": cases,
            "rows": [{"c": r["case_id"], "k": r["provision_key"], "s": r["outline_support"]} for r in sheet["tier_a"]],
            "checks": [{"c": h["case_id"], "t": h["text"]} for h in sheet["hand_checks"]]}
    with open(TEMPLATE, encoding="utf-8") as fh:
        html = fh.read()
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    out = os.path.join(run, "grading.html")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
                 "</head><body>\n" + html.replace("__DATA__", blob) + "\n</body></html>\n")
    return out


def merge(run: str, export: str | None) -> str:
    export = export or os.path.join(run, "handgrade-export.json")
    ex = _load(export)
    path = os.path.join(run, "handgrade.json")
    sheet = _load(path)
    if ex.get("format") != "ff14-handgrade-export/1":
        raise SystemExit("not an F-F14 grading export")
    if ex.get("run_id") != sheet["run_id"]:
        raise SystemExit(f"the export is for run {ex.get('run_id')}, not {sheet['run_id']}")
    if not str(ex.get("grader", "")).strip():
        raise SystemExit("the export names no grader")
    rows = {(r["case_id"], r["provision_key"]): r for r in ex["tier_a"]}
    filled = 0
    for r in sheet["tier_a"]:
        x = rows.get((r["case_id"], r["provision_key"]))
        if not x:
            continue
        if x.get("A1") not in A1 or x.get("A2") not in A2 or x.get("A3") not in A3:
            raise SystemExit(f"unknown grade value on {r['case_id']} {r['provision_key']}")
        r.update({"A1": x.get("A1"), "A2": x.get("A2"), "A3": x.get("A3"), "notes": x.get("notes", "")})
        filled += bool(x.get("A1") and x.get("A2") and x.get("A3"))
    if len(ex.get("hand_checks", [])) == len(sheet["hand_checks"]):
        for h, x in zip(sheet["hand_checks"], ex["hand_checks"]):
            if x.get("case_id") != h["case_id"] or x.get("result") not in ("pass", "fail", None):
                raise SystemExit("hand checks do not line up with the sheet")
            h.update({"result": x.get("result"), "notes": x.get("notes", "")})
    sheet["grader"] = ex["grader"].strip()
    sheet["graded_at"] = ex["graded_at"]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(sheet, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"filled {filled} of {len(sheet['tier_a'])} tier A rows, grader {sheet['grader']}")
    return path


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("build", "merge"):
        print(__doc__)
        return 2
    if argv[0] == "build":
        print(build(argv[1]))
    else:
        merge(argv[1], argv[2] if len(argv) > 2 else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
