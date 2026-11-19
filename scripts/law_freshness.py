#!/usr/bin/env python3
"""X-37: is the committed IRPA and IRPR index (law/, X-17.1) still the law Justice Canada publishes?

    python scripts/law_freshness.py check [--keep DIR] [--law DIR] [--report audit/reports]

GET requests only, standard library only. For each instrument it downloads the consolidated XML from
laws-lois.justice.gc.ca, compares its SHA-256 with the pin in <law>/manifest.json, reads the XML root's lims dates
(current-date, lastAmendedDate) and the "current to ... and last amended on ..." line of the Justice Laws page.
When an XML differs from its pin, it parses it in memory with scripts/law_index.py and diffs the rows against the
committed JSONL of that instrument. The review names the keys Module F cites (ref/citation_map.json) whose text
changed or that are gone, the cited keys whose lead-in text (an enclosing unit's own words) changed, every signed
citation row of that instrument whose reviewed_text_sha256 no longer equals the provision's new text hash, the new
sections, the units added inside existing sections, and the amendments newly listed as not yet in force.

Exit codes: 1 reload needed (an XML changed, the report lists the review), else 3 something could not be read (a fetch,
a parse or a Justice Laws page line, so a lag cannot be ruled out), else 2 the page names a later amendment than the
XML (the feed lags, wait for it), else 0 current. Any unexpected error is 3, never 1. A report goes to
<report>/law-freshness-<YYYY-MM-DD>.md. --keep DIR (outside the repo) keeps the fresh XML of both instruments, so the
reload is `python scripts/law_index.py build --irpa DIR/IRPA.xml --irpr DIR/IRPR.xml --out law`, a reviewed commit of
law/, then the loader on Rizwan's go-ahead (specs/X-37.1-law-freshness.md). --law DIR checks against another index
folder, such as the last commit's law/ restored outside the repo.

The XML is public law text, never executed, never committed (the manifest pins its SHA-256). Cadence (X-37): run it
at least quarterly and whenever IRCC announces regulatory amendments, and reload on exit code 1.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import law_index as li  # noqa: E402

REPO = os.path.dirname(HERE)
UA = "immi-os-law-check/1"
SOURCES = {
    "IRPA": ("https://laws-lois.justice.gc.ca/eng/XML/I-2.5.xml", "https://laws-lois.justice.gc.ca/eng/acts/I-2.5/"),
    "IRPR": ("https://laws-lois.justice.gc.ca/eng/XML/SOR-2002-227.xml",
             "https://laws-lois.justice.gc.ca/eng/regulations/SOR-2002-227/"),
}
_DATE = r"(\d{4}-\d{2}-\d{2})"
# "Act current to 2026-10-29 and last amended on 2026-03-26." / "Regulations are current to 2026-10-29  and last ..."
_PAGE = re.compile(r"current\s+to\s+" + _DATE + r"\s+and\s+last\s+amended\s+on\s+" + _DATE, re.I)
_ROOT = re.compile(rb"<(?:Statute|Regulation)\s[^>]*>")


class FreshnessError(Exception):
    pass


def fetch(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status != 200:
            raise FreshnessError(f"{url}: HTTP {r.status}")
        return r.read()


def xml_dates(xml: bytes) -> dict:
    # The root element's own attributes only: inner elements carry their own lastAmendedDate (measured 2026-11-19, the
    # first one in the IRPR file reads 2022-03-04 while the root reads 2026-10-23).
    m = _ROOT.search(xml[:8192])
    if m is None:
        raise FreshnessError("the XML has no Statute or Regulation root element in its first 8 KB")
    got = dict(re.findall(r'lims:(current-date|lastAmendedDate)="(\d{4}-\d{2}-\d{2})"', m.group(0).decode("utf-8", "replace")))
    if "current-date" not in got or "lastAmendedDate" not in got:
        raise FreshnessError("the XML root carries no lims current-date and lastAmendedDate")
    return {"current_to": got["current-date"], "last_amended": got["lastAmendedDate"]}


def page_dates(html: bytes) -> dict | None:
    text = re.sub(r"<[^>]+>", " ", html.decode("utf-8", "replace"))
    m = _PAGE.search(text)
    return {"current_to": m.group(1), "last_amended": m.group(2)} if m else None


def cited(citation_map: dict) -> tuple[set, list]:
    rows = citation_map.get("rows") if isinstance(citation_map.get("rows"), list) else \
        next((v for v in citation_map.values() if isinstance(v, list)), [])
    return {r["provision_key"] for r in rows}, rows


def review(old_rows: list, new_rows: list, citation_map: dict, instrument: str) -> dict:
    """The X-37 review list of one instrument: the diff, the cited keys it touches (own text or lead-in) and the signed
    rows of that instrument it makes stale. Citation rows of the other instrument are not judged here."""
    d = li.diff(old_rows, new_rows)
    keys, rows = cited(citation_map)
    prefix = instrument + " "
    keys = {k for k in keys if k.startswith(prefix)}
    rows = [r for r in rows if str(r.get("provision_key", "")).startswith(prefix)]
    old = {r["key"]: r for r in old_rows}
    new = {r["key"]: r for r in new_rows}
    touched = sorted(k for k in keys if k in set(d["changed"]) | set(d["removed"]))
    # A paragraph's text_sha256 covers it and its sub-units, not the words above it. A cited key whose enclosing unit's own
    # text changed (the lead-in, such as "A foreign national is a member of the class if") reads differently although its
    # own hash holds (review 2026-11-19).
    lead_in = []
    for k in sorted(keys):
        par = (new.get(k) or {}).get("parent_key")
        while par:
            if par in old and par in new and old[par].get("own_text") != new[par].get("own_text"):
                lead_in.append([k, par])
                break
            par = (new.get(par) or {}).get("parent_key")
    stale = sorted({(r.get("document_type", ""), r["visa_code"], r["provision_key"]) for r in rows
                    if r.get("reviewed_text_sha256") and (r["provision_key"] not in new
                                                          or new[r["provision_key"]]["text_sha256"] != r["reviewed_text_sha256"])})
    order = {r["key"]: r["ord"] for r in new_rows}
    added = sorted(d["added"], key=lambda x: order[x])
    new_sections = [k for k in added if new[k].get("level") == "section"]
    inside = [k for k in added if new[k].get("level") != "section" and f"{instrument} {new[k]['section']}" in old]
    return {**d, "cited_touched": touched, "cited_lead_in_changed": lead_in, "signed_rows_stale": [list(x) for x in stale],
            "new_sections": new_sections, "added_inside_existing": inside}


def check(manifest: dict, citation_map: dict, get=None, law_dir: str | None = None, keep: str | None = None) -> dict:
    get = get or fetch   # resolved per call, so a test can replace the module's fetch
    law_dir = law_dir or os.path.join(REPO, "law")
    pins = {i["instrument"]: i for i in manifest["instruments"]}
    out: dict = {"instruments": {}, "exit": 0}
    fresh: dict = {}
    xmls: dict = {}
    for inst, (xml_url, page_url) in SOURCES.items():
        pin = pins.get(inst)
        if pin is None:
            raise FreshnessError(f"law/manifest.json has no {inst} entry")
        xml = get(xml_url)
        xmls[inst] = xml
        sha = hashlib.sha256(xml).hexdigest()
        xd = xml_dates(xml)
        pd = page_dates(get(page_url))
        res = {"pinned": {k: pin.get(k) for k in ("current_to", "last_amended", "source_sha256")},
               "xml": {**xd, "sha256": sha, "equals_pin": sha == pin.get("source_sha256")}, "page": pd}
        if pd is None:
            res["page_unread"] = True
        elif pd["last_amended"] > xd["last_amended"]:
            res["feed_lags"] = True
        if not res["xml"]["equals_pin"]:
            fresh[inst] = xml
        out["instruments"][inst] = res
    if fresh:
        if keep:
            # Every XML is kept, the unchanged ones too, since law_index build needs both instruments.
            os.makedirs(keep, exist_ok=True)
            for inst, data in xmls.items():
                with open(os.path.join(keep, inst + ".xml"), "wb") as f:
                    f.write(data)
        for inst, data in fresh.items():
            instrument, rows = li.parse(data)
            if instrument["instrument"] != inst:
                raise FreshnessError(f"{SOURCES[inst][0]} parsed as {instrument['instrument']}")
            old = li.load_jsonl(os.path.join(law_dir, inst + ".jsonl"))
            out["instruments"][inst]["review"] = review(old, rows, citation_map, inst)
            out["instruments"][inst]["xml"]["units"] = instrument["units"]
            # Amendments registered but not yet in force (the RelatedOrNotInForce schedule): the next reload's warning.
            before = set(pins[inst].get("related_or_not_in_force") or [])
            out["instruments"][inst]["pending_new"] = [x for x in instrument["related_or_not_in_force"] if x not in before]
        out["kept"] = keep
    states = list(out["instruments"].values())
    out["exit"] = (1 if fresh else 3 if any(r.get("page_unread") for r in states)
                   else 2 if any(r.get("feed_lags") for r in states) else 0)
    return out


def report(res: dict, today: str) -> str:
    lines = [f"# Law freshness check {today} (X-37)", "",
             "Source: Justice Canada consolidated XML and the Justice Laws page of each instrument. GET only.", ""]
    verdict = {0: "current, no reload", 1: "RELOAD NEEDED", 2: "the XML feed lags the Justice Laws page, wait",
               3: "INCOMPLETE, a page could not be read"}[res["exit"]]
    lines += [f"Result: **{verdict}** (exit {res['exit']}).", ""]
    for inst, r in res["instruments"].items():
        p, x, g = r["pinned"], r["xml"], r["page"] or {}
        lines += [f"## {inst}", "",
                  f"- pinned: current to {p['current_to']}, last amended {p['last_amended']}",
                  f"- XML: current to {x['current_to']}, last amended {x['last_amended']}, "
                  f"{'equals the pin' if x['equals_pin'] else 'differs from the pin'}",
                  f"- page: current to {g.get('current_to', 'not read')}, last amended {g.get('last_amended', 'not read')}"]
        if r.get("feed_lags"):
            lines.append("- the page names a later amendment than the XML: the XML feed has not caught up")
        if r.get("page_unread"):
            lines.append("- the page's current-to line could not be read, so a lagging feed cannot be ruled out")
        rv = r.get("review")
        if rv:
            lines += [f"- diff: {len(rv['added'])} added, {len(rv['changed'])} changed, {len(rv['removed'])} removed units",
                      f"- cited keys touched (ref/citation_map.json): {', '.join(rv['cited_touched']) or 'none'}",
                      f"- cited keys whose lead-in changed: "
                      f"{', '.join(f'{k} (under {q})' for k, q in rv['cited_lead_in_changed']) or 'none'}",
                      f"- signed citation rows made stale: "
                      f"{', '.join(f'{a} {b} {c}' for a, b, c in rv['signed_rows_stale']) or 'none'}",
                      f"- changed: {', '.join(rv['changed']) or 'none'}",
                      f"- removed: {', '.join(rv['removed']) or 'none'}",
                      f"- new sections (document order): {', '.join(rv['new_sections']) or 'none'}",
                      f"- units added inside existing sections: {', '.join(rv['added_inside_existing']) or 'none'}",
                      f"- amendments registered, not yet in force, new since the pin: "
                      f"{', '.join(r.get('pending_new') or []) or 'none'}"]
        lines.append("")
    return "\n".join(lines)


def inside_repo(path: str) -> bool:
    """True when path is the repo or inside it, after resolving links, case and drive letters (Windows)."""
    a = os.path.normcase(os.path.realpath(path))
    r = os.path.normcase(os.path.realpath(REPO))
    try:
        return os.path.commonpath([a, r]) == r
    except ValueError:   # another drive
        return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--keep", help="folder outside the repo that keeps the fresh XML for the reload")
    c.add_argument("--law", default=os.path.join(REPO, "law"), help="index folder to check against (default law/)")
    c.add_argument("--report", default=os.path.join(REPO, "audit", "reports"))
    args = ap.parse_args(argv)
    if args.keep and inside_repo(args.keep):
        print("--keep must be outside the repo (the XML is never committed)", file=sys.stderr)
        return 3
    try:
        with open(os.path.join(args.law, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        with open(os.path.join(REPO, "ref", "citation_map.json"), encoding="utf-8") as f:
            citation_map = json.load(f)
        res = check(manifest, citation_map, law_dir=args.law, keep=args.keep)
    except Exception as exc:   # anything unexpected is exit 3, never the 1 that means "reload needed" (review 2026-11-19)
        print(f"law_freshness: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    today = dt.date.today().isoformat()
    text = report(res, today)
    os.makedirs(args.report, exist_ok=True)
    path = os.path.join(args.report, f"law-freshness-{today}.md")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text + "\n")
    print(text)
    print(f"Report: {path}")
    return res["exit"]


if __name__ == "__main__":
    sys.exit(main())
