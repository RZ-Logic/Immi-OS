#!/usr/bin/env python3
"""IRPA and IRPR provision index (X-17.1, decided by Rizwan 2026-11-02, X-17 option B).

Reads the Justice Canada consolidated XML of the Immigration and Refugee Protection Act (I-2.5) and the
Immigration and Refugee Protection Regulations (SOR-2002-227) and writes one row per citable unit (section,
subsection, paragraph, subparagraph, clause, subclause) to law/<instrument>.jsonl, plus law/manifest.json.
The committed JSONL is the canonical index F-F13 anti-joins against and the source of the Stage 2 grounding
text. It is deterministic grounding, never vectorized (X-17, X-32). A git diff of the JSONL after a reload is
the amendment diff X-37 reviews, and `diff` lists the keys whose text hash changed.

Row fields:
    key            canonical key, "<instrument> <section><labels>", e.g. "IRPR 216(1)(b)"
    instrument     IRPA or IRPR
    section        section label, e.g. "216" or "12.02"
    level          section, subsection, paragraph, subparagraph, clause or subclause
    label          the unit's own label, "(1)", "(b)", or the section number
    parent_key     the enclosing unit's key, null for a section
    ord            document order within the instrument
    lims_id        Justice Laws provision ID (lims:id), lims_fid the first ID (lims:fid)
    marginal_note  the unit's own marginal note, else the nearest enclosing one
    heading_path   the Part, Division and subdivision headings above the section, " > " joined
    status         in_force, repealed or amending (an "[Amendments]" placeholder, never citable)
    inforce_start_date, last_amended_date   from the lims attributes (last_amended_date on sections only)
    own_text       the unit's own words, its label and its sub-units excluded
    text_sha256    SHA-256 of the rendered text of the unit and every sub-unit (labels included,
                   marginal notes, historical notes and footnotes excluded, since none is part of the enactment)

Only the consolidated Body is indexed. Amendments not yet in force sit in the RelatedOrNotInForce schedule and
are counted in the manifest as related_or_not_in_force (an X-37 watch signal), not indexed. Definitions stay inside
the own text of their section, since a definition is cited through its section.

Usage:
    python scripts/law_index.py build --irpa PATH --irpr PATH [--out law]
    python scripts/law_index.py diff OLD.jsonl NEW.jsonl
    python scripts/law_index.py sql [--law law] > provisions_seed.sql

Standard library only. The XML files are read, never executed, and never committed (the manifest pins their
SHA-256). Source: https://laws-lois.justice.gc.ca/eng/XML/I-2.5.xml and .../SOR-2002-227.xml.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

LIMS = "{http://justice.gc.ca/lims}"
INSTRUMENTS = {"I-2.5": "IRPA", "SOR-2002-227": "IRPR"}
TITLES = {"IRPA": "Immigration and Refugee Protection Act", "IRPR": "Immigration and Refugee Protection Regulations"}
LEVELS = {"Section": "section", "Subsection": "subsection", "Paragraph": "paragraph",
          "Subparagraph": "subparagraph", "Clause": "clause", "Subclause": "subclause"}
STRUCTURAL = set(LEVELS)
# Not part of the enactment text (Interpretation Act s.14 for marginal notes), or labels handled separately.
SKIP_TEXT = {"Label", "MarginalNote", "HistoricalNote", "Footnote", "FootnoteRef"}
STATUSES = ("in_force", "repealed", "amending")
RANGE = re.compile(r"^(\d+(?:\.\d+)*)\s+(to|and)\s+(\d+(?:\.\d+)*)$")


class LawIndexError(Exception):
    pass


def _ws(text):
    return re.sub(r"\s+", " ", text or "").strip()


def _text_of(elem):
    """Visible text of an element, footnote references and notes dropped, whitespace collapsed."""
    parts = []

    def walk(e):
        if e.tag in ("FootnoteRef", "Footnote", "HistoricalNote"):
            if e.tail:
                parts.append(e.tail)
            return
        if e.text:
            parts.append(e.text)
        for c in e:
            walk(c)
        if e.tail:
            parts.append(e.tail)

    if elem.text:
        parts.append(elem.text)
    for c in elem:
        walk(c)
    return _ws(" ".join(parts))


def _label(elem):
    lab = elem.find("Label")
    return "" if lab is None else _text_of(lab).replace(" ", "")


def _own_text(elem):
    """The unit's own words: every child that is not a label, note or sub-unit, in document order."""
    return _ws(" ".join(_text_of(c) for c in elem if c.tag not in SKIP_TEXT and c.tag not in STRUCTURAL))


def _is_repealed(elem):
    for c in elem:
        if c.tag == "Text" and c.find("Repealed") is not None:
            return _own_text(elem) == _ws(_text_of(c.find("Repealed")))
    return False


def _render(elem):
    """Label, own text and sub-units, the text Stage 2 injects and the hash covers."""
    pieces = [_label(elem), _own_text(elem)]
    pieces += [_render(c) for c in elem if c.tag in STRUCTURAL]
    return _ws(" ".join(p for p in pieces if p))


def render_rows(rows, i):
    """Rendered text of rows[i] and its sub-units from the index rows alone, in document order. The same
    rendering as law.provision_text() in the migration, so a stored hash can be checked in the database."""
    prefix = rows[i]["key"] + "("
    parts = [_ws(rows[i]["label"] + " " + rows[i]["own_text"])]
    for r in rows[i + 1:]:
        if not r["key"].startswith(prefix):
            break
        parts.append(_ws(r["label"] + " " + r["own_text"]))
    return _ws(" ".join(parts))


SUB_LABEL = re.compile(r"^\(([0-9]+(?:\.[0-9]+)*|[A-Za-z]+(?:\.[0-9]+)*)\)$")
SUB_RANGE = re.compile(r"^\(([0-9]+|[a-z])\)(and|to)\(([0-9]+|[a-z])\)$")


def _sub_labels(label, key):
    """A sub-unit label as one or more canonical labels. '(2)and(3)' and '(d)to(g)' are repealed groups that
    Justice Laws prints under one label, and each member stays citable as repealed. 'a)' (a source typo, measured
    in IRPR 87(12) and 209.2(3.1)) gets its opening parenthesis back. Anything else fails closed."""
    if not label:
        raise LawIndexError(f"{key}: unlabelled sub-unit")
    if re.fullmatch(r"[0-9A-Za-z.]+\)", label):
        label = "(" + label
    if SUB_LABEL.match(label):
        return [label]
    m = SUB_RANGE.match(label)
    if not m:
        raise LawIndexError(f"{key}: unexpected label {label!r}")
    lo, op, hi = m.groups()
    if op == "and":
        return [f"({lo})", f"({hi})"]
    if lo.isdigit() and hi.isdigit() and int(lo) < int(hi):
        return [f"({n})" for n in range(int(lo), int(hi) + 1)]
    if lo.isalpha() and hi.isalpha() and lo < hi:
        return [f"({chr(n)})" for n in range(ord(lo), ord(hi) + 1)]
    raise LawIndexError(f"{key}: unexpected label range {label!r}")


def _expand_range(label):
    """'211 to 214' -> 211..214, '204 and 205' -> both, '227.1 to 232' -> 227.1, 228..232."""
    m = RANGE.match(label)
    if not m:
        return None
    lo, op, hi = m.groups()
    if op == "and":
        return [lo, hi]
    start = int(lo.split(".")[0]) + 1 if "." in lo else int(lo)
    if "." in hi:
        raise LawIndexError(f"range with a decimal upper bound: {label}")
    out = [lo] if "." in lo else []
    out += [str(n) for n in range(start, int(hi) + 1)]
    return out


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _date(elem, attr):
    return elem.get(LIMS + attr)


def parse(xml_bytes):
    """Parse one consolidated instrument. Returns (instrument_row, provision_rows)."""
    root = ET.fromstring(xml_bytes)
    num = root.find("Identification/Chapter/ConsolidatedNumber")
    if num is None:
        num = root.find("Identification/InstrumentNumber")
    code = _ws(num.text if num is not None else "").replace("/", "-")
    code = re.sub(r"^SOR-(\d{4})-", r"SOR-\1-", code)
    if code not in INSTRUMENTS:
        raise LawIndexError(f"unexpected instrument number {code!r}")
    inst = INSTRUMENTS[code]
    body = root.find("Body")
    if body is None:
        raise LawIndexError(f"{inst}: no Body element")

    rows, headings, ord_ = [], {}, [0]

    def add(elem, key, section, level, label, parent, note, path, status):
        ord_[0] += 1
        rows.append({
            "key": key, "instrument": inst, "section": section, "level": level, "label": label,
            "parent_key": parent, "ord": ord_[0],
            "lims_id": elem.get(LIMS + "id"), "lims_fid": elem.get(LIMS + "fid"),
            "marginal_note": note, "heading_path": path, "status": status,
            "inforce_start_date": _date(elem, "inforce-start-date"),
            "last_amended_date": _date(elem, "lastAmendedDate"),
            "own_text": _own_text(elem), "text_sha256": None,
        })

    def walk(elem, key, section, note, path):
        for c in elem:
            if c.tag not in STRUCTURAL:
                continue
            labels = _sub_labels(_label(c), key)
            cnote = _ws(_text_of(c.find("MarginalNote"))) if c.find("MarginalNote") is not None else note
            status = "repealed" if _is_repealed(c) else "in_force"
            if len(labels) > 1 and any(g.tag in STRUCTURAL for g in c):
                raise LawIndexError(f"{key}: ranged {c.tag} {labels} has sub-units")
            for lab in labels:
                add(c, key + lab, section, LEVELS[c.tag], lab, key, cnote, path, status)
            if len(labels) == 1:
                walk(c, key + labels[0], section, cnote, path)

    for child in body:
        if child.tag == "Heading":
            level = int(child.get("level") or 1)
            headings = {k: v for k, v in headings.items() if k < level}
            headings[level] = _text_of(child)
            continue
        if child.tag != "Section":
            continue
        path = " > ".join(headings[k] for k in sorted(headings))
        lab = _text_of(child.find("Label")) if child.find("Label") is not None else ""
        note = _ws(_text_of(child.find("MarginalNote"))) if child.find("MarginalNote") is not None else None
        expanded = _expand_range(lab)
        if expanded is not None:
            for sec in expanded:
                add(child, f"{inst} {sec}", sec, "section", sec, None, note, path, "amending")
            continue
        if not re.fullmatch(r"\d+(\.\d+)*", lab):
            raise LawIndexError(f"{inst}: unexpected section label {lab!r}")
        key = f"{inst} {lab}"
        add(child, key, lab, "section", lab, None, note, path, "repealed" if _is_repealed(child) else "in_force")
        walk(child, key, lab, note, path)

    keys = [r["key"] for r in rows]
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    if dupes:
        raise LawIndexError(f"{inst}: duplicate keys {dupes[:10]}")
    for i, r in enumerate(rows):
        r["text_sha256"] = _sha(render_rows(rows, i))

    pending = [_ws(_text_of(h)).lstrip("— ").strip()
               for r in root.iter("RelatedOrNotInForce") for h in r.findall("Heading")]
    instrument = {
        "instrument": inst, "title": TITLES[inst], "consolidated_number": code,
        "current_to": root.get(LIMS + "current-date"), "point_in_time": root.get(LIMS + "pit-date"),
        "last_amended": root.get(LIMS + "lastAmendedDate"),
        "source_sha256": hashlib.sha256(xml_bytes).hexdigest(),
        "sections": sum(1 for r in rows if r["level"] == "section"),
        "units": len(rows),
        "status_counts": {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES},
        "related_or_not_in_force": pending,
    }
    return instrument, rows


def write(out_dir, results):
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"source": "https://laws-lois.justice.gc.ca/eng/XML/", "instruments": []}
    for instrument, rows in results:
        path = os.path.join(out_dir, instrument["instrument"] + ".jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=False) + "\n")
        manifest["instruments"].append(instrument)
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return manifest


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def diff(old_rows, new_rows):
    """Keys added, removed, and changed (text hash or status). The X-37 review list."""
    old = {r["key"]: r for r in old_rows}
    new = {r["key"]: r for r in new_rows}
    changed = sorted(k for k in old.keys() & new.keys()
                     if (old[k]["text_sha256"], old[k]["status"]) != (new[k]["text_sha256"], new[k]["status"]))
    return {"added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()), "changed": changed}


def _q(value):
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


INSTRUMENT_COLS = ("instrument", "title", "consolidated_number", "current_to", "point_in_time", "last_amended",
                   "source_sha256", "related_or_not_in_force")
PROVISION_COLS = ("key", "instrument", "section", "level", "label", "parent_key", "ord", "lims_id", "lims_fid",
                  "marginal_note", "heading_path", "status", "inforce_start_date", "last_amended_date",
                  "own_text", "text_sha256")


def to_sql(manifest, rows_by_instrument):
    """One transaction: upsert the instruments and every unit, mark keys missing from the load absent, then gate.
    Nothing is deleted, because X-17.2 citation mapping rows reference provision keys. An absent key gives up its
    ord. The deferred UNIQUE (instrument, ord) and parent_key FK absorb the shifts while rows move, and
    SET CONSTRAINTS ALL IMMEDIATE checks them once every row is final, ahead of the gate, so the loader's --check
    (which ends in ROLLBACK, where deferred checks never run) fails exactly when the real load would. The gate runs
    inside the transaction, before COMMIT, so a load whose units or rendered hashes differ from law/ raises and
    nothing of it is ever visible."""
    out = ["BEGIN;"]
    for inst in manifest["instruments"]:
        vals = [inst[c] if c != "related_or_not_in_force" else json.dumps(inst[c], ensure_ascii=False)
                for c in INSTRUMENT_COLS]
        out.append("INSERT INTO law.instruments (" + ", ".join(INSTRUMENT_COLS) + ", loaded_at) VALUES ("
                   + ", ".join(_q(v) for v in vals) + ", now()) ON CONFLICT (instrument) DO UPDATE SET "
                   + ", ".join(f"{c} = EXCLUDED.{c}" for c in INSTRUMENT_COLS[1:]) + ", loaded_at = now();")
        rows = rows_by_instrument[inst["instrument"]]
        for r in rows:
            out.append("INSERT INTO law.provisions (" + ", ".join(PROVISION_COLS) + ", loaded_at) VALUES ("
                       + ", ".join(_q(r[c]) for c in PROVISION_COLS) + ", now()) ON CONFLICT (key) DO UPDATE SET "
                       + ", ".join(f"{c} = EXCLUDED.{c}" for c in PROVISION_COLS[1:]) + ", loaded_at = now();")
        keys = ", ".join(_q(r["key"]) for r in rows)
        out.append(f"UPDATE law.provisions SET status = 'absent', ord = NULL, loaded_at = now() "
                   f"WHERE instrument = {_q(inst['instrument'])} AND status <> 'absent' AND key NOT IN ({keys});")
    out.append("SET CONSTRAINTS ALL IMMEDIATE;")
    out.append(_gate_sql(manifest, rows_by_instrument))
    out.append("COMMIT;")
    return "\n".join(out) + "\n"


def _gate_sql(manifest, rows_by_instrument):
    """A DO block that raises unless the database now holds exactly this load: per instrument the source SHA-256
    of the manifest and as many non-absent units as the load has, and no non-absent unit whose
    law.provision_text() hashes differently from its text_sha256. The raise aborts the transaction."""
    checks = []
    for inst in manifest["instruments"]:
        name = _q(inst["instrument"])
        n = len(rows_by_instrument[inst["instrument"]])
        checks.append(
            f"  SELECT count(*) INTO n FROM law.provisions WHERE instrument = {name} AND status <> 'absent';\n"
            f"  IF n <> {n} THEN RAISE EXCEPTION 'X-17.1 load gate: % holds % units, the load has {n}', {name}, n; END IF;\n"
            f"  IF NOT EXISTS (SELECT 1 FROM law.instruments WHERE instrument = {name} AND source_sha256 = "
            f"{_q(inst['source_sha256'])}) THEN RAISE EXCEPTION 'X-17.1 load gate: % source_sha256 differs', {name}; "
            f"END IF;")
    checks.append(
        "  SELECT count(*) INTO n FROM law.provisions c JOIN law.provisions p ON p.key = c.parent_key "
        "WHERE c.status <> 'absent' AND p.status = 'absent';\n"
        "  IF n <> 0 THEN RAISE EXCEPTION 'X-17.1 load gate: % live units sit under an absent parent', n; END IF;")
    checks.append(
        "  SELECT count(*) INTO n FROM law.provisions p WHERE p.status <> 'absent' AND "
        "encode(sha256(convert_to(law.provision_text(p.key), 'UTF8')), 'hex') IS DISTINCT FROM p.text_sha256;\n"
        "  IF n <> 0 THEN RAISE EXCEPTION 'X-17.1 load gate: % units render a text whose hash differs', n; END IF;")
    return "DO $gate$\nDECLARE n integer;\nBEGIN\n" + "\n".join(checks) + "\nEND\n$gate$;"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--irpa", required=True)
    b.add_argument("--irpr", required=True)
    b.add_argument("--out", default="law")
    d = sub.add_parser("diff")
    d.add_argument("old")
    d.add_argument("new")
    s = sub.add_parser("sql")
    s.add_argument("--law", default="law")
    args = ap.parse_args(argv)

    if args.cmd == "build":
        results = []
        for p in (args.irpa, args.irpr):
            with open(p, "rb") as f:
                results.append(parse(f.read()))
        got = [i["instrument"] for i, _ in results]
        if got != ["IRPA", "IRPR"]:
            raise LawIndexError(f"--irpa and --irpr gave {got}")
        manifest = write(args.out, results)
        for i in manifest["instruments"]:
            print(f"{i['instrument']}: current to {i['current_to']}, {i['sections']} sections, {i['units']} units, "
                  f"{i['status_counts']}, {len(i['related_or_not_in_force'])} related or not-in-force provisions")
        return 0
    if args.cmd == "diff":
        result = diff(load_jsonl(args.old), load_jsonl(args.new))
        print(json.dumps(result, indent=2))
        return 1 if any(result.values()) else 0
    if args.cmd == "sql":
        with open(os.path.join(args.law, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        rows = {i["instrument"]: load_jsonl(os.path.join(args.law, i["instrument"] + ".jsonl"))
                for i in manifest["instruments"]}
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")  # byte-exact seed on Windows too
        sys.stdout.write(to_sql(manifest, rows))
        return 0
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LawIndexError as e:
        print(f"law_index: {e}", file=sys.stderr)
        sys.exit(1)
