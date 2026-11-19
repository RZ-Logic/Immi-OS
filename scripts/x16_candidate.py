"""X-16.2: build the push candidate of the Module F Drafting Chain that makes the Draft Reviews rows writable.

Usage (from the repo root):
    python scripts/x16_candidate.py --id-sequence 203 --out <folder outside the repo>

Measured 2026-11-17 (T1 of specs/X-16.1-review-trail.md, run f9939a2e): Draft Reviews row 185 got Airtable 422 "Cannot
parse value" for Validator Detail, because Make hands the validator's JSONB detail over as an object. Its Resume handler
logged it and the run ended Success with no row. The six rows after the validator map the same value. From the committed
snapshot of scenario 7049689 (version 9) the candidate:

    inserts J, a json:TransformToJSON of {{11.detail}}, right after validator 11 on router 8 route 1, with [Logger, Resume]
    maps Validator Detail of rows 176, 179, 185, 191, 194 and 197 to {{J.json}}
    maps Validation ID of those six rows to {{parseNumber(11.ledger_id)}} and Grounding ID of those six and of row 200 to
    {{parseNumber(4.grounding_id)}} (BIGINT columns, which node-postgres hands over as text by default)

Router 8 changes in its child list only. Nothing else changes (specs/X-16.2-row-types.md, check E38 X-16.2).

--id-sequence is the scenario's live idSequence, so the new IDs sit above it (make_push refuses otherwise). Nothing here
writes to Make. The candidate goes to --out (refused inside the repo), because it holds the Logger hook URL copied from the
snapshot's own Logger calls.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import audit_blueprints as ab  # noqa: E402
import make_push as mp  # noqa: E402
import x32_candidate as xc  # noqa: E402

REPO = os.path.dirname(HERE)
FIX = "X-16.2"
SID = 7049689
VALIDATOR, GROUNDING, ROUTER, LOGGER_TEMPLATE = 11, 4, 8, 112
J_NAME = "Validator detail as JSON text (X-16.2)"


class BuildError(Exception):
    pass


def rows_of(bp: dict, pin: ab.X16Pin) -> dict:
    """{anchor update ID: Draft Reviews create ID} over the seven pinned routes."""
    idx = xc._index(bp)
    out = {}
    for anchor, router, route, *_rest in ab.X16_ROUTES:
        flow = idx[router]["routes"][route]["flow"]
        hits = [x["id"] for x in flow if x.get("module") == "airtable:ActionCreateRecord"
                and (x.get("mapper") or {}).get("table") == pin.table_id]
        if len(hits) != 1:
            raise BuildError(f"route {route + 1} of router {router} holds {len(hits)} Draft Reviews creates, not 1")
        out[anchor] = hits[0]
    return out


def build(live: dict, id_sequence: int, pin: ab.X16Pin) -> tuple[dict, dict]:
    cand = copy.deepcopy(live)
    idx = xc._index(cand)
    j_id, log_id, res_id = id_sequence + 1, id_sequence + 2, id_sequence + 3
    if any(i in idx for i in (j_id, log_id, res_id)):
        raise BuildError(f"module IDs {j_id} to {res_id} already exist in the snapshot")
    if LOGGER_TEMPLATE not in idx or idx[LOGGER_TEMPLATE].get("module") != "http:MakeRequest":
        raise BuildError(f"Logger template {LOGGER_TEMPLATE} is not an HTTP module in the snapshot")
    flow = idx[ROUTER]["routes"][0]["flow"]
    ids = [m.get("id") for m in flow]
    if VALIDATOR not in ids or ids[ids.index(VALIDATOR) + 1:ids.index(VALIDATOR) + 2] != [12]:
        raise BuildError(f"router {ROUTER} route 1 is not [..., {VALIDATOR}, 12, ...] ({ids})")
    xy = (idx[VALIDATOR].get("metadata") or {}).get("designer") or {"x": 0, "y": 0}
    x, y = xy.get("x", 0) + 150, xy.get("y", 0)
    j = {"id": j_id, "module": "json:TransformToJSON", "version": 1, "parameters": {},
         "mapper": {"object": f"{{{{{VALIDATOR}.detail}}}}"},
         "metadata": {"designer": {"x": x, "y": y, "name": J_NAME}}}
    j["onerror"] = [xc._logger_copy(idx[LOGGER_TEMPLATE], j_id, J_NAME, log_id, x, y + 150),
                    {"id": res_id, "mapper": {}, "module": "builtin:Resume", "version": 1,
                     "metadata": {"designer": {"x": x + 150, "y": y + 150}}, "parameters": {}}]
    flow.insert(ids.index(VALIDATOR) + 1, j)
    f = pin.fields
    rows = rows_of(cand, pin)
    changed = [ROUTER]
    for anchor, router, route, outcome, after_v, doc in ab.X16_ROUTES:
        rec = idx[rows[anchor]]["mapper"]["record"]
        rec[f["grounding_id"]] = f"{{{{parseNumber({GROUNDING}.grounding_id)}}}}"
        if after_v:
            rec[f["validation_id"]] = f"{{{{parseNumber({VALIDATOR}.ledger_id)}}}}"
            rec[f["validator_detail"]] = f"{{{{{j_id}.json}}}}"
        changed.append(rows[anchor])
    return cand, {"fix": FIX, "scenario": SID, "changed": sorted(changed), "added": [j_id, log_id, res_id], "j": j_id}


def main(argv: list[str] | None = None) -> int:
    from call_rows import _inside_repo  # noqa: E402  (same refusal as X-36.2)
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--id-sequence", type=int, required=True, help="live idSequence of scenario 7049689")
    ap.add_argument("--out", required=True, help="folder for the candidate, outside the repo")
    args = ap.parse_args(argv)
    out = os.path.abspath(args.out)
    if _inside_repo(out):
        print("--out must be outside the repo (a candidate is never committed)", file=sys.stderr)
        return 2
    try:
        pin = ab.load_x16(ab.DEFAULT_X16, required=True)
        live = json.load(open(mp.find_snapshot(os.path.join(REPO, "blueprints"), SID), encoding="utf-8"))
        cand, plan = build(live, args.id_sequence, pin)
    except (BuildError, mp.Abort, ab.InputError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "X-16.2-module-f-drafting-chain.candidate.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cand, fh, indent=2, ensure_ascii=False)
    print(f"candidate: {path}")
    print(f"changed {plan['changed']}, added {plan['added']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
