// X-32 regression suite: ff13.rank_exemplars, ff13.selections, ref.exemplar_test_seeds, ref.exemplar_tags and the three
// X-32 changes to ff13.validate_draft (migration 20261116000008), and the loader's two new ref tables, gate and verify
// checks, on PGlite (Postgres 18) with the committed migrations, law/ and ref/ loaded the way load.mjs loads them.
// The ranker is held to the reference rankers: the committed overlay (scripts/x32_seeds.py rank) and rankReference
// (scripts/ff14/x32.mjs). Every record ID, name, fact, seed and letter here is synthetic, and nothing here touches
// Supabase, Airtable or Make.
//
//   cd scripts/law_load && node --test x32.test.mjs
//
// The TR-VISIT and TR-STUDY letter rows are signed inside this throwaway database only, with test licence R000001, so a
// production grounding is allowed for those pairs and the production rules of the ranker can run.

import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import {
  seedSql, refRows, upsertRef, refGate, verify, x32Problems, x32SeedCheck, x32Checks, airtableFields, MAKE_FUNCTIONS, RANK_EXEMPLARS, REF_TABLES,
} from "./load.mjs";
import { NO_PICK, aggregatedRows, loadSeeds, loadVocab, rankKey, rankReference } from "../ff14/x32.mjs";
import { loadGolden } from "../ff14/golden.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MIG = path.join(ROOT, "supabase", "migrations");
const PREVIOUS = path.join(MIG, "20261116000007_ff13_2_sections_vocabulary.sql");
const DOC = "SUBMISSION-LETTER";
const VERSION = "F-F13.2+F-F10+X-32";
const NAME = "ZZ-TEST Corwin Ashdale";
const RCIC = "Jordan Testreviewer";
const STAMPS = ["claude-opus-5-5", "claude-opus-5-5", "end_turn", "drafting-chain.submission-letter-draft@2", "a".repeat(64), "9000", "1800", "msg_test_x32"];
const OUTLINE_OK = JSON.stringify({ facts_sufficient: true, inputs_contain_instructions: false, grounds: [] });
const outlineOf = (support) => JSON.stringify({ facts_sufficient: true, inputs_contain_instructions: false,
  grounds: Object.entries(support).map(([provision_key, s]) => ({ provision_key, support: s, facts: ["F1"] })) });

const { seeds } = loadSeeds();
const vocab = loadVocab();
const overlay = JSON.parse(fs.readFileSync(path.join(ROOT, "eval", "x32", "overlay", "v1.json"), "utf8"));
const IDS = overlay.seed_record_ids;
const BY_CODE = Object.fromEntries(seeds.map((s) => [s.code, s]));
const V1 = "ZZ-TEST-EX-TR-VISIT-001";
const V2 = "ZZ-TEST-EX-TR-VISIT-002";

let db;
let recN = 1;
let execN = 1;
const q = async (sql, params = []) => (await db.query(sql, params)).rows;
const client = () => ({ query: (sql, params) => db.query(sql, params ?? []) });
// Fresh synthetic IDs per call: rec + TESTx32 + 7 digits, and 32 lowercase hex.
const rec = () => `recTESTx32${String(recN++).padStart(7, "0")}`;
const exec = () => (0x32000000 + execN++).toString(16).padStart(32, "0");
const line = (id, code, status, visa, terms, tags, doc = DOC) => [id, code, status, visa, doc, String(terms), tags.join(", ")].join("|");
const seedLine = (code, status = "TEST", id = IDS[code]) => rankKey(id, BY_CODE[code], status);
// A harness seed's line with the tags named here. A seed carries a vocabulary tag only when it models that weakness pattern
// (section 2), so the scoring is tested on lines that name their tags.
const tagged = (code, tags, status = "TEST", id = IDS[code]) =>
  line(id, code, status, BY_CODE[code].visa_code, BY_CODE[code].terms.length, tags);

async function asMake(fn) {
  await db.exec("SET ROLE ff13_make");
  try {
    return await fn();
  } finally {
    await db.exec("RESET ROLE");
  }
}
async function inTx(fn) {
  await db.exec("BEGIN");
  try {
    return await fn();
  } finally {
    await db.exec("ROLLBACK");
  }
}

async function listRecord(r) {
  await q(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on)
           VALUES ($1, (now() AT TIME ZONE 'America/Toronto')::date, (now() AT TIME ZONE 'America/Toronto')::date + 1)`, [r]);
}
// A grounded record and execution, as ff13_make. mode test lists the record and ticks the flag, production does neither.
async function grounded(visa, mode = "test", doc = DOC) {
  const r = rec();
  const e = exec();
  if (mode === "test") await listRecord(r);
  const [g] = await asMake(() => q("SELECT * FROM ff13.drafting_context($1, $2, $3, $4, $5)", [r, e, visa, doc, mode === "test" ? "true" : "false"]));
  return { r, e, g };
}
async function rank(t, visa, outline, candidates, doc = DOC) {
  const [x] = await asMake(() => q("SELECT * FROM ff13.rank_exemplars($1, $2, $3, $4, $5, $6)", [t.r, t.e, visa, doc, outline, candidates]));
  return { ...x, flagList: JSON.parse(x.flags) };
}
const selection = async (id) => (await q("SELECT * FROM ff13.selections WHERE id = $1", [id]))[0];
async function validate(t, visa, draft, { terms = "", facts = "Facts only.", name = NAME } = {}) {
  const [r] = await asMake(() => q("SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    [t.r, t.e, visa, DOC, draft, name, facts, terms, ...STAMPS]));
  return r;
}
const hard = (r) => r.detail.hard_fails.map((e) => e.check);
const soft = (r) => r.detail.soft_flags.map((e) => e.check);
const letter = (body) => [`Draft for review by RCIC ${RCIC}. Not for submission until the RCIC of record has reviewed and signed it.`,
  `Re: Application of ${NAME}`, "Dear Officer,", "Introduction", body, "Background", "The applicant works and lives at home.",
  "Legal framework", "The provisions set the requirements.", "Submissions", "The facts meet them.", "Conclusion",
  "The officer is asked to approve the application.", "Respectfully submitted,", RCIC].join("\n\n");

before(async () => {
  db = await PGlite.create();
  await db.exec(`CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;
                 CREATE ROLE authenticator NOINHERIT;`);
  for (const f of fs.readdirSync(MIG).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(fs.readFileSync(path.join(MIG, f), "utf8"));
  }
  const seed = seedSql();
  const ref = refRows();
  await db.exec(seed.head);
  await upsertRef(client(), ref);
  await db.exec(seed.tail);
  assert.deepEqual(await refGate(client(), ref), []);
  await db.exec("COMMIT");
  await db.exec(`
    UPDATE ref.citation_map m SET reviewed_by_licence = 'R000001', reviewed_on = '2026-11-16', reviewed_text_sha256 = p.text_sha256,
           reviewed_row_sha256 = ref.citation_row_sha256(m.document_type, m.visa_code, m.provision_key, m.purpose)
      FROM law.provisions p
     WHERE p.key = m.provision_key AND m.document_type = '${DOC}' AND m.visa_code IN ('TR-VISIT', 'TR-STUDY')`);
  // The harness seed IDs of the overlay, listed in this throwaway database only.
  for (const [code, id] of Object.entries(IDS)) {
    await q("INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ($1, $2, '2026-11-16')", [id, code]);
  }
  // The previous validator, to prove a call without a selection row validates exactly as before.
  const prev = fs.readFileSync(PREVIOUS, "utf8");
  const start = prev.indexOf("CREATE OR REPLACE FUNCTION ff13.validate_draft(");
  const body = prev.slice(start, prev.indexOf("\n$$;\n", start) + 5);
  // In a schema of its own, so the law, ref and ff13 definer and grant checks below see only the migrations' functions.
  await db.exec("CREATE SCHEMA x32prev; REVOKE ALL ON SCHEMA x32prev FROM PUBLIC;");
  await db.exec(body.replace("CREATE OR REPLACE FUNCTION ff13.validate_draft(", "CREATE FUNCTION x32prev.validate_draft_prev("));
});

// --- The ranker ---------------------------------------------------------------------------------------------------------

test("test mode picks a listed TEST seed, records one selection row of IDs, keys, counts and flags, and returns none otherwise", async () => {
  const t = await grounded("TR-VISIT");
  assert.equal(t.g.allowed, "true");
  const x = await rank(t, "TR-VISIT", outlineOf({ "IRPR 183(2)": "partly_supported", "IRPR 179(b)": "supported" }),
    [tagged(V1, ["home-ties-thin"]), tagged(V2, ["stay-funds-modest"])].join("\n"));
  assert.deepEqual([x.exemplar_record_id, x.exemplar_code, x.score, x.candidate_count, x.eligible_count], [IDS[V2], V2, 1, 2, 2]);
  assert.deepEqual(x.flagList, ["test_mode"]);
  const row = await selection(x.selection_id);
  assert.deepEqual([row.airtable_record_id, row.make_execution_id, row.gate_mode, row.exemplar_record_id, row.exemplar_code, row.score,
    row.term_count, row.weak_keys, row.function_version], [t.r, t.e, "test", IDS[V2], V2, 1, BY_CODE[V2].terms.length, ["IRPR 183(2)"], "X-32"]);
  assert.equal(row.grounding_id, t.g.grounding_id);
  // Values only: the column name supported_keys is not outline text (2026-11-19).
  const raw = JSON.stringify(Object.values(row));
  for (const s of [...BY_CODE[V2].terms, "Introduction", "supported", "facts_sufficient"]) assert.ok(!raw.includes(s), `selection row holds ${s}`);
});

test("ties break by code, then by record ID in byte order, and a score of 0 still selects", async () => {
  const t = await grounded("TR-VISIT");
  const lines = [seedLine(V2), seedLine(V1)].join("\n");
  const x = await rank(t, "TR-VISIT", OUTLINE_OK, lines);
  assert.deepEqual([x.exemplar_code, x.score], [V1, 0]);
  // Same code under two IDs: the lower ID in byte order (upper case first).
  await q("INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recTESTx32tiesxxa', $1, '2026-11-16'), ('recTESTx32tiesxxB', $1, '2026-11-16')", [V1]);
  const twin = [seedLine(V1, "TEST", "recTESTx32tiesxxa"), seedLine(V1, "TEST", "recTESTx32tiesxxB")].join("\n");
  const y = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, twin);
  assert.equal(y.exemplar_record_id, "recTESTx32tiesxxB");
});

test("conflicts first: a seed whose tags leave out a supported ground loses to one that does not, even at a higher score", async () => {
  // Decided by Rizwan 2026-11-19 (specs/X-32-exemplars.md). A tag says the letter leaves its keys out, so a supported key
  // it addresses is a conflict. home-ties-thin addresses IRPR 179(b), stay-funds-modest IRPR 183(2).
  const supported179 = outlineOf({ "IRPR 179(b)": "supported", "IRPR 183(2)": "not_supported" });
  // The tie at 0 that sent ff14-018 the outland letter: V1 (the lower code) conflicts, so the bare V2 wins.
  const tie = await rank(await grounded("TR-VISIT"), "TR-VISIT", outlineOf({ "IRPR 179(b)": "supported" }),
    [tagged(V1, ["home-ties-thin"]), seedLine(V2)].join("\n"));
  assert.deepEqual([tie.exemplar_code, tie.score], [V2, 0]);
  const row = await selection(tie.selection_id);
  assert.deepEqual([row.supported_keys, row.conflicts, row.weak_keys], [["IRPR 179(b)"], 0, []]);
  // Conflicts outrank the score: V1 covers the weak 183(2) but leaves out the supported 179(b).
  const x = await rank(await grounded("TR-VISIT"), "TR-VISIT", supported179,
    [tagged(V1, ["home-ties-thin", "stay-funds-modest"]), seedLine(V2)].join("\n"));
  assert.deepEqual([x.exemplar_code, x.score], [V2, 0]);
  // Both seeds conflict once: the score decides, and the pick still selects (a case always gets an exemplar).
  const y = await rank(await grounded("TR-VISIT"), "TR-VISIT", supported179,
    [tagged(V1, ["home-ties-thin", "stay-funds-modest"]), tagged(V2, ["home-ties-thin", "first-trip-abroad"])].join("\n"));
  assert.deepEqual([y.exemplar_code, y.score], [V1, 1]);
  assert.equal((await selection(y.selection_id)).conflicts, 1);
  // Fewer non-zero conflicts win over the lower code: V1 leaves out both supported keys, V2 only 179(b).
  const both = outlineOf({ "IRPR 179(b)": "supported", "IRPR 183(2)": "supported" });
  const w = await rank(await grounded("TR-VISIT"), "TR-VISIT", both,
    [tagged(V1, ["home-ties-thin", "stay-funds-modest"]), tagged(V2, ["first-trip-abroad"])].join("\n"));
  assert.deepEqual([w.exemplar_code, w.score], [V2, 0]);
  assert.equal((await selection(w.selection_id)).conflicts, 1);
  // A supported ground the grounding did not provide is no conflict.
  const z = await rank(await grounded("TR-VISIT"), "TR-VISIT", outlineOf({ "IRPR 216(1)(b)": "supported" }),
    [tagged(V1, ["home-ties-thin"]), seedLine(V2)].join("\n"));
  assert.deepEqual([z.exemplar_code, (await selection(z.selection_id)).supported_keys], [V1, []]);
});

test("the score counts distinct weak keys, not tags", async () => {
  // Two TR-VISIT tags that both address IRPR 179(b): two tags, one key.
  const two = tagged(V1, ["home-ties-thin", "first-trip-abroad"]);
  const t = await grounded("TR-VISIT");
  const x = await rank(t, "TR-VISIT", outlineOf({ "IRPR 179(b)": "not_supported" }), two);
  assert.deepEqual([x.exemplar_code, x.score], [V1, 1]);
  // A seed with no tag scores 0 and is still selected.
  const bare = await rank(await grounded("TR-VISIT"), "TR-VISIT", outlineOf({ "IRPR 179(b)": "not_supported" }), seedLine(V1));
  assert.deepEqual([bare.exemplar_code, bare.score], [V1, 0]);
  // A ground the grounding did not provide is not a weak key.
  const y = await rank(await grounded("TR-VISIT"), "TR-VISIT", outlineOf({ "IRPR 216(1)(b)": "not_supported" }), two);
  assert.equal(y.score, 0);
  assert.deepEqual((await selection(y.selection_id)).weak_keys, []);
});

test("test mode refuses an Active row, an unlisted seed, a retired seed and a seed listed under another code", async () => {
  const lines = (status, id = IDS[V1]) => seedLine(V1, status, id);
  for (const [what, cands] of [["Active", lines("Active")], ["Pending Review", lines("Pending Review")],
    ["unlisted", lines("TEST", "recTESTx32unlistd")], ["EX code", line(IDS[V1], "EX-TR-VISIT-001", "TEST", "TR-VISIT", 2, ["home-ties-thin"])]]) {
    const x = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, cands);
    assert.deepEqual([x.exemplar_record_id, x.exemplar_code, x.eligible_count], [NO_PICK, "", 0], what);
    assert.ok(x.flagList.includes("test_mode"), what);
  }
  await inTx(async () => {
    await q("UPDATE ref.exemplar_test_seeds SET retired_on = '2026-11-16' WHERE airtable_record_id = $1", [IDS[V1]]);
    const x = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, lines("TEST"));
    assert.equal(x.exemplar_record_id, NO_PICK);
    // The other seed of the cell is still picked: the test plan's X4.
    const y = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, [lines("TEST"), seedLine(V2)].join("\n"));
    assert.equal(y.exemplar_code, V2);
  });
  await inTx(async () => {
    await q("INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recTESTx32othercd', 'ZZ-TEST-EX-TR-VISIT-777', '2026-11-16')");
    const x = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, seedLine(V1, "TEST", "recTESTx32othercd"));
    assert.equal(x.exemplar_record_id, NO_PICK);
  });
});

test("production refuses a TEST status, a ZZ-TEST- code and a listed ID, each alone, for the whole run", async () => {
  const p = await grounded("TR-VISIT", "production");
  assert.deepEqual([p.g.allowed, p.g.gate_mode], ["true", "production"]);
  const active = line("recTESTx32prodok1", "EX-TR-VISIT-001", "Active", "TR-VISIT", 2, ["home-ties-thin"]);
  const ok = await rank(p, "TR-VISIT", OUTLINE_OK, active);
  assert.deepEqual([ok.exemplar_record_id, ok.exemplar_code], ["recTESTx32prodok1", "EX-TR-VISIT-001"]);
  assert.ok(!ok.flagList.includes("test_mode"));
  for (const [what, bad] of [
    ["TEST status", line("recTESTx32prodbd1", "EX-TR-VISIT-002", "TEST", "TR-VISIT", 2, ["home-ties-thin"])],
    ["Pending Review", line("recTESTx32prodbd2", "EX-TR-VISIT-002", "Pending Review", "TR-VISIT", 2, ["home-ties-thin"])],
    ["ZZ-TEST- code", line("recTESTx32prodbd3", "ZZ-TEST-EX-TR-VISIT-002", "Active", "TR-VISIT", 2, ["home-ties-thin"])],
    ["listed ID", line(IDS[V2], "EX-TR-VISIT-002", "Active", "TR-VISIT", 2, ["home-ties-thin"])]]) {
    // The good row first: the refusal still stops the whole run.
    const x = await rank(await grounded("TR-VISIT", "production"), "TR-VISIT", OUTLINE_OK, [active, bad].join("\n"));
    assert.deepEqual([x.exemplar_record_id, x.exemplar_code, x.eligible_count], [NO_PICK, "", 0], what);
    assert.ok(x.flagList.includes("test_seed_in_production"), what);
  }
  // A retired listing is still refused in production.
  await inTx(async () => {
    await q("UPDATE ref.exemplar_test_seeds SET retired_on = '2026-11-16' WHERE airtable_record_id = $1", [IDS[V2]]);
    const x = await rank(await grounded("TR-VISIT", "production"), "TR-VISIT", OUTLINE_OK, line(IDS[V2], "EX-TR-VISIT-002", "Active", "TR-VISIT", 2, ["home-ties-thin"]));
    assert.ok(x.flagList.includes("test_seed_in_production"));
  });
  // The table itself refuses a TEST seed code selected in production.
  await inTx(async () => {
    await assert.rejects(q(`INSERT INTO ff13.selections (gate_mode, candidate_count, eligible_count, exemplar_record_id, exemplar_code, score, term_count,
                             weak_keys, supported_keys, conflicts, flags, function_version)
                             VALUES ('production', 1, 1, 'recTESTx32prodbd4', 'ZZ-TEST-EX-TR-VISIT-001', 0, 1, '{}', '{}', 0, '[]', 'X-32')`),
    (e) => e.code === "23514");
  });
});

test("production scores signed tag rows only, an unreviewed tag is unknown", async () => {
  const active = line("recTESTx32prodok2", "EX-TR-VISIT-003", "Active", "TR-VISIT", 1, ["stay-funds-modest"]);
  const x = await rank(await grounded("TR-VISIT", "production"), "TR-VISIT", outlineOf({ "IRPR 183(2)": "partly_supported" }), active);
  assert.deepEqual([x.exemplar_code, x.score, x.flagList.includes("unknown_tag")], ["EX-TR-VISIT-003", 0, true]);
  await inTx(async () => {
    await q("UPDATE ref.exemplar_tags SET review_state = 'reviewed', reviewer_licence = 'R000001', reviewed_on = '2026-11-16' WHERE tag = 'stay-funds-modest' AND visa_code = 'TR-VISIT'");
    const y = await rank(await grounded("TR-VISIT", "production"), "TR-VISIT", outlineOf({ "IRPR 183(2)": "partly_supported" }), active);
    assert.deepEqual([y.score, y.flagList.includes("unknown_tag")], [1, false]);
  });
});

test("no grounding, a refused grounding, another pair, an excluded cell, a NO DRAFT or unreadable outline all select none", async () => {
  const cands = [seedLine(V1), seedLine(V2)].join("\n");
  const none = async (t, visa, outline, flag, doc = DOC) => {
    const x = await rank(t, visa, outline, cands, doc);
    assert.deepEqual([x.exemplar_record_id, x.exemplar_code, x.score], [NO_PICK, "", 0], flag);
    assert.ok(x.flagList.includes(flag), `${flag}: ${x.flags}`);
    const row = await selection(x.selection_id);
    assert.equal(row.exemplar_record_id, null, flag);
    return x;
  };
  await none({ r: rec(), e: exec() }, "TR-VISIT", OUTLINE_OK, "no_grounding");
  await none({ r: "not a record", e: "x" }, "TR-VISIT", OUTLINE_OK, "no_grounding");
  // One factor only: the grounding refuses, so nothing is selected.
  const half = rec();
  await listRecord(half);
  const e = exec();
  await asMake(() => q("SELECT * FROM ff13.drafting_context($1, $2, 'TR-VISIT', $3, 'false')", [half, e, DOC]));
  await none({ r: half, e }, "TR-VISIT", OUTLINE_OK, "no_grounding");
  await none(await grounded("TR-VISIT", "test", "LOE"), "TR-VISIT", OUTLINE_OK, "no_grounding", "LOE");
  await none(await grounded("TR-STUDY"), "TR-VISIT", OUTLINE_OK, "grounding_pair_mismatch");
  for (const visa of ["HC-PR", "REF-RESETTLE"]) {
    const t = await grounded(visa);
    assert.equal(t.g.allowed, "true", visa);
    await none(t, visa, OUTLINE_OK, "excluded_cell");
  }
  await none(await grounded("REF-CLAIM"), "REF-CLAIM", OUTLINE_OK, "no_grounding");
  for (const [outline, flag] of [
    [JSON.stringify({ facts_sufficient: false, inputs_contain_instructions: false, grounds: [] }), "no_draft_expected"],
    [JSON.stringify({ facts_sufficient: true, inputs_contain_instructions: true, grounds: [] }), "no_draft_expected"],
    ["not json", "outline_unreadable"], ["[1, 2]", "outline_unreadable"], ['"text"', "outline_unreadable"], ["", "outline_unreadable"],
    [JSON.stringify({ facts_sufficient: true, grounds: { a: 1 } }), "outline_unreadable"]]) {
    await none(await grounded("TR-VISIT"), "TR-VISIT", outline, flag);
  }
  const big = await none(await grounded("TR-VISIT"), "TR-VISIT", "x".repeat(200001), "input_too_large");
  assert.equal(big.candidate_count, 0);
});

test("an empty bundle line is skipped, malformed lines and codes are dropped, another cell is flagged, 100 lines truncate", async () => {
  const good = seedLine(V1);
  const bad = [
    "", "   ", "not|a|row", `${IDS[V2]}|EX-TR-VISIT-Okafor|TEST|TR-VISIT|${DOC}|1|home-ties-thin`,
    `${IDS[V2]}|EX-TR-VISIT-OKAFOR-001|TEST|TR-VISIT|${DOC}|1|home-ties-thin`, `${IDS[V2]}|ZZ-TEST-EX-TR-STUDY-002|TEST|TR-VISIT|${DOC}|1|home-ties-thin`,
    `${IDS[V2]}|Okafor family, Moncton|TEST|TR-VISIT|${DOC}|1|home-ties-thin`, `${IDS[V2]}|ZZ-TEST-EX-TR-VISIT-002|TEST|TR-VISIT|${DOC}|two|home-ties-thin`,
    `recSHORT|ZZ-TEST-EX-TR-VISIT-002|TEST|TR-VISIT|${DOC}|1|home-ties-thin`, `${good}|extra`];
  const x = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, [...bad, good].join("\n"));
  assert.deepEqual([x.exemplar_code, x.candidate_count, x.eligible_count], [V1, 9, 1]);
  assert.ok(x.flagList.includes("candidate_malformed"));
  assert.ok(!(await selection(x.selection_id)).flags.some((f) => /Okafor|Moncton/.test(f)));
  // Only empty lines: the search's one empty bundle.
  const empty = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, "");
  assert.deepEqual([empty.exemplar_record_id, empty.candidate_count, empty.flagList], [NO_PICK, 0, ["test_mode"]]);
  const cross = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, seedLine("ZZ-TEST-EX-TR-STUDY-001"));
  assert.deepEqual([cross.exemplar_record_id, cross.flagList.includes("cross_cell_candidate")], [NO_PICK, true]);
  const zero = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, line(IDS[V1], V1, "TEST", "TR-VISIT", 0, ["home-ties-thin"]));
  assert.equal(zero.exemplar_record_id, NO_PICK);
  const many = Array.from({ length: 99 }, () => "x|y").concat(good).join("\n");
  const full = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, many);
  assert.deepEqual([full.exemplar_code, full.candidate_count, full.flagList.includes("candidates_truncated")], [V1, 100, true]);
  const fewer = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, Array.from({ length: 98 }, () => "x|y").concat(good).join("\n"));
  assert.ok(!fewer.flagList.includes("candidates_truncated"));
});

test("hostile input: exactly one row, never raises, and nothing but codes reaches the selection row", async () => {
  for (const args of [[null, null, null, null, null, null], ["x".repeat(200000), "y".repeat(200000), "z".repeat(200000), DOC, "o".repeat(300000), "c".repeat(300000)],
    ["'; DROP TABLE ff13.selections; --", exec(), "TR-VISIT", DOC, "{", "|||||||"], [rec(), exec(), "TR-VISIT'); --", DOC, OUTLINE_OK, seedLine(V1)]]) {
    const rows = await asMake(() => q("SELECT * FROM ff13.rank_exemplars($1, $2, $3, $4, $5, $6)", args));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].exemplar_record_id, NO_PICK);
  }
  assert.ok((await q("SELECT to_regclass('ff13.selections') IS NOT NULL AS ok"))[0].ok);
  // A failure inside the body (a CHECK added for this test only rejects the pick's row): the ranker answers none with
  // ranker_error and still writes its row.
  await inTx(async () => {
    await q("ALTER TABLE ff13.selections ADD CONSTRAINT x32_test_fail CHECK (score IS NULL) NOT VALID");
    const x = await rank(await grounded("TR-VISIT"), "TR-VISIT", OUTLINE_OK, seedLine(V1));
    assert.deepEqual([x.exemplar_record_id, x.exemplar_code, x.flagList], [NO_PICK, "", ["ranker_error", "test_mode"]]);
    assert.deepEqual((await selection(x.selection_id)).flags, ["ranker_error", "test_mode"]);
  });
});

// --- Held to the reference rankers -----------------------------------------------------------------------------------------

test("every golden case picks what the committed overlay (scripts/x32_seeds.py rank) says, from its expected support labels", async () => {
  let picked = 0;
  for (const c of loadGolden()) {
    const want = overlay.cases[c.id];
    assert.ok(want, c.id);
    const e = c.expected || {};
    if (!(e.grounding?.allowed === "true" && e.outcome === "letter" && c.kind !== "control")) continue;
    const visa = c.inputs.visa_code;
    const t = await grounded(visa);
    assert.equal(t.g.allowed, "true", c.id);
    const agg = aggregatedRows(seeds, IDS, visa, c.inputs.document_code);
    const x = await rank(t, visa, outlineOf(e.support || {}), agg.map((a) => a.rank_key).join("\n"));
    assert.equal(x.exemplar_code || null, want.pick, `${c.id}: ${x.flags}`);
    if (want.pick) {
      assert.equal(x.score, want.score, c.id);
      assert.equal((await selection(x.selection_id)).conflicts, want.conflicts, c.id);
      assert.equal(x.exemplar_record_id, IDS[want.pick], c.id);
      picked++;
    } else {
      assert.equal(x.exemplar_record_id, NO_PICK, c.id);
    }
  }
  assert.ok(picked >= 4, `${picked} golden cases picked a seed`);
  // The NO DRAFT negatives select nothing (X6), whatever the cell holds.
  for (const id of ["ff14-024", "ff14-025"]) {
    const c = loadGolden().find((k) => k.id === id);
    const x = await rank(await grounded(c.inputs.visa_code), c.inputs.visa_code,
      JSON.stringify({ facts_sufficient: id !== "ff14-024", inputs_contain_instructions: id === "ff14-025", grounds: [] }),
      aggregatedRows(seeds, IDS, c.inputs.visa_code, DOC).map((a) => a.rank_key).join("\n"));
    assert.equal(x.exemplar_record_id, NO_PICK, id);
  }
});

// A small deterministic generator (mulberry32), so the cases are the same on every run.
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("the database ranker equals rankReference (scripts/ff14/x32.mjs) on 120 generated candidate sets, both modes", async () => {
  const rnd = prng(32);
  const pick = (list) => list[Math.floor(rnd() * list.length)];
  const cmap = refRows().citation_map;
  const signedTag = { tag: "stay-funds-modest", visa_code: "TR-VISIT" };
  const prodVocab = vocab.map((v) => (v.tag === signedTag.tag && v.visa_code === signedTag.visa_code ? { ...v, review_state: "reviewed" } : v));
  await q("UPDATE ref.exemplar_tags SET review_state = 'reviewed', reviewer_licence = 'R000001', reviewed_on = '2026-11-16' WHERE tag = $1 AND visa_code = $2",
    [signedTag.tag, signedTag.visa_code]);
  try {
    for (let n = 0; n < 120; n++) {
      const mode = n % 3 === 0 ? "production" : "test";
      const visa = pick(["TR-VISIT", "TR-STUDY"]);
      const keys = cmap.filter((r) => r.visa_code === visa && r.document_type === DOC).map((r) => r.provision_key);
      const weak = keys.filter(() => rnd() < 0.35);
      // Supported keys too, so the conflicts-first order (2026-11-19) is held to the reference as well.
      const strong = keys.filter((k) => !weak.includes(k) && rnd() < 0.5);
      const tagsOf = (v) => vocab.filter((x) => x.visa_code === v).map((x) => x.tag);
      const lines = [];
      const count = 1 + Math.floor(rnd() * 6);
      for (let i = 0; i < count; i++) {
        const kind = rnd();
        const lv = rnd() < 0.85 ? visa : pick(["TR-VISIT", "TR-STUDY"]);
        const tags = [...tagsOf(lv), "no-such-tag"].filter(() => rnd() < 0.4);
        if (kind < 0.1) {
          lines.push(pick(["", "  ", "junk|line", `${IDS[V1]}|EX-${lv}-Okafor|TEST|${lv}|${DOC}|1|`]));
        } else if (kind < 0.55) {
          // A harness seed of the line's cell: listed, TEST, or with another status.
          const code = pick(Object.keys(IDS).filter((k) => BY_CODE[k].visa_code === lv)) || V1;
          lines.push(line(IDS[code], code, pick(["TEST", "TEST", "Active", "Pending Review"]), BY_CODE[code].visa_code, pick([0, 1, 2, 3]), tags));
        } else {
          // A real-looking Active row, never listed.
          const id = `recTESTx32gen${String(n * 10 + i).padStart(4, "0")}`;
          const code = `${rnd() < 0.2 ? "ZZ-TEST-" : ""}EX-${lv}-${String(100 + Math.floor(rnd() * 5)).padStart(3, "0")}`;
          lines.push(line(id, code, pick(["Active", "Active", "TEST"]), lv, pick([0, 1, 2]), tags));
        }
      }
      const text = lines.join("\n");
      const t = await grounded(visa, mode);
      const labels = { ...Object.fromEntries(weak.map((k) => [k, pick(["not_supported", "partly_supported"])])),
        ...Object.fromEntries(strong.map((k) => [k, "supported"])) };
      const db1 = await rank(t, visa, outlineOf(labels), text);
      const listed = new Set(Object.values(IDS));
      const ref1 = rankReference(text, weak, visa, DOC, mode === "test" ? vocab : prodVocab, listed, mode, strong);
      const strip = (f) => [...new Set(f)].filter((x) => x !== "test_mode").sort();
      const conf = (await selection(db1.selection_id)).conflicts ?? 0;
      assert.deepEqual([db1.exemplar_record_id, db1.exemplar_code, db1.score, conf, strip(db1.flagList)],
        [ref1.exemplar_record_id, ref1.exemplar_code, ref1.score, ref1.conflicts, strip(ref1.flags)], `case ${n} (${mode})\n${text}\nweak ${weak}`);
    }
  } finally {
    await q("UPDATE ref.exemplar_tags SET review_state = 'unreviewed', reviewer_licence = NULL, reviewed_on = NULL WHERE tag = $1 AND visa_code = $2",
      [signedTag.tag, signedTag.visa_code]);
  }
});

// --- The seeds through the validator ---------------------------------------------------------------------------------------

test("every seed skeleton, its placeholders filled, follows the F-F13.2 sections and holds no citation or citation-like text", async () => {
  assert.equal(seeds.length, 19);
  const bad = ["section_missing", "section_out_of_order", "section_empty", "unresolved_reference", "fabricated_citation", "not_in_force",
    "forbidden_content", "placeholder", "unreadable_character", "mixed_script", "below_word_floor", "applicant_name_absent"];
  for (const s of seeds) {
    const text = s.skeleton.replace("[ZZ-TEST SEED] ", "").replaceAll("[RCIC OF RECORD]", RCIC).replaceAll("[APPLICANT NAME]", NAME)
      .replaceAll(" [CITATION]", "").replace(/\[[A-Z][A-Z ]*[A-Z]\]/g, "Zed");
    const r = await validate({ r: rec(), e: exec() }, s.visa_code, text);
    assert.deepEqual(hard(r).filter((c) => bad.includes(c)), [], `${s.code}: ${r.review_note}`);
    assert.deepEqual(r.detail.citations, [], s.code);
    assert.ok(!soft(r).some((c) => c.startsWith("vocabulary_")), `${s.code}: ${r.review_note}`);
  }
});

// --- The validator ---------------------------------------------------------------------------------------------------------

test("@08 cross-check: the selected seed's terms pass, a missing or extra term fails, fold-empty lines do not count", async () => {
  const t = await grounded("TR-VISIT");
  const x = await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V2));
  assert.equal(x.exemplar_code, V2);
  const terms = BY_CODE[V2].terms;
  const draft = letter("A visit of three weeks.");
  const okay = await validate(t, "TR-VISIT", draft, { terms: terms.join("\n") });
  assert.ok(!hard(okay).some((c) => c.startsWith("exemplar_")), okay.review_note);
  const padded = await validate(t, "TR-VISIT", draft, { terms: `${terms.join("\r\n")}\n\n  \n_` });
  assert.ok(!hard(padded).some((c) => c.startsWith("exemplar_")), padded.review_note);
  const fewer = await validate(t, "TR-VISIT", draft, { terms: terms.slice(1).join("\n") });
  const m = fewer.detail.hard_fails.find((e) => e.check === "exemplar_terms_mismatch");
  assert.ok(m, fewer.review_note);
  assert.equal(m.info, `${terms.length - 1} term line(s), the selection recorded ${terms.length}`);
  assert.ok(hard(await validate(t, "TR-VISIT", draft, { terms: [...terms, "Extra Term"].join("\n") })).includes("exemplar_terms_mismatch"));
  assert.ok(hard(await validate(t, "TR-VISIT", draft, { terms: "" })).includes("exemplar_terms_mismatch"));
  // The ledger keeps the check code and its counts, never a term.
  const row = (await q("SELECT hard_fails::text AS h FROM ff13.validations WHERE id = $1", [fewer.ledger_id]))[0];
  for (const s of terms) assert.ok(!row.h.includes(s));
});

test("@08 cross-check: a selection of none needs an empty @08", async () => {
  const t = await grounded("TR-VISIT");
  const x = await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V1, "TEST", "recTESTx32unlistd"));
  assert.equal(x.exemplar_record_id, NO_PICK);
  const draft = letter("A visit of three weeks.");
  const bad = await validate(t, "TR-VISIT", draft, { terms: "Some Term" });
  assert.ok(hard(bad).includes("exemplar_terms_unexpected"), bad.review_note);
  const good = await validate(t, "TR-VISIT", draft, { terms: "" });
  assert.ok(!hard(good).some((c) => c.startsWith("exemplar_")), good.review_note);
  assert.ok(good.review_note.endsWith("\nExemplar used: none"), good.review_note);
  assert.deepEqual([good.detail.exemplar_code, good.detail.exemplar_term_count, good.detail.selection_id], [null, 0, x.selection_id]);
});

test("the newest selection of the same record and execution is the one checked, another execution's is not", async () => {
  const t = await grounded("TR-VISIT");
  await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V1, "TEST", "recTESTx32unlistd"));
  const x = await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V1));
  const r = await validate(t, "TR-VISIT", letter("A visit."), { terms: BY_CODE[V1].terms.join("\n") });
  assert.equal(r.detail.selection_id, x.selection_id);
  assert.ok(!hard(r).some((c) => c.startsWith("exemplar_terms_")), r.review_note);
  // Same record, another execution with only a grounding: no selection, no X-32 rule.
  const other = { r: t.r, e: exec() };
  await asMake(() => q("SELECT * FROM ff13.drafting_context($1, $2, 'TR-VISIT', $3, 'true')", [other.r, other.e, DOC]));
  const s = await validate(other, "TR-VISIT", letter("A visit."), { terms: "Unrelated Term" });
  assert.ok(!("selection_id" in s.detail));
  assert.ok(!hard(s).some((c) => c.startsWith("exemplar_terms_")));
});

test("a term the case facts also hold is a soft flag with a selection row, and a hard leak without one or when the facts lack it", async () => {
  const term = BY_CODE[V1].terms[0];
  const draft = letter(`The applicant works with the ${term} in the home country.`);
  const t = await grounded("TR-VISIT");
  await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V1));
  const shared = await validate(t, "TR-VISIT", draft, { terms: BY_CODE[V1].terms.join("\n"), facts: `Works with the ${term} since last year.` });
  assert.ok(!hard(shared).includes("exemplar_leak"), shared.review_note);
  const flag = shared.detail.soft_flags.find((e) => e.check === "exemplar_term_in_facts");
  assert.ok(flag, shared.review_note);
  assert.equal(flag.info, "term 1");
  assert.equal(draft.substr(flag.offset, term.length), term);
  const leak = await validate(t, "TR-VISIT", draft, { terms: BY_CODE[V1].terms.join("\n"), facts: "Facts that name no exemplar detail." });
  assert.ok(hard(leak).includes("exemplar_leak"), leak.review_note);
  assert.ok(!soft(leak).includes("exemplar_term_in_facts"));
  // No selection row for this execution: exactly the F-F13.2 rule, a hard leak even when the facts hold the term.
  const bare = { r: t.r, e: exec() };
  await asMake(() => q("SELECT * FROM ff13.drafting_context($1, $2, 'TR-VISIT', $3, 'true')", [bare.r, bare.e, DOC]));
  const today = await validate(bare, "TR-VISIT", draft, { terms: term, facts: `Works with the ${term}.` });
  assert.ok(hard(today).includes("exemplar_leak"));
  assert.ok(!soft(today).includes("exemplar_term_in_facts"));
});

test("the facts test keeps case: a common noun in the facts never excuses a proper noun in the draft (finding 2026-11-16)", async () => {
  const other = BY_CODE[V1].terms[1];
  const terms = `Mission\n${other}`;
  const draft = letter("The applicant is employed in Mission, British Columbia, and returns there.");
  const t = await grounded("TR-VISIT");
  await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V1));
  // The facts hold the word only as a common noun: a hard leak at the draft's occurrence, no soft flag.
  const noun = await validate(t, "TR-VISIT", draft, { terms, facts: "She volunteers with a church mission every weekend." });
  assert.ok(hard(noun).includes("exemplar_leak"), noun.review_note);
  assert.ok(!soft(noun).includes("exemplar_term_in_facts"), noun.review_note);
  assert.equal(noun.verdict, "reject");
  const leak = noun.detail.hard_fails.find((e) => e.check === "exemplar_leak");
  assert.equal(draft.substr(leak.offset, "Mission".length), "Mission");
  // The client's own town, written the same way: the soft flag.
  const town = await validate(t, "TR-VISIT", draft, { terms, facts: "She lives in Mission, British Columbia." });
  assert.ok(!hard(town).includes("exemplar_leak"), town.review_note);
  assert.ok(soft(town).includes("exemplar_term_in_facts"), town.review_note);
  // Facts in capitals do not excuse a draft in title case: it fails closed.
  const caps = await validate(t, "TR-VISIT", draft, { terms, facts: "Address: MISSION, BRITISH COLUMBIA." });
  assert.ok(hard(caps).includes("exemplar_leak"), caps.review_note);
  // Every occurrence counts: the town once as the facts write it and once in another case is still a leak, at the second.
  const twice = letter("The applicant lives in Mission and works at the MISSION depot.");
  const mixed = await validate(t, "TR-VISIT", twice, { terms, facts: "She lives in Mission, British Columbia." });
  const at = mixed.detail.hard_fails.find((e) => e.check === "exemplar_leak");
  assert.ok(at, mixed.review_note);
  assert.equal(twice.substr(at.offset, "MISSION".length), "MISSION");
  assert.ok(!soft(mixed).includes("exemplar_term_in_facts"));
  // A term whose whitespace differs in the draft is read as the draft writes it.
  const spaced = await validate(t, "TR-VISIT", letter(`The applicant lives in the ${other.replace(" ", "   ")}.`), { terms, facts: `Lives in the ${other}.` });
  assert.ok(!hard(spaced).includes("exemplar_leak"), spaced.review_note);
  assert.ok(soft(spaced).includes("exemplar_term_in_facts"));
});

test("the review note ends with the exemplar used and keeps its test-mode start, detail names the selection", async () => {
  const t = await grounded("TR-VISIT");
  const x = await rank(t, "TR-VISIT", OUTLINE_OK, seedLine(V2));
  const r = await validate(t, "TR-VISIT", letter("A visit."), { terms: BY_CODE[V2].terms.join("\n") });
  assert.ok(r.review_note.startsWith("F-F13 TEST MODE"), r.review_note);
  assert.equal(r.review_note.split("\n").at(-1), `Exemplar used: ${V2}`);
  assert.deepEqual([r.detail.exemplar_code, r.detail.exemplar_term_count, r.detail.selection_id, r.detail.validator_version],
    [V2, BY_CODE[V2].terms.length, x.selection_id, VERSION]);
  assert.equal((await q("SELECT validator_version FROM ff13.validations WHERE id = $1", [r.ledger_id]))[0].validator_version, VERSION);
});

test("without a selection row the validator answers exactly as the F-F13.2+F-F10 one did", async () => {
  const term = BY_CODE[V1].terms[0];
  const drafts = [
    [letter("A visit of three weeks."), ""],
    [letter(`The applicant knows the ${term}.`), BY_CODE[V1].terms.join("\n")],
    [letter(`The applicant knows the ${term}, under IRPR 179(b).`), `${term}\n\nother`],
    [letter("[PLACEHOLDER] and a section 99 reference."), "x"],
    ["NO DRAFT PREPARED. The case facts support none of the provided grounds.", ""],
    ["", ""]];
  for (const mode of ["test", "production"]) {
    for (const [draft, terms] of drafts) {
      const t = await grounded("TR-VISIT", mode);
      const args = [t.r, t.e, "TR-VISIT", DOC, draft, NAME, `Knows the ${term}.`, terms, ...STAMPS];
      const [now] = await asMake(() => q("SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", args));
      const [was] = await q("SELECT * FROM x32prev.validate_draft_prev($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", args);
      const norm = (r) => ({ verdict: r.verdict, hard: r.hard_fail_count, soft: r.soft_flag_count,
        note: r.review_note.replace(/Ledger row \d+\./, "Ledger row N."),
        detail: { ...r.detail, ledger_id: null, validator_version: null } });
      assert.deepEqual(norm(now), norm(was), `${mode}: ${draft.slice(0, 60)}`);
      assert.equal(now.detail.validator_version, VERSION);
    }
  }
});

// --- Tables, grants and the loader -----------------------------------------------------------------------------------------

test("ff13.selections is append-only and ref.exemplar_test_seeds retire-only, for the owner too", async () => {
  for (const sql of ["UPDATE ff13.selections SET score = 0", "DELETE FROM ff13.selections", "TRUNCATE ff13.selections"]) {
    await inTx(() => assert.rejects(q(sql), /append-only/, sql));
  }
  await inTx(async () => {
    await db.exec("SET session_replication_role = replica");
    await assert.rejects(q("DELETE FROM ff13.selections"), /append-only/);
  });
  for (const sql of ["DELETE FROM ref.exemplar_test_seeds", "TRUNCATE ref.exemplar_test_seeds"]) {
    await inTx(() => assert.rejects(q(sql), /never deleted/, sql));
  }
  for (const sql of [`UPDATE ref.exemplar_test_seeds SET exemplar_code = 'ZZ-TEST-EX-TR-VISIT-555' WHERE airtable_record_id = '${IDS[V1]}'`,
    `UPDATE ref.exemplar_test_seeds SET added_on = added_on - 1 WHERE airtable_record_id = '${IDS[V1]}'`]) {
    await inTx(() => assert.rejects(q(sql), /keeps its record ID, exemplar_code and added_on/, sql));
  }
  await inTx(async () => {
    await q("UPDATE ref.exemplar_test_seeds SET retired_on = '2026-11-17' WHERE airtable_record_id = $1", [IDS[V1]]);
    await assert.rejects(q("UPDATE ref.exemplar_test_seeds SET retired_on = NULL WHERE airtable_record_id = $1", [IDS[V1]]), /never cleared or moved/);
  });
  for (const sql of ["INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recTESTx32badcod1', 'EX-TR-VISIT-001', '2026-11-16')",
    "INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recShort', 'ZZ-TEST-EX-TR-VISIT-001', '2026-11-16')",
    "INSERT INTO ref.exemplar_tags (tag, visa_code, addresses, label, review_state) VALUES ('x', 'HC-PR', ARRAY['IRPA 25(1)'], 'Excluded cell tag', 'unreviewed')",
    "INSERT INTO ref.exemplar_tags (tag, visa_code, addresses, label, review_state, reviewer_licence) VALUES ('x', 'TR-VISIT', ARRAY['IRPR 179(b)'], 'Half a review', 'reviewed', 'R000001')",
    "INSERT INTO ff13.selections (gate_mode, candidate_count, eligible_count, weak_keys, supported_keys, flags, function_version) VALUES ('test', 0, 0, '{}', '{}', '[\"free text\"]', 'X-32')",
    // A pick without its conflicts count, and conflicts without a pick (2026-11-19).
    "INSERT INTO ff13.selections (gate_mode, candidate_count, eligible_count, exemplar_record_id, exemplar_code, score, term_count, weak_keys, supported_keys, flags, function_version) VALUES ('test', 1, 1, 'recTESTx32nocon01', 'ZZ-TEST-EX-TR-VISIT-001', 0, 1, '{}', '{}', '[]', 'X-32')",
    "INSERT INTO ff13.selections (gate_mode, candidate_count, eligible_count, weak_keys, supported_keys, conflicts, flags, function_version) VALUES ('test', 0, 0, '{}', '{}', 0, '[]', 'X-32')"]) {
    await inTx(() => assert.rejects(q(sql), (e) => ["23514", "23502"].includes(e.code), sql));
  }
});

test("ff13_make executes the ranker and reads none of the new tables, no API role reaches them", async () => {
  assert.ok(MAKE_FUNCTIONS.includes(RANK_EXEMPLARS));
  const fns = await q(`SELECT p.oid::regprocedure::text AS name FROM pg_proc p
                        WHERE p.pronamespace::regnamespace::text IN ('law', 'ref', 'ff13') AND has_function_privilege('ff13_make', p.oid, 'EXECUTE') ORDER BY 1`);
  assert.deepEqual(fns.map((f) => f.name), [...MAKE_FUNCTIONS].sort());
  const definers = await q(`SELECT p.oid::regprocedure::text AS name FROM pg_proc p
                             WHERE p.pronamespace::regnamespace::text IN ('law', 'ref', 'ff13') AND p.prosecdef ORDER BY 1`);
  assert.deepEqual(definers.map((f) => f.name), [...MAKE_FUNCTIONS].sort());
  const [a] = await q(`SELECT pg_get_function_arguments('${RANK_EXEMPLARS}'::regprocedure) AS a, pg_get_function_result('${RANK_EXEMPLARS}'::regprocedure) AS r,
                              (SELECT proconfig FROM pg_proc WHERE oid = '${RANK_EXEMPLARS}'::regprocedure) AS c,
                              (SELECT provolatile FROM pg_proc WHERE oid = '${RANK_EXEMPLARS}'::regprocedure) AS v`);
  assert.equal(a.a, "p_airtable_record_id text, p_make_execution_id text, p_visa_code text, p_document_type text, p_outline text, p_candidates text");
  assert.equal(a.r, "TABLE(exemplar_record_id text, exemplar_code text, score integer, candidate_count integer, eligible_count integer, flags text, selection_id bigint)");
  assert.deepEqual([a.c, a.v], [["search_path=pg_catalog, pg_temp"], "v"]);
  await asMake(async () => {
    for (const sql of ["SELECT 1 FROM ff13.selections LIMIT 1", "SELECT 1 FROM ref.exemplar_test_seeds LIMIT 1", "SELECT 1 FROM ref.exemplar_tags LIMIT 1",
      "INSERT INTO ff13.selections (gate_mode, candidate_count, eligible_count, weak_keys, flags, function_version) VALUES ('test', 0, 0, '{}', '[]', 'X-32')",
      "INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recTESTx32makeins', 'ZZ-TEST-EX-TR-VISIT-001', current_date)",
      "UPDATE ref.exemplar_test_seeds SET retired_on = NULL", "SELECT ff13.selections_append_only()"]) {
      await assert.rejects(q(sql), /permission denied/, sql);
    }
  });
  for (const role of ["anon", "authenticated", "service_role"]) {
    const [f] = await q("SELECT has_function_privilege($1, $2, 'EXECUTE') AS h", [role, RANK_EXEMPLARS]);
    assert.equal(f.h, false, role);
    for (const t of ["ff13.selections", "ref.exemplar_test_seeds", "ref.exemplar_tags"]) {
      const [x] = await q("SELECT has_table_privilege($1, $2, 'SELECT, INSERT, UPDATE, DELETE') AS h", [role, t]);
      assert.equal(x.h, false, `${role} ${t}`);
    }
  }
});

test("loader: the two ref tables load from their files, an empty seed list loads, and the gate refuses a stray address or seed code", async () => {
  const ref = refRows();
  assert.deepEqual(ref.exemplar_test_seeds, []);
  assert.equal(ref.exemplar_tags.length, vocab.length);
  assert.ok(REF_TABLES.some((t) => t.table === "exemplar_test_seeds" && t.allowEmpty && t.extra === "refuse"));
  assert.deepEqual(await x32Problems(client()), []);
  await inTx(async () => {
    await q("UPDATE ref.exemplar_tags SET addresses = addresses || 'IRPR 216(1)(b)'::text WHERE tag = 'stay-funds-modest' AND visa_code = 'TR-VISIT'");
    await q("UPDATE ref.exemplar_tags SET addresses = addresses || addresses[1] WHERE tag = 'home-ties-thin' AND visa_code = 'TR-VISIT'");
    await q("INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recTESTx32nocode1', 'ZZ-TEST-EX-TR-NOPE-001', '2026-11-16'), ('recTESTx32hcprxx1', 'ZZ-TEST-EX-HC-PR-001', '2026-11-16')");
    const p = await x32Problems(client());
    assert.ok(p.some((x) => x.includes("stay-funds-modest TR-VISIT IRPR 216(1)(b)")), p.join("\n"));
    assert.ok(p.some((x) => x.includes("naming a provision key twice") && x.includes("home-ties-thin")), p.join("\n"));
    assert.ok(p.some((x) => x.includes("recTESTx32nocode1") && x.includes("recTESTx32hcprxx1")), p.join("\n"));
  });
  // A file seed list with a row: loads like the test records, and a seed the file drops fails the gate.
  await inTx(async () => {
    const r = structuredClone(ref);
    r.exemplar_test_seeds = [{ airtable_record_id: "recTESTx32filerow", exemplar_code: "ZZ-TEST-EX-TR-VISIT-005", added_on: "2026-11-16", retired_on: null }];
    await upsertRef(client(), r);
    const gate = await refGate(client(), r);
    assert.ok(gate.some((x) => x.startsWith("exemplar_test_seeds in the database and not in ref/exemplar_test_seeds.json")), gate.join("\n"));
  });
});

const PIN = { exemplars_table_id: "tblTESTexemplar01", field_ids: { status: "fldTESTstatus0001", exemplar_code: "fldTESTexcode0001" } };
function fakeAirtable(byId, { status = 200, seen = [] } = {}) {
  return async (url, init) => {
    seen.push({ url, init });
    if (status !== 200) return { ok: false, status, json: async () => ({}) };
    const ids = [...JSON.parse(init.body).filterByFormula.matchAll(/RECORD_ID\(\)='(rec[A-Za-z0-9]{14})'/g)].map((m) => m[1]);
    return { ok: true, status: 200, json: async () => ({ records: ids.filter((id) => byId.has(id)).map((id) => ({ id, fields: byId.get(id) })) }) };
  };
}

test("loader verify: the TEST seed read asks for Status and Exemplar Code only, by POST, and fails closed", async () => {
  const pat = "fake-test-value";
  const baseId = "appTESTbase000001";
  const fields = (code, st = "TEST") => ({ fldTESTstatus0001: st, fldTESTexcode0001: code });
  // Every seed listed in this database, the overlay's and the tie-break pair, as Airtable would hold them.
  const all = new Map((await q("SELECT airtable_record_id AS id, exemplar_code AS code FROM ref.exemplar_test_seeds")).map((r) => [r.id, fields(r.code)]));
  const seen = [];
  const ok = await x32SeedCheck(client(), { pat, baseId, pin: PIN, fetchImpl: fakeAirtable(all, { seen }) });
  assert.deepEqual(ok.slice(0, 2), ["TEST seeds in Airtable", true]);
  assert.equal(seen[0].url, "https://api.airtable.com/v0/appTESTbase000001/tblTESTexemplar01/listRecords");
  const body = JSON.parse(seen[0].init.body);
  assert.deepEqual(body.fields, ["fldTESTstatus0001", "fldTESTexcode0001"]);
  assert.equal(body.returnFieldsByFieldId, true);
  assert.equal(seen[0].init.method, "POST");
  assert.ok(!seen[0].url.includes("rec"));
  const firstId = IDS[V1];
  for (const [what, value] of [["Active", fields(V1, "Active")], ["Pending Review", fields(V1, "Pending Review")], ["another code", fields(V2)],
    ["an EX code", fields("EX-TR-VISIT-001")]]) {
    const m = new Map(all);
    m.set(firstId, value);
    const r = await x32SeedCheck(client(), { pat, baseId, pin: PIN, fetchImpl: fakeAirtable(m) });
    assert.equal(r[1], false, what);
    assert.match(r[2], new RegExp(firstId), what);
  }
  const retired = new Map(all);
  retired.set(firstId, fields(V1, "Retired"));
  assert.equal((await x32SeedCheck(client(), { pat, baseId, pin: PIN, fetchImpl: fakeAirtable(retired) }))[1], true);
  const missing = new Map(all);
  missing.delete(firstId);
  assert.equal((await x32SeedCheck(client(), { pat, baseId, pin: PIN, fetchImpl: fakeAirtable(missing) }))[1], false);
  const denied = await x32SeedCheck(client(), { pat, baseId, pin: PIN, fetchImpl: fakeAirtable(all, { status: 403 }) });
  assert.deepEqual(denied, ["TEST seeds in Airtable", false, "Airtable read failed: Airtable answered HTTP 403"]);
  assert.ok(!denied[2].includes(pat));
  assert.match((await x32SeedCheck(client(), { pat: null }))[2], /no AIRTABLE_PAT/);
  const unpinned = await x32SeedCheck(client(), { pat, baseId, pin: { exemplars_table_id: null, field_ids: {} }, fetchImpl: fakeAirtable(all) });
  assert.equal(unpinned[1], false);
  assert.match(unpinned[2], /pins no Exemplars table ID/);
  await assert.rejects(airtableFields(["recTESTx32x"], { pat, baseId, table: PIN.exemplars_table_id, fields: [], fetchImpl: fakeAirtable(all) }), /malformed/);
  // Nothing listed: Airtable is not read.
  await inTx(async () => {
    await db.exec("ALTER TABLE ref.exemplar_test_seeds DISABLE TRIGGER ALL");
    await q("DELETE FROM ref.exemplar_test_seeds");
    let called = false;
    const closed = await x32SeedCheck(client(), { pat, baseId, pin: PIN, fetchImpl: async () => { called = true; throw new Error("must not be called"); } });
    assert.equal(closed[1], null);
    assert.equal(called, false);
  });
});

test("loader verify: the X-32 behaviour checks pass, leave nothing behind and work inside a caller's transaction", async () => {
  const before = (await q("SELECT count(*)::int AS n FROM ff13.selections"))[0].n;
  const got = await x32Checks(client());
  assert.deepEqual(got.map(([n]) => n), ["rank_exemplars without a grounding row", "rank_exemplars test mode picks only a listed TEST seed",
    "validate_draft cross-checks @08 against the selection"]);
  for (const [n, ok, d] of got) assert.equal(ok, true, `${n}: ${d}`);
  assert.equal((await q("SELECT count(*)::int AS n FROM ff13.selections"))[0].n, before);
  await inTx(async () => {
    const inner = await x32Checks(client());
    assert.ok(inner.every(([, ok]) => ok === true), JSON.stringify(inner));
  });
  // A ranker that picks an unlisted seed fails the check.
  await inTx(async () => {
    await q("INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on) VALUES ('recVERIFYx32seed2', 'ZZ-TEST-EX-TR-VISIT-998', '2026-11-16')");
    const bad = await x32Checks(client());
    assert.equal(bad[0][1], false);
    assert.match(bad[0][2], /must never be/);
  });
});

test("loader verify: the full verify reports the X-32 tables, triggers, grants and checks", async () => {
  const all = await verify(client(), { airtable: { pat: null } });
  const by = Object.fromEntries(all.map(([n, ok, d]) => [n, [ok, d]]));
  for (const name of ["Make function definers", "ff13_make access", "function ff13.rank_exemplars grants", "table ff13.selections grants",
    "table ff13.selections RLS", "table ref.exemplar_test_seeds RLS", "table ref.exemplar_tags RLS", "table ref.exemplar_tags grants",
    "selections append-only", "TEST seeds retired, never deleted", "function search_path", "exemplar_tags equals ref/",
    "rank_exemplars without a grounding row", "rank_exemplars test mode picks only a listed TEST seed", "validate_draft cross-checks @08 against the selection"]) {
    assert.ok(by[name], `${name} reported`);
    assert.equal(by[name][0], true, `${name}: ${by[name][1]}`);
  }
  assert.match(by["ff13_make access"][1], /ff13\.rank_exemplars\(text,text,text,text,text,text\)/);
  // The harness seeds listed in this database are not in the committed file, and nothing listed can be read without a token.
  assert.equal(by["exemplar_test_seeds equals ref/"][0], false);
  assert.equal(by["TEST seeds in Airtable"][0], false);
  assert.equal(by["selection rows"][0], null);
});
