// F-F10 regression suite: ff13.drafting_context, the test path into ff13.validate_draft, ref.test_records and the
// loader's F-F10 checks, on PGlite (Postgres 18) with the committed migrations, law/ and ref/ loaded the way load.mjs
// loads them. Every record ID, name, draft and fact here is synthetic, and nothing here touches Supabase or Airtable
// (the Airtable read runs against a fake fetch).
//
//   cd scripts/law_load && node --test ff10.test.mjs
//
// Mapping rows are signed inside this throwaway database only, with a test licence, so one pair has current, amended,
// changed and unreviewed rows, and one pair has no unreviewed or current row.

import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { seedSql, refRows, upsertRef, refGate, verify, ff10Checks, syntheticCheck, syntheticFlags, readEnv, readAirtablePat,
  canonicalJson, DRAFTING_CONTEXT, MAKE_FUNCTIONS } from "./load.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MIG = path.join(ROOT, "supabase", "migrations");
const DOC = "SUBMISSION-LETTER";
const LISTED = "recTESTff10list01";
const LISTED2 = "recTESTff10list02";
const RETIRED = "recTESTff10retd01";
const EXPIRED = "recTESTff10expd01";
const FUTURE = "recTESTff10futr01";
const UNLISTED = "recTESTff10unls01";
const NAME = "TEST Applicanta Zed";
const FACTS = "Arrived on 2024-03-03. Employment began 2021-06-15.";
const FILLER = Array(40).fill("The applicant has provided the supporting documents listed in the enclosed index for the officer to review.").join(" ");
const STAMPS = ["claude-opus-5-5", "claude-opus-5-5", "end_turn", "F-F10.draft@1", "a".repeat(64), "1200", "2400", "req_test_0001"];
const V1 = "document type not in F-F10 v1";
const MISMATCH = "test marker mismatch";

let db;
let execN = 1;
const q = async (sql, params = []) => (await db.query(sql, params)).rows;
const client = () => ({ query: (sql, params) => db.query(sql, params ?? []) });
// A fresh Make execution ID per call, 32 lowercase hex.
const exec = () => (execN++).toString(16).padStart(32, "0");
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
// The body under test inside the letter structure F-F13.2 requires (specs/F-F13.2-sections-vocabulary.md), with the
// neutral filler as the Background. The name appears once, in the Re line.
const RCIC = "Jordan Testreviewer";
const letter = (body, name = NAME) => [`Draft for review by RCIC ${RCIC}. Not for submission until the RCIC of record has reviewed and signed it.`,
  `Re: Application of ${name}`, "Dear Officer,", "Introduction", body, "Background", FILLER, "Legal framework",
  "The provisions cited above set the requirements.", "Submissions", "The facts meet the requirements.", "Conclusion",
  "The officer is asked to approve the application.", "Respectfully submitted,", RCIC].join("\n\n");

async function asMake(fn) {
  await db.exec("SET ROLE ff13_make");
  try {
    return await fn();
  } finally {
    await db.exec("RESET ROLE");
  }
}

// One ff13.drafting_context call as ff13_make, with the JSON columns parsed.
async function ground(rec, ex, visa, doc, flag) {
  const [r] = await asMake(() => q("SELECT * FROM ff13.drafting_context($1, $2, $3, $4, $5)", [rec, ex, visa, doc, flag]));
  return { ...r, keys: JSON.parse(r.provision_keys), provs: JSON.parse(r.provisions), flagList: JSON.parse(r.flags) };
}

async function validate(rec, ex, visa, draft, { name = NAME, doc = DOC } = {}) {
  const [r] = await asMake(() => q("SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    [rec, ex, visa, doc, draft, name, FACTS, "", ...STAMPS]));
  return r;
}

const checks = (list) => list.map((e) => e.check);
const ledger = async (id) => (await q("SELECT * FROM ff13.validations WHERE id = $1", [id]))[0];
const groundingRow = async (id) => (await q("SELECT * FROM ff13.groundings WHERE id = $1", [id]))[0];

async function inTx(fn) {
  await db.exec("BEGIN");
  try {
    return await fn();
  } finally {
    await db.exec("ROLLBACK");
  }
}

async function addRecord(id, addedOffset, expiresOffset, retired = false) {
  await q(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on, retired_on)
           SELECT $1, d + $2::int, d + $3::int, CASE WHEN $4 THEN d + $2::int END FROM (SELECT (now() AT TIME ZONE 'America/Toronto')::date AS d) t`,
  [id, addedOffset, expiresOffset, retired]);
}

before(async () => {
  db = await PGlite.create();
  await db.exec(`CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;
                 CREATE ROLE authenticator NOINHERIT;`);
  for (const f of fs.readdirSync(MIG).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(fs.readFileSync(path.join(MIG, f), "utf8"));
  }
  const seed = seedSql();
  // The suite lists its own synthetic records below, so the committed file's live entries (listed since commit
  // 75348b7) stay out of this throwaway database. The file itself is checked by the loader tests further down.
  const ref = { ...refRows(), test_records: [] };
  await db.exec(seed.head);
  await upsertRef(client(), ref);
  await db.exec(seed.tail);
  assert.deepEqual(await refGate(client(), ref), []);
  await db.exec("COMMIT");
  // PR-EE-CEC: (a) and (c) current, (d) amended (stale text hash), 87.1(3)(b) changed (stale row hash), the rest unreviewed.
  await db.exec(`
    UPDATE ref.citation_map m SET reviewed_by_licence = 'R000001', reviewed_on = '2026-11-15',
           reviewed_text_sha256 = CASE WHEN m.provision_key = 'IRPR 87.1(2)(d)' THEN repeat('0', 64) ELSE p.text_sha256 END,
           reviewed_row_sha256 = CASE WHEN m.provision_key = 'IRPR 87.1(3)(b)' THEN repeat('1', 64)
                                      ELSE ref.citation_row_sha256(m.document_type, m.visa_code, m.provision_key, m.purpose) END
      FROM law.provisions p
     WHERE p.key = m.provision_key AND m.visa_code = 'PR-EE-CEC' AND m.document_type = '${DOC}'
       AND m.provision_key IN ('IRPR 87.1(2)(a)', 'IRPR 87.1(2)(c)', 'IRPR 87.1(2)(d)', 'IRPR 87.1(3)(b)')`);
  // TR-SUPER: every row signed against a stale text, so it holds no unreviewed and no current row.
  await db.exec(`
    UPDATE ref.citation_map m SET reviewed_by_licence = 'R000001', reviewed_on = '2026-11-15', reviewed_text_sha256 = repeat('0', 64),
           reviewed_row_sha256 = ref.citation_row_sha256(m.document_type, m.visa_code, m.provision_key, m.purpose)
     WHERE m.visa_code = 'TR-SUPER' AND m.document_type = '${DOC}'`);
  await addRecord(LISTED, 0, 30);
  await addRecord(LISTED2, -2, 5);
  await addRecord(RETIRED, -1, 10, true);
  await addRecord(EXPIRED, -40, -10);
  await addRecord(FUTURE, 1, 5);
});

const catalogue = () => q(`SELECT v.code AS visa, d.code AS doc FROM ref.visa_types v CROSS JOIN ref.document_types d
                            WHERE d.restricted_to_visa_code IS NULL OR d.restricted_to_visa_code = v.code ORDER BY 2, 1`);

async function production(visa, doc) {
  const [g] = await q("SELECT * FROM ref.drafting_gate($1, $2)", [visa, doc]);
  const c = await q(`SELECT c.provision_key AS key, c.purpose, c.text FROM ref.citation_context($1, $2)
                       WITH ORDINALITY c(provision_key, purpose, text, n) ORDER BY c.n`, [visa, doc]);
  return { allowed: String(g.allowed), reason: g.reason, keys: g.provision_keys, flags: g.flags, provs: c };
}
const shape = (r) => ({ allowed: r.allowed, reason: r.reason, keys: r.keys, flags: r.flagList, provs: r.provs });

test("production: an unlisted record, or an inactive listing, with a false flag equals ref.drafting_gate plus ref.citation_context on every catalogue pair", async () => {
  const pairs = await catalogue();
  assert.ok(pairs.length >= 30, `${pairs.length} pairs`);
  let allowed = 0;
  for (const p of pairs) {
    const want = await production(p.visa, p.doc);
    for (const [rec, flag] of [[UNLISTED, "false"], [UNLISTED, ""], [UNLISTED, null], [UNLISTED, " FALSE "], [UNLISTED, "yes"],
      [RETIRED, "false"], [EXPIRED, "false"], [FUTURE, null]]) {
      const got = await ground(rec, exec(), p.visa, p.doc, flag);
      assert.equal(got.gate_mode, "production", `${p.doc} ${p.visa} ${rec} ${flag}`);
      if (p.doc === DOC) {
        assert.equal(canonicalJson(shape(got)), canonicalJson(want), `${p.doc} ${p.visa} ${rec} ${flag}`);
      } else {
        assert.deepEqual(shape(got), { allowed: "false", reason: V1, keys: [], flags: [], provs: [] }, `${p.doc} ${p.visa}`);
      }
    }
    if (p.doc === DOC && want.allowed === "true") allowed++;
  }
  assert.equal(allowed, 1, "only the signed PR-EE-CEC letter pair is allowed in production");
  const cec = await ground(UNLISTED, exec(), "PR-EE-CEC", DOC, "false");
  assert.deepEqual(cec.keys, ["IRPR 87.1(2)(a)", "IRPR 87.1(2)(c)"]);
  assert.deepEqual(cec.flagList, ["amended since review: IRPR 87.1(2)(d)", "changed since review: IRPR 87.1(3)(b)"]);
  assert.deepEqual(cec.provs.map((x) => Object.keys(x).sort()), [["key", "purpose", "text"], ["key", "purpose", "text"]]);
  assert.ok(cec.provs.every((x) => x.text.length > 20 && x.purpose.length > 10));
});

test("test mode needs both factors: an active listing and the flag true", async () => {
  for (const flag of ["true", "TRUE", " True ", "  tRuE"]) {
    const r = await ground(LISTED, exec(), "TR-VISIT", DOC, flag);
    assert.equal(r.gate_mode, "test", JSON.stringify(flag));
    assert.equal(r.allowed, "true", r.reason);
  }
  // btrim strips spaces only, so a line break or a tab around the text is not the flag.
  for (const [rec, flag] of [[LISTED, "false"], [LISTED, ""], [LISTED, null], [LISTED, "1"], [LISTED, "yes"], [LISTED, "true!"], [LISTED, "true\n"],
    [LISTED, "\ttrue"], [UNLISTED, "true"], [RETIRED, "true"], [EXPIRED, "true"], [FUTURE, "true"]]) {
    const r = await ground(rec, exec(), "TR-VISIT", DOC, flag);
    assert.deepEqual([r.allowed, r.reason, r.gate_mode, r.keys, r.provs, r.flagList], ["false", MISMATCH, "production", [], [], []], `${rec} ${flag}`);
  }
});

test("test mode: unreviewed rows ground a pair the production gate refuses, flagged", async () => {
  const r = await ground(LISTED, exec(), "TR-VISIT", DOC, "true");
  const s = await q("SELECT provision_key FROM ref.citation_status('TR-VISIT', $1) ORDER BY sort_order, provision_key", [DOC]);
  assert.deepEqual(r.keys, s.map((x) => x.provision_key));
  assert.deepEqual(r.provs.map((x) => x.key), r.keys);
  assert.deepEqual(r.flagList, ["test_mode", "test_mode_unreviewed_grounding"]);
  assert.equal((await production("TR-VISIT", DOC)).reason, "no current reviewed citation rows");
});

test("test mode: changed and amended rows stay out and flagged, current and unreviewed rows go in, sort order kept", async () => {
  const r = await ground(LISTED, exec(), "PR-EE-CEC", DOC, "true");
  assert.equal(r.allowed, "true");
  assert.deepEqual(r.keys, ["IRPA 10.1(1)", "IRPR 87.1(2)(a)", "IRPR 87.1(2)(c)", "IRPR 87.1(3)(c)"]);
  assert.deepEqual(r.flagList, ["test_mode", "test_mode_unreviewed_grounding", "amended since review: IRPR 87.1(2)(d)",
    "changed since review: IRPR 87.1(3)(b)"]);
  const texts = await q("SELECT k AS key, law.provision_text(k) AS text FROM unnest($1::text[]) k", [r.keys]);
  for (const t of texts) assert.equal(r.provs.find((x) => x.key === t.key).text, t.text, t.key);
});

test("test mode: no key outside state current or unreviewed on any pair, and a pair with neither refuses", async () => {
  for (const p of (await catalogue()).filter((x) => x.doc === DOC)) {
    const r = await ground(LISTED, exec(), p.visa, p.doc, "true");
    const ok = (await q("SELECT provision_key FROM ref.citation_status($1, $2) WHERE state IN ('current', 'unreviewed')", [p.visa, p.doc]))
      .map((x) => x.provision_key);
    assert.ok(r.keys.every((k) => ok.includes(k)), `${p.visa}: ${r.keys}`);
    assert.equal(r.gate_mode, "test");
    assert.equal(r.flagList[0], "test_mode");
  }
  const sup = await ground(LISTED, exec(), "TR-SUPER", DOC, "true");
  assert.deepEqual([sup.allowed, sup.reason, sup.keys, sup.provs], ["false", "no unreviewed or current citation rows", [], []]);
  assert.ok(sup.flagList.includes("test_mode") && !sup.flagList.includes("test_mode_unreviewed_grounding"), sup.flags);
  assert.equal((await production("TR-SUPER", DOC)).reason, "no current reviewed citation rows");
});

test("test mode keeps every other production refusal", async () => {
  const irb = await ground(LISTED, exec(), "REF-CLAIM", DOC, "true");
  assert.deepEqual([irb.allowed, irb.reason, irb.gate_mode], ["false", "IRB matter, Module F does not draft", "test"]);
  for (const visa of ["XX-NOPE", "", null, "pr-ee-cec"]) {
    const r = await ground(LISTED, exec(), visa, DOC, "true");
    assert.deepEqual([r.allowed, r.reason], ["false", "unknown visa code"], String(visa));
  }
  await inTx(async () => {
    await q("UPDATE ref.visa_types SET active = false WHERE code = 'HC-PR'");
    const r = await ground(LISTED, exec(), "HC-PR", DOC, "true");
    assert.deepEqual([r.allowed, r.reason], ["false", "visa code inactive"]);
  });
  await inTx(async () => {
    await q("UPDATE law.provisions SET status = 'repealed' WHERE key = 'IRPR 66'");
    const t = await ground(LISTED, exec(), "HC-PR", DOC, "true");
    assert.deepEqual([t.allowed, t.reason, t.keys], ["false", "a mapped provision is not in force", []]);
    const p = await ground(UNLISTED, exec(), "HC-PR", DOC, "false");
    assert.deepEqual([p.allowed, p.reason], ["false", "a mapped provision is not in force"]);
  });
});

test("a document type other than SUBMISSION-LETTER refuses in both modes", async () => {
  for (const doc of ["LOE", "STUDY-PLAN", "submission-letter", " SUBMISSION-LETTER", "", null]) {
    const t = await ground(LISTED, exec(), "TR-STUDY", doc, "true");
    assert.deepEqual([t.allowed, t.reason, t.gate_mode, t.keys, t.provs, t.flagList], ["false", V1, "test", [], [], ["test_mode"]], String(doc));
    const p = await ground(UNLISTED, exec(), "TR-STUDY", doc, "false");
    assert.deepEqual([p.allowed, p.reason, p.gate_mode, p.keys, p.provs, p.flagList], ["false", V1, "production", [], [], []], String(doc));
  }
});

test("malformed record and execution IDs refuse with their own reason and never reach the groundings", async () => {
  for (const rec of ["Client Name", "rec123", "recTESTff10list01x", " recTESTff10list01", "", null, "RECTESTff10list01"]) {
    const r = await ground(rec, exec(), "TR-VISIT", DOC, "true");
    assert.deepEqual([r.allowed, r.reason, r.gate_mode, r.keys], ["false", "airtable record id malformed", "production", []], String(rec));
    const row = await groundingRow(r.grounding_id);
    assert.equal(row.airtable_record_id, null);
    if (rec) assert.ok(!JSON.stringify(row).includes(rec.trim()), JSON.stringify(row));
  }
  for (const ex of ["xyz", "0123456789ABCDEF0123456789ABCDEF", "0".repeat(31), "0".repeat(33), "", null, "Jane Doe"]) {
    const r = await ground(LISTED, ex, "TR-VISIT", DOC, "true");
    assert.deepEqual([r.allowed, r.reason, r.gate_mode], ["false", "make execution id malformed", "production"], String(ex));
    const row = await groundingRow(r.grounding_id);
    assert.equal(row.make_execution_id, null);
    assert.equal(row.airtable_record_id, LISTED);
  }
});

test("every call appends exactly one grounding row with IDs, codes, keys and the provisions hash only", async () => {
  const [{ n: before }] = await q("SELECT count(*)::int AS n FROM ff13.groundings");
  const ex = exec();
  const r = await ground(LISTED, ex, "PR-EE-CEC", DOC, "true");
  const junk = await ground(UNLISTED, exec(), "JOHN-SMITH", "JANE DOE", "maybe");
  const [{ n: after }] = await q("SELECT count(*)::int AS n FROM ff13.groundings");
  assert.equal(after, before + 2);
  const row = await groundingRow(r.grounding_id);
  assert.deepEqual([row.airtable_record_id, row.make_execution_id, row.visa_code, row.document_type, row.gate_mode, row.allowed, row.reason],
    [LISTED, ex, "PR-EE-CEC", DOC, "test", true, "ok"]);
  assert.deepEqual(row.provision_keys, r.keys);
  assert.equal(row.provisions_sha256, sha(r.provisions));
  assert.ok(!JSON.stringify(row).includes(r.provs[0].text.slice(0, 40)), "no provision text in the row");
  const jrow = await groundingRow(junk.grounding_id);
  assert.deepEqual([jrow.visa_code, jrow.document_type, jrow.allowed, jrow.reason, jrow.gate_mode], [null, null, false, V1, "production"]);
  assert.ok(!JSON.stringify(jrow).includes("JOHN") && !JSON.stringify(jrow).includes("JANE"), JSON.stringify(jrow));
  const refused = await groundingRow((await ground(UNLISTED, exec(), "TR-VISIT", DOC, "false")).grounding_id);
  assert.equal(refused.provisions_sha256, sha("[]"));
});

test("the groundings are append-only for every role, the owner included, also in replica mode", async () => {
  const [{ id }] = await q("SELECT min(id) AS id FROM ff13.groundings");
  for (const mode of ["origin", "replica"]) {
    await db.exec(`SET session_replication_role = ${mode}`);
    try {
      await assert.rejects(q("UPDATE ff13.groundings SET allowed = true WHERE id = $1", [id]), /append-only/);
      await assert.rejects(q("DELETE FROM ff13.groundings WHERE id = $1", [id]), /append-only/);
      await assert.rejects(q("TRUNCATE ff13.groundings"), /append-only/);
    } finally {
      await db.exec("RESET session_replication_role");
    }
  }
});

test("validate_draft runs test mode only with the matching test grounding row", async () => {
  const ex = exec();
  const g = await ground(LISTED, ex, "TR-VISIT", DOC, "true");
  assert.equal(g.allowed, "true");
  const draft = letter("Under IRPR 179(a) the applicant qualifies.");
  const t = await validate(LISTED, ex, "TR-VISIT", draft);
  assert.equal(t.detail.gate_mode, "test");
  assert.equal(t.detail.validator_version, "F-F13.2+F-F10+X-32");
  assert.equal(t.verdict, "pass_with_flags", t.review_note);
  assert.equal(t.hard_fail_count, 0, t.review_note);
  assert.deepEqual(checks(t.detail.soft_flags), ["test_mode", "test_mode_unreviewed_grounding"]);
  assert.deepEqual(t.detail.citations.map((c) => [c.key, c.state]), [["IRPR 179(a)", "provided_unreviewed"]]);
  assert.deepEqual(t.detail.gate.provision_keys, g.keys);
  assert.ok(t.review_note.startsWith("F-F13 TEST MODE"), t.review_note);
  const row = await ledger(t.ledger_id);
  assert.equal(row.gate_mode, "test");
  assert.deepEqual(row.provided_keys, g.keys);
  assert.ok(!JSON.stringify(row).includes("Applicanta"));

  // The same record with another execution, an unlisted record, a malformed execution ID: the production gate, which refuses.
  for (const [rec, x] of [[LISTED, exec()], [LISTED, "not-an-execution"], [LISTED, null], [UNLISTED, ex]]) {
    const p = await validate(rec, x, "TR-VISIT", draft);
    assert.equal(p.detail.gate_mode, "production", `${rec} ${x}`);
    assert.ok(p.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "no current reviewed citation rows"), p.review_note);
    assert.ok(!checks(p.detail.soft_flags).includes("test_mode"), p.review_note);
    assert.ok(!p.review_note.includes("TEST MODE"), p.review_note);
    assert.equal((await ledger(p.ledger_id)).gate_mode, "production");
  }
});

test("validate_draft: a production or mismatch grounding row, or a test row for a record never listed, is production", async () => {
  const draft = letter("Under IRPR 179(a) the applicant qualifies.");
  for (const [rec, flag] of [[UNLISTED, "false"], [LISTED, "false"], [UNLISTED, "true"]]) {
    const ex = exec();
    await ground(rec, ex, "TR-VISIT", DOC, flag);
    const r = await validate(rec, ex, "TR-VISIT", draft);
    assert.equal(r.detail.gate_mode, "production", `${rec} ${flag}`);
  }
  // A test row can only come from drafting_context, but even one written by the owner for a record never listed is ignored.
  const ex = exec();
  await q(`INSERT INTO ff13.groundings (airtable_record_id, make_execution_id, visa_code, document_type, gate_mode, allowed, reason,
                                        provision_keys, provisions_sha256)
           VALUES ($1, $2, 'TR-VISIT', $3, 'test', true, 'ok', ARRAY['IRPR 179(a)'], repeat('0', 64))`, [UNLISTED, ex, DOC]);
  const r = await validate(UNLISTED, ex, "TR-VISIT", draft);
  assert.equal(r.detail.gate_mode, "production");
  assert.ok(r.detail.hard_fails.some((e) => e.check === "gate_refused"), r.review_note);
});

test("validate_draft test mode: current keys stay provided, a refused or other-pair grounding refuses in test mode", async () => {
  const ex = exec();
  await ground(LISTED, ex, "PR-EE-CEC", DOC, "true");
  const r = await validate(LISTED, ex, "PR-EE-CEC", letter("Under IRPR 87.1(2)(a) and IRPA 10.1(1) the applicant qualifies. IRPR 87.1(2)(d) also applies."));
  const state = Object.fromEntries(r.detail.citations.map((c) => [c.key, c.state]));
  assert.deepEqual(state, { "IRPR 87.1(2)(a)": "provided", "IRPA 10.1(1)": "provided_unreviewed", "IRPR 87.1(2)(d)": "amended_since_review" }, r.review_note);
  assert.ok(r.detail.soft_flags.some((e) => e.check === "test_mode_unreviewed_grounding" && e.info === "IRPA 10.1(1), IRPR 87.1(3)(c)"), r.review_note);
  assert.ok(r.detail.soft_flags.some((e) => e.check === "gate_flag" && e.info === "changed since review: IRPR 87.1(3)(b)"), r.review_note);
  assert.equal(r.hard_fail_count, 0, r.review_note);

  const other = await validate(LISTED, ex, "TR-VISIT", letter("Under IRPR 179(a) the applicant qualifies."));
  assert.equal(other.detail.gate_mode, "test");
  assert.ok(other.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "grounding pair mismatch"), other.review_note);

  const ex2 = exec();
  await ground(LISTED, ex2, "TR-SUPER", DOC, "true");
  const sup = await validate(LISTED, ex2, "TR-SUPER", letter("text"));
  assert.equal(sup.detail.gate_mode, "test");
  assert.ok(sup.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "no unreviewed or current citation rows"), sup.review_note);
  assert.deepEqual(sup.detail.gate.provision_keys, []);
});

test("validate_draft test mode: a key that left state current or unreviewed after grounding is no longer provided", async () => {
  const ex = exec();
  await ground(LISTED, ex, "PR-EE-CEC", DOC, "true");
  await inTx(async () => {
    await q(`UPDATE ref.citation_map SET purpose = purpose || ' (reworded)' WHERE visa_code = 'PR-EE-CEC' AND document_type = $1
               AND provision_key = 'IRPR 87.1(2)(a)'`, [DOC]);
    const r = await validate(LISTED, ex, "PR-EE-CEC", letter("Under IRPR 87.1(2)(a) the applicant qualifies."));
    assert.ok(!r.detail.gate.provision_keys.includes("IRPR 87.1(2)(a)"), JSON.stringify(r.detail.gate));
    assert.deepEqual(r.detail.citations.map((c) => [c.key, c.state]), [["IRPR 87.1(2)(a)", "changed_since_review"]]);
  });
});

test("validate_draft test mode hard-fails a name that is not a TEST name, production does not check it", async () => {
  for (const [name, ok] of [["TEST Applicanta Zed", true], ["ZZ-TEST Applicanta Zed", true], ["TEST-001 Zed", true], ["  TEST Zed", true],
    ["Testa Applicanta Zed", false], ["TESTER Zed", false], ["Zed TEST", false], ["ZZ TEST Zed", false], ["test Zed", false]]) {
    const ex = exec();
    await ground(LISTED, ex, "TR-VISIT", DOC, "true");
    const r = await validate(LISTED, ex, "TR-VISIT", letter("Under IRPR 179(a) the applicant qualifies.", name), { name });
    assert.equal(checks(r.detail.hard_fails).includes("test_mode_name_not_synthetic"), !ok, `${name}: ${r.review_note}`);
    const row = await ledger(r.ledger_id);
    assert.ok(!JSON.stringify(row).includes("Zed"), "the name never reaches the ledger");
  }
  const p = await validate(UNLISTED, exec(), "PR-EE-CEC", letter("Under IRPR 87.1(2)(a) the applicant qualifies.", "Testa Applicanta Zed"),
    { name: "Testa Applicanta Zed" });
  assert.equal(p.detail.gate_mode, "production");
  assert.ok(!checks(p.detail.hard_fails).includes("test_mode_name_not_synthetic"), p.review_note);
});

test("validate_draft: the review note names unreviewed rows only when the grounding held some", async () => {
  const UNREV = "F-F13 TEST MODE: grounded on unreviewed citation rows, not for client use.";
  const NEUTRAL = "F-F13 TEST MODE: grounded in test mode, not for client use.";
  const draft = letter("Under IRPR 179(a) the applicant qualifies.");
  const ex = exec();
  await ground(LISTED, ex, "TR-VISIT", DOC, "true");
  const unrev = await validate(LISTED, ex, "TR-VISIT", draft);
  assert.ok(checks(unrev.detail.soft_flags).includes("test_mode_unreviewed_grounding"), unrev.review_note);
  assert.equal(unrev.review_note.split("\n")[0], UNREV);
  // Every TR-VISIT letter row signed against the current text: the test grounding holds current rows only.
  await inTx(async () => {
    await q(`UPDATE ref.citation_map m SET reviewed_by_licence = 'R000001', reviewed_on = '2026-11-15', reviewed_text_sha256 = p.text_sha256,
                    reviewed_row_sha256 = ref.citation_row_sha256(m.document_type, m.visa_code, m.provision_key, m.purpose)
               FROM law.provisions p WHERE p.key = m.provision_key AND m.visa_code = 'TR-VISIT' AND m.document_type = $1`, [DOC]);
    const states = await q("SELECT DISTINCT state FROM ref.citation_status('TR-VISIT', $1)", [DOC]);
    assert.deepEqual(states.map((x) => x.state), ["current"]);
    const ex2 = exec();
    const g = await ground(LISTED, ex2, "TR-VISIT", DOC, "true");
    assert.deepEqual([g.allowed, g.gate_mode, g.flagList], ["true", "test", ["test_mode"]]);
    const r = await validate(LISTED, ex2, "TR-VISIT", draft);
    assert.equal(r.detail.gate_mode, "test");
    assert.deepEqual(checks(r.detail.soft_flags), ["test_mode"], r.review_note);
    assert.deepEqual(r.detail.citations.map((c) => [c.key, c.state]), [["IRPR 179(a)", "provided"]]);
    assert.equal(r.review_note.split("\n")[0], NEUTRAL);
    assert.ok(!r.review_note.includes("unreviewed"), r.review_note);
  });
  // A test grounding the gate refused grounded nothing, so the note does not claim unreviewed rows either.
  const ex3 = exec();
  const irb = await ground(LISTED, ex3, "REF-CLAIM", DOC, "true");
  assert.deepEqual([irb.allowed, irb.gate_mode], ["false", "test"]);
  const r = await validate(LISTED, ex3, "REF-CLAIM", draft);
  assert.equal(r.detail.gate_mode, "test");
  assert.ok(r.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "IRB matter, Module F does not draft"), r.review_note);
  assert.equal(r.review_note.split("\n")[0], NEUTRAL);
});

test("validate_draft reads the newest grounding row of the record and execution", async () => {
  const draft = letter("Under IRPR 179(a) the applicant qualifies.");
  // Test row first, then a production row for the same execution (the entry retired in between): production.
  await inTx(async () => {
    const ex = exec();
    const t = await ground(LISTED, ex, "TR-VISIT", DOC, "true");
    assert.equal(t.gate_mode, "test");
    await q("UPDATE ref.test_records SET retired_on = added_on WHERE airtable_record_id = $1", [LISTED]);
    const p = await ground(LISTED, ex, "TR-VISIT", DOC, "true");
    assert.deepEqual([p.gate_mode, p.reason], ["production", MISMATCH]);
    assert.ok(Number(p.grounding_id) > Number(t.grounding_id));
    const r = await validate(LISTED, ex, "TR-VISIT", draft);
    assert.equal(r.detail.gate_mode, "production", r.review_note);
    assert.ok(r.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "no current reviewed citation rows"), r.review_note);
    assert.ok(!r.review_note.includes("TEST MODE"), r.review_note);
  });
  // The mirror: a production row first, then a test row for the same execution: test.
  const ex = exec();
  const p = await ground(LISTED, ex, "TR-VISIT", DOC, "false");
  assert.deepEqual([p.gate_mode, p.reason], ["production", MISMATCH]);
  const t = await ground(LISTED, ex, "TR-VISIT", DOC, "true");
  assert.equal(t.gate_mode, "test");
  const r = await validate(LISTED, ex, "TR-VISIT", draft);
  assert.equal(r.detail.gate_mode, "test", r.review_note);
  assert.equal(r.hard_fail_count, 0, r.review_note);
});

test("validate_draft: a record retired after grounding still validates in test mode (ever registered)", async () => {
  const ex = exec();
  await ground(LISTED2, ex, "TR-VISIT", DOC, "true");
  await inTx(async () => {
    await q("UPDATE ref.test_records SET retired_on = added_on WHERE airtable_record_id = $1", [LISTED2]);
    const r = await validate(LISTED2, ex, "TR-VISIT", letter("Under IRPR 179(a) the applicant qualifies."));
    assert.equal(r.detail.gate_mode, "test");
    const again = await ground(LISTED2, exec(), "TR-VISIT", DOC, "true");
    assert.deepEqual([again.allowed, again.reason], ["false", MISMATCH], "a retired record grounds no new test run");
  });
});

test("the exception paths write the mode decided so far, unknown before it", { concurrency: false }, async () => {
  const draft = letter("Under IRPR 179(a) the applicant qualifies.");
  // Before the mode: the test record list is gone, so the mode query fails.
  const exU = exec();
  await ground(LISTED, exU, "TR-VISIT", DOC, "true");
  await inTx(async () => {
    await db.exec("ALTER TABLE ref.test_records RENAME TO test_records_gone");
    const r = await validate(LISTED, exU, "TR-VISIT", draft);
    assert.deepEqual(r.detail.hard_fails, [{ check: "validator_error", info: "SQLSTATE 42P01" }]);
    assert.equal(r.detail.gate_mode, "unknown");
    assert.equal((await ledger(r.ledger_id)).gate_mode, "unknown");
    const g = await ground(LISTED, exec(), "TR-VISIT", DOC, "true");
    assert.deepEqual([g.allowed, g.reason, g.gate_mode, g.grounding_id === null], ["false", "drafting context error (SQLSTATE 42P01)", "unknown", false]);
    assert.equal((await groundingRow(g.grounding_id)).gate_mode, "unknown");
  });
  // After the mode: the test gate fails in test mode, the production gate in production.
  const exT = exec();
  await ground(LISTED, exT, "TR-VISIT", DOC, "true");
  await inTx(async () => {
    await db.exec(`CREATE OR REPLACE FUNCTION ff13._test_gate(p_visa_code TEXT, p_document_type TEXT)
      RETURNS TABLE (allowed BOOLEAN, reason TEXT, provision_keys TEXT[], flags TEXT[])
      LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS 'SELECT true, ''ok'', ARRAY[(1/0)::text], ''{}''::text[]'`);
    const r = await validate(LISTED, exT, "TR-VISIT", draft);
    assert.deepEqual(r.detail.hard_fails, [{ check: "validator_error", info: "SQLSTATE 22012" }]);
    assert.equal(r.detail.gate_mode, "test");
    assert.equal((await ledger(r.ledger_id)).gate_mode, "test");
    assert.ok(r.review_note.startsWith("F-F13 TEST MODE"), r.review_note);
    const g = await ground(LISTED, exec(), "TR-VISIT", DOC, "true");
    assert.deepEqual([g.allowed, g.reason, g.gate_mode, g.flagList, g.provs], ["false", "drafting context error (SQLSTATE 22012)", "test", ["test_mode"], []]);
  });
  await inTx(async () => {
    await db.exec(`CREATE OR REPLACE FUNCTION ref.drafting_gate(p_visa_code TEXT, p_document_type TEXT)
      RETURNS TABLE (allowed BOOLEAN, reason TEXT, provision_keys TEXT[], flags TEXT[])
      LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS 'SELECT true, ''ok'', ARRAY[(1/0)::text], ''{}''::text[]'`);
    const r = await validate(UNLISTED, exec(), "TR-VISIT", draft);
    assert.equal(r.detail.gate_mode, "production");
    assert.equal((await ledger(r.ledger_id)).gate_mode, "production");
    const g = await ground(UNLISTED, exec(), "PR-EE-CEC", DOC, "false");
    assert.deepEqual([g.allowed, g.reason, g.gate_mode], ["false", "drafting context error (SQLSTATE 22012)", "production"]);
    assert.equal((await groundingRow(g.grounding_id)).gate_mode, "production");
  });
});

test("drafting_context returns exactly one row on hostile input and never raises", async () => {
  for (const args of [[null, null, null, null, null], ["x".repeat(200000), "y".repeat(200000), "z".repeat(200000), DOC, "t".repeat(200000)],
    ["'; DROP TABLE ff13.groundings; --", exec(), "PR-EE-CEC", DOC, "true"], [LISTED, exec(), "PR-EE-CEC'); --", DOC, "true"]]) {
    const rows = await asMake(() => q("SELECT * FROM ff13.drafting_context($1, $2, $3, $4, $5)", args));
    assert.equal(rows.length, 1);
    assert.ok(["true", "false"].includes(rows[0].allowed));
  }
  assert.ok((await q("SELECT to_regclass('ff13.groundings') IS NOT NULL AS ok"))[0].ok);
});

test("the ledger column gate_mode: required, three values, no default left", async () => {
  const [c] = await q(`SELECT is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'ff13' AND table_name = 'validations' AND column_name = 'gate_mode'`);
  assert.deepEqual([c.is_nullable, c.column_default], ["NO", null]);
  await assert.rejects(q(`INSERT INTO ff13.validations (validator_version, law_sources, draft_sha256, draft_chars, verdict, provided_keys, citations, hard_fails, soft_flags, gate_mode)
                          VALUES ('x', 'x', repeat('a', 64), 0, 'pass', '{}', '[]', '[]', '[]', 'staging')`), (e) => e.code === "23514");
  await assert.rejects(q(`INSERT INTO ff13.validations (validator_version, law_sources, draft_sha256, draft_chars, verdict, provided_keys, citations, hard_fails, soft_flags)
                          VALUES ('x', 'x', repeat('a', 64), 0, 'pass', '{}', '[]', '[]', '[]')`), (e) => e.code === "23502");
});

test("ff13_make can execute exactly the Make functions and read nothing", async () => {
  const fns = await q(`SELECT p.oid::regprocedure::text AS name FROM pg_proc p
                        WHERE p.pronamespace::regnamespace::text IN ('law', 'ref', 'ff13') AND has_function_privilege('ff13_make', p.oid, 'EXECUTE') ORDER BY 1`);
  assert.deepEqual(fns.map((f) => f.name), [...MAKE_FUNCTIONS].sort());
  assert.ok(MAKE_FUNCTIONS.includes(DRAFTING_CONTEXT));
  await asMake(async () => {
    for (const sql of ["SELECT 1 FROM ff13.groundings LIMIT 1", "SELECT 1 FROM ref.test_records LIMIT 1", "SELECT * FROM ff13._test_gate('TR-VISIT', 'SUBMISSION-LETTER')",
      "INSERT INTO ff13.groundings (gate_mode, allowed, reason, provision_keys, provisions_sha256) VALUES ('test', true, 'ok', '{}', repeat('0', 64))",
      `INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on) VALUES ('${UNLISTED}', current_date, current_date)`,
      `UPDATE ref.test_records SET retired_on = NULL`, "SELECT * FROM ref.citation_context('PR-EE-CEC', 'SUBMISSION-LETTER')"]) {
      await assert.rejects(q(sql), /permission denied/, sql);
    }
  });
  for (const role of ["anon", "authenticated", "service_role"]) {
    for (const f of MAKE_FUNCTIONS) {
      const [x] = await q("SELECT has_function_privilege($1, $2, 'EXECUTE') AS h", [role, f]);
      assert.equal(x.h, false, `${role} ${f}`);
    }
    for (const t of ["ff13.groundings", "ref.test_records"]) {
      const [x] = await q("SELECT has_table_privilege($1, $2, 'SELECT, INSERT, UPDATE, DELETE') AS h", [role, t]);
      assert.equal(x.h, false, `${role} ${t}`);
    }
  }
});

test("exactly the Make functions are security definers in law, ref and ff13, every function pins its search_path", async () => {
  const fns = await q(`SELECT p.oid::regprocedure::text AS name, p.prosecdef, p.proconfig, p.provolatile FROM pg_proc p
                        WHERE p.pronamespace::regnamespace::text IN ('law', 'ref', 'ff13') ORDER BY 1`);
  assert.deepEqual(fns.filter((f) => f.prosecdef).map((f) => f.name), [...MAKE_FUNCTIONS].sort());
  for (const f of fns) assert.deepEqual(f.proconfig, ["search_path=pg_catalog, pg_temp"], f.name);
  for (const f of fns.filter((x) => x.prosecdef)) assert.equal(f.provolatile, "v", f.name);
  const [v] = await q(`SELECT pg_get_function_result('ff13.validate_draft(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text)'::regprocedure) AS r,
                              pg_get_function_arguments('ff13.validate_draft(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text)'::regprocedure) AS a`);
  assert.equal(v.r, "TABLE(ledger_id bigint, verdict text, hard_fail_count integer, soft_flag_count integer, review_note text, detail jsonb)");
  assert.equal(v.a.split(", ").map((x) => x.split(" ")[0]).join(","), "p_airtable_record_id,p_make_execution_id,p_visa_code,p_document_type,p_draft,"
    + "p_applicant_name,p_case_facts,p_exemplar_terms,p_model_requested,p_model_served,p_stop_reason,p_prompt_version,p_prompt_sha256,"
    + "p_input_tokens,p_output_tokens,p_request_id");
  const [d] = await q(`SELECT pg_get_function_arguments('${DRAFTING_CONTEXT}'::regprocedure) AS a, pg_get_function_result('${DRAFTING_CONTEXT}'::regprocedure) AS r`);
  assert.equal(d.a, "p_airtable_record_id text, p_make_execution_id text, p_visa_code text, p_document_type text, p_synthetic_flag text");
  assert.equal(d.r, "TABLE(allowed text, reason text, gate_mode text, provision_keys text, provisions text, flags text, grounding_id bigint)");
});

test("ref.test_records: never deleted, never re-dated (expires_on included), never un-retired, at most 30 days", async () => {
  await inTx(async () => {
    await assert.rejects(q("DELETE FROM ref.test_records WHERE airtable_record_id = $1", [RETIRED]), /never deleted/);
  });
  await inTx(async () => {
    await assert.rejects(q("TRUNCATE ref.test_records"), /never deleted/);
  });
  for (const sql of [`UPDATE ref.test_records SET retired_on = NULL WHERE airtable_record_id = '${RETIRED}'`,
    `UPDATE ref.test_records SET retired_on = retired_on + 1 WHERE airtable_record_id = '${RETIRED}'`,
    `UPDATE ref.test_records SET added_on = added_on - 1 WHERE airtable_record_id = '${LISTED}'`,
    `UPDATE ref.test_records SET airtable_record_id = '${UNLISTED}' WHERE airtable_record_id = '${LISTED}'`,
    // Re-dating inside the 30-day bound, later or earlier, active or retired.
    `UPDATE ref.test_records SET expires_on = expires_on + 1 WHERE airtable_record_id = '${LISTED2}'`,
    `UPDATE ref.test_records SET expires_on = expires_on - 1 WHERE airtable_record_id = '${LISTED2}'`,
    `UPDATE ref.test_records SET expires_on = added_on + 30 WHERE airtable_record_id = '${RETIRED}'`]) {
    await inTx(async () => {
      await assert.rejects(q(sql), /keeps its record ID, added_on and expires_on/, sql);
    });
  }
  // An expired entry stays closed: moving its expiry forward is refused, so the test path never reopens.
  await inTx(async () => {
    await addRecord("recTESTff10redt01", -20, -10);
    const before = await ground("recTESTff10redt01", exec(), "TR-VISIT", DOC, "true");
    assert.deepEqual([before.allowed, before.reason, before.gate_mode], ["false", MISMATCH, "production"]);
    await db.exec("SAVEPOINT redate");
    await assert.rejects(q("UPDATE ref.test_records SET expires_on = added_on + 30 WHERE airtable_record_id = 'recTESTff10redt01'"),
      /keeps its record ID, added_on and expires_on/);
    await db.exec("ROLLBACK TO SAVEPOINT redate");
    const after = await ground("recTESTff10redt01", exec(), "TR-VISIT", DOC, "true");
    assert.deepEqual([after.allowed, after.reason, after.gate_mode], ["false", MISMATCH, "production"]);
  });
  await inTx(async () => {
    // The trigger refuses any re-dating first, so the 30-day bound is shown on an insert.
    await assert.rejects(q(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on) VALUES ('recTESTff10long01', current_date, current_date + 31)`),
      (e) => e.code === "23514");
  });
  await inTx(async () => {
    await q(`UPDATE ref.test_records SET retired_on = added_on WHERE airtable_record_id = '${LISTED}'`);
    const r = await ground(LISTED, exec(), "TR-VISIT", DOC, "true");
    assert.equal(r.reason, MISMATCH, "retiring closes the test path at once");
  });
  for (const bad of ["rec123", "recTESTff10list01x", "Client Name"]) {
    await inTx(async () => {
      await assert.rejects(q("INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on) VALUES ($1, current_date, current_date)", [bad]),
        (e) => e.code === "23514", bad);
    });
  }
});

test("loader: an empty test_records file loads, the list is required, rows are checked", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ff10-ref-"));
  try {
    for (const f of fs.readdirSync(path.join(ROOT, "ref")).filter((x) => x.endsWith(".json"))) fs.copyFileSync(path.join(ROOT, "ref", f), path.join(dir, f));
    const write = (doc) => fs.writeFileSync(path.join(dir, "test_records.json"), JSON.stringify(doc));
    write({ test_records: [] });
    assert.deepEqual(refRows(dir).test_records, []);
    write({});
    assert.throws(() => refRows(dir), /has no test_records list/);
    write({ test_records: [{ airtable_record_id: LISTED, added_on: "2026-11-15", expires_on: "2026-11-20" }] });
    assert.throws(() => refRows(dir), /exactly airtable_record_id, added_on, expires_on, retired_on/);
    write({ test_records: [{ airtable_record_id: LISTED, added_on: "15/11/2026", expires_on: "2026-11-20", retired_on: null }] });
    assert.throws(() => refRows(dir), /wrong type in added_on/);
    write({ test_records: [{ airtable_record_id: LISTED, added_on: "2026-11-15", expires_on: null, retired_on: null }] });
    assert.throws(() => refRows(dir), /wrong type in expires_on/);
    write({ test_records: [{ airtable_record_id: LISTED, added_on: "2026-11-15", expires_on: "2026-11-20", retired_on: null }] });
    assert.equal(refRows(dir).test_records.length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // Every other table still refuses an empty list.
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "ff10-ref-"));
  try {
    for (const f of fs.readdirSync(path.join(ROOT, "ref")).filter((x) => x.endsWith(".json"))) fs.copyFileSync(path.join(ROOT, "ref", f), path.join(dir2, f));
    fs.writeFileSync(path.join(dir2, "prompt_bindings.json"), JSON.stringify({ prompt_bindings: [] }));
    assert.throws(() => refRows(dir2), /has no prompt_bindings list/);
  } finally {
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test("loader: an entry dropped from the file fails the gate, a retirement loads, an un-retirement or re-dating is refused", async () => {
  const today = (await q("SELECT ((now() AT TIME ZONE 'America/Toronto')::date)::text AS d"))[0].d;
  const base = refRows();
  const withRows = (list) => ({ ...base, test_records: list });
  const entry = (o = {}) => ({ airtable_record_id: "recTESTff10load01", added_on: today, expires_on: today, retired_on: null, ...o });
  const gateFor = async (data) => {
    await upsertRef(client(), data);
    await db.exec("SET CONSTRAINTS ALL IMMEDIATE");
    return refGate(client(), data);
  };
  await inTx(async () => {
    // The fixtures added in before() are in the database and not in the file, so the gate refuses until they are listed.
    const dropped = await gateFor(withRows([entry()]));
    assert.ok(dropped.some((p) => p.startsWith("test_records in the database and not in ref/test_records.json") && p.includes(LISTED)), dropped.join("\n"));
  });
  await inTx(async () => {
    const current = (await q(`SELECT airtable_record_id, added_on::text AS added_on, expires_on::text AS expires_on, retired_on::text AS retired_on
                               FROM ref.test_records ORDER BY 1`));
    assert.deepEqual(await gateFor(withRows([...current, entry()])), []);
    // Retire it: loads.
    assert.deepEqual(await gateFor(withRows([...current, entry({ retired_on: today })])), []);
    const [r] = await q("SELECT retired_on::text AS d FROM ref.test_records WHERE airtable_record_id = 'recTESTff10load01'");
    assert.equal(r.d, today);
    // Un-retire it: the table refuses.
    await db.exec("SAVEPOINT un");
    await assert.rejects(upsertRef(client(), withRows([...current, entry()])), /retirement is never cleared or moved/);
    await db.exec("ROLLBACK TO SAVEPOINT un");
    await db.exec("SAVEPOINT added");
    await assert.rejects(upsertRef(client(), withRows([...current, entry({ added_on: "2026-01-01", expires_on: "2026-01-02", retired_on: "2026-01-01" })])),
      /keeps its record ID, added_on and expires_on/);
    await db.exec("ROLLBACK TO SAVEPOINT added");
    // Re-date it in the file, inside the 30-day bound: the table refuses.
    const [{ d: later }] = await q("SELECT ((now() AT TIME ZONE 'America/Toronto')::date + 5)::text AS d");
    await assert.rejects(upsertRef(client(), withRows([...current, entry({ expires_on: later, retired_on: today })])),
      /keeps its record ID, added_on and expires_on/);
  });
  await inTx(async () => {
    await assert.rejects(upsertRef(client(), withRows([entry({ airtable_record_id: "recTESTff10load02", expires_on: "2099-01-01" })])), (e) => e.code === "23514");
  });
});

test("loader verify: the F-F10 checks pass here, leave nothing behind and work inside a caller's transaction", async () => {
  const [{ n: before }] = await q("SELECT count(*)::int AS n FROM ff13.groundings");
  const own = await ff10Checks(client());
  assert.deepEqual(own.map(([n, ok]) => [n, ok]), [["drafting_context production equals the gate", true], ["drafting_context test mode keys", true],
    ["drafting_context one factor refuses", true]], JSON.stringify(own));
  const [{ n: after }] = await q("SELECT count(*)::int AS n FROM ff13.groundings");
  assert.equal(after, before, "no grounding row survives verify");
  assert.equal((await q("SELECT count(*)::int AS n FROM ref.test_records WHERE airtable_record_id = 'recVERIFYlistedxx'"))[0].n, 0);
  await inTx(async () => {
    await q("CREATE TEMP TABLE ff10_probe (a int)");
    const inner = await ff10Checks(client());
    assert.ok(inner.every(([, ok]) => ok === true), JSON.stringify(inner));
    assert.equal((await q("SELECT count(*)::int AS n FROM ff10_probe"))[0].n, 0, "the caller's transaction is still open");
  });
  await inTx(async () => {
    await q("INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on) VALUES ('recVERIFYunlisted', current_date, current_date)");
    const clash = await ff10Checks(client());
    assert.equal(clash[0][1], false);
    assert.match(clash[0][2], /must never be listed/);
  });
});

// Replace ff13.drafting_context, inside the caller's transaction, by a wrapper that returns the real function's row
// with the given select list (columns of o, the real row, and the five p_ arguments).
async function driftDraftingContext(select) {
  await db.exec(`ALTER FUNCTION ${DRAFTING_CONTEXT} RENAME TO drafting_context_real`);
  await db.exec(`CREATE FUNCTION ff13.drafting_context(p_airtable_record_id TEXT, p_make_execution_id TEXT, p_visa_code TEXT,
                   p_document_type TEXT, p_synthetic_flag TEXT)
                 RETURNS TABLE (allowed TEXT, reason TEXT, gate_mode TEXT, provision_keys TEXT, provisions TEXT, flags TEXT, grounding_id BIGINT)
                 LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp
                 AS $f$ SELECT ${select} FROM ff13.drafting_context_real($1, $2, $3, $4, $5) o $f$`);
}

test("loader verify: each F-F10 check fails when drafting_context drifts from its rule", async () => {
  const names = ["drafting_context production equals the gate", "drafting_context test mode keys", "drafting_context one factor refuses"];
  const COLS = { allowed: "o.allowed", reason: "o.reason", gate_mode: "o.gate_mode", provision_keys: "o.provision_keys", provisions: "o.provisions",
    flags: "o.flags", grounding_id: "o.grounding_id" };
  const select = (over) => Object.entries({ ...COLS, ...over }).map(([k, v]) => `${v} AS ${k}`).join(", ");
  const [chg] = await q("SELECT state FROM ref.citation_status('PR-EE-CEC', $1) WHERE provision_key = 'IRPR 87.1(3)(b)'", [DOC]);
  assert.ok(!["current", "unreviewed"].includes(chg.state), chg.state);
  const cases = [
    // Production adds a flag.
    [names[0], { flags: `CASE WHEN o.gate_mode = 'production' THEN (o.flags::jsonb || '["drift"]'::jsonb)::text ELSE o.flags END` }],
    // Production adds a key.
    [names[0], { provision_keys: `CASE WHEN o.gate_mode = 'production' AND o.allowed = 'true' THEN (o.provision_keys::jsonb || '["IRPR 87.1(3)(b)"]'::jsonb)::text ELSE o.provision_keys END` }],
    // Test mode returns a key in a state other than current or unreviewed, provided and listed alike.
    [names[1], { provision_keys: `CASE WHEN o.gate_mode = 'test' AND p_visa_code = 'PR-EE-CEC' AND o.allowed = 'true'
                                       THEN (o.provision_keys::jsonb || '["IRPR 87.1(3)(b)"]'::jsonb)::text ELSE o.provision_keys END`,
                 provisions: `CASE WHEN o.gate_mode = 'test' AND p_visa_code = 'PR-EE-CEC' AND o.allowed = 'true'
                                   THEN (o.provisions::jsonb || jsonb_build_array(jsonb_build_object('key', 'IRPR 87.1(3)(b)', 'purpose', 'x', 'text', 'x')))::text
                                   ELSE o.provisions END` }],
    // Test mode drops its flag.
    [names[1], { flags: `CASE WHEN o.gate_mode = 'test' THEN (o.flags::jsonb - 'test_mode')::text ELSE o.flags END` }],
    // An active listing with a false flag is allowed.
    [names[2], { allowed: `CASE WHEN p_airtable_record_id = 'recVERIFYlistedxx' AND coalesce(btrim(lower(p_synthetic_flag)), '') <> 'true' THEN 'true' ELSE o.allowed END` }],
    // An unlisted record with a true flag grounds provisions.
    [names[2], { provisions: `CASE WHEN p_airtable_record_id = 'recVERIFYunlisted' AND coalesce(btrim(lower(p_synthetic_flag)), '') = 'true'
                                   THEN '[{"key": "IRPR 179(a)"}]' ELSE o.provisions END` }]];
  for (const [failing, over] of cases) {
    await inTx(async () => {
      await driftDraftingContext(select(over));
      const got = Object.fromEntries((await ff10Checks(client())).map(([n, ok, d]) => [n, [ok, d]]));
      assert.deepEqual(Object.keys(got), names, JSON.stringify(got));
      for (const n of names) assert.equal(got[n][0], n !== failing, `${JSON.stringify(over)}: ${n}: ${got[n][1]}`);
    });
  }
  // The wrapper with no drift passes every check, so each failure above is the drift alone.
  await inTx(async () => {
    await driftDraftingContext(select({}));
    const got = await ff10Checks(client());
    assert.ok(got.every(([, ok]) => ok === true), JSON.stringify(got));
  });
});

test("loader verify: the full verify reports the F-F10 grants, definers, triggers and checks as passing", async () => {
  const all = await verify(client(), { airtable: { pat: "fake-test-value", baseId: "appTESTbase000001", fetchImpl: fakeAirtable(new Map([[LISTED, true], [LISTED2, true]])) } });
  const by = Object.fromEntries(all.map(([n, ok, d]) => [n, [ok, d]]));
  for (const name of ["Make function definers", "groundings append-only", "test records retired, never deleted", "ledger append-only",
    "function ff13.drafting_context grants", "function ff13.validate_draft grants", "ff13_make access", "table ff13.groundings grants",
    "table ff13.groundings RLS", "table ref.test_records RLS", "table ref.test_records grants", "function search_path",
    "drafting_context production equals the gate", "drafting_context test mode keys", "drafting_context one factor refuses",
    "test records Synthetic Test Case"]) {
    assert.ok(by[name], `${name} reported`);
    assert.equal(by[name][0], true, `${name}: ${by[name][1]}`);
  }
  assert.match(by["ff13_make access"][1], /ff13\.drafting_context\(text,text,text,text,text\)/);
  assert.equal(by["test_records equals ref/"][0], false, "the fixtures are not in the committed file");
  assert.equal(by["grounding rows"][0], null);
});

function fakeAirtable(flags, { status = 200, seen = [] } = {}) {
  return async (url, init) => {
    seen.push({ url, init });
    if (status !== 200) return { ok: false, status, json: async () => ({}) };
    const body = JSON.parse(init.body);
    const ids = [...body.filterByFormula.matchAll(/RECORD_ID\(\)='(rec[A-Za-z0-9]{14})'/g)].map((m) => m[1]);
    return { ok: true, status: 200, json: async () => ({ records: ids.filter((id) => flags.has(id)).map((id) => ({ id, fields: flags.get(id) ? { fldsCjg7ftgursZvl: true } : {} })) }) };
  };
}

test("loader verify: the Airtable read asks for Synthetic Test Case only, by POST, and fails closed", async () => {
  const seen = [];
  const pat = "fake-test-value";
  const flags = await syntheticFlags([LISTED, LISTED2], { pat, baseId: "appTESTbase000001", fetchImpl: fakeAirtable(new Map([[LISTED, true]]), { seen }) });
  assert.deepEqual([...flags], [[LISTED, true]]);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "https://api.airtable.com/v0/appTESTbase000001/tblHk09sCKLcOJXr9/listRecords");
  assert.equal(seen[0].init.method, "POST");
  const body = JSON.parse(seen[0].init.body);
  assert.deepEqual(body.fields, ["fldsCjg7ftgursZvl"]);
  assert.equal(body.returnFieldsByFieldId, true);
  assert.ok(!seen[0].url.includes("rec"), "no record ID in the URL");

  const ok = await syntheticCheck(client(), { pat, baseId: "appTESTbase000001", fetchImpl: fakeAirtable(new Map([[LISTED, true], [LISTED2, true]])) });
  assert.deepEqual(ok.slice(0, 2), ["test records Synthetic Test Case", true]);
  const unticked = await syntheticCheck(client(), { pat, baseId: "appTESTbase000001", fetchImpl: fakeAirtable(new Map([[LISTED, true], [LISTED2, false]])) });
  assert.equal(unticked[1], false);
  assert.match(unticked[2], new RegExp(LISTED2));
  const missing = await syntheticCheck(client(), { pat, baseId: "appTESTbase000001", fetchImpl: fakeAirtable(new Map([[LISTED, true]])) });
  assert.equal(missing[1], false);
  const denied = await syntheticCheck(client(), { pat, baseId: "appTESTbase000001", fetchImpl: fakeAirtable(new Map(), { status: 403 }) });
  assert.deepEqual(denied, ["test records Synthetic Test Case", false, "Airtable read failed: Airtable answered HTTP 403"]);
  assert.ok(!denied[2].includes(pat));
  const noPat = await syntheticCheck(client(), { pat: null });
  assert.equal(noPat[1], false);
  assert.match(noPat[2], /no AIRTABLE_PAT/);
  await inTx(async () => {
    await q("UPDATE ref.test_records SET retired_on = added_on WHERE retired_on IS NULL");
    let called = false;
    const closed = await syntheticCheck(client(), { pat, baseId: "appTESTbase000001", fetchImpl: async () => { called = true; throw new Error("must not be called"); } });
    assert.equal(closed[1], null);
    assert.equal(called, false, "Airtable is not read when no record is active");
  });
});

test("loader: AIRTABLE_PAT is read by the .env parser only when asked, and never with the database keys", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ff10-env-"));
  try {
    const file = path.join(dir, ".env");
    fs.writeFileSync(file, "SUPABASE_DB_URL=postgres://u@localhost:5432/db\nAIRTABLE_PAT='fake-test-value'\nOTHER=x\n");
    const saved = process.env.AIRTABLE_PAT;
    delete process.env.AIRTABLE_PAT;
    try {
      assert.equal(readAirtablePat(file), "fake-test-value");
      assert.deepEqual(Object.keys(readEnv(file)), ["SUPABASE_DB_URL"]);
      assert.equal(readAirtablePat(path.join(dir, "missing.env")), null);
    } finally {
      if (saved !== undefined) process.env.AIRTABLE_PAT = saved;
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
