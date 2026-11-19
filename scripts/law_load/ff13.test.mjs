// F-F13.1 regression suite: the validator, its ledger and its grants on PGlite (Postgres 18), with the committed
// migrations, law/ and ref/ loaded the way load.mjs loads them. Every draft, name and fact here is synthetic.
//
//   cd scripts/law_load && node --test ff13.test.mjs
//
// Two mapping rows are signed inside this throwaway database only, with a test licence, so the gate allows one
// pair. Nothing here touches Supabase.
//
//   FF13_LIVE=1 node --test ff13.test.mjs
//
// Live mode runs the same expectations on the database in the repo .env (load.mjs's connection, TLS verified)
// inside one transaction that is rolled back at the end, so no ledger row, signature or word-band change survives.
// It exists because the character classes follow the database ctype: Supabase is ICU en_US.UTF-8, PGlite libc
// C.UTF-8 (measured 2026-11-03). Every statement runs under a savepoint, so an expected error does not abort the
// transaction. The validator runs as the connecting role, not ff13_make (it is a definer, so the checks are the
// same). Tests that need a fresh session, a new role or a function swap are skipped live: they do not depend on
// ctype and PGlite covers them.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import { seedSql, refRows, upsertRef, refGate, readEnv, connectionConfig } from "./load.mjs";
import { scramVerifier } from "./make_role.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MIG = path.join(ROOT, "supabase", "migrations");
const VISA = "PR-EE-CEC";
const DOC = "SUBMISSION-LETTER";
const REC = "recTESTabcdefghi1";
const EXEC = "0123456789abcdef0123456789abcdef";
const NAME = "Testa Applicanta Zed";
const FACTS = "Arrived on 2024-03-03. Employment began 2021-06-15. Language test taken 2025-01-20.";
// About 620 words of neutral text that triggers no rule.
const FILLER = Array(40).fill("The applicant has provided the supporting documents listed in the enclosed index for the officer to review.").join(" ");

const LIVE = process.env.FF13_LIVE === "1";
const SKIP_LIVE = LIVE && "needs a fresh session, a new role or a function swap, covered on PGlite";
let db;
let liveClient;
const q = async (sql, params = []) => (await db.query(sql, params)).rows;
const STAMPS = { model_requested: "claude-opus-5-5", model_served: "claude-opus-5-5", stop_reason: "end_turn", prompt_version: "F-F10.stage4@1",
  prompt_sha256: "a".repeat(64), input_tokens: "1200", output_tokens: "2400", request_id: "req_test_0001" };

async function validate(draft, o = {}) {
  const a = { record: REC, exec: EXEC, visa: VISA, doc: DOC, name: NAME, facts: FACTS, terms: "", ...STAMPS, ...o };
  if (!LIVE) await db.exec("SET ROLE ff13_make");
  try {
    const [r] = await q("SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
      [a.record, a.exec, a.visa, a.doc, draft, a.name, a.facts, a.terms, a.model_requested, a.model_served, a.stop_reason,
        a.prompt_version, a.prompt_sha256, a.input_tokens, a.output_tokens, a.request_id]);
    return r;
  } finally {
    if (!LIVE) await db.exec("RESET ROLE");
  }
}
const checks = (list) => list.map((e) => e.check);
// The body under test inside the letter structure F-F13.2 requires (specs/F-F13.2-sections-vocabulary.md), with the
// neutral filler as the Background, so each test reads only its own body. The name appears once, in the Re line.
const RCIC = "Jordan Testreviewer";
const letter = (body) => [`Draft for review by RCIC ${RCIC}. Not for submission until the RCIC of record has reviewed and signed it.`,
  `Re: Application for permanent residence of ${NAME}`, "Dear Officer,", "Introduction", body, "Background", FILLER, "Legal framework",
  "The provisions cited above set the requirements.", "Submissions", "The facts meet the requirements.", "Conclusion",
  "The officer is asked to approve the application.", "Respectfully submitted,", RCIC].join("\n\n");
const ledger = async (id) => (await q("SELECT * FROM ff13.validations WHERE id = $1", [id]))[0];

async function openLive() {
  const { caPath, ...cfg } = connectionConfig(readEnv());
  liveClient = new pg.Client(cfg);
  await liveClient.connect();
  await liveClient.query("BEGIN");
  await liveClient.query("SET LOCAL statement_timeout = '120s'");
  const guarded = async (sql, params) => {
    await liveClient.query("SAVEPOINT ff13_test");
    try {
      const r = await liveClient.query(sql, params);
      await liveClient.query("RELEASE SAVEPOINT ff13_test");
      return Array.isArray(r) ? r[r.length - 1] : r;
    } catch (e) {
      await liveClient.query("ROLLBACK TO SAVEPOINT ff13_test");
      throw e;
    }
  };
  db = { query: (sql, params = []) => guarded(sql, params), exec: (sql) => guarded(sql) };
}

after(async () => {
  if (liveClient) {
    await liveClient.query("ROLLBACK");
    await liveClient.end();
  }
});

before(async () => {
  if (LIVE) {
    await openLive();
    return signRows();
  }
  db = await PGlite.create();
  await db.exec(`CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;
                 CREATE ROLE authenticator NOINHERIT;`);
  for (const f of fs.readdirSync(MIG).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(fs.readFileSync(path.join(MIG, f), "utf8"));
  }
  const seed = seedSql();
  await db.exec(seed.head);
  await upsertRef({ query: (sql, params) => db.query(sql, params) }, refRows());
  await db.exec(seed.tail);
  const problems = await refGate({ query: (sql, params) => db.query(sql, params ?? []) }, refRows());
  assert.deepEqual(problems, []);
  await db.exec("COMMIT");
  await signRows();
});

async function signRows() {
  // Sign two rows of one pair (current) and one with a stale text hash (amended since review).
  await db.exec(`
    UPDATE ref.citation_map m SET reviewed_by_licence = 'R000001', reviewed_on = '2026-11-03',
           reviewed_text_sha256 = CASE WHEN m.provision_key = 'IRPR 87.1(2)(d)' THEN repeat('0', 64) ELSE p.text_sha256 END,
           reviewed_row_sha256 = ref.citation_row_sha256(m.document_type, m.visa_code, m.provision_key, m.purpose)
      FROM law.provisions p
     WHERE p.key = m.provision_key AND m.visa_code = '${VISA}' AND m.document_type = '${DOC}'
       AND m.provision_key IN ('IRPR 87.1(2)(a)', 'IRPR 87.1(2)(c)', 'IRPR 87.1(2)(d)')`);
}

test("the gate allows the signed pair with the current rows only", async () => {
  const [g] = await q(`SELECT * FROM ref.drafting_gate('${VISA}', '${DOC}')`);
  assert.equal(g.allowed, true);
  assert.deepEqual(g.provision_keys.sort(), ["IRPR 87.1(2)(a)", "IRPR 87.1(2)(c)"]);
  assert.deepEqual(g.flags, ["amended since review: IRPR 87.1(2)(d)"]);
});

test("a clean draft passes apart from the gate flag, and the ledger holds no client text", async () => {
  const r = await validate(letter("Under IRPR 87.1(2)(a) and paragraph 87.1(2)(c) of the IRPR the applicant qualifies. "
    + "The applicant arrived on March 3, 2024 and has worked since June 2021."));
  assert.equal(r.verdict, "pass_with_flags", r.review_note);
  assert.equal(r.hard_fail_count, 0, r.review_note);
  assert.deepEqual(checks(r.detail.soft_flags), ["gate_flag"]);
  assert.deepEqual(r.detail.citations.map((c) => [c.key, c.state]), [["IRPR 87.1(2)(a)", "provided"], ["IRPR 87.1(2)(c)", "provided"]]);
  const row = await ledger(r.ledger_id);
  const raw = JSON.stringify(row);
  for (const pii of [NAME, "Testa", "March 3, 2024", "June 2021", "2024-03-03", "supporting documents"]) {
    assert.ok(!raw.includes(pii), `ledger holds ${pii}`);
  }
  assert.equal(row.airtable_record_id, REC);
  assert.equal(row.draft_sha256.length, 64);
  assert.equal(row.validator_version, "F-F13.2+F-F10+X-32");
  assert.match(row.law_sources, /^IRPA:[0-9a-f]{16},IRPR:[0-9a-f]{16}$/);
});

test("fabricated, repealed and unprovided citations", async () => {
  const r = await validate(letter("See IRPR 847 and IRPA 13(2). Also IRPA 25(1) and IRPA, s. 11(1)."));
  assert.equal(r.verdict, "reject");
  const hard = r.detail.hard_fails;
  assert.ok(hard.some((e) => e.check === "fabricated_citation" && e.key === "IRPR 847"), r.review_note);
  assert.ok(hard.some((e) => e.check === "not_in_force" && e.key === "IRPA 13(2)" && e.info === "repealed"), r.review_note);
  const soft = r.detail.soft_flags;
  assert.ok(soft.some((e) => e.check === "unprovided_citation" && e.key === "IRPA 25(1)"), r.review_note);
  assert.ok(soft.some((e) => e.check === "unprovided_citation" && e.key === "IRPA 11(1)"), r.review_note);
});

test("a sub-unit of a provided key is provided, a cited amended row is flagged", async () => {
  const r = await validate(letter("IRPR 87.1(2)(d) applies."));
  assert.ok(r.detail.soft_flags.some((e) => e.check === "amended_since_review" && e.key === "IRPR 87.1(2)(d)"), r.review_note);
  assert.equal(r.hard_fail_count, 0, r.review_note);
});

test("citation-like text in any other form is unresolved", async () => {
  for (const bad of ["section 25 of the Act", "sections 12 and 13 of the IRPA", "R179(b)", "IRPR 87.1(2)(a) and (c)",
    "s. 5 of the Citizenship Act", "§ 25", "IRPR 87.1(abcdefgh)", "IRPA s 25 and s 26"]) {
    const r = await validate(letter(`As set out in ${bad}, the applicant qualifies.`));
    assert.ok(checks(r.detail.hard_fails).includes("unresolved_reference"), `${bad}: ${r.review_note}`);
  }
  for (const ok of ["it's 2 years", "the applicant's 3 children", "IRPA s 25(1)", "subsection 25(1) of the Immigration and Refugee Protection Act"]) {
    const r = await validate(letter(`Note ${ok} here.`));
    assert.ok(!checks(r.detail.hard_fails).includes("unresolved_reference"), `${ok}: ${r.review_note}`);
  }
});

test("case law and file numbers are forbidden, a precedent name inside the applicant's name is not", async () => {
  for (const [bad, kind] of [["Baker v. Canada", "style of cause"], ["2019 SCC 65", "neutral citation"], ["IMM-1234-22", "court or IRB file number"],
    ["TB1-12345", "court or IRB file number"], ["Vavilov", "precedent name"], ["2003 FC 1234", "neutral citation"], ["[2004] 1 F.C.R. 3", "law report"]]) {
    const r = await validate(letter(`As held in ${bad}, the officer erred.`));
    assert.ok(r.detail.hard_fails.some((e) => e.check === "forbidden_content" && e.info === kind), `${bad}: ${r.review_note}`);
  }
  const r = await validate(letter("Mr. Ribic Testname applies.").replace(NAME, "Ribic Testname"), { name: "Ribic Testname" });
  assert.ok(!checks(r.detail.hard_fails).includes("forbidden_content"), r.review_note);
});

test("leftover placeholders", async () => {
  for (const bad of ["[Applicant Name]", "{{name}}", "Dear ____,", "TODO add facts", "<<NAME>>", "%FIRST_NAME%", "${name}", "Lorem ipsum"]) {
    const r = await validate(letter(`Text ${bad} text.`));
    assert.ok(checks(r.detail.hard_fails).includes("placeholder"), `${bad}: ${r.review_note}`);
  }
});

test("word band: under the floor rejects, over the ceiling flags", async () => {
  const short = await validate(`${NAME} applies under IRPR 87.1(2)(a).`);
  assert.ok(short.detail.hard_fails.some((e) => e.check === "below_word_floor"), short.review_note);
  const long = await validate(letter(Array(8).fill(FILLER).join(" ")));
  assert.ok(long.detail.soft_flags.some((e) => e.check === "above_word_ceiling"), long.review_note);
  assert.equal(long.hard_fail_count, 0, long.review_note);
});

test("applicant name: absent or missing rejects, whitespace differences do not", async () => {
  const absent = await validate(letter("text").replace(NAME, "Someone Else"));
  assert.ok(checks(absent.detail.hard_fails).includes("applicant_name_absent"), absent.review_note);
  const missing = await validate(letter("text"), { name: "  " });
  assert.ok(checks(missing.detail.hard_fails).includes("applicant_name_missing"), missing.review_note);
  const spaced = await validate(letter("text").replace(NAME, "Testa  Applicanta\nZed"));
  assert.ok(!checks(spaced.detail.hard_fails).some((c) => c.startsWith("applicant_name")), spaced.review_note);
  const cased = await validate(letter("text").replace(NAME, NAME.toUpperCase()));
  assert.ok(checks(cased.detail.hard_fails).includes("applicant_name_absent"), cased.review_note);
});

test("an exemplar term leaks, and the ledger keeps its line number only", async () => {
  const r = await validate(letter("Like the case of Exemplo Persona, this one qualifies."), { terms: "Nobody Here\nexemplo persona\n" });
  const e = r.detail.hard_fails.find((x) => x.check === "exemplar_leak");
  assert.ok(e && e.info === "term 2", r.review_note);
  const row = await ledger(r.ledger_id);
  assert.ok(!JSON.stringify(row).toLowerCase().includes("exemplo"));
  const regexy = await validate(letter("Paid C$1.5 (net)."), { terms: "C$1.5 (net)\na.b" });
  assert.ok(checks(regexy.detail.hard_fails).includes("exemplar_leak"), regexy.review_note);
  assert.equal(regexy.detail.hard_fails.filter((x) => x.check === "exemplar_leak").length, 1, regexy.review_note);
});

test("dates: in the facts, not in the facts, invalid, ambiguous, and the letter's own date", async () => {
  const [{ today }] = await q("SELECT to_char((now() AT TIME ZONE 'America/Toronto')::date, 'FMMonth FMDD, YYYY') AS today");
  const r = await validate(letter(`Dated ${today}. Arrived 3 March 2024 and on 2024-03-03. Since June 2021. `
    + "Left on April 5, 2023. Born February 30, 2024. Signed 03/04/2024. Tested January 2025."));
  const soft = r.detail.soft_flags;
  const of = (c) => soft.filter((e) => e.check === c).map((e) => e.text);
  assert.deepEqual(of("date_not_in_facts"), ["April 5, 2023"], r.review_note);
  assert.deepEqual(of("invalid_date"), ["February 30, 2024"], r.review_note);
  assert.deepEqual(of("ambiguous_date"), ["03/04/2024"], r.review_note);
  assert.ok(r.review_note.includes('"April 5, 2023"'));
  const row = await ledger(r.ledger_id);
  assert.ok(!JSON.stringify(row).includes("April 5"));
  assert.ok(row.soft_flags.some((e) => e.check === "date_not_in_facts" && Number.isInteger(e.offset)));
});

test("gate refusals reject", async () => {
  const unsigned = await validate(letter("IRPR 87.1(2)(a)."), { doc: "LOE" });
  assert.ok(unsigned.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "no current reviewed citation rows"), unsigned.review_note);
  assert.ok(unsigned.detail.soft_flags.some((e) => e.check === "unprovided_citation"), unsigned.review_note);
  const irb = await validate(letter("text"), { visa: "REF-CLAIM" });
  assert.ok(irb.detail.hard_fails.some((e) => e.check === "gate_refused" && e.info === "IRB matter, Module F does not draft"), irb.review_note);
  const junk = await validate(letter("text"), { visa: "'; DROP TABLE x; --", doc: null });
  assert.ok(checks(junk.detail.hard_fails).includes("gate_refused"), junk.review_note);
  assert.equal((await ledger(junk.ledger_id)).visa_code, null);
});

test("inputs and stamps", async () => {
  const cut = await validate(letter("text"), { stop_reason: "max_tokens" });
  assert.ok(cut.detail.hard_fails.some((e) => e.check === "stop_reason_not_end_turn" && e.info === "max_tokens"), cut.review_note);
  const bare = await validate(letter("text"), { exec: null, model_requested: "", model_served: null, stop_reason: null,
    prompt_version: null, prompt_sha256: null, input_tokens: null, output_tokens: null, request_id: null });
  assert.ok(bare.detail.soft_flags.some((e) => e.check === "stamps_missing"), bare.review_note);
  assert.equal(bare.hard_fail_count, 0, bare.review_note);
  const odd = await validate(letter("text"), { prompt_sha256: "xyz", input_tokens: "12a", exec: "Name Of Client" });
  assert.ok(odd.detail.soft_flags.some((e) => e.check === "stamps_malformed" && e.info === "make_execution_id, prompt_sha256, input_tokens"), odd.review_note);
  const row = await ledger(odd.ledger_id);
  assert.equal(row.make_execution_id, null);
  assert.equal(row.input_tokens, null);
  const norec = await validate(letter("text"), { record: "Client Name" });
  assert.ok(checks(norec.detail.hard_fails).includes("airtable_record_id_malformed"), norec.review_note);
  assert.equal((await ledger(norec.ledger_id)).airtable_record_id, null);
  const big = await validate("x ".repeat(60000));
  assert.ok(checks(big.detail.hard_fails).includes("input_too_large"), big.review_note);
  const empty = await validate(null);
  assert.ok(checks(empty.detail.hard_fails).includes("draft_empty"), empty.review_note);
});

test("the same input gives the same verdict", async () => {
  const d = letter("IRPR 847. IRPA 25(1). Left on April 5, 2023.");
  const a = await validate(d);
  const b = await validate(d);
  assert.notEqual(a.ledger_id, b.ledger_id);
  assert.deepEqual({ ...a.detail, ledger_id: 0 }, { ...b.detail, ledger_id: 0 });
});

test("the ledger is append-only for every role, the owner included", async () => {
  const [{ id }] = await q("SELECT min(id) AS id FROM ff13.validations");
  await assert.rejects(q("UPDATE ff13.validations SET verdict = 'pass' WHERE id = $1", [id]), /append-only/);
  await assert.rejects(q("DELETE FROM ff13.validations WHERE id = $1", [id]), /append-only/);
  await assert.rejects(q("TRUNCATE ff13.validations"), /append-only/);
});

test("ff13_make can run the validator and nothing else", { skip: SKIP_LIVE }, async () => {
  await db.exec("SET ROLE ff13_make");
  try {
    for (const sql of ["SELECT 1 FROM law.provisions LIMIT 1", "SELECT 1 FROM ref.citation_map LIMIT 1", "SELECT 1 FROM ff13.validations LIMIT 1",
      "SELECT * FROM ff13._dates('March 3, 2024')", "SELECT * FROM ref.drafting_gate('PR-EE-CEC', 'LOE')",
      "INSERT INTO ff13.validations (validator_version, law_sources, draft_sha256, draft_chars, verdict, provided_keys, citations, hard_fails, soft_flags) VALUES ('x', 'x', repeat('a', 64), 0, 'pass', '{}', '[]', '[]', '[]')",
      "CREATE TABLE ff13.x (a int)"]) {
      await assert.rejects(q(sql), /permission denied/, sql);
    }
  } finally {
    await db.exec("RESET ROLE");
  }
  for (const role of ["anon", "authenticated", "service_role"]) {
    const [x] = await q("SELECT has_function_privilege($1, 'ff13.validate_draft(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text)', 'EXECUTE') AS h", [role]);
    assert.equal(x.h, false, role);
  }
});

test("make_role's SCRAM verifier equals the one Postgres builds, and Postgres stores it as given", { skip: SKIP_LIVE }, async () => {
  await db.exec("CREATE ROLE scram_probe NOLOGIN; SET password_encryption = 'scram-sha-256'; ALTER ROLE scram_probe PASSWORD 'pencil-not-a-secret'");
  const [{ rolpassword: theirs }] = await q("SELECT rolpassword FROM pg_authid WHERE rolname = 'scram_probe'");
  const m = /^SCRAM-SHA-256\$(\d+):([^$]+)\$/.exec(theirs);
  assert.ok(m, "Postgres verifier format");
  assert.equal(scramVerifier("pencil-not-a-secret", Buffer.from(m[2], "base64"), Number(m[1])), theirs);
  const mine = scramVerifier("another-test-value");
  await db.exec(`ALTER ROLE scram_probe PASSWORD '${mine}'`);
  const [{ rolpassword: stored }] = await q("SELECT rolpassword FROM pg_authid WHERE rolname = 'scram_probe'");
  assert.equal(stored, mine);
  await db.exec("DROP ROLE scram_probe");
});

// Pre-apply review 2026-11-03: every confirmed finding keeps a regression case here.
const hardOf = (r) => checks(r.detail.hard_fails);
async function expectHard(body, check, o = {}) {
  const r = await validate(letter(body), o);
  assert.ok(hardOf(r).includes(check), `${JSON.stringify(body)} expected ${check}: ${r.review_note}`);
  return r;
}
async function expectClean(body, check, o = {}) {
  const r = await validate(letter(body), o);
  assert.ok(!hardOf(r).includes(check), `${JSON.stringify(body)} must not give ${check}: ${r.review_note}`);
  return r;
}

test("review: Unicode spaces, dashes, fullwidth forms and lookalikes are read, invisible characters reject", async () => {
  for (const [body, check] of [["Under IRPR 999(9)", "fabricated_citation"], ["IRPR 999(9)", "fabricated_citation"],
    ["IRPR, s. 999(9)", "fabricated_citation"], ["section 999 of the IRPA", "fabricated_citation"], ["IRPA 13(2)", "not_in_force"],
    ["IRPR ９９９(9)", "fabricated_citation"], ["IRPR 87.1(2)（z）", "fabricated_citation"],
    ["IRPR​999(9)", "unreadable_character"], ["IR‍PR 999(9)", "unreadable_character"], ["IРPR 999(9)", "mixed_script"],
    ["Baker v. Canada", "forbidden_content"], ["IMM–1234–22", "forbidden_content"], ["IRPR 87.1(2)(a)—(c)", "unresolved_reference"]]) {
    await expectHard(body, check);
  }
  const d = await validate(letter("Left on April 5, 2023."));
  assert.ok(d.detail.soft_flags.some((e) => e.check === "date_not_in_facts"), d.review_note);
  const text = letter("The applicant’s résumé “shows” growth — steady… IRPR 87.1(2)(a).");
  const clean = await validate(text);
  assert.equal(clean.hard_fail_count, 0, clean.review_note);
  const f = clean.detail.citations.find((c) => c.key === "IRPR 87.1(2)(a)");
  assert.equal(text.substr(f.offset - 1, 15), "IRPR 87.1(2)(a)", "offsets index the draft as received");
});

test("review: a unit after whitespace, a list, a range or a bare number after a citation is unresolved", async () => {
  for (const bad of ["IRPR 87.1 (2)(z)", "IRPR 87.1(2) (z)", "IRPR 87.1(2)\n(z)", "IRPA 13 (2)", "IRPR 87.1(2)(a) through (c)",
    "IRPR 87.1(2)(a)/(c)", "IRPR 87.1(2)(a) and/or (c)", "IRPR 87.1(2)(a) & (c)", "IRPR 87.1(2)(a)‑(c)", "IRPR 87.1(2)(a) and 87.1(2)(b)",
    "IRPA 25(1) and 13(2)", "paragraph 87.1(2)(a) of the IRPR and (c)", "IRPR 87.1(2) (a) and (c)"]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["IRPR 87.1(2)(a) (the Canadian experience class)", "(the experience class)", "(CEC)", "(emphasis added)", "2 (two)",
    "CLB 9 (IELTS)", "IRPA 25(1) and 2 years", "(T4) and (T4A)", "(2019) to (2021)", "(IELTS) or (CELPIP)",
    "conditions (a) and (b) listed above", "items (i), (ii) and (iii)"]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review: other citation shapes are unresolved, ordinary tokens are not", async () => {
  for (const bad of ["87.1(2)(z) of the IRPR", "999 of the Act", "Reg 216", "R 216(1)(b)", "R216", "IRPR-216", "IRPR: 216(1)",
    "Division 7 of the IRPR", "s25(1) of the Act", "S25(1)", "S. 25 of the Act"]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["A 12-month work permit", "R3T 2N2", "DELF A2", "Schedule 4 and Part 2 of the IMM 0008", "SK S7K 3J8",
    "Saskatchewan S4P 1C8", "SS3", "her S4 examinations", "Room S201", "Singapore S238823", "M.S. 2020", "U.S. 10-year visitor visa"]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review: style of cause forms are caught, vs comparisons are prose", async () => {
  for (const bad of ["Canada (Citizenship and Immigration) v. Khosa", "Baker v. M.C.I.", "Singh v. M.E.I.", "Muñoz v. Canada",
    "Ahmed v The Minister", "IMM 1234-22", "Baker v Canada"]) {
    await expectHard(`As held in ${bad}, the officer erred.`, "forbidden_content");
  }
  for (const ok of ["Her income (CAD) vs. expenses", "Tuition in the UK vs Canada", "compared Toronto vs. Vancouver", "studied Biology vs. Chemistry"]) {
    await expectClean(ok, "forbidden_content");
  }
});

test("review: a precedent name or a T- or A- number in the case facts is a person or an address", async () => {
  const facts = `${FACTS} Sponsor Rajan Kanthasamy. Address Unit A-12-03, Menara Sentral.`;
  await expectClean("The sponsor Rajan Kanthasamy supports the application.", "forbidden_content", { facts });
  await expectHard("The sponsor Rajan Kanthasamy supports the application.", "forbidden_content");
  await expectHard("As held in Kanthasamy v. Canada, the officer erred.", "forbidden_content", { facts });
  await expectClean("The applicant lives at Unit A-12-03, Menara Sentral.", "forbidden_content", { facts });
  await expectHard("The applicant lives at Unit A-12-03, Menara Sentral.", "forbidden_content");
  await expectHard("See T-1234-22 and A-123-22.", "forbidden_content", { facts });
});

test("review: exemplar terms match across whitespace, typography and Unicode forms", async () => {
  for (const [term, body] of [["Exemplo Persona", "Exemplo  Persona"], ["Exemplo Persona", "Exemplo\nPersona"], ["Exemplo Persona", "Exemplo Persona"],
    ["O'Brienna", "O’Brienna"], ["O’Brienna", "O'Brienna"], ["Eléna", "Eléna"], ["Eléna", "Eléna"]]) {
    await expectHard(`Like the case of ${body}, this one qualifies.`, "exemplar_leak", { terms: term });
  }
});

test("review: the applicant name is a whole word, typography folded, case kept", async () => {
  await expectHard("text", "applicant_name_absent", { name: "Testa Applicanta Ze" });
  const own = await validate(letter("text").replace(NAME, `${NAME}'s file`));
  assert.ok(!hardOf(own).some((c) => c.startsWith("applicant_name")), own.review_note);
  for (const [name, inDraft, ok] of [["Testa O'Brien", "Testa O’Brien", true], ["Testa O’Brien", "Testa O'Brien", true],
    ["Jean‑Luc Testa", "Jean-Luc Testa", true], ["Testa O'Brien", "Testa OBrien", false], ["Testa O'Brien", "TESTA O'BRIEN", false]]) {
    const r = await validate(letter("text").replace(NAME, inDraft), { name });
    assert.equal(hardOf(r).includes("applicant_name_absent"), !ok, `${name} / ${inDraft}: ${r.review_note}`);
  }
});

test("review: a fabricated key never carries client text into the ledger", async () => {
  const r = await validate(letter("Under IRPR 87.1(2)(Smith) and IRPR 87.1(Jones)(a) the applicant qualifies."));
  assert.ok(hardOf(r).includes("unresolved_reference"), r.review_note);
  const raw = JSON.stringify(await ledger(r.ledger_id));
  assert.ok(!raw.includes("Smith") && !raw.includes("Jones"), raw);
});

test("review: an error before the gate assigns is caught and logged as a reject", { skip: SKIP_LIVE }, async () => {
  await db.exec(`BEGIN;
    CREATE OR REPLACE FUNCTION ref.drafting_gate(p_visa_code TEXT, p_document_type TEXT)
      RETURNS TABLE (allowed BOOLEAN, reason TEXT, provision_keys TEXT[], flags TEXT[])
      LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS 'SELECT true, ''ok'', ARRAY[(1/0)::text], ''{}''::text[]';`);
  try {
    const r = await validate(letter("text"));
    assert.deepEqual(r.detail.hard_fails, [{ check: "validator_error", info: "SQLSTATE 22012" }]);
    assert.equal(r.detail.gate.allowed, null);
    assert.equal((await ledger(r.ledger_id)).verdict, "reject");
  } finally {
    await db.exec("ROLLBACK");
  }
});

test("review: dense dates in full-size inputs finish well inside the role's 20 s timeout", async () => {
  const unit = "On March 3, 2024 and 2024-03-04. ";
  const body = unit.repeat(Math.ceil(100000 / unit.length));
  const draft = (NAME + " " + body).slice(0, 99990);
  const t = Date.now();
  const r = await validate(draft, { facts: body.slice(0, 99990) });
  const ms = Date.now() - t;
  assert.ok(ms < 8000, `${ms} ms`);
  assert.ok(!hardOf(r).includes("validator_error"), r.review_note.slice(0, 300));
  assert.ok(r.detail.hard_fails.some((e) => e.check === "too_many_matches" && e.info === "dates"), "the date cap is reported, not silent");
});

test("review: the append-only triggers fire under session_replication_role = replica", async () => {
  const [{ id }] = await q("SELECT min(id) AS id FROM ff13.validations");
  await db.exec("SET session_replication_role = replica");
  try {
    await assert.rejects(q("UPDATE ff13.validations SET verdict = 'pass' WHERE id = $1", [id]), /append-only/);
    await assert.rejects(q("DELETE FROM ff13.validations WHERE id = $1", [id]), /append-only/);
    await assert.rejects(q("TRUNCATE ff13.validations"), /append-only/);
  } finally {
    await db.exec("RESET session_replication_role");
  }
});

test("review: a sub-unit of a provided key is provided, a parent of a provided key is not", async () => {
  await db.exec(`
    UPDATE ref.citation_map m SET reviewed_by_licence = 'R000001', reviewed_on = '2026-11-03', reviewed_text_sha256 = p.text_sha256,
           reviewed_row_sha256 = ref.citation_row_sha256(m.document_type, m.visa_code, m.provision_key, m.purpose)
      FROM law.provisions p
     WHERE p.key = m.provision_key AND m.visa_code = 'TR-VISIT' AND m.document_type = '${DOC}' AND m.provision_key = 'IRPR 183(2)'`);
  const r = await validate(letter("Under IRPR 183(2)(a) the applicant qualifies, and IRPR 183(2) applies. IRPR 183 sets the conditions."), { visa: "TR-VISIT" });
  const state = Object.fromEntries(r.detail.citations.map((c) => [c.key, c.state]));
  assert.deepEqual(r.detail.gate.provision_keys, ["IRPR 183(2)"]);
  assert.equal(state["IRPR 183(2)"], "provided", r.review_note);
  assert.equal(state["IRPR 183(2)(a)"], "provided", r.review_note);
  assert.equal(state["IRPR 183"], "unprovided", r.review_note);
});

test("review: a type with no word band rejects", async () => {
  await db.exec(`UPDATE ref.document_types SET min_words = NULL WHERE code = '${DOC}'`);
  try {
    const r = await validate(letter("IRPR 87.1(2)(a)."));
    assert.ok(r.detail.hard_fails.some((e) => e.check === "no_word_band" && e.info === DOC), r.review_note);
  } finally {
    await db.exec(`UPDATE ref.document_types SET min_words = 500 WHERE code = '${DOC}'`);
  }
});

test("review: pg_temp types cannot shadow the definer's types (fresh session, no warm-up call)", { skip: SKIP_LIVE }, async () => {
  const fresh = await PGlite.create();
  try {
    await fresh.exec("CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;");
    for (const f of fs.readdirSync(MIG).filter((f) => f.endsWith(".sql")).sort()) {
      await fresh.exec(fs.readFileSync(path.join(MIG, f), "utf8"));
    }
    await fresh.exec(`SET ROLE ff13_make;
      CREATE FUNCTION pg_temp.evil(x pg_catalog.text) RETURNS pg_catalog.bool LANGUAGE plpgsql AS
        'BEGIN IF current_user <> ''ff13_make'' THEN RAISE EXCEPTION ''ran as %'', current_user; END IF; RETURN true; END';
      CREATE DOMAIN pg_temp.text AS pg_catalog.text CHECK (pg_temp.evil(VALUE));
      CREATE DOMAIN pg_temp.int4range AS pg_catalog.int4range CHECK (pg_temp.evil(VALUE::pg_catalog.text));
      CREATE DOMAIN pg_temp.jsonb AS pg_catalog.jsonb CHECK (pg_temp.evil(VALUE::pg_catalog.text));`);
    const [r] = (await fresh.query("SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
      [REC, EXEC, VISA, DOC, letter("IRPR 847."), NAME, FACTS, "", ...Object.values(STAMPS)])).rows;
    assert.ok(!checks(r.detail.hard_fails).includes("validator_error"), r.review_note);
    assert.ok(checks(r.detail.hard_fails).includes("gate_refused"), r.review_note);
  } finally {
    await fresh.close();
  }
});

// Second review round 2026-11-03.
const cp = (n) => String.fromCodePoint(n);

test("review 2: McGill style of cause and R v X are case law, also with the name in the facts", async () => {
  for (const bad of ["Canada (Citizenship and Immigration) v Khosa", "Canada v Khosa", "Canada (MCI) v Smith", "Canada (Attorney General) v Ishaq",
    "Smith v Jones", "R v Appulonappa", "R. v. Appulonappa"]) {
    await expectHard(`As held in ${bad}, the officer erred.`, "forbidden_content");
  }
  await expectHard("As held in Canada (Minister of Citizenship and Immigration) v Vavilov, the officer erred.", "forbidden_content",
    { facts: `${FACTS} Sponsor Ivan Vavilov.` });
  for (const ok of ["Type V visa", "Grade V piano", "Part V of the guide", "the R value", "Tuition in the UK vs Canada"]) {
    await expectClean(ok, "forbidden_content");
  }
});

test("review 2: a unit word before a parenthesized unit is unresolved", async () => {
  for (const bad of ["subparagraph (iv) of IRPR 87.1(2)(a)", "paragraph (z) of IRPR 87.1(2)", "paragraph (z) of subsection 87.1(2) of the IRPR",
    "paragraph (2)(z) of IRPR 87.1", "subsection (2) of section 87.1 of the IRPR", "subparagraph (iv) of paragraph 87.1(2)(a) of the IRPR",
    "clause (A) of IRPR 87.1(2)(a)", "paragraph (z)"]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["the relevant section(s) of the guide", "the paragraph(s) above"]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review 2: a list after a citation ends on a unit, joined by any mix of punctuation and up to three words", async () => {
  for (const bad of ["IRPR 87.1(2)(a), and (c)", "IRPR 87.1(2)(a), or (z)", "IRPR 87.1(2)(a); see also (z)", "IRPR 87.1(2)(a) and, in particular, (z)",
    "IRPR 87.1, subsection (2)(z)", "IRPR 87.1(2) (aa)", "IRPR 87.1(2)(a) (CEC) and (c)", "IRPR 87.1(2)(a) and (2.1)", "IRPR 87.1(2)(a) and (ii.1)",
    "IRPR 87.1(2)(a) and (III)", "IRPR 87.1(2)(a) or (iv)", "IRPR 87.1(2)(a) and (A)", "IRPR 87.1(2)(a), (c)"]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["IRPR 87.1(2)(a), she lived in Ontario (ON).", "IRPR 87.1(2)(a) for the class (CEC) applies.",
    "IRPR 87.1(2)(a), the applicant has three (3) years.", "Under IRPR 87.1(2)(a) through Express Entry (EE), the applicant applies.",
    "IRPR 87.1(2)(c) is met (2023).", "IRPR 87.1(2)(a) language results (CLB) are attached.", "IRPR 87.1(2)(a) via the visa (TRV) office.",
    "paragraph 87.1(2)(a) of the IRPR through Express Entry (EE) applies."]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review 2: default-ignorable characters and ASCII lookalikes reject, a key cut short is unresolved", async () => {
  for (const n of [0xfe0f, 0xfe00, 0xe0041, 0xe0100, 0x180b, 0x2065, 0x1bca0, 0x1d173]) {
    await expectHard(`IR${cp(n)}PR 999(9)`, "unreadable_character");
  }
  for (const body of ["IRPRﾠ999(9)", "sectionㅤ999 of the IRPR", "IRPR 8️47", "IRPR ٨٤٧",
    `IRPR ${cp(0x1d7d6)}${cp(0x1d7d2)}${cp(0x1d7d5)}`, "IRPR 8⁴7", `${cp(0x1d5a8)}${cp(0x1d5b1)}${cp(0x1d5af)}${cp(0x1d5b1)} 847`, "ⅠRPR 847"]) {
    await expectHard(body, "unreadable_character");
  }
  const tag = await validate(letter(`IR${cp(0xe0041)}PR 999(9)`));
  assert.ok(tag.detail.hard_fails.some((e) => e.check === "unreadable_character" && e.info === "U+E0041"), tag.review_note);
  for (const body of ["IRPᎡ 847", "IR̲PR 847"]) {
    await expectHard(body, "mixed_script");
  }
  await expectHard("IRPR 8²7", "unresolved_reference");
  for (const ok of ["The applicant's résumé shows growth.", "Muñoz and Zoë applied.", "The apartment is 75 m².",
    "Paid €500 — “in full”…", "Brand™ products."]) {
    const r = await expectClean(ok, "mixed_script");
    assert.ok(!hardOf(r).includes("unreadable_character"), `${ok}: ${r.review_note}`);
  }
});

test("review 2: fullwidth brackets, braces and low line are placeholders, fullwidth prose punctuation is not", async () => {
  for (const bad of ["［Officer Name］", "｛｛name｝｝", "＿＿＿＿", "＜＜NAME＞＞",
    "＄｛name｝", "％FIRST_NAME％"]) {
    await expectHard(`Text ${bad} text.`, "placeholder");
  }
  await expectClean("Really！ Why？ Note： 50％ ＆ more.", "placeholder");
});

test("review 2: the forbidden-content cap is a hard fail, and case does not hide case law", async () => {
  const facts = `${FACTS} Sponsor Rajan Ribic.`;
  const r = await validate(letter(`${"Ribic ".repeat(500)}Vavilov`), { facts });
  assert.ok(r.detail.hard_fails.some((e) => e.check === "too_many_matches" && e.info === "forbidden content"), r.review_note.slice(0, 300));
  for (const bad of ["DUNSMUIR", "STANDARD OF REVIEW: VAVILOV", "2019 CANLII 1234", "45 IMM. L.R. (4th) 1"]) {
    await expectHard(`See ${bad} here.`, "forbidden_content");
  }
  await expectClean("SPONSOR: RAJAN DUNSMUIR", "forbidden_content", { facts: `${FACTS} Sponsor Rajan Dunsmuir.` });
});

test("review 2: schedules to the instrument, four-digit-year file numbers and split acronyms", async () => {
  for (const bad of ["Schedule 9 to the IRPR", "Schedule 1 to the Immigration and Refugee Protection Regulations", "Schedule 9 to these Regulations",
    "Division 7 to the IRPR", "Part 3 of these Regulations", "IR-\nPR 847", "IR PR 847", "I-\nRPR 847"]) {
    await expectHard(bad, "unresolved_reference");
  }
  await expectHard("See IMM-1234-2022.", "forbidden_content");
  for (const ok of ["Express Entry was introduced in 2015 under the IRPA", "The amendments made in 2023 to the Regulations apply",
    "Part 2 of the Employment Insurance Act"]) {
    await expectClean(ok, "unresolved_reference");
  }
  for (const terms of ["Alpha Partners\rBravo Holdings", "Alpha Partners Bravo Holdings"]) {
    const x = await validate(letter("The firm Bravo Holdings advised."), { terms });
    assert.ok(x.detail.hard_fails.some((e) => e.check === "exemplar_leak" && e.info === "term 2"), x.review_note);
  }
});

test("review 2: shapes the F-F10 prompt must avoid stay hard fails (language scores, glued sub-references, a list right after a citation)", async () => {
  for (const bad of ["L 8.5, R 7.5, W 7.0 and S 7.5", "L10, R9, W9 and S10", "R 28, L 27, S 25 and W 26", "Reading section 28", "IMM 5257(E)",
    "Tab 4(a)", "question 2(b) of the IMM 5257", "IRPR 87.1(2)(a): (a) that she has ties", "IRPR 87.1(2)(a)\n(a) that she has ties"]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["Listening 8.5, Reading 7.5, Writing 7.0 and Speaking 7.5", "L: 8.5, R: 7.5, W: 7.0, S: 7.5", "CLB 9 in each of the four abilities",
    "IMM 5257 (E)", "Tab 4A", "IRPR 87.1(2)(a). (a) that she has ties", "IRPR 87.1(2)(a)\n\n1. She has ties"]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review 2: unknown codes and off-shape stamps never reach the ledger, nor a mixed-case unit", async () => {
  const r = await validate(letter("section 87(Za)(ch) of the IRPR applies."), { visa: "ABCDEF", doc: "XYZ", model_requested: "JohnSmith",
    model_served: "john@example.com", stop_reason: "JaneDoe", prompt_version: "john@example.com", request_id: "janedoe" });
  assert.ok(r.detail.hard_fails.some((e) => e.check === "stop_reason_not_end_turn" && e.info === "not a known stop reason"), r.review_note);
  assert.ok(hardOf(r).includes("unresolved_reference"), r.review_note);
  const row = await ledger(r.ledger_id);
  for (const c of ["visa_code", "document_type", "model_requested", "model_served", "stop_reason", "prompt_version", "request_id"]) {
    assert.equal(row[c], null, c);
  }
  const raw = JSON.stringify(row);
  for (const t of ["ABCDEF", "XYZ", "John", "Jane", "janedoe", "Za"]) {
    assert.ok(!raw.includes(t), `${t} in ${raw}`);
  }
  const ok = await ledger((await validate(letter("text"))).ledger_id);
  assert.deepEqual([ok.visa_code, ok.model_requested, ok.stop_reason, ok.prompt_version, ok.request_id],
    [VISA, "claude-opus-5-5", "end_turn", "F-F10.stage4@1", "req_test_0001"]);
});

// Third review round 2026-11-03.
test("review 3: a bare number listed or ranged after a citation is unresolved, a time span or figure is not", async () => {
  for (const bad of ["IRPR 75 and 76", "IRPR 75-999", "IRPR 75 and 98", "IRPR 87.1(2)(a), 999 and 1000", "IRPA 25(1) and 25.1", "IRPR, s. 75 and 76",
    "section 75 of the IRPR and 999", "IRPR 75 and 76 set out the requirements.", "IRPR 75 to 999", "IRPR 75 & 999", "IRPR 75/999", "IRPR 75; 999"]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["Under IRPR 87.1(2)(a), 12 months of full-time work", "IRPA 10.1(1), 60-day", "IRPA 25(1) and 2 years",
    "The applicant meets:\n1. IRPR 87.1(2)(a);\n2. IRPR 87.1(2)(c)."]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review 3: markdown underscore emphasis does not switch the rules off", async () => {
  for (const [bad, check] of [["_IRPR 999_", "fabricated_citation"], ["＿IRPR 999＿", "fabricated_citation"], ["__IRPR 98__", "not_in_force"],
    ["_s. 999_", "unresolved_reference"], ["_section 999 of the Act_", "unresolved_reference"], ["_Baker v. Canada_", "forbidden_content"],
    ["_Kanthasamy_", "forbidden_content"], ["__Vavilov__", "forbidden_content"], ["_2019 SCC 65_", "forbidden_content"], ["_IMM-1234-22_", "forbidden_content"],
    ["_TBD_", "placeholder"]]) {
    await expectHard(`As held in ${bad}, the officer erred.`, check);
  }
  const u = await validate(letter("Under _IRPA 25_ and on _March 9, 2023_ the applicant applied."));
  assert.ok(u.detail.soft_flags.some((e) => e.check === "unprovided_citation"), u.review_note);
  assert.ok(u.detail.soft_flags.some((e) => e.check === "date_not_in_facts"), u.review_note);
  await expectHard("Like _Sunrise Bakery_, this one qualifies.", "exemplar_leak", { terms: "Sunrise Bakery" });
  const clean = await validate(letter("Under _IRPR 87.1(2)(a)_ the applicant qualifies.").replace(NAME, `_${NAME}_`));
  assert.equal(clean.hard_fail_count, 0, clean.review_note);
  const p = await validate(letter("Signed: ________ for %FIRST_NAME%."));
  assert.equal(p.detail.hard_fails.filter((e) => e.check === "placeholder").length, 2, p.review_note);
});

test("review 3: a style of cause with a capital V is case law, a Roman numeral V, a middle initial or a list item is not", async () => {
  for (const bad of ["## APPLICATION OF BAKER V. CANADA\nThe officer erred.", "BAKER V CANADA", "As held in Baker V. Canada, the officer erred.",
    "KHOSA V. CANADA (CITIZENSHIP AND IMMIGRATION)", "CANADA (MCI) V. KHOSA", "CANADA V KHOSA", "BAKER V. M.C.I.", "SINGH V. THE MINISTER",
    "Baker\tv. Canada", "Baker v.\nCanada", "Ahmed v The Minister"]) {
    await expectHard(bad, "forbidden_content");
  }
  const facts = `${FACTS} Priya V. Sharma. Employer contact R. V. Krishnan.`;
  for (const ok of ["PART V. CONCLUSION", "PART V: CANADIAN EXPERIENCE", "TAB V BANK STATEMENTS", "TYPE V VISA", "GRADE V. Canada offers more.",
    "IV. TIES TO CANADA\nV. CONCLUSION", "RE: PRIYA V. SHARMA", "Employer contact: R. V. KRISHNAN", "Vancouver, BC, Canada V6B 1A1"]) {
    await expectClean(ok, "forbidden_content", { facts });
  }
  for (const [end4, v] of [["Police Certificate", "Bank Statements"], ["Title Deed", "Bank Statements"], ["Police Certificate (original)", "Bank Statements"],
    ["Police Certificate", "Canada Revenue Agency Notices of Assessment"]]) {
    for (const nl of ["\n", "\r\n"]) {
      await expectClean(["Enclosed documents:", "i. Passport", "ii. Pension Statement", "iii. Title Deed", `iv. ${end4}`, `v. ${v}`].join(nl), "forbidden_content");
    }
  }
});

test("review 3: a unit or list before \"of\" and an accepted citation is unresolved", async () => {
  for (const bad of ["See (z) of IRPR 87.1(2).", "See conditions (a) and (z) of IRPR 87.1(2).", "See items (a) to (z) of IRPR 87.1(2).",
    "See (a)-(z) of IRPR 87.1(2).", "See (z) of IRPR 87.1(2)(a).", "See (z) of paragraph 87.1(2)(a) of the IRPR.", "See (2)(z) of IRPR 87.1.",
    "See (Z) OF THE IRPR 87.1(2).", "See (z) of\nIRPR 87.1(2).", "See (iv) of IRPR, s. 87.1(2)(a)."]) {
    await expectHard(bad, "unresolved_reference");
  }
  for (const ok of ["The Canadian Experience Class (CEC) of IRPR 87.1(2)(a) applies.", "Her results (2023) of IRPR 87.1(2)(a) apply.",
    "conditions (a) and (b) listed above", "(1) Under IRPR 87.1(2)(a), the applicant has one year of work.",
    "The applicant meets IRPR 87.1(2)(a). (1) Of note, IRPR 87.1(2)(c) is also met."]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review 3: abbreviated unit words, a padded table row and an elided or quoted unit word are references", async () => {
  for (const bad of ["IRPR Sec. 999", "Sec. 999", "Sect. 999", "subs. 999", "IRPA subs. 25", "cl. 999", "IRPR Sec 999", "subpara. 999",
    "IRPR sch. 9", "IRPR, pt 6", "IRPA, art 5", "subs. (99) of IRPR 87.1", "cl. (Z) of IRPR 87.1(2)(a)", "sec. (2) of IRPR 87.1",
    "| Instrument | Provision |\n|---|---|\n| IRPR       | 999        |", "| IRPR  | 98 |", "IRPR\t|\t\t999",
    "'section 999'", "‘section 179’ of the Regulations", "‘paragraph (z) of IRPR 87.1(2)’", "‘Schedule 9 to the IRPR’", "l'article 999"]) {
    await expectHard(`See ${bad} for details.`, "unresolved_reference");
  }
  for (const ok of ["Her employer files SEC 10-K reports.", "She holds CL 7.", "The family has 3 children, incl. 2 minors.", "All costs excl. 5% tax.",
    "Her Class 10, Sec. B results.", "The clip runs 30 secs and 2 frames.", "| Provision     | Years |\n|---|---|\n| IRPR 87.1(2)(c)     | 2     |",
    "it's 2 years", "the applicant's 3 children", "L'Assomption, D'Arcy O'Reilly"]) {
    await expectClean(ok, "unresolved_reference");
  }
});

test("review 3: an HTML character reference is unreadable, a plain ampersand is prose", async () => {
  for (const bad of ["See &sect; 999 here.", "See &sect;&nbsp;999 here.", "See &#167; 999 here.", "See &#xA7; 999 here.", "See &#167 999 here.",
    "As held in Baker&nbsp;v.&nbsp;Canada, the officer erred.", "Under IRPR&nbsp;999 the applicant qualifies.",
    "Under IRPA,&nbsp;s.&nbsp;999 the applicant qualifies.", "Under IR&shy;PR 999 the applicant qualifies."]) {
    const r = await expectHard(bad, "unreadable_character");
    assert.ok(r.detail.hard_fails.some((e) => e.check === "unreadable_character" && e.info === "HTML character reference"), r.review_note);
  }
  for (const ok of ["Citizenship & Immigration Canada received it.", "She led R&D; then joined AT&T; and later Q&A sessions.",
    "The portal link https://example.test/a?b=1&c=2 was used."]) {
    await expectClean(ok, "unreadable_character");
  }
});

test("review 3: glued plurals and numbered list items are prose, a list after a citation stays unresolved", async () => {
  for (const ok of ["Under IRPR 87.1(2)(a), the family member(s) must show ties.", "As IRPR 87.1(2)(a) requires, each applicant(s) must show experience.",
    "Under IRPR 87.1(2)(a), the business(es) confirmed the hours.", "Under IRPR 87.1(2)(a) the relevant section(s) apply.",
    "IRPR 87.1(2)(a): APPLICANT(S) MUST SHOW EXPERIENCE.", "Education:\n1. Bachelor of Arts.\n2. Diploma in Education.",
    "Reasons:\n1. The labs are state-of-the-art.\n2. Two co-op terms.", "Ties:\n1. Respect for Canadian laws and regulations\n2. A permanent job",
    "Enclosed:\r\n1. Contract with all clauses\r\n10. Pay stubs", "Plan:\n1. Program rules\n2) Housing"]) {
    await expectClean(ok, "unresolved_reference");
  }
  for (const bad of ["IRPR 87.1(2)(a), the applicant(s) and (c)", "IRPR 87.1(2)(a) and paragraph(s) (c)", "IRPR 87.1(2)(a) and (s)",
    "IRPR 87.1(2)(a) and (es)", "IRPR 87.1(2)(a) and(c)", "IRPR 87.1(2)(a), s(c)", "art. 5 of the Code", "art.5", "reg. 216", "section\n847",
    "regulation\r\n216", "Section 3. Background"]) {
    await expectHard(bad, "unresolved_reference");
  }
});

test("review 3: Latin orthography letters, modifier apostrophes and the numero sign are readable", async () => {
  for (const name of ["Rəşad Məmmədov", "Gʻayrat Oʻrinov", "Saʿid al-Masri", "Aɗamu Bello", "Kɔfi Mensah"]) {
    const r = await validate(letter("text").replace(NAME, name), { name, facts: `${FACTS} ${name}.` });
    assert.ok(!hardOf(r).includes("mixed_script") && !hardOf(r).includes("applicant_name_absent"), `${name}: ${r.review_note}`);
  }
  await expectHard("IRʻPR 847", "unresolved_reference");
  for (const body of ["IRPR ʒ47", "ɨRPR 847", "IRPʀ 847", "IRPɑ 25(1)"]) {
    await expectHard(body, "mixed_script");
  }
  await expectClean("Certificate № 4471 confirms his pension.", "unreadable_character");
  await expectClean("Certificate №4471 confirms his pension.", "mixed_script");
  await expectHard("IRPR № 999 applies.", "unresolved_reference");
  await expectHard("IRPR №999 applies.", "unresolved_reference");
  await expectHard("Under №minee rules.", "mixed_script");
  await expectHard("ℐRPR 847", "unreadable_character");
});

test("review 3: grade fractions are not ambiguous dates, same-separator numeric dates still are", async () => {
  for (const ok of ["a GPA of 3.45/4.00", "a GPA of 3.72/4.50", "85.5/100 in the capstone", "a CGPA of 8.5/10.0", "a CGPA of 8.25/10.00", "class rank 12/140"]) {
    const r = await validate(letter(`The applicant earned ${ok} at graduation.`));
    assert.ok(!checks(r.detail.soft_flags).includes("ambiguous_date"), `${ok}: ${r.review_note}`);
  }
  for (const bad of ["03/04/2024", "03.04.2024", "3/4/24", "1.5.2024"]) {
    const r = await validate(letter(`Signed ${bad} by the employer.`));
    assert.deepEqual(r.detail.soft_flags.filter((e) => e.check === "ambiguous_date").map((e) => e.text), [bad], r.review_note);
  }
});
