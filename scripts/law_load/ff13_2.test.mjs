// F-F13.2 regression suite: the required sections and the IRCC vocabulary in ff13.validate_draft, and the loader's
// document_sections and ircc_vocabulary tables, on PGlite (Postgres 18) with the committed migrations, law/ and ref/
// loaded the way load.mjs loads them. Every record ID, name, fact and letter here is synthetic, and nothing here
// touches Supabase, Airtable or Make.
//
//   cd scripts/law_load && node --test ff13_2.test.mjs
//
// The TR-VISIT and PR-EE-CEC letter rows are signed inside this throwaway database only, with test licence R000001,
// so the production gate allows both pairs and a compliant letter reaches a clean pass.

import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { seedSql, refRows, upsertRef, refGate, verify, sectionAndVocabularyProblems } from "./load.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MIG = path.join(ROOT, "supabase", "migrations");
const DOC = "SUBMISSION-LETTER";
const REC = "recTESTff132abcd1";
const EXEC = "fedcba9876543210fedcba9876543210";
const NAME = "ZZ-TEST Amara Okafor";
const RCIC = "Jordan Testreviewer";
const FACTS = "Employed by the same accounting firm in Lagos since 2019-02-11. Planned visit to her sister in Toronto from 2026-06-02 "
  + "to 2026-06-23. Married, two children in Lagos. Return ticket booked. Bank statements for the last six months.";
const STAMPS = ["claude-opus-5-5", "claude-opus-5-5", "end_turn", "drafting-chain.submission-letter-draft@1", "a".repeat(64), "9000", "1800", "msg_test_0001"];
const REVIEW = `Draft for review by RCIC ${RCIC}. Not for submission until the RCIC of record has reviewed and signed it.`;

let db;
const q = async (sql, params = []) => (await db.query(sql, params)).rows;
const client = () => ({ query: (sql, params) => db.query(sql, params ?? []) });
const checks = (list) => list.map((e) => e.check);
const hard = (r) => checks(r.detail.hard_fails);
const soft = (r) => checks(r.detail.soft_flags);
const ledger = async (id) => (await q("SELECT * FROM ff13.validations WHERE id = $1", [id]))[0];

async function validate(draft, { visa = "TR-VISIT", doc = DOC, name = NAME, facts = FACTS } = {}) {
  await db.exec("SET ROLE ff13_make");
  try {
    const [r] = await q("SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
      [REC, EXEC, visa, doc, draft, name, facts, "", ...STAMPS]);
    return r;
  } finally {
    await db.exec("RESET ROLE");
  }
}

// The compliant sample: a TR-VISIT letter written to every rule of the F-F10 draft prompt (specs/F-F10-prompts.md),
// as the sections below, joined by one blank line. Facts, names and dates are synthetic.
const SECTIONS = {
  review: REVIEW,
  re: `Re: Application for a visitor visa, also called a temporary resident visa, for ${NAME}`,
  salutation: "Dear Officer,",
  introduction: ["Introduction",
    `${NAME} is a citizen of Nigeria who lives in Lagos with her husband and their two children. She works as a senior accountant `
    + "at an accounting firm in Lagos. This letter supports her application for a temporary resident visa so that she can visit her "
    + "sister in Toronto for three weeks and then return home to her family and her work."],
  background: ["Background",
    `${NAME} has worked for the same accounting firm in Lagos since February 11, 2019. Her role is permanent and full time, and her `
    + "employer has approved her leave for the planned visit. She is married, and her husband and their two children will remain in "
    + "Lagos while she travels.",
    "Her sister lives in Toronto as a permanent resident of Canada and has invited her to visit. The planned visit runs from June 2, 2026 "
    + "to June 23, 2026. She has booked a return ticket for the end of the visit, and her bank statements for the last six months show "
    + "the funds she will use for the trip.",
    "During the visit she plans to stay with her sister, attend a family gathering and spend time with her nieces. She has no plan to "
    + "work or study in Canada, and her travel plan sets out each week of the stay. Her employer expects her back at her desk when the "
    + "leave ends, and her husband will care for their two children while she is away."],
  legal: ["Legal framework",
    "IRPA 11(1) requires the officer to be satisfied, before a visa is issued, that the applicant meets the legal requirements that "
    + "govern the visa.",
    "IRPR 179(a) requires that the applicant has applied for the visa as a member of the visitor class. IRPR 179(b) requires that the "
    + "applicant will leave Canada by the end of the period authorized for the stay. IRPR 179(e) requires that the applicant is not "
    + "inadmissible."],
  submissions: ["Submissions",
    `${NAME} applied for a temporary resident visa as a member of the visitor class, for a family visit of three weeks. The purpose of the `
    + "trip is clear and limited, and it matches the requirement in IRPR 179(a).",
    "The facts show strong reasons to return home at the end of the stay. She has held a permanent, full-time position with the same "
    + "employer since February 11, 2019, and her employer has approved a fixed period of leave. Her husband and their two children "
    + "live in Lagos and will stay there while she travels. She has booked a return ticket for the end of the visit. Taken together, "
    + "these facts support a finding that she will leave Canada by the end of the period authorized for her stay, as IRPR 179(b) requires.",
    "Her bank statements for the last six months show the funds for the trip, so the visit does not depend on work in Canada or on "
    + "support she has not shown. The visit is to family who are settled in Canada, and the plan is the same from start to finish.",
    "The length of the visit is modest and fits its purpose. A stay of three weeks with family, during approved leave from a permanent "
    + "position, is consistent with a temporary visit and gives the officer a clear point at which the stay ends.",
    "On admissibility, the facts in the file speak to her employment, her family ties and her travel plans. Nothing in them points to a "
    + "concern under IRPR 179(e), and the officer can confirm the remaining grounds through the usual checks."],
  conclusion: ["Conclusion",
    `For these reasons, ${NAME} respectfully asks the officer to find that she meets the requirements of IRPA 11(1) and to issue `
    + "a temporary resident visa for the planned visit to her sister in Toronto."],
  closing: "Respectfully submitted,",
  signature: RCIC,
};
const ORDER = ["review", "re", "salutation", "introduction", "background", "legal", "submissions", "conclusion", "closing", "signature"];
// The Introduction states the request as a TRV, so a letter checked under another code asks without naming the program.
const ASK = "This letter supports her application for a temporary resident visa";
const NEUTRAL = { introduction: [SECTIONS.introduction[0], SECTIONS.introduction[1].replace(ASK, "This letter supports her application")] };
const sample = (over = {}, order = ORDER) => order.flatMap((k) => [k in over ? over[k] : SECTIONS[k]].flat()).filter((x) => x !== null).join("\n\n");

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
     WHERE p.key = m.provision_key AND m.document_type = '${DOC}' AND m.visa_code IN ('TR-VISIT', 'PR-EE-CEC')`);
});

test("the compliant sample letter passes in production with no flag, and the ledger holds no letter text", async () => {
  const text = sample();
  const words = text.split(/\s+/).filter(Boolean).length;
  assert.ok(words >= 500 && words <= 4000, `${words} words`);
  const r = await validate(text);
  assert.equal(r.verdict, "pass", r.review_note);
  assert.equal(r.hard_fail_count, 0, r.review_note);
  assert.equal(r.soft_flag_count, 0, r.review_note);
  assert.equal(r.detail.validator_version, "F-F13.2+F-F10+X-32");
  const row = await ledger(r.ledger_id);
  assert.equal(row.validator_version, "F-F13.2+F-F10+X-32");
  const raw = JSON.stringify(row);
  for (const s of [NAME, "Okafor", RCIC, "Testreviewer", "Lagos", "Toronto", "Dear Officer", "Introduction", "visitor visa"]) {
    assert.ok(!raw.includes(s), `ledger holds ${s}`);
  }
});

test("the shape the live chain returns passes: CRLF, a trailing line break, padded lines, a colon after a heading, any case", async () => {
  const crlf = sample().replace(/\n/g, "\r\n") + "\r\n";
  assert.equal((await validate(crlf)).verdict, "pass");
  const padded = `\n\n  ${sample().split("\n\n").join("  \n\n\t")}\n\n\n`;
  const r = await validate(padded);
  assert.equal(r.verdict, "pass", r.review_note);
  for (const [k, v] of [["introduction", "Introduction:"], ["background", "BACKGROUND"], ["legal", "Legal Framework"], ["submissions", "Submission"],
    ["conclusion", "Conclusions"], ["legal", "_Legal framework_"], ["salutation", "Dear  officer,"]]) {
    const over = { [k]: [v, ...[SECTIONS[k]].flat().slice(1)] };
    if (k === "salutation") over[k] = v;
    const x = await validate(sample(over));
    assert.equal(x.hard_fail_count, 0, `${v}: ${x.review_note}`);
  }
  // Every other line break the validator reads: NEL, U+2028, U+2029, a lone CR.
  for (const br of ["\u0085", " ", " ", "\r"]) {
    const x = await validate(sample().replace(/\n\n/g, br));
    assert.equal(x.hard_fail_count, 0, `${JSON.stringify(br)}: ${x.review_note}`);
  }
});

test("each required section missing is a hard fail naming it", async () => {
  const labels = { review: "Review line", re: "Re line", salutation: "Salutation", introduction: "Introduction", background: "Background",
    legal: "Legal framework", submissions: "Submissions", conclusion: "Conclusion", closing: "Closing", signature: "RCIC signature" };
  for (const k of ORDER) {
    const over = { [k]: Array.isArray(SECTIONS[k]) ? SECTIONS[k].slice(1) : null };
    const r = await validate(sample(over));
    assert.equal(r.verdict, "reject", `${k}: ${r.review_note}`);
    const miss = r.detail.hard_fails.filter((e) => e.check === "section_missing").map((e) => e.info);
    assert.deepEqual(miss, [labels[k]], `${k}: ${r.review_note}`);
    assert.ok(r.review_note.includes(`Hard fail: section missing (${labels[k]})`), r.review_note);
  }
});

test("sections out of order are a hard fail at the line found, and the ledger keeps the label and offset only", async () => {
  const swapped = ORDER.slice();
  [swapped[4], swapped[5]] = [swapped[5], swapped[4]];
  const text = sample({}, swapped);
  const r = await validate(text);
  // Matching runs forward, so the section left behind is the one reported: Background is found after the Legal
  // framework, and the Legal framework is then out of order.
  const e = r.detail.hard_fails.find((x) => x.check === "section_out_of_order");
  assert.equal(e.info, "Legal framework", r.review_note);
  assert.equal(text.substr(e.offset - 1, 15), "Legal framework");
  assert.deepEqual(hard(r), ["section_out_of_order"], r.review_note);
  const row = await ledger(r.ledger_id);
  assert.deepEqual(row.hard_fails, [{ check: "section_out_of_order", info: "Legal framework", offset: e.offset }]);
  // The review line second, after the Re line.
  const late = sample({}, ["re", "review", ...ORDER.slice(2)]);
  const l = await validate(late);
  assert.ok(l.detail.hard_fails.some((x) => x.check === "section_out_of_order" && x.info === "Review line"), l.review_note);
  // The Conclusion before the Submissions.
  const c = await validate(sample({}, [...ORDER.slice(0, 6), "conclusion", "submissions", "closing", "signature"]));
  assert.ok(c.detail.hard_fails.some((x) => x.check === "section_out_of_order" && x.info === "Conclusion"), c.review_note);
});

test("a heading with no paragraph before the next section is empty", async () => {
  const r = await validate(sample({ legal: "Legal framework" }));
  assert.deepEqual(r.detail.hard_fails.map((e) => [e.check, e.info]), [["section_empty", "Legal framework"]], r.review_note);
  const last = await validate(sample({ conclusion: "Conclusion" }));
  assert.deepEqual(last.detail.hard_fails.map((e) => [e.check, e.info]), [["section_empty", "Conclusion"]], last.review_note);
});

test("the first line: exact wording with a named RCIC, the first non-blank line", async () => {
  for (const bad of [`Draft for review by RCIC ${RCIC}.`, `Draft for review by ${RCIC}. Not for submission until the RCIC of record has reviewed and signed it.`,
    "Draft for review by RCIC . Not for submission until the RCIC of record has reviewed and signed it.",
    `DRAFT FOR REVIEW BY RCIC ${RCIC}. Not for submission until the RCIC of record has reviewed it.`,
    `Note: Draft for review by RCIC ${RCIC}. Not for submission until the RCIC of record has reviewed and signed it.`]) {
    const r = await validate(sample({ review: bad }));
    assert.ok(r.detail.hard_fails.some((e) => e.check === "section_missing" && e.info === "Review line"), `${bad}: ${r.review_note}`);
    // With no RCIC named, the signature is not compared, so the only section fail is the review line.
    assert.deepEqual(r.detail.hard_fails.filter((e) => e.check.startsWith("section_")).length, 1, `${bad}: ${r.review_note}`);
  }
  const cased = await validate(sample({ review: REVIEW.toUpperCase().replace(RCIC.toUpperCase(), RCIC) }));
  assert.equal(cased.hard_fail_count, 0, cased.review_note);
  // A name with a period of its own, copied literally (two periods) or written the ordinary way (one period).
  const jr = await validate(sample({ review: REVIEW.replace(RCIC, "Jordan Testreviewer Jr."), signature: "Jordan Testreviewer Jr." }));
  assert.equal(jr.hard_fail_count, 0, jr.review_note);
  for (const name of ["Jordan Testreviewer Jr.", "Jordan Testreviewer Ph.D.", "Jordan Q."]) {
    const one = await validate(sample({ review: REVIEW.replace(`${RCIC}.`, name), signature: name }));
    assert.equal(one.hard_fail_count, 0, `${name}: ${one.review_note}`);
  }
  // A name of record that starts with RCIC, written once in the first line.
  const prefixed = await validate(sample({ signature: `RCIC ${RCIC}` }));
  assert.equal(prefixed.hard_fail_count, 0, prefixed.review_note);
  // A period after a whole surname is still not the RCIC of the first line.
  const dotted = await validate(sample({ signature: `${RCIC}.` }));
  assert.deepEqual(dotted.detail.hard_fails.map((e) => [e.check, e.info]), [["section_missing", "RCIC signature"]], dotted.review_note);
});

test("the signature: the RCIC of the first line, exactly, right after the closing and last", async () => {
  for (const [over, check] of [[{ signature: "Jordan Testreviewer, RCIC" }, "section_missing"], [{ signature: "jordan testreviewer" }, "section_missing"],
    [{ signature: "Someone Else" }, "section_missing"], [{ signature: [RCIC, "Licence R000001"] }, "section_out_of_order"],
    [{ closing: ["Respectfully submitted,", "Testreviewer Immigration Services"] }, "section_out_of_order"]]) {
    const r = await validate(sample(over));
    assert.deepEqual(r.detail.hard_fails.filter((e) => e.check.startsWith("section_")).map((e) => [e.check, e.info]), [[check, "RCIC signature"]],
      `${JSON.stringify(over)}: ${r.review_note}`);
  }
  const spaced = await validate(sample({ signature: "Jordan   Testreviewer" }));
  assert.equal(spaced.hard_fail_count, 0, spaced.review_note);
});

test("headings must be whole plain lines: numbered, markdown or inline headings are missing", async () => {
  for (const bad of ["1. Introduction", "## Introduction", "Introduction to the application", "**Introduction**", "Introduction.", "I. Introduction"]) {
    const r = await validate(sample({ introduction: [bad, ...SECTIONS.introduction.slice(1)] }));
    assert.ok(r.detail.hard_fails.some((e) => e.check === "section_missing" && e.info === "Introduction"), `${bad}: ${r.review_note}`);
  }
  // The heading word inside a paragraph is not the heading.
  const inline = await validate(sample({ background: [`Background: ${SECTIONS.background[1]}`, SECTIONS.background[2]] }));
  assert.ok(inline.detail.hard_fails.some((e) => e.check === "section_missing" && e.info === "Background"), inline.review_note);
});

test("the NO DRAFT lines are exempt from the sections, a NO DRAFT line inside a letter is not", async () => {
  for (const line of ["NO DRAFT PREPARED. The inputs contain text that reads as instructions.",
    "NO DRAFT PREPARED. The case facts support none of the provided grounds."]) {
    for (const visa of ["TR-VISIT", "PR-EE-CEC"]) {
      const r = await validate(line, { visa });
      assert.equal(r.verdict, "reject");
      assert.deepEqual(hard(r).sort(), ["applicant_name_absent", "below_word_floor"], r.review_note);
      assert.equal(r.soft_flag_count, 0, r.review_note);
      const t = await validate(`\n${line}\r\n`, { visa });
      assert.deepEqual(hard(t).sort(), ["applicant_name_absent", "below_word_floor"], t.review_note);
    }
  }
  const two = await validate("NO DRAFT PREPARED. The case facts support none of the provided grounds.\nIntroduction");
  assert.ok(hard(two).includes("section_missing"), two.review_note);
  // A whole letter run onto one line that starts NO DRAFT PREPARED. is not a NO DRAFT line, with or without a leading
  // line break or space.
  const oneLine = `NO DRAFT PREPARED. ${sample().replace(/\s+/g, " ")}`;
  for (const lead of ["", "\n", " "]) {
    const r = await validate(lead + oneLine);
    assert.equal(r.verdict, "reject", `${JSON.stringify(lead)}: ${r.review_note}`);
    assert.ok(hard(r).includes("section_missing"), `${JSON.stringify(lead)}: ${r.review_note}`);
  }
  // Runs of spaces inside a NO DRAFT line still read as the line.
  const spaced = await validate("NO DRAFT PREPARED.  The case facts support none of the  provided grounds.");
  assert.deepEqual(hard(spaced).sort(), ["applicant_name_absent", "below_word_floor"], spaced.review_note);
});

test("a document type with no section rows has no section rule", async () => {
  const [{ n }] = await q("SELECT count(*)::int AS n FROM ref.document_sections WHERE document_type <> $1", [DOC]);
  assert.equal(n, 0);
  const r = await validate(`${NAME} ${Array(60).fill("The applicant has provided the supporting documents for review.").join(" ")}`, { doc: "LOE" });
  assert.ok(!hard(r).some((c) => c.startsWith("section_")), r.review_note);
});

test("vocabulary: a former name is a soft flag naming the current one, once per row, matched text in the note only", async () => {
  const text = sample({ background: [...SECTIONS.background, "She first applied through the visa office in Berlin, then the Visa office in Berlin, Germany, "
    + "and wrote to Citizenship and Immigration Canada and to CIC about the Case Processing Centre in Vegreville."] });
  const r = await validate(text);
  assert.equal(r.verdict, "pass_with_flags", r.review_note);
  const f = r.detail.soft_flags.filter((e) => e.check === "vocabulary_former_name");
  assert.deepEqual(f.map((e) => [e.key, e.info]), [
    ["office-vo-berlin", "now Visa office in Vienna, Austria"],
    ["org-cic", "now Immigration, Refugees and Citizenship Canada"],
    ["office-cpc-vegreville", "now Case Processing Centre in Edmonton"]], r.review_note);
  assert.equal(text.substr(f[0].offset - 1, 21), "visa office in Berlin");
  assert.equal(f[0].text, "visa office in Berlin");
  const row = await ledger(r.ledger_id);
  assert.ok(!JSON.stringify(row).includes("Berlin, then"));
  assert.ok(row.soft_flags.every((e) => !("text" in e)));
  assert.ok(r.review_note.includes('Soft flag: vocabulary former name office-vo-berlin (now Visa office in Vienna, Austria), "visa office in Berlin" at character'), r.review_note);
  // RCIC, CICC and a lowercase cic are not the old department name.
  const ok = await validate(sample({ background: [...SECTIONS.background, "The RCIC is a member of the CICC, and the file name ends in cic."] }));
  assert.equal(ok.soft_flag_count, 0, ok.review_note);
});

// Runs every case and compares the whole set at once, so a failure names every case that is wrong, not only the first.
async function cases(list, run, want) {
  const got = {};
  const expected = {};
  const notes = [];
  for (const c of list) {
    const k = Array.isArray(c) ? c[0] : c;
    const r = await run(c);
    got[k] = r.value;
    expected[k] = want(c);
    if (JSON.stringify(r.value) !== JSON.stringify(expected[k])) notes.push(`${k}: ${r.note}`);
  }
  assert.deepEqual(got, expected, notes.join("\n\n"));
}
const flags = (r) => r.detail.soft_flags.map((e) => [e.check, e.key ?? null, e.info ?? null]);
const inBackground = (s) => validate(sample({ background: [...SECTIONS.background, s] })).then((r) => ({ value: { soft: flags(r), hard: hard(r) }, note: r.review_note }));
const officeAt = (s) => inBackground(`Her file went to ${s} for review.`);

test("vocabulary: an office named with a proper noun that matches no office row is a soft flag", async () => {
  const unknown = { soft: [["vocabulary_unknown_office", null, "no IRCC vocabulary row"]], hard: [] };
  await cases(["the visa office in Toronto", "the Kampala visa office", "the Case Processing Centre in Vancouver", "CPC Halifax",
    "the visa office in Sydney", "the IRCC office in London", "the Global Operations Centre in Dublin", "the Toronto Case Processing Centre",
    "the IRCC processing centre in Toronto"], officeAt, () => unknown);
  await cases(["the Case Processing Centre in Edmonton", "the visa office in New Delhi", "the New Delhi visa office", "the Bogotá visa office",
    "the Bogota visa office", "the visa office in São Paulo, Brazil", "the IRCC office in Montréal", "the IRCC office in Montreal", "CPC Ottawa",
    "the Visa office in Sydney, Australia", "the Visa office in Ankara, Türkiye", "the visa office in Port-au-Prince", "the visa office in Port au Prince",
    "the visa office in the applicant's country", "the responsible visa office", "the Canadian visa office in Paris", "the case processing centre",
    "the Centralized Intake Office in Sydney"], officeAt, () => ({ soft: [], hard: [] }));
});

test("vocabulary: a real office name with a place it is not in is an unknown office, and the Global Operations Centres in their natural form are known", async () => {
  // The office row covers the office words, never the place, so only the place tells "in Sydney" from "in Mississauga".
  const unknown = { soft: [["vocabulary_unknown_office", null, "no IRCC vocabulary row"]], hard: [] };
  await cases(["the Centralized Intake Office in Mississauga", "the Operations Support Centre in Montreal", "the Resettlement Operations Centre in Winnipeg",
    "the Digitization Centre in Toronto", "the IRCC Digitization Centre in Toronto", "the CPC in Vancouver"], officeAt, () => unknown);
  await cases(["the Global Operations Centre in Manila", "the Global Operations Centre in Bucharest"], officeAt, () => ({ soft: [], hard: [] }));
});

test("vocabulary: an employer's processing or operations centre in a work history is no IRCC office", async () => {
  await cases(["Her sister works at the Canada Post processing centre in Mississauga.", "Her husband works at the Amazon processing centre near Toronto.",
    "Her brother works at the HSBC Global Operations Centre in Hyderabad.", "She once worked at a processing centre in Mississauga.",
    "Her cousin runs the payroll processing centre at Deloitte.", "Her sister works at the Citi Global Operations Centre in Chennai.",
    "Her uncle drives for a Purolator processing centre."], inBackground, () => ({ soft: [], hard: [] }));
});

test("vocabulary: a former visa office names its successor, and both offices where the 2026 list names two", async () => {
  const nigeria = "now Visa office in Nairobi, Kenya (temporary residents) or Accra, Ghana (permanent residents)";
  const us = "now Visa office in Los Angeles or New York, United States (the 2026 list names both)";
  await cases([["Abuja", "office-vo-abuja", nigeria], ["Lagos", "office-vo-lagos", nigeria], ["Addis Ababa", "office-vo-addis-ababa", "now Visa office in Nairobi, Kenya"],
    ["Washington", "office-vo-washington", us], ["Miami", "office-vo-miami", us]],
  ([city]) => inBackground(`Her earlier visa was issued by the visa office in ${city}.`),
  ([, key, now]) => ({ soft: [["vocabulary_former_name", key, now]], hard: [] }));
});

test("vocabulary: the short former aliases NSE and SDS are ordinary words, so they no longer flag, and the long forms still do", async () => {
  await cases(["Her husband has worked as a risk analyst at the NSE in Mumbai for many years.", "At the firm she also keeps the SDS records for the office."],
    inBackground, () => ({ soft: [], hard: [] }));
  await cases([["Her niece studied in Canada under the Student Direct Stream.", "prog-sds"], ["Her niece studied in Canada under the Nigeria Student Express.", "prog-nse"]],
    ([s]) => inBackground(s), ([, key]) => ({ soft: [["vocabulary_former_name", key, "now Study permit"]], hard: [] }));
});

test("vocabulary: the caregiver programs that ended in 2019 are former names, and the current pilots are rows", async () => {
  await cases(["Her sister came to Canada under the Caring for Children pathway.", "Her sister came to Canada under the Caring for Children Program.",
    "Her sister came to Canada under the Caring for People with High Medical Needs Program."], inBackground,
  () => ({ soft: [["vocabulary_former_name", "prog-caring-pathways", "now Home Care Worker Immigration Pilots"]], hard: [] }));
  await cases([["This application under the Rural Community Immigration Pilot is made in good faith.", "prog-rcip"],
    ["This application under the Francophone Community Immigration Pilot is made in good faith.", "prog-fcip"],
    ["This application under the Home Care Worker Immigration Pilots is made in good faith.", "prog-hcwip"],
    // The regulatory class since the IRPR amendment of 2026-10-23 (IRPR 87.4), an alias of the pilot row.
    ["This application under the rural community immigration class is made in good faith.", "prog-rcip"]],
  ([s]) => inBackground(s), ([, key]) => ({ soft: [["vocabulary_program_mismatch", key, "not a program of TR-VISIT"]], hard: [] }));
});

test("vocabulary: the visa codes follow the cited pages (an open work permit for a PGWP, a TRV with a study permit, non-Express Entry PNP)", async () => {
  const mismatch = (r) => r.detail.soft_flags.filter((e) => e.check === "vocabulary_program_mismatch").map((e) => e.key);
  const run = ([, visa, over]) => validate(sample({ ...NEUTRAL, ...over }), { visa }).then((r) => ({ value: mismatch(r), note: r.review_note }));
  await cases([
    ["PGWP Re line", "TR-PGWP", { re: `Re: Application for a post-graduation work permit, an open work permit, for ${NAME}` }],
    ["PGWP body", "TR-PGWP", { re: `Re: Application for a post-graduation work permit for ${NAME}`,
      conclusion: [...SECTIONS.conclusion, "This application for an open work permit rests on her graduation."] }],
    ["PNP non-Express Entry", "PR-PNP-BASE", { re: `Re: Application for permanent residence under the Provincial Nominee Program, non-Express Entry process, for ${NAME}` }],
    ["study permit and TRV", "TR-STUDY", { re: `Re: Application for a study permit and a temporary resident visa for ${NAME}` }],
    ["work permit and eTA", "TR-WP-EMP", { re: `Re: Application for an employer-specific work permit and an electronic travel authorization for ${NAME}` }],
    // F-F14 ff14-010 (2026-11-19): a super visa is a multiple entry temporary resident visa (Ministerial Instructions 2026),
    // and IRCC's own form asks for a "Visitor visa or super visa", so the visitor visa row is a program of TR-SUPER.
    ["super visa as a TRV", "TR-SUPER", { re: `Re: Application for a temporary resident visa (super visa) for ${NAME}` }],
    ["ff14-010 head", "TR-SUPER", { re: `Re: Application for a temporary resident visa to visit a Canadian citizen son for an extended period, for ${NAME}` }]],
  run, () => []);
  // A study permit is still not a program of TR-SUPER, and neither is an eTA: a visa-exempt applicant applies for one only
  // after the super visa is approved (review 2026-11-19).
  await cases([["super visa study permit", "TR-SUPER", { re: `Re: Application for a study permit for ${NAME}` }]], run, () => ["prog-study-permit"]);
  await cases([["super visa as an eTA", "TR-SUPER", { re: `Re: Application for an electronic travel authorization for ${NAME}` }]], run, () => ["prog-eta"]);
  // Express Entry alone is still not a program of PR-PNP-BASE.
  await cases([["Express Entry", "PR-PNP-BASE", { re: `Re: Application for permanent residence under Express Entry for ${NAME}` }]], run, () => ["prog-express-entry"]);
});

test("vocabulary: a program named for the application that is not one of the visa code is a soft flag", async () => {
  const head = await validate(sample({ re: `Re: Application under Express Entry for ${NAME}` }));
  assert.deepEqual(head.detail.soft_flags.map((e) => [e.check, e.key, e.info]),
    [["vocabulary_program_mismatch", "prog-express-entry", "not a program of TR-VISIT"]], head.review_note);
  const mismatch = (key) => ({ soft: [["vocabulary_program_mismatch", key, "not a program of TR-VISIT"]], hard: [] });
  const inConclusion = (s) => validate(sample({ conclusion: [...SECTIONS.conclusion, s] })).then((r) => ({ value: { soft: flags(r), hard: hard(r) }, note: r.review_note }));
  await cases([["This application for a study permit is made in good faith.", "prog-study-permit"],
    ["She applies under the International Mobility Program.", "prog-imp"], [`${NAME} is applying for a study permit.`, "prog-study-permit"]],
  ([s]) => inConclusion(s), ([, key]) => mismatch(key));
  // History is not the application, and a program of the code is fine anywhere.
  await cases(["She held a study permit and a post-graduation work permit before.", "This application for a visitor visa is her first.",
    "She previously applied under Express Entry.", "This application for an Electronic travel authorization was not needed."], inConclusion, () => ({ soft: [], hard: [] }));
  // The same words fit a PR-EE-CEC record, and an unknown visa code checks nothing.
  const cec = await validate(sample({ ...NEUTRAL, re: `Re: Application under Express Entry for ${NAME}` }), { visa: "PR-EE-CEC" });
  assert.ok(!soft(cec).includes("vocabulary_program_mismatch"), cec.review_note);
  const unknown = await validate(sample({ re: `Re: Application under Express Entry for ${NAME}` }), { visa: "XX-NONE" });
  assert.ok(!soft(unknown).includes("vocabulary_program_mismatch"), unknown.review_note);
});

test("vocabulary: the Introduction's statement of the request names the application, in the possessive form the sample itself uses", async () => {
  const intro = SECTIONS.introduction[1];
  assert.ok(intro.includes(ASK));
  await cases([["This letter supports her application for a study permit", "prog-study-permit"],
    ["This letter supports her application under Express Entry", "prog-express-entry"],
    ["This letter supports an application under the International Mobility Program", "prog-imp"],
    ["This letter supports his application for a study permit", "prog-study-permit"],
    ["This letter supports the applicant's application for a study permit", "prog-study-permit"],
    ["This submission is in support of her application for a study permit", "prog-study-permit"],
    ["This letter supports her request for a study permit", "prog-study-permit"]],
  ([s]) => validate(sample({ introduction: [SECTIONS.introduction[0], intro.replace(ASK, s)] }))
    .then((r) => ({ value: { soft: flags(r), hard: hard(r) }, note: r.review_note })),
  ([, key]) => ({ soft: [["vocabulary_program_mismatch", key, "not a program of TR-VISIT"]], hard: [] }));
});

test("vocabulary: a negated, future or third-party apply is not the application", async () => {
  await cases(["She has no plan to work or study in Canada and will not apply for a study permit during the visit.",
    "Her sister in Toronto is applying for the Canadian Experience Class this year.", "She will never apply for a study permit.",
    "Her husband applies under Express Entry next year.", "Her application for a study permit was refused years ago."],
  inBackground, () => ({ soft: [], hard: [] }));
});

test("vocabulary: short names match only as whole words in capitals", async () => {
  const caps = await validate(sample({ conclusion: [...SECTIONS.conclusion, "This application under the IMP is not made."] }));
  assert.deepEqual(caps.detail.soft_flags.map((e) => e.key), ["prog-imp"], caps.review_note);
  for (const s of ["This application under the imp is not made.", "This application under the IMPs is not made.", "This application for a rad visit."]) {
    const r = await validate(sample({ conclusion: [...SECTIONS.conclusion, s] }));
    assert.equal(r.soft_flag_count, 0, `${s}: ${r.review_note}`);
  }
});

test("vocabulary: an office that is never an addressee, or only on request, flags in the letter head only", async () => {
  const vac = await validate(sample({ re: `Re: Application for a visitor visa sent to the Visa application centre for ${NAME}` }));
  assert.deepEqual(vac.detail.soft_flags.map((e) => [e.check, e.key, e.info]),
    [["vocabulary_not_addressee", "office-vac", "never an addressee"]], vac.review_note);
  const asked = await validate(sample({ re: `Re: Documents for the IRCC office in Calgary, visitor visa of ${NAME}` }));
  assert.deepEqual(asked.detail.soft_flags.map((e) => [e.check, e.info]), [["vocabulary_not_addressee", "an addressee only when that office asked"]],
    asked.review_note);
  const body = await validate(sample({ background: [...SECTIONS.background, "She gave her biometrics at the visa application centre in Lagos."] }));
  assert.equal(body.soft_flag_count, 0, body.review_note);
});

test("vocabulary rules never reject, offsets index the draft as received, and the verdict is deterministic", async () => {
  const text = sample({ re: `Re: Application under Express Entry to the VAC for ${NAME}`,
    background: [...SECTIONS.background, "Then the visa office in Toronto and the visa office in Kyiv wrote."] });
  const a = await validate(text);
  const b = await validate(text);
  assert.equal(a.hard_fail_count, 0, a.review_note);
  assert.deepEqual(a.detail.soft_flags, b.detail.soft_flags);
  assert.deepEqual(soft(a).sort(), ["vocabulary_former_name", "vocabulary_not_addressee", "vocabulary_program_mismatch", "vocabulary_unknown_office"]);
  for (const e of a.detail.soft_flags) assert.equal(text.substr(e.offset - 1, e.text.length), e.text, e.check);
});

test("too many vocabulary matches or lines fail closed, and a dense long draft stays fast", async () => {
  const many = await validate(sample({ background: [...SECTIONS.background, Array(510).fill("IRCC").join(" ")] }));
  assert.ok(many.detail.hard_fails.some((e) => e.check === "too_many_matches" && e.info === "vocabulary"), many.review_note);
  const lines = await validate(sample({ background: [...SECTIONS.background, Array(1001).fill("word").join("\n")] }));
  assert.ok(lines.detail.hard_fails.some((e) => e.check === "too_many_matches" && e.info === "lines"), lines.review_note);
  const dense = sample({ background: [...SECTIONS.background, Array(900).fill("the visa office in Toronto, Express Entry and Bogotá").join(" ").slice(0, 90000)] });
  const t = Date.now();
  const r = await validate(dense);
  assert.ok(Date.now() - t < 15000, `${Date.now() - t} ms`);
  assert.notEqual(r.detail.hard_fails[0]?.check, "validator_error", r.review_note);
});

test("ff13_make reads neither new table and calls no new helper", async () => {
  await db.exec("SET ROLE ff13_make");
  try {
    for (const sql of ["SELECT 1 FROM ref.document_sections LIMIT 1", "SELECT 1 FROM ref.ircc_vocabulary LIMIT 1", "SELECT * FROM ff13._lines('a')",
      "SELECT ff13._vfold('a')", "SELECT ff13._vkey('a')", "SELECT ff13._line_match('a', 'line', 'a', '{}', NULL)", "SELECT * FROM ff13._vocab_patterns()"]) {
      await assert.rejects(q(sql), /permission denied/, sql);
    }
  } finally {
    await db.exec("RESET ROLE");
  }
  for (const role of ["anon", "authenticated"]) {
    const [x] = await q("SELECT has_table_privilege($1, 'ref.ircc_vocabulary', 'SELECT') AS v, has_table_privilege($1, 'ref.document_sections', 'SELECT') AS s",
      [role]);
    assert.deepEqual(x, { v: false, s: false }, role);
  }
});

test("helpers: lines keep offsets, diacritics fold one for one, keys join hyphens and spaces", async () => {
  const [{ l }] = await q("SELECT json_agg(json_build_object('n', n, 'pos', pos, 'line', line) ORDER BY n) AS l FROM ff13._lines($1)", ["  a\r\n\r\n b c  \nd"]);
  assert.deepEqual(l, [{ n: 1, pos: 3, line: "a" }, { n: 2, pos: 9, line: "b c" }, { n: 3, pos: 15, line: "d" }]);
  const [{ f, k }] = await q("SELECT ff13._vfold('Bogotá São Montréal Türkiye Łódź') AS f, ff13._vkey(' Port-au–Prince  ') AS k");
  assert.equal(f, "Bogota Sao Montreal Turkiye Lodz");
  assert.equal(k, "port au–prince");
  const [{ n }] = await q("SELECT count(*)::int AS n FROM regexp_split_to_table(ff13._vfold(chr(192) || chr(7929)), '') c WHERE c !~ '^[A-Za-z]$'");
  assert.equal(n, 0);
});

// A change inside a transaction that is always rolled back, and the ref gate on the committed files with one mutation.
async function inTx(fn) {
  await db.exec("BEGIN");
  try {
    return await fn();
  } finally {
    await db.exec("ROLLBACK");
  }
}
const gateWith = (mut, opts) => inTx(async () => {
  const r = structuredClone(refRows());
  mut(r);
  await upsertRef(client(), r);
  await db.exec("SET CONSTRAINTS ALL IMMEDIATE");
  return refGate(client(), r, opts);
});

test("loader: both files load, verify compares them, and the gates refuse what the CHECKs cannot", async () => {
  const ref = refRows();
  assert.equal(ref.ircc_vocabulary.length, 151);
  assert.equal(ref.document_sections.length, 10);
  // No Airtable token, so the committed test record's Synthetic Test Case check fails closed without a request.
  const checksOut = await verify(client(), { data: true, airtable: { pat: null } });
  for (const name of ["document_sections equals ref/", "ircc_vocabulary equals ref/", "function search_path", "Make function definers", "ff13_make access"]) {
    const c = checksOut.find((x) => x[0] === name);
    assert.ok(c && c[1] === true, `${name}: ${c && c[2]}`);
  }
  const shared = await gateWith((r) => { r.ircc_vocabulary.find((x) => x.id === "office-vo-paris").common_variants.push("rome visa office"); });
  assert.ok(shared.some((p) => p.includes("phrases shared by two rows") && p.includes("rome visa office")), shared.join("\n"));
  const hyphen = await gateWith((r) => { r.ircc_vocabulary.find((x) => x.id === "office-vo-rome").common_variants.push("paris-visa office"); });
  assert.ok(hyphen.some((p) => p.includes("paris visa office")), hyphen.join("\n"));
  const chain = await gateWith((r) => { r.ircc_vocabulary.find((x) => x.id === "office-vo-miami").replaced_by = "office-vo-washington"; });
  assert.ok(chain.some((p) => p.includes("replaced by a former row") && p.includes("office-vo-miami")), chain.join("\n"));
  const code = await gateWith((r) => { r.ircc_vocabulary.find((x) => x.id === "prog-cec").visa_codes.push("PR-NOPE"); });
  assert.ok(code.some((p) => p.includes("visa codes not in visa_types") && p.includes("PR-NOPE")), code.join("\n"));
  const dropped = await gateWith((r) => { r.ircc_vocabulary = r.ircc_vocabulary.filter((x) => x.id !== "prog-cec"); });
  assert.ok(dropped.some((p) => p.startsWith("ircc_vocabulary in the database and not in ref/ircc_vocabulary.json") && p.includes("prog-cec")), dropped.join("\n"));
  const twoFirst = await gateWith((r) => {
    r.document_sections.push({ ...r.document_sections[0], section: "Second review line", ordinal: 11 });
  });
  assert.ok(twoFirst.some((p) => p.includes("document_sections whose first or last line")), twoFirst.join("\n"));
  // A section the file drops is deleted (the table is the file), and the rest still load.
  const fewer = await gateWith((r) => { r.document_sections = r.document_sections.filter((x) => x.section !== "Closing"); });
  assert.deepEqual(fewer, []);
  // The CHECKs: a second {rcic} in a template, an alias in capitals, a program addressed, a former row with no replacement.
  for (const [sql, re] of [
    ["UPDATE ref.document_sections SET text = text || ' {rcic}' WHERE match_kind = 'first_line'", /check/i],
    ["UPDATE ref.ircc_vocabulary SET ircc_aliases = ARRAY['CPC Edmonton'] WHERE id = 'office-cpc-edmonton'", /check/i],
    ["UPDATE ref.ircc_vocabulary SET letter_addressee = 'yes' WHERE id = 'prog-cec'", /check/i],
    ["UPDATE ref.ircc_vocabulary SET status = 'former' WHERE id = 'prog-cec'", /check/i],
    ["UPDATE ref.ircc_vocabulary SET source_urls = ARRAY['http://example.org'] WHERE id = 'prog-cec'", /check/i],
    ["UPDATE ref.ircc_vocabulary SET successor_note = 'Visa office in Paris, France' WHERE id = 'prog-cec'", /check/i]]) {
    await inTx(() => assert.rejects(q(sql), re, sql));
  }
  // A file whose row lacks a column, or holds a wrong type, is refused before any upsert.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ff13-2-"));
  try {
    for (const f of fs.readdirSync(path.join(ROOT, "ref"))) fs.copyFileSync(path.join(ROOT, "ref", f), path.join(dir, f));
    const doc = JSON.parse(fs.readFileSync(path.join(dir, "ircc_vocabulary.json"), "utf8"));
    doc.ircc_vocabulary[0].visa_codes = "TR-VISIT";
    fs.writeFileSync(path.join(dir, "ircc_vocabulary.json"), JSON.stringify(doc));
    assert.throws(() => refRows(dir), /wrong type in visa_codes/);
    const sec = JSON.parse(fs.readFileSync(path.join(dir, "document_sections.json"), "utf8"));
    delete sec.document_sections[0].note;
    fs.writeFileSync(path.join(dir, "document_sections.json"), JSON.stringify(sec));
    doc.ircc_vocabulary[0].visa_codes = [];
    fs.writeFileSync(path.join(dir, "ircc_vocabulary.json"), JSON.stringify(doc));
    assert.throws(() => refRows(dir), /does not have exactly/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("loader: the section text and every variant are held to the form the matcher compares", async () => {
  // The text and the variants must be in the form the matcher compares: a doubled space, an edge space, a tab or a line
  // break could never equal a line, so the variant would silently do nothing.
  for (const bad of ["Legal  basis", "Legal basis ", " Legal basis", "Legal\tbasis", "Legal basis\t", "Legal\nbasis", "Legal\u00a0basis"]) {
    await inTx(() => assert.rejects(q("UPDATE ref.document_sections SET variants = ARRAY[$1] WHERE section = 'Legal framework'", [bad]), /check/i,
      JSON.stringify(bad)));
  }
  for (const bad of ["Legal\tframework", "Legal framework\t", "Legal\nframework", "Legal framework "]) {
    await inTx(() => assert.rejects(q("UPDATE ref.document_sections SET text = $1 WHERE section = 'Legal framework'", [bad]), /check/i,
      JSON.stringify(bad)));
  }
  // A variant in the matcher's form is accepted and does match the heading.
  await inTx(async () => {
    await q("UPDATE ref.document_sections SET variants = ARRAY['Legal basis'] WHERE section = 'Legal framework'");
    const r = await validate(sample({ legal: ["Legal basis", ...SECTIONS.legal.slice(1)] }));
    assert.equal(r.hard_fail_count, 0, r.review_note);
  });
});

test("loader: the gate runs the validator's vocabulary pattern and refuses one that does not compile or is too slow", async () => {
  // The vocabulary probe: the validator's own pattern build and one scan, under the budget. A vocabulary about five
  // times today's phrases (synthetic provincial streams) no longer compiles, and the gate refuses it instead of loading a
  // file that would end every draft in validator_error.
  const ok = await gateWith(() => {});
  assert.deepEqual(ok, []);
  const slow = await inTx(() => sectionAndVocabularyProblems(client(), { vocabBudgetMs: -1 }));
  assert.ok(slow.some((p) => p.startsWith("ircc_vocabulary pattern too slow")), slow.join("\n"));
  const word = (i) => Array.from(String(i), (d) => "abcdefghij"[d]).join("").replace(/^./, (c) => c.toUpperCase());
  const huge = await gateWith((r) => {
    const base = r.ircc_vocabulary.length;
    for (let i = 0; i < 600; i++) {
      r.ircc_vocabulary.push({ ...r.ircc_vocabulary.find((x) => x.id === "prog-cec"), id: `prog-zz-synthetic-stream-${i}`,
        canonical_name: `Synthetic Provincial Stream ${word(i)}`, ircc_aliases: [`synthetic provincial stream ${word(i).toLowerCase()} program`,
          `zz province ${word(i).toLowerCase()} graduate stream`], common_variants: [`zz ${word(i).toLowerCase()} skilled worker stream`],
        visa_codes: [], note: null, sort_order: (base + i + 1) * 10 + 5 });
    }
  });
  assert.ok(huge.some((p) => p.startsWith("ircc_vocabulary pattern does not run in the validator: SQLSTATE")), huge.join("\n"));
});
