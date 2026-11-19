// F-F14: grounding and validation through the same ff13 functions as the Make chain, in two short transactions per
// case that always roll back (specs/F-F14-evaluation-harness.md, "Grounding and validation").
//
//   Tx G  BEGIN, the ff13_make role's timeouts, list the synthetic record in ref.test_records, ff13.drafting_context,
//         ROLLBACK. The two Claude calls then run with no transaction open.
//   Tx V  BEGIN, the same, ff13.drafting_context again (its provisions must hash the same as Tx G), then
//         ff13.validate_draft with the 16 arguments, ROLLBACK.
//
// Nothing persists: the test_records, groundings and validations rows are undone by ROLLBACK, and no other session can
// read them under READ COMMITTED. This file holds no commit statement, and a unit test fails if it ever does. After a
// run, committedRows on a fresh connection proves no row for any record or execution ID of the run was committed.

import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { connectionConfig, readEnv, sha256Hex } from "../law_load/load.mjs";
import { GROUND_ARGS, ROOT, VALIDATE_ARGS, argList } from "./chain.mjs";
import { Fatal, Refusal } from "./iml.mjs";

export const LAW_LOAD = path.join(ROOT, "scripts", "law_load");
// pg and PGlite resolve from scripts/law_load, so the harness runs the one pinned pg (8.23.1) and PGlite (0.5.9).
const lawRequire = createRequire(path.join(LAW_LOAD, "package.json"));
export const ENV_KEYS = ["SUPABASE_DB_URL", "SUPABASE_DB_PASSWORD", "SUPABASE_DB_CA", "ANTHROPIC_API_KEY"];
const TIMEOUTS = ["SET LOCAL statement_timeout = '20s'", "SET LOCAL idle_in_transaction_session_timeout = '60s'"];
const LIST = `INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on)
              VALUES ($1, (now() AT TIME ZONE 'America/Toronto')::date, (now() AT TIME ZONE 'America/Toronto')::date)`;
const GROUND = "SELECT * FROM ff13.drafting_context($1, $2, $3, $4, $5)";
export const RECORD_PREFIX = "recFF14ZZTEST";
const VALIDATE = "SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)";
const PROVIDED = `SELECT s.provision_key AS key FROM ref.citation_status($1, $2) s WHERE s.state IN ('current', 'unreviewed')
                   ORDER BY s.sort_order, s.provision_key`;

export const pgVersion = () => JSON.parse(fs.readFileSync(lawRequire.resolve("pg/package.json"), "utf8")).version;

// The live owner connection: SUPABASE_DB_URL through connectionConfig (Session pooler, TLS verified against the CA).
// pg emits 'error' on an idle client when the socket drops or the server ends the session, and an 'error' event with
// no listener ends the process before the run's proof and files are written. The listener records the loss on the
// client (as load.mjs does), and the next transaction or case turns it into a Fatal.
export async function liveClient(env) {
  const pg = lawRequire("pg");
  const config = connectionConfig(env);
  delete config.caPath;
  const client = new pg.Client({ ...config, application_name: "immi-os-ff14", keepAlive: true });
  watchClient(client);
  await client.connect();
  return client;
}

export function watchClient(client) {
  client.lost = null;
  client.on("error", (e) => {
    client.lost = e;
  });
  return client;
}

export const lostError = (client) => new Fatal(`the database connection was lost (${client.lost?.code ? `SQLSTATE ${client.lost.code}` : "connection ended"}). Nothing is committed on a lost session`);

export const readSecrets = (file) => readEnv(file, ENV_KEYS);

const rows = async (client, sql, params) => (await client.query(sql, params)).rows;

// One transaction that always rolls back. The body gets the client inside it.
async function rolledBack(client, body) {
  if (client.lost) throw lostError(client);
  await client.query("BEGIN");
  try {
    for (const s of TIMEOUTS) await client.query(s);
    return await body();
  } finally {
    await client.query("ROLLBACK");
  }
}

async function listRecord(client, record) {
  const [{ n }] = await rows(client, "SELECT count(*)::int AS n FROM ref.test_records WHERE airtable_record_id = $1", [record]);
  if (n !== 0) throw new Fatal(`${record} is committed in ref.test_records. An earlier run left a row: stop and investigate`);
  await client.query(LIST, [record]);
}

const groundingOf = (r) => ({
  allowed: r.allowed, reason: r.reason, gate_mode: r.gate_mode, provision_keys: JSON.parse(r.provision_keys),
  flags: JSON.parse(r.flags), provisions: r.provisions, provisions_sha256: sha256Hex(r.provisions), grounding_id_void: r.grounding_id,
});

// Tx G. c.listed false skips the listing (the one-factor and production controls).
export async function ground(client, c) {
  return rolledBack(client, async () => {
    if (c.listed) await listRecord(client, c.record);
    const [r] = await rows(client, GROUND, argList(GROUND_ARGS, c));
    const provided = (await rows(client, PROVIDED, [c.visa, c.doc])).map((x) => x.key);
    return { ...groundingOf(r), citation_status_keys: provided };
  });
}

// Tx V. args: the 16 validator arguments after record and execution ID are filled here from v.
export async function validate(client, c, expected, v) {
  return rolledBack(client, async () => {
    if (c.listed) await listRecord(client, c.record);
    const [r] = await rows(client, GROUND, argList(GROUND_ARGS, c));
    const g = groundingOf(r);
    if (g.gate_mode !== expected.gate_mode || g.allowed !== expected.allowed || g.provisions_sha256 !== expected.provisions_sha256) {
      return { void: true, reason: "the grounding changed between Tx G and Tx V (law, map or test gate moved mid-case)" };
    }
    const [x] = await rows(client, VALIDATE, argList(VALIDATE_ARGS, c, v));
    return { void: false, ledger_id_void: x.ledger_id, verdict: x.verdict, hard_fail_count: x.hard_fail_count,
      soft_flag_count: x.soft_flag_count, review_note: x.review_note, detail: x.detail };
  });
}

// Any committed harness record, read before the first case: one leftover means an earlier run broke the no-persist
// guarantee, and the retire-only trigger keeps it forever, so the whole run refuses before any spend.
export async function leftoverRecords(client) {
  return (await rows(client, "SELECT airtable_record_id AS id FROM ref.test_records WHERE starts_with(airtable_record_id, $1) ORDER BY 1",
    [RECORD_PREFIX])).map((x) => x.id);
}

// Committed rows for the run's record and execution IDs, read outside any transaction (a fresh connection live).
export async function committedRows(client, records, execs) {
  const out = {};
  out["ref.test_records"] = (await rows(client, "SELECT count(*)::int AS n FROM ref.test_records WHERE airtable_record_id = ANY($1)", [records]))[0].n;
  for (const t of ["ff13.groundings", "ff13.validations"]) {
    out[t] = (await rows(client, `SELECT count(*)::int AS n FROM ${t} WHERE airtable_record_id = ANY($1) OR make_execution_id = ANY($2)`,
      [records, execs]))[0].n;
  }
  return out;
}

export async function lawSources(client) {
  return rows(client, "SELECT instrument, current_to::text AS current_to, source_sha256 FROM law.instruments ORDER BY 1");
}

// X-32 (specs/X-32-exemplars.md section 10). Used only by the --arms runs (scripts/ff14/x32.mjs). validate and ground
// above are unchanged, so every run without --arms sends exactly the statements it sent before.
//
// ff13.rank_exemplars once the X-32 migration exists. Its step 1 reads the newest ff13.groundings row of the same record
// and execution, so it runs in a transaction that has just grounded. The harness seed IDs (recX32ZZTEST...) are listed
// in ref.exemplar_test_seeds inside the same transaction, which rolls back. Before the migration it returns null.
const HAS_RANKER = "SELECT to_regprocedure('ff13.rank_exemplars(text,text,text,text,text,text)') IS NOT NULL AS ok";
const HAS_SEED_LIST = "SELECT to_regclass('ref.exemplar_test_seeds') IS NOT NULL AS ok";
const LIST_SEED = `INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on)
                   VALUES ($1, $2, (now() AT TIME ZONE 'America/Toronto')::date)`;
const RANK = "SELECT * FROM ff13.rank_exemplars($1, $2, $3, $4, $5, $6)";

async function rankHere(client, c, rank) {
  const [{ ok }] = await rows(client, HAS_RANKER);
  if (!ok) return null;
  if ((await rows(client, HAS_SEED_LIST))[0].ok) {
    for (const s of rank.seeds) await client.query(LIST_SEED, [s.id, s.code]);
  }
  const [r] = await rows(client, RANK, [c.record, c.exec, c.visa, c.doc, rank.outline, rank.candidates]);
  let flags = r.flags;
  try {
    flags = typeof flags === "string" ? JSON.parse(flags) : flags;
  } catch {
    // kept as text
  }
  return { exemplar_record_id: r.exemplar_record_id, exemplar_code: r.exemplar_code, score: r.score, flags,
    candidate_count: r.candidate_count ?? null, eligible_count: r.eligible_count ?? null, selection_id_void: r.selection_id ?? null };
}

// Tx S: the selection before the draft. null before the migration (the caller then uses the reference port).
export async function selectExemplarDb(client, c, rank) {
  return rolledBack(client, async () => {
    if (c.listed) await listRecord(client, c.record);
    await rows(client, GROUND, argList(GROUND_ARGS, c));
    return rankHere(client, c, rank);
  });
}

// Tx V with @08, p_exemplar_terms, set to the selected exemplar's term lines. With rank, ff13.rank_exemplars runs again
// after the grounding and before ff13.validate_draft, so the validator's @08 cross-check finds the selection row of the
// same record and execution (the Tx S row has rolled back). The result carries that selection for metric X5.
export async function validateWithTerms(client, c, expected, v, terms, rank = null) {
  if (typeof terms !== "string") throw new Refusal("validateWithTerms needs the exemplar terms as text");
  return rolledBack(client, async () => {
    if (c.listed) await listRecord(client, c.record);
    const [r] = await rows(client, GROUND, argList(GROUND_ARGS, c));
    const g = groundingOf(r);
    if (g.gate_mode !== expected.gate_mode || g.allowed !== expected.allowed || g.provisions_sha256 !== expected.provisions_sha256) {
      return { void: true, reason: "the grounding changed between Tx G and Tx V (law, map or test gate moved mid-case)" };
    }
    const selection = rank ? await rankHere(client, c, rank) : null;
    const args = argList(VALIDATE_ARGS, c, v);
    args[Object.keys(VALIDATE_ARGS).sort().indexOf("@08:text")] = terms;
    const [x] = await rows(client, VALIDATE, args);
    return { void: false, ledger_id_void: x.ledger_id, verdict: x.verdict, hard_fail_count: x.hard_fail_count,
      soft_flag_count: x.soft_flag_count, review_note: x.review_note, detail: x.detail, selection };
  });
}

// The X-32 tables, counted like committedRows once they exist: selections of the run's records or executions, and the
// harness seed IDs in ref.exemplar_test_seeds. A table that does not exist yet counts 0.
export async function committedX32Rows(client, records, execs, seedIds) {
  const out = {};
  if ((await rows(client, "SELECT to_regclass('ff13.selections') IS NOT NULL AS ok"))[0].ok) {
    out["ff13.selections"] = (await rows(client, "SELECT count(*)::int AS n FROM ff13.selections WHERE airtable_record_id = ANY($1) OR make_execution_id = ANY($2)",
      [records, execs]))[0].n;
  }
  if ((await rows(client, HAS_SEED_LIST))[0].ok) {
    out["ref.exemplar_test_seeds"] = (await rows(client, "SELECT count(*)::int AS n FROM ref.exemplar_test_seeds WHERE airtable_record_id = ANY($1)",
      [seedIds]))[0].n;
  }
  return out;
}
