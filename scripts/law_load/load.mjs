#!/usr/bin/env node
// Applies the law and ref schemas and loads the committed provision index (law/, X-17.1) and visa types
// (ref/visa_types.json, X-20.1) into Supabase, then verifies access. Every X-37 reload runs the same way.
//
//   node scripts/law_load/load.mjs --ping             connect (TLS and password) and report, change nothing
//   node scripts/law_load/load.mjs --push --dry-run   Supabase CLI db push --dry-run of the committed migrations
//   node scripts/law_load/load.mjs --push             Supabase CLI db push of the committed migrations
//   node scripts/law_load/load.mjs --check            full load, constraints and gate in a transaction, ROLLBACK
//   node scripts/law_load/load.mjs                    the load, committed only if the constraints and gate pass
//   node scripts/law_load/load.mjs --verify-only      no load, only the checks
//
// One parser reads the connection, and no shell ever evaluates it (review 2026-11-02: sourcing .env in bash ran
// the password as shell code and mangled a Windows CA path). The values come from the environment or the repo
// .env and are never printed:
//   SUPABASE_DB_URL       the Session pooler URI from the Connect dialog with the password removed
//   SUPABASE_DB_PASSWORD  the database password
//   SUPABASE_DB_CA        path to the project's CA certificate (Database Settings, SSL Configuration)
// TLS is verified against that CA, for the loader and for the CLI (PGSSLMODE=verify-full, PGSSLROOTCERT, set in
// the CLI's environment only). LAW_LOAD_LOCAL=1 allows a plaintext connection to localhost only, with a fixed
// rehearsal password, for the local PGlite rehearsal.
//
// The schema goes through the pinned Supabase CLI, which keeps the migration history. --push copies the
// migrations from the committed HEAD into a temporary workdir, so an uncommitted migration is never pushed and the
// CLI never reads the repo .env (it loads <workdir>/.env). The seed does not go through the CLI: db push
// --include-seed runs a seed file only the first time it sees it (supabase/cli seed-ops.ts, v2.121.0).
//
// The seed is generated here from `python scripts/law_index.py sql` as bytes, so no shell redirect can re-encode
// it. It ends with SET CONSTRAINTS ALL IMMEDIATE and the load gate (law_index._gate_sql) before COMMIT.
//
// The visa types (X-20.1) load in the same transaction: the law upserts, then the ref/visa_types.json upserts,
// then SET CONSTRAINTS ALL IMMEDIATE, the law gate and the ref gate, then COMMIT (ROLLBACK for --check). So the
// deferred constraints of both tables are checked before either gate, one commit covers both, and --check works on
// a fresh project, where governing_provision can only point at keys this same transaction loads.

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const ROLES = ["anon", "authenticated", "service_role", "authenticator"];
const MIGRATIONS_DIR = "supabase/migrations";
const SUPABASE_CLI = "supabase@2.121.0";
const ENV_KEYS = ["SUPABASE_DB_URL", "SUPABASE_DB_PASSWORD", "SUPABASE_DB_CA"];
// The read-only Airtable token (data.records:read, this base only). Only verify's F-F10 checkbox read uses it, and the
// Supabase CLI never gets it.
const AIRTABLE_KEYS = ["AIRTABLE_PAT"];
const LOADED = ["law", "ref", "scripts/law_index.py", "scripts/law_load", MIGRATIONS_DIR];
const SCHEMAS = ["law", "ref", "ff13"];
// The F-F13 access path: the one role Make logs in as, and the only grants any schema here may hold.
const MAKE_ROLE = "ff13_make";
const VALIDATOR = "ff13.validate_draft(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text)";
// F-F10: the grounding call (record ID, execution ID, visa code, document type, synthetic flag).
export const DRAFTING_CONTEXT = "ff13.drafting_context(text,text,text,text,text)";
// X-32: the exemplar ranker (record ID, execution ID, visa code, document type, outline text, Rank Key lines).
export const RANK_EXEMPLARS = "ff13.rank_exemplars(text,text,text,text,text,text)";
// The three functions Make calls, and the only definers allowed anywhere in law, ref and ff13.
export const MAKE_FUNCTIONS = [VALIDATOR, DRAFTING_CONTEXT, RANK_EXEMPLARS];
const EXPECTED_GRANTS = { "schema ff13": [MAKE_ROLE], "function ff13.validate_draft": [MAKE_ROLE], "function ff13.drafting_context": [MAKE_ROLE],
  "function ff13.rank_exemplars": [MAKE_ROLE] };
// X-32: the Exemplars table (audit/x32.json) and the excluded cells, for the TEST seed read and the gate.
const X32_PIN = "audit/x32.json";
const X32_EXCLUDED = ["REF-CLAIM", "REF-RESETTLE", "HC-PR"];
// F-F10 test factor 1, read by verify for every active test record (fields[] this field only, hard rule 5).
const APPLICANTS_TABLE = "tblHk09sCKLcOJXr9";
const SYNTHETIC_TEST_CASE = "fldsCjg7ftgursZvl";
// The F-F10 behaviour checks ground every catalogue pair as the owner inside a rolled-back transaction. Neither ID is a
// real record: the unlisted one must be absent from ref.test_records, and the listed one exists only in that transaction.
const VERIFY_UNLISTED = "recVERIFYunlisted";
const VERIFY_LISTED = "recVERIFYlistedxx";
const VERIFY_EXEC = "0".repeat(32);
const MAKE_ROLE_SETTINGS = ["idle_in_transaction_session_timeout=60s", "statement_timeout=20s"];
const SEARCH_PATH = "search_path=pg_catalog, pg_temp";
const PRIV_SQL = {
  table: "SELECT has_table_privilege($1, $2, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER') OR has_any_column_privilege($1, $2, 'SELECT, INSERT, UPDATE, REFERENCES') AS h",
  sequence: "SELECT has_sequence_privilege($1, $2, 'USAGE, SELECT, UPDATE') AS h",
  function: "SELECT has_function_privilege($1, $2, 'EXECUTE') AS h",
};
// The ref tables in foreign-key order. Each loads from ref/<table>.json, {"<table>": [row, ...]}, every row exactly
// its cols. extra "refuse": a row in the database that the file lacks fails the gate (removing a visa code or a
// document type is a reviewed decision). extra "delete": the table is the file, so rows the file dropped are deleted.
// insertOnly: rows are inserted and never updated (ref.prompts, X-36.1: a registered version is immutable), and the gate
// refuses a file row that differs from the row the database already holds.
// allowEmpty: the file may hold an empty list (ref.test_records, F-F10, and ref.exemplar_test_seeds, X-32: empty or all
// retired is the kill switch). Their entries are retired, never deleted, so extra "refuse" and the tables' triggers keep
// every entry ever loaded.
export const REF_TABLES = [
  { table: "visa_types", key: ["code"], extra: "refuse",
    cols: ["code", "display_name", "category", "governing_provision", "ircc_url", "intake_status", "intake_note",
      "licence_class_required", "active", "aliases", "sort_order", "last_verified"] },
  { table: "document_types", key: ["code"], extra: "refuse",
    cols: ["code", "display_name", "restricted_to_visa_code", "active", "sort_order", "min_words", "max_words"] },
  // F-F13.2: the required sections of a document type. The table is the file, like the mapping.
  { table: "document_sections", key: ["document_type", "section"], extra: "delete",
    cols: ["document_type", "section", "ordinal", "part", "match_kind", "text", "variants", "note"] },
  { table: "citation_map", key: ["document_type", "visa_code", "provision_key"], extra: "delete",
    cols: ["document_type", "visa_code", "provision_key", "purpose", "origin", "reviewed_by_licence", "reviewed_on",
      "reviewed_text_sha256", "reviewed_row_sha256", "sort_order"] },
  { table: "prompts", key: ["stage", "version"], extra: "refuse", insertOnly: true,
    cols: ["stage", "version", "description", "model", "template", "template_sha256", "registered_on"] },
  { table: "prompt_bindings", key: ["scenario_id", "module_id"], extra: "delete",
    cols: ["scenario_id", "module_id", "stage", "version"] },
  { table: "test_records", key: ["airtable_record_id"], extra: "refuse", allowEmpty: true,
    cols: ["airtable_record_id", "added_on", "expires_on", "retired_on"] },
  // F-F13.2: the IRCC vocabulary. A name is never dropped, only marked former, so a row the file lacks fails the gate.
  { table: "ircc_vocabulary", key: ["id"], extra: "refuse",
    cols: ["id", "kind", "canonical_name", "ircc_aliases", "common_variants", "status", "replaced_by", "successor_note", "organization", "letter_addressee",
      "visa_codes", "note", "source_urls", "source_note", "sort_order", "last_verified"] },
  // X-32: the fact-pattern tag vocabulary, an unreviewed worksheet until an RCIC signs a row. The table is the file.
  { table: "exemplar_tags", key: ["tag", "visa_code"], extra: "delete",
    cols: ["tag", "visa_code", "addresses", "label", "review_state", "reviewer_licence", "reviewed_on"] },
  // X-32: the TEST seed record IDs, retired and never deleted. Starts empty: an ID enters only after Rizwan confirms it.
  { table: "exemplar_test_seeds", key: ["airtable_record_id"], extra: "refuse", allowEmpty: true,
    cols: ["airtable_record_id", "exemplar_code", "added_on", "retired_on"] },
];
const REF_DATES = new Set(["last_verified", "reviewed_on", "registered_on", "added_on", "expires_on", "retired_on"]);
const REF_BOOLS = new Set(["active"]);
const REF_INTS = new Set(["sort_order", "min_words", "max_words", "version", "scenario_id", "module_id", "ordinal"]);
const REF_JSON = new Set(["template"]);
const REF_ARRAYS = new Set(["aliases", "variants", "ircc_aliases", "common_variants", "visa_codes", "source_urls", "addresses"]);
const REF_NULLABLE = new Set(["intake_note", "restricted_to_visa_code", "reviewed_by_licence", "reviewed_on", "reviewed_text_sha256",
  "reviewed_row_sha256", "replaced_by", "successor_note", "note", "reviewer_licence", "retired_on"]);
const MODES = ["--ping", "--push", "--check", "--verify-only"];

class Refusal extends Error {}

export function parseArgs(argv) {
  const allowed = new Set([...MODES, "--dry-run"]);
  const bad = argv.filter((a) => !allowed.has(a));
  const modes = MODES.filter((m) => argv.includes(m));
  if (bad.length || modes.length > 1 || (argv.includes("--dry-run") && modes[0] !== "--push")) {
    throw new Refusal("usage: load.mjs [--ping | --push [--dry-run] | --check | --verify-only]" +
      (bad.length ? `, unknown: ${bad.join(" ")}` : ""));
  }
  return { mode: modes[0] || "--load", dryRun: argv.includes("--dry-run") };
}

export function readEnv(file = path.join(ROOT, ".env"), keys = ENV_KEYS) {
  const env = {};
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z_]+)\s*=(.*)$/);
      if (m && keys.includes(m[1])) env[m[1]] = m[2].trim().replace(/^(['"])(.*)\1$/, "$2");
    }
  }
  for (const k of keys) {
    if (process.env[k]) env[k] = process.env[k];
  }
  return env;
}

// The Airtable token for the F-F10 checkbox read, through the same parser. Never printed.
export function readAirtablePat(file = path.join(ROOT, ".env")) {
  return readEnv(file, AIRTABLE_KEYS).AIRTABLE_PAT || null;
}

export function connectionConfig(env, { local = false } = {}) {
  const raw = env.SUPABASE_DB_URL;
  if (!raw) throw new Refusal("SUPABASE_DB_URL is not set");
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Refusal("SUPABASE_DB_URL is not a URL");
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol)) throw new Refusal("SUPABASE_DB_URL is not a postgres URI");
  const authority = raw.split("://")[1]?.split(/[/?#]/)[0] || "";
  const userinfo = authority.includes("@") ? authority.slice(0, authority.lastIndexOf("@")) : "";
  if (url.password || userinfo.includes(":")) {
    throw new Refusal("SUPABASE_DB_URL holds a password field. Remove it, the password goes in SUPABASE_DB_PASSWORD");
  }
  if (url.search || url.hash) throw new Refusal("SUPABASE_DB_URL carries a query string. Remove it, TLS is set here");
  const port = Number(url.port || 5432);
  if (port === 6543) throw new Refusal("port 6543 is the transaction pooler. Use the Session pooler (5432)");
  const host = url.hostname;
  const config = {
    host,
    port,
    user: decodeURIComponent(url.username),
    database: decodeURIComponent(url.pathname.replace(/^\//, "")) || "postgres",
    application_name: "immi-os-law-load",
  };
  if (local) {
    if (!LOCAL_HOSTS.has(host)) throw new Refusal("LAW_LOAD_LOCAL=1 is for localhost only");
    // Never the live password: whatever listens on localhost would receive it.
    config.password = "local-rehearsal";
    config.ssl = false;
    config.caPath = null;
  } else {
    if (!env.SUPABASE_DB_PASSWORD) throw new Refusal("SUPABASE_DB_PASSWORD is not set");
    if (!env.SUPABASE_DB_CA || !fs.existsSync(env.SUPABASE_DB_CA)) throw new Refusal("SUPABASE_DB_CA does not name a file");
    const ca = fs.readFileSync(env.SUPABASE_DB_CA, "utf8");
    if (!ca.includes("BEGIN CERTIFICATE")) throw new Refusal("SUPABASE_DB_CA is not a PEM certificate");
    config.password = env.SUPABASE_DB_PASSWORD;
    config.ssl = { ca, rejectUnauthorized: true, servername: host };
    config.caPath = path.resolve(env.SUPABASE_DB_CA);
  }
  return config;
}

function gitClean() {
  const out = execFileSync("git", ["status", "--porcelain", "--", ...LOADED], { cwd: ROOT }).toString();
  if (out.trim()) throw new Refusal(`${LOADED.join(", ")} must be committed. Only committed files are pushed or loaded`);
}

// The law seed split at SET CONSTRAINTS: head is BEGIN and the upserts, tail is SET CONSTRAINTS and the gate,
// without COMMIT. The caller runs the ref upserts between them and ends the transaction itself.
export function seedSql() {
  const bytes = execFileSync(process.env.PYTHON || "python", ["scripts/law_index.py", "sql"], {
    cwd: ROOT,
    maxBuffer: 256 * 1024 * 1024,
  });
  const sql = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!sql.startsWith("BEGIN;\n") || !sql.endsWith("$gate$;\nCOMMIT;\n") || !sql.includes("\nSET CONSTRAINTS ALL IMMEDIATE;\nDO $gate$")) {
    throw new Refusal("the generated seed does not have the shape BEGIN, upserts, SET CONSTRAINTS, gate, COMMIT");
  }
  const cut = sql.indexOf("\nSET CONSTRAINTS ALL IMMEDIATE;\n");
  if (sql.indexOf("\nSET CONSTRAINTS ALL IMMEDIATE;\n", cut + 1) !== -1) throw new Refusal("the generated seed sets constraints twice");
  return { head: sql.slice(0, cut + 1), tail: sql.slice(cut + 1, -"COMMIT;\n".length) };
}

function readJson(rel) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));
}

const refFile = (t) => `ref/${t.table}.json`;
const rowId = (t, r) => t.key.map((k) => r[k]).join(" | ");

// Every ref file, {table: rows}. The tables' CHECKs and foreign keys are the authority on values, this only refuses
// a file the upsert would misread.
export function refRows(dir = path.join(ROOT, "ref")) {
  const out = {};
  for (const t of REF_TABLES) {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, `${t.table}.json`), "utf8"));
    const list = doc && doc[t.table];
    if (!Array.isArray(list) || (!list.length && !t.allowEmpty)) throw new Refusal(`${refFile(t)} has no ${t.table} list`);
    const seen = new Set();
    for (const r of list) {
      const keys = r && typeof r === "object" ? Object.keys(r).sort() : [];
      if (keys.join() !== [...t.cols].sort().join()) throw new Refusal(`${refFile(t)}: a row does not have exactly ${t.cols.join(", ")}`);
      const id = rowId(t, r);
      if (seen.has(id)) throw new Refusal(`${refFile(t)}: ${id} twice`);
      seen.add(id);
      for (const c of t.cols) {
        const v = r[c];
        if (v === null && REF_NULLABLE.has(c)) continue;
        const ok = REF_DATES.has(c) ? typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)
          : REF_BOOLS.has(c) ? typeof v === "boolean"
          : REF_INTS.has(c) ? Number.isSafeInteger(v)
          : REF_ARRAYS.has(c) ? Array.isArray(v) && v.every((a) => typeof a === "string")
          : REF_JSON.has(c) ? v !== null && typeof v === "object" && !Array.isArray(v)
          : typeof v === "string";
        if (!ok) throw new Refusal(`${refFile(t)}: ${id} has a wrong type in ${c}`);
      }
    }
    out[t.table] = list;
  }
  return out;
}

// The canonical JSON of scripts/prompt_registry.py canonical: sorted keys, no whitespace, text as is. jsonb reorders keys,
// so every comparison of a JSON column and every prompt hash goes through it.
export function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}

export const sha256Hex = (text) => createHash("sha256").update(text, "utf8").digest("hex");
// BIGINT columns. node-pg returns int8 as a string and ::int overflows past 2^31 - 1, so they are read and compared as text.
const REF_BIGINTS = new Set(["scenario_id"]);
const sameCell = (c, a, b) => (REF_JSON.has(c) ? canonicalJson(a) === canonicalJson(b)
  : REF_BIGINTS.has(c) ? String(a) === String(b) : JSON.stringify(a) === JSON.stringify(b));
// Dates and BIGINTs as text, the other integers as int.
const selectCols = (t) => t.cols.map((c) => (REF_DATES.has(c) || REF_BIGINTS.has(c) ? `${c}::text AS ${c}`
  : REF_INTS.has(c) ? `${c}::int AS ${c}` : c)).join(", ");

export async function upsertRef(client, ref) {
  for (const t of REF_TABLES) {
    const list = ref[t.table];
    if (t.extra === "delete") {
      // Rows the file no longer has. Nothing references a mapping row, so the table can equal the file.
      await client.query(`DELETE FROM ref.${t.table} WHERE NOT (ARRAY[${t.key.join(", ")}]::text[] = ANY (
          SELECT ARRAY[${t.key.map((_, i) => `k${i}`).join(", ")}]::text[] FROM unnest(${t.key.map((_, i) => `$${i + 1}::text[]`).join(", ")}) AS f(${t.key.map((_, i) => `k${i}`).join(", ")})))`,
        t.key.map((k) => list.map((r) => r[k])));
    }
    const sets = t.cols.filter((c) => !t.key.includes(c)).map((c) => `${c} = EXCLUDED.${c}`).join(", ");
    for (const r of list) {
      await client.query(
        `INSERT INTO ref.${t.table} (${t.cols.join(", ")}, loaded_at) VALUES (${t.cols.map((_, i) => `$${i + 1}`).join(", ")}, now()) ` +
        (t.insertOnly ? `ON CONFLICT (${t.key.join(", ")}) DO NOTHING` : `ON CONFLICT (${t.key.join(", ")}) DO UPDATE SET ${sets}, loaded_at = now()`),
        t.cols.map((c) => (REF_JSON.has(c) ? JSON.stringify(r[c]) : r[c])));
    }
  }
}

// Runs after SET CONSTRAINTS ALL IMMEDIATE, inside the transaction. Returns the problems, empty when it passes.
export async function refGate(client, ref, opts = {}) {
  const problems = [];
  for (const t of REF_TABLES.filter((x) => x.extra === "refuse")) {
    // Every key column, so a dropped version of a stage that still has others is caught too.
    const want = new Set(ref[t.table].map((r) => rowId(t, r)));
    const got = await rows(client, `SELECT ${t.key.join(", ")} FROM ref.${t.table}`);
    const extra = got.map((r) => rowId(t, r)).filter((id) => !want.has(id)).sort();
    if (extra.length) problems.push(`${t.table} in the database and not in ${refFile(t)}: ${extra.join(", ")}`);
  }
  for (const t of REF_TABLES.filter((x) => x.insertOnly)) {
    // ON CONFLICT DO NOTHING kept the stored row, so a file row that differs from it is an edited version.
    const byId = new Map((await rows(client, `SELECT ${selectCols(t)} FROM ref.${t.table}`)).map((r) => [rowId(t, r), r]));
    const changed = ref[t.table].filter((w) => {
      const g = byId.get(rowId(t, w));
      return g && t.cols.some((c) => !sameCell(c, g[c], w[c]));
    }).map((w) => rowId(t, w));
    if (changed.length) problems.push(`${t.table} rows differ from the registered version, which never changes (register a new version): ${changed.join(", ")}`);
  }
  // A prompt's hash is the SHA-256 of its canonical template, and its model is the template's (Postgres cannot reproduce
  // the canonical JSON, so the loader checks it).
  const badHash = ref.prompts.filter((r) => sha256Hex(canonicalJson(r.template)) !== r.template_sha256 || r.model !== r.template.model)
    .map((r) => `${r.stage}@${r.version}`);
  if (badHash.length) problems.push(`prompts whose template_sha256 or model does not match the template: ${badHash.join(", ")}`);
  const dead = await rows(client, `SELECT v.code, p.status FROM ref.visa_types v JOIN law.provisions p ON p.key = v.governing_provision
                                    WHERE p.status <> 'in_force' ORDER BY 1`);
  if (dead.length) problems.push(`governing_provision not in force: ${dead.map((r) => `${r.code} (${r.status})`).join(", ")}`);
  const shared = await rows(client, `SELECT a FROM ref.visa_types, unnest(aliases) a GROUP BY a HAVING count(DISTINCT code) > 1 ORDER BY 1`);
  if (shared.length) problems.push(`aliases shared by two codes: ${shared.map((r) => r.a).join(", ")}`);
  const padded = await rows(client, "SELECT DISTINCT code FROM ref.visa_types, unnest(aliases) a WHERE a <> btrim(a) ORDER BY 1");
  if (padded.length) problems.push(`aliases with surrounding spaces: ${padded.map((r) => r.code).join(", ")}`);
  // Mapping rows: in force, for a document type that applies to the code, and never for an IRB matter.
  const mapDead = await rows(client, `SELECT m.document_type, m.visa_code, m.provision_key, p.status FROM ref.citation_map m
                                       JOIN law.provisions p ON p.key = m.provision_key WHERE p.status <> 'in_force' ORDER BY 1, 2, 3`);
  if (mapDead.length) problems.push(`citation_map provision not in force: ${mapDead.map((r) => `${r.document_type} ${r.visa_code} ${r.provision_key} (${r.status})`).join(", ")}`);
  const wrongPair = await rows(client, `SELECT DISTINCT m.document_type, m.visa_code FROM ref.citation_map m JOIN ref.document_types d ON d.code = m.document_type
                                         WHERE d.restricted_to_visa_code IS NOT NULL AND d.restricted_to_visa_code <> m.visa_code ORDER BY 1, 2`);
  if (wrongPair.length) problems.push(`citation_map rows for a document type that does not apply: ${wrongPair.map((r) => `${r.document_type} ${r.visa_code}`).join(", ")}`);
  const irb = await rows(client, `SELECT DISTINCT m.visa_code FROM ref.citation_map m JOIN ref.visa_types v ON v.code = m.visa_code
                                   WHERE v.licence_class_required = 'RCIC-IRB' ORDER BY 1`);
  if (irb.length) problems.push(`citation_map rows for an IRB matter, which Module F never drafts: ${irb.map((r) => r.visa_code).join(", ")}`);
  // law.provision_text() of a key includes its sub-units, so a parent and its child in one pair inject text twice.
  const nested = await rows(client, `SELECT a.document_type, a.visa_code, a.provision_key AS parent, b.provision_key AS child
                                      FROM ref.citation_map a JOIN ref.citation_map b
                                        ON b.document_type = a.document_type AND b.visa_code = a.visa_code
                                       AND left(b.provision_key, length(a.provision_key) + 1) = a.provision_key || '('
                                     ORDER BY 1, 2, 3, 4`);
  if (nested.length) problems.push(`citation_map pairs that map a provision and its own sub-unit: ${nested.map((r) => `${r.document_type} ${r.visa_code} ${r.parent} > ${r.child}`).join(", ")}`);
  for (const p of await sectionAndVocabularyProblems(client, opts)) problems.push(p);
  for (const p of await x32Problems(client)) problems.push(p);
  return problems;
}

// X-32: what the table CHECKs cannot hold. Every tag addresses only provision keys the citation map holds for its visa
// code and SUBMISSION-LETTER, the link between a fact pattern and an outline weakness. Every TEST seed code names a visa
// code that exists and is not excluded, so a listed seed can only ever match a candidate of a draftable cell.
export async function x32Problems(client) {
  const problems = [];
  const stray = await rows(client, `SELECT t.tag, t.visa_code, a FROM ref.exemplar_tags t, unnest(t.addresses) a
                                     WHERE NOT EXISTS (SELECT 1 FROM ref.citation_map m WHERE m.document_type = 'SUBMISSION-LETTER'
                                                         AND m.visa_code = t.visa_code AND m.provision_key = a)
                                     ORDER BY 1, 2, 3`);
  if (stray.length) problems.push(`exemplar_tags addresses no SUBMISSION-LETTER citation_map row of its visa code: ${stray.map((r) => `${r.tag} ${r.visa_code} ${r.a}`).join(", ")}`);
  const twice = await rows(client, `SELECT tag, visa_code FROM ref.exemplar_tags WHERE cardinality(addresses) <> (SELECT count(DISTINCT a) FROM unnest(addresses) a)
                                     ORDER BY 1, 2`);
  if (twice.length) problems.push(`exemplar_tags naming a provision key twice: ${twice.map((r) => `${r.tag} ${r.visa_code}`).join(", ")}`);
  const seeds = await rows(client, `SELECT s.airtable_record_id AS id, s.exemplar_code AS code FROM ref.exemplar_test_seeds s
                                     WHERE NOT EXISTS (SELECT 1 FROM ref.visa_types v WHERE s.exemplar_code = 'ZZ-TEST-EX-' || v.code || '-' || right(s.exemplar_code, 3)
                                                         AND v.code <> ALL ($1::text[]))
                                     ORDER BY 1`, [X32_EXCLUDED]);
  if (seeds.length) problems.push(`exemplar_test_seeds whose code names no draftable visa code: ${seeds.map((r) => `${r.id} ${r.code}`).join(", ")}`);
  return problems;
}

// F-F13.2: what the table CHECKs cannot hold. Required sections: at most one first_line, at the lowest ordinal, and at
// most one last_line, at the highest, which needs a first_line to name the RCIC. Vocabulary: a former row points at a
// current row of its own kind, every visa code exists, and no phrase key (diacritics folded, lowercase, hyphens and
// whitespace as one space, ff13._vkey) belongs to two rows, so a matched name always resolves to one row. Last, the
// vocabulary probe: the validator's own pattern build (ff13._vocab_patterns) and one ff13._hits per pattern over a fixed
// text of VOCAB_PROBE_CHARS characters made of the vocabulary's names. A pattern Postgres cannot compile or run (too
// complex, an allocation over its limit) would end every validate_draft call in validator_error, so it is refused. So is
// a probe slower than vocabBudgetMs, since a draft is up to 100,000 characters and ff13_make has a 20 s statement
// timeout: a probe over the budget on a fifth of that length leaves no room for a full-size draft.
export const VOCAB_PROBE_CHARS = 20000;
export const VOCAB_BUDGET_MS = 4000;
export async function sectionAndVocabularyProblems(client, { vocabBudgetMs = VOCAB_BUDGET_MS } = {}) {
  const problems = [];
  const shape = await rows(client, `
    SELECT document_type FROM (SELECT document_type, match_kind, ordinal, min(ordinal) OVER w AS lo, max(ordinal) OVER w AS hi
                                 FROM ref.document_sections WINDOW w AS (PARTITION BY document_type)) s
     GROUP BY document_type
    HAVING count(*) FILTER (WHERE match_kind = 'first_line') > 1 OR count(*) FILTER (WHERE match_kind = 'last_line') > 1
        OR count(*) FILTER (WHERE match_kind = 'last_line') > count(*) FILTER (WHERE match_kind = 'first_line')
        OR bool_or(match_kind = 'first_line' AND ordinal <> lo) OR bool_or(match_kind = 'last_line' AND ordinal <> hi)
     ORDER BY 1`);
  if (shape.length) problems.push(`document_sections whose first or last line is not one row at the first or last ordinal: ${shape.map((r) => r.document_type).join(", ")}`);
  const replaced = await rows(client, `SELECT v.id FROM ref.ircc_vocabulary v JOIN ref.ircc_vocabulary r ON r.id = v.replaced_by
                                        WHERE r.status <> 'current' OR r.kind <> v.kind ORDER BY 1`);
  if (replaced.length) problems.push(`ircc_vocabulary rows replaced by a former row or a row of another kind: ${replaced.map((r) => r.id).join(", ")}`);
  const codes = await rows(client, `SELECT v.id, c FROM ref.ircc_vocabulary v, unnest(v.visa_codes) c
                                     WHERE NOT EXISTS (SELECT 1 FROM ref.visa_types t WHERE t.code = c) ORDER BY 1, 2`);
  if (codes.length) problems.push(`ircc_vocabulary visa codes not in visa_types: ${codes.map((r) => `${r.id} ${r.c}`).join(", ")}`);
  const keys = await rows(client, `SELECT k, string_agg(DISTINCT id, ', ' ORDER BY id) AS ids
                                     FROM (SELECT v.id, ff13._vkey(p) AS k FROM ref.ircc_vocabulary v,
                                                  unnest(ARRAY[v.canonical_name] || v.ircc_aliases || v.common_variants) p) x
                                    GROUP BY k HAVING count(DISTINCT id) > 1 OR k = '' ORDER BY 1`);
  if (keys.length) problems.push(`ircc_vocabulary phrases shared by two rows or empty after folding: ${keys.map((r) => `"${r.k}" (${r.ids})`).join(", ")}`);
  // The probe runs under a savepoint, so a failed pattern leaves the load transaction usable for the ROLLBACK.
  await client.query("SAVEPOINT ff13_2_vocab_probe");
  const t = Date.now();
  try {
    await rows(client, `
      WITH s AS (SELECT ff13._vfold(left(repeat(string_agg(canonical_name, '. ' ORDER BY sort_order) || '. ', 1000), $1)) AS txt
                   FROM ref.ircc_vocabulary)
      SELECT count(*)::int AS n FROM s, ff13._vocab_patterns() p, generate_subscripts(p.vre, 1) i,
             LATERAL ff13._hits(s.txt, p.vre[i], CASE i WHEN 1 THEN 'i' ELSE '' END, 0) h
       WHERE p.vre[i] IS NOT NULL`, [VOCAB_PROBE_CHARS]);
    const ms = Date.now() - t;
    await client.query("RELEASE SAVEPOINT ff13_2_vocab_probe");
    if (ms > vocabBudgetMs) problems.push(`ircc_vocabulary pattern too slow: the probe took ${ms} ms over ${VOCAB_PROBE_CHARS} characters, budget ${vocabBudgetMs} ms`);
  } catch (e) {
    await client.query("ROLLBACK TO SAVEPOINT ff13_2_vocab_probe");
    await client.query("RELEASE SAVEPOINT ff13_2_vocab_probe");
    problems.push(`ircc_vocabulary pattern does not run in the validator: SQLSTATE ${typeof e.code === "string" ? e.code : "unknown"}`);
  }
  return problems;
}

function lawRows(instrument) {
  return fs.readFileSync(path.join(ROOT, "law", `${instrument}.jsonl`), "utf8")
    .split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

async function rows(client, sql, params) {
  return (await client.query(sql, params)).rows;
}

// The F-F10 test records active today (America/Toronto), by the rule ff13.drafting_context applies.
export async function activeTestRecords(client) {
  return (await rows(client, `SELECT airtable_record_id AS id FROM ref.test_records
                               WHERE retired_on IS NULL AND (now() AT TIME ZONE 'America/Toronto')::date BETWEEN added_on AND expires_on
                               ORDER BY 1`)).map((r) => r.id);
}

// Test factor 1 for each record ID: the Applicants checkbox Synthetic Test Case, read with the read-only token, that one
// field only, by field ID. POST listRecords keeps the IDs out of the URL. Returns a Map of ID to true when ticked. The
// token is never printed, and a failed request reports its HTTP status only.
export async function syntheticFlags(ids, { pat, baseId, fetchImpl = globalThis.fetch }) {
  if (!/^app[A-Za-z0-9]{14}$/.test(baseId || "")) throw new Refusal("no Airtable base ID in audit/airtable_links.json");
  const flags = new Map();
  for (let i = 0; i < ids.length; i += 50) {
    const chunk = ids.slice(i, i + 50);
    if (chunk.some((id) => !/^rec[A-Za-z0-9]{14}$/.test(id))) throw new Refusal("a test record ID is malformed");
    let offset;
    do {
      const body = { fields: [SYNTHETIC_TEST_CASE], returnFieldsByFieldId: true, pageSize: 100,
        filterByFormula: `OR(${chunk.map((id) => `RECORD_ID()='${id}'`).join(",")})`, ...(offset ? { offset } : {}) };
      const r = await fetchImpl(`https://api.airtable.com/v0/${baseId}/${APPLICANTS_TABLE}/listRecords`, {
        method: "POST", headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Refusal(`Airtable answered HTTP ${r.status}`);
      const page = await r.json();
      for (const rec of page.records || []) flags.set(rec.id, rec.fields?.[SYNTHETIC_TEST_CASE] === true);
      offset = page.offset;
    } while (offset);
  }
  return flags;
}

// F-F10 test factor 1 as one check: every active test record must have Synthetic Test Case ticked in Airtable. With no
// active record Airtable is not read. airtable: { pat, baseId, fetchImpl }, from the repo .env and
// audit/airtable_links.json when not given.
export async function syntheticCheck(client, airtable = {}) {
  const name = "test records Synthetic Test Case";
  const active = await activeTestRecords(client);
  if (!active.length) return [name, null, "no active test record, Airtable not read (the test path is closed)"];
  const pat = "pat" in airtable ? airtable.pat : readAirtablePat();
  if (!pat) return [name, false, `${active.length} active test record(s) and no AIRTABLE_PAT to read Synthetic Test Case`];
  const baseId = "baseId" in airtable ? airtable.baseId : readJson("audit/airtable_links.json").base_id;
  try {
    const flags = await syntheticFlags(active, { pat, baseId, fetchImpl: airtable.fetchImpl });
    const bad = active.filter((id) => flags.get(id) !== true);
    return [name, bad.length === 0, bad.length ? `not ticked or not found in Applicants: ${bad.join(", ")}`
      : `${active.length} active test record(s), every one ticked in Airtable`];
  } catch (e) {
    return [name, false, `Airtable read failed: ${e instanceof Refusal ? e.message : e.name}`];
  }
}

// F-F10 behaviour, run as the owner inside a transaction (or a savepoint of the caller's) that is always rolled back,
// so no grounding row or test entry survives. For an unlisted record and a false flag, ff13.drafting_context is
// ref.drafting_gate plus ref.citation_context row for row on every SUBMISSION-LETTER pair and refuses every other
// document type. In test mode no key outside state current or unreviewed is ever returned. A listed record with a
// false flag and an unlisted record with a true flag both refuse.
export async function ff10Checks(client) {
  const checks = [];
  const add = (name, ok, detail) => checks.push([name, ok, detail]);
  let owned = false;
  try {
    await client.query("SAVEPOINT ff10_verify");
  } catch (e) {
    if (e.code !== "25P01") throw e;
    await client.query("BEGIN");
    owned = true;
  }
  try {
    const clash = await rows(client, "SELECT airtable_record_id FROM ref.test_records WHERE airtable_record_id = ANY($1)", [[VERIFY_UNLISTED, VERIFY_LISTED]]);
    if (clash.length) {
      add("drafting_context checks", false, `${clash.map((r) => r.airtable_record_id).join(", ")} is in ref.test_records, the verify IDs must never be listed`);
      return checks;
    }
    const pairs = await rows(client, `SELECT v.code AS visa, d.code AS doc FROM ref.visa_types v CROSS JOIN ref.document_types d
                                       WHERE d.restricted_to_visa_code IS NULL OR d.restricted_to_visa_code = v.code ORDER BY 2, 1`);
    const ground = async (rec, visa, doc, flag) =>
      (await rows(client, "SELECT * FROM ff13.drafting_context($1, $2, $3, $4, $5)", [rec, VERIFY_EXEC, visa, doc, flag]))[0];
    const letters = pairs.filter((p) => p.doc === "SUBMISSION-LETTER");

    const differ = [];
    for (const p of pairs) {
      const got = await ground(VERIFY_UNLISTED, p.visa, p.doc, "false");
      const have = { allowed: got.allowed, reason: got.reason, gate_mode: got.gate_mode, provision_keys: JSON.parse(got.provision_keys),
        flags: JSON.parse(got.flags), provisions: JSON.parse(got.provisions) };
      let want;
      if (p.doc !== "SUBMISSION-LETTER") {
        want = { allowed: "false", reason: "document type not in F-F10 v1", gate_mode: "production", provision_keys: [], flags: [], provisions: [] };
      } else {
        const [g] = await rows(client, "SELECT allowed, reason, provision_keys, flags FROM ref.drafting_gate($1, $2)", [p.visa, p.doc]);
        const c = await rows(client, `SELECT c.provision_key AS key, c.purpose, c.text FROM ref.citation_context($1, $2)
                                        WITH ORDINALITY c(provision_key, purpose, text, n) ORDER BY c.n`, [p.visa, p.doc]);
        want = { allowed: String(g.allowed), reason: g.reason, gate_mode: "production", provision_keys: g.provision_keys, flags: g.flags, provisions: c };
      }
      if (canonicalJson(have) !== canonicalJson(want)) differ.push(`${p.doc} ${p.visa}`);
    }
    add("drafting_context production equals the gate", differ.length === 0,
      differ.length ? `differs on ${differ.slice(0, 10).join(", ")}` : `${pairs.length} pairs, ${letters.length} SUBMISSION-LETTER pairs equal ref.drafting_gate plus ref.citation_context, the rest refused as not in F-F10 v1`);

    await client.query(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on)
                        VALUES ($1, (now() AT TIME ZONE 'America/Toronto')::date, (now() AT TIME ZONE 'America/Toronto')::date + 1)`, [VERIFY_LISTED]);
    const outside = [];
    let allowed = 0;
    for (const p of letters) {
      const got = await ground(VERIFY_LISTED, p.visa, p.doc, "true");
      const keys = JSON.parse(got.provision_keys);
      const ok = (await rows(client, "SELECT s.provision_key FROM ref.citation_status($1, $2) s WHERE s.state IN ('current', 'unreviewed')", [p.visa, p.doc]))
        .map((r) => r.provision_key);
      const provided = JSON.parse(got.provisions).map((x) => x.key);
      if (got.gate_mode !== "test" || !JSON.parse(got.flags).includes("test_mode") || keys.some((k) => !ok.includes(k))
          || canonicalJson(provided) !== canonicalJson(keys)) outside.push(`${p.doc} ${p.visa}`);
      if (got.allowed === "true") allowed++;
    }
    add("drafting_context test mode keys", outside.length === 0,
      outside.length ? `a key outside state current or unreviewed, or not test mode: ${outside.slice(0, 10).join(", ")}`
        : `${letters.length} pairs in test mode, ${allowed} allowed, every key current or unreviewed`);

    const loose = [];
    for (const p of letters) {
      for (const [rec, flag] of [[VERIFY_LISTED, "false"], [VERIFY_UNLISTED, "true"]]) {
        const got = await ground(rec, p.visa, p.doc, flag);
        if (got.allowed !== "false" || got.reason !== "test marker mismatch" || got.provisions !== "[]") loose.push(`${p.visa} ${rec === VERIFY_LISTED ? "listed, flag false" : "unlisted, flag true"}`);
      }
    }
    add("drafting_context one factor refuses", loose.length === 0,
      loose.length ? `not refused: ${loose.slice(0, 10).join(", ")}` : `${letters.length * 2} calls, a listed record with a false flag and an unlisted one with a true flag refuse`);
  } catch (e) {
    add("drafting_context checks", false, `stopped: ${e.code ? `SQLSTATE ${e.code} ` : ""}${e.message}`);
  } finally {
    if (owned) {
      await client.query("ROLLBACK");
    } else {
      await client.query("ROLLBACK TO SAVEPOINT ff10_verify");
      await client.query("RELEASE SAVEPOINT ff10_verify");
    }
  }
  return checks;
}

// X-32: every listed TEST seed read back from the Exemplars table with the read-only token (fields[] Status and Exemplar
// Code only, by field ID, hard rule 5): Status must be TEST or Retired and the code must start ZZ-TEST- and equal the
// listed code. With no listed seed Airtable is not read. airtable: { pat, baseId, pin, fetchImpl }, from the repo .env,
// audit/airtable_links.json and audit/x32.json when not given.
export async function x32SeedCheck(client, airtable = {}) {
  const name = "TEST seeds in Airtable";
  const listed = await rows(client, "SELECT airtable_record_id AS id, exemplar_code AS code FROM ref.exemplar_test_seeds ORDER BY 1");
  if (!listed.length) return [name, null, "no TEST seed listed, Airtable not read (the TEST seed path is closed)"];
  const pat = "pat" in airtable ? airtable.pat : readAirtablePat();
  if (!pat) return [name, false, `${listed.length} listed TEST seed(s) and no AIRTABLE_PAT to read their Status`];
  const pin = "pin" in airtable ? airtable.pin : readJson(X32_PIN);
  const table = pin?.exemplars_table_id;
  const fStatus = pin?.field_ids?.status;
  const fCode = pin?.field_ids?.exemplar_code;
  if (!/^tbl[A-Za-z0-9]{14}$/.test(table || "") || !/^fld[A-Za-z0-9]{14}$/.test(fStatus || "") || !/^fld[A-Za-z0-9]{14}$/.test(fCode || "")) {
    return [name, false, `${X32_PIN} pins no Exemplars table ID or no Status and Exemplar Code field IDs, so the listed seeds cannot be read`];
  }
  const baseId = "baseId" in airtable ? airtable.baseId : readJson("audit/airtable_links.json").base_id;
  try {
    const got = await airtableFields(listed.map((r) => r.id), { pat, baseId, table, fields: [fStatus, fCode], fetchImpl: airtable.fetchImpl });
    const bad = listed.filter((r) => {
      const f = got.get(r.id);
      return !f || !["TEST", "Retired"].includes(f[fStatus]) || typeof f[fCode] !== "string" || !f[fCode].startsWith("ZZ-TEST-") || f[fCode] !== r.code;
    }).map((r) => r.id);
    return [name, bad.length === 0, bad.length ? `not found, not TEST or Retired, or another code in Exemplars: ${bad.join(", ")}`
      : `${listed.length} listed TEST seed(s), every one TEST or Retired in Airtable with its listed ZZ-TEST- code`];
  } catch (e) {
    return [name, false, `Airtable read failed: ${e instanceof Refusal ? e.message : e.name}`];
  }
}

// Named fields of the given records of one table, by field ID, by POST listRecords so no record ID reaches a URL. Returns a
// Map of record ID to its fields. The token is never printed, and a failed request reports its HTTP status only.
export async function airtableFields(ids, { pat, baseId, table, fields, fetchImpl = globalThis.fetch }) {
  if (!/^app[A-Za-z0-9]{14}$/.test(baseId || "")) throw new Refusal("no Airtable base ID in audit/airtable_links.json");
  if (!/^tbl[A-Za-z0-9]{14}$/.test(table || "")) throw new Refusal("no Airtable table ID");
  const out = new Map();
  for (let i = 0; i < ids.length; i += 50) {
    const chunk = ids.slice(i, i + 50);
    if (chunk.some((id) => !/^rec[A-Za-z0-9]{14}$/.test(id))) throw new Refusal("a record ID is malformed");
    let offset;
    do {
      const body = { fields, returnFieldsByFieldId: true, pageSize: 100,
        filterByFormula: `OR(${chunk.map((id) => `RECORD_ID()='${id}'`).join(",")})`, ...(offset ? { offset } : {}) };
      const r = await fetchImpl(`https://api.airtable.com/v0/${baseId}/${table}/listRecords`, {
        method: "POST", headers: { Authorization: `Bearer ${pat}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Refusal(`Airtable answered HTTP ${r.status}`);
      const page = await r.json();
      for (const rec of page.records || []) out.set(rec.id, rec.fields || {});
      offset = page.offset;
    } while (offset);
  }
  return out;
}

// X-32 behaviour, run as the owner inside a transaction (or a savepoint of the caller's) that is always rolled back, so no
// grounding, selection, validation or listing survives. Without a grounding row the ranker selects none. In test mode, on
// the first SUBMISSION-LETTER pair that grounds, it picks a TEST seed listed inside the savepoint and refuses the same line
// under an unlisted ID, and the validator then holds @08 to the newest selection (none, so a term is unexpected).
const VERIFY_SEED = "recVERIFYx32seed1";
const VERIFY_SEED_UNLISTED = "recVERIFYx32seed2";
export async function x32Checks(client) {
  const checks = [];
  const add = (name, ok, detail) => checks.push([name, ok, detail]);
  let owned = false;
  try {
    await client.query("SAVEPOINT x32_verify");
  } catch (e) {
    if (e.code !== "25P01") throw e;
    await client.query("BEGIN");
    owned = true;
  }
  try {
    const clash = await rows(client, `SELECT airtable_record_id AS id FROM ref.test_records WHERE airtable_record_id = ANY($1)
                                      UNION ALL SELECT airtable_record_id FROM ref.exemplar_test_seeds WHERE airtable_record_id = ANY($2)`,
    [[VERIFY_UNLISTED, VERIFY_LISTED], [VERIFY_SEED, VERIFY_SEED_UNLISTED]]);
    if (clash.length) {
      add("rank_exemplars checks", false, `${clash.map((r) => r.id).join(", ")} is listed, the verify IDs must never be`);
      return checks;
    }
    const outline = JSON.stringify({ facts_sufficient: true, inputs_contain_instructions: false, grounds: [] });
    const rank = async (rec, visa, line) => (await rows(client, "SELECT * FROM ff13.rank_exemplars($1, $2, $3, $4, $5, $6)",
      [rec, VERIFY_EXEC, visa, "SUBMISSION-LETTER", outline, line]))[0];
    const lineOf = (id, visa) => `${id}|ZZ-TEST-EX-${visa}-999|TEST|${visa}|SUBMISSION-LETTER|1|`;
    const none = await rank(VERIFY_UNLISTED, "TR-VISIT", lineOf(VERIFY_SEED, "TR-VISIT"));
    add("rank_exemplars without a grounding row", none.exemplar_record_id === "none" && JSON.parse(none.flags).includes("no_grounding"),
      `answered ${none.exemplar_record_id} with flags ${none.flags}, expected none and no_grounding`);

    await client.query(`INSERT INTO ref.test_records (airtable_record_id, added_on, expires_on)
                        VALUES ($1, (now() AT TIME ZONE 'America/Toronto')::date, (now() AT TIME ZONE 'America/Toronto')::date + 1)`, [VERIFY_LISTED]);
    const codes = await rows(client, "SELECT v.code AS visa FROM ref.visa_types v WHERE v.code <> ALL ($1::text[]) ORDER BY v.sort_order, v.code",
      [X32_EXCLUDED]);
    let visa = null;
    for (const p of codes) {
      const [g] = await rows(client, "SELECT * FROM ff13.drafting_context($1, $2, $3, $4, $5)", [VERIFY_LISTED, VERIFY_EXEC, p.visa, "SUBMISSION-LETTER", "true"]);
      if (g.allowed === "true" && g.gate_mode === "test") {
        visa = p.visa;
        break;
      }
    }
    if (!visa) {
      add("rank_exemplars test mode picks only a listed TEST seed", null, "no SUBMISSION-LETTER pair grounds in test mode, the test path is closed");
      return checks;
    }
    await client.query(`INSERT INTO ref.exemplar_test_seeds (airtable_record_id, exemplar_code, added_on)
                        VALUES ($1, $2, (now() AT TIME ZONE 'America/Toronto')::date)`, [VERIFY_SEED, `ZZ-TEST-EX-${visa}-999`]);
    const pick = await rank(VERIFY_LISTED, visa, lineOf(VERIFY_SEED, visa));
    const refused = await rank(VERIFY_LISTED, visa, lineOf(VERIFY_SEED_UNLISTED, visa));
    add("rank_exemplars test mode picks only a listed TEST seed",
      pick.exemplar_record_id === VERIFY_SEED && JSON.parse(pick.flags).includes("test_mode") && refused.exemplar_record_id === "none",
      `${visa}: the listed seed answered ${pick.exemplar_record_id}, the unlisted one ${refused.exemplar_record_id}, expected ${VERIFY_SEED} and none`);
    // The newest selection is the refusal (none), so a term in @08 is unexpected and an empty @08 passes the cross-check.
    const validate = async (terms) => (await rows(client, "SELECT * FROM ff13.validate_draft($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
      [VERIFY_LISTED, VERIFY_EXEC, visa, "SUBMISSION-LETTER", "x", "TEST Verify", "x", terms, "", "", "", "", "", "", "", ""]))[0];
    const withTerm = await validate("Verify Term");
    const empty = await validate("");
    const x = (r) => r.detail.hard_fails.map((e) => e.check).filter((c) => c.startsWith("exemplar_"));
    const named = /\nExemplar used: none$/.test(withTerm.review_note);
    add("validate_draft cross-checks @08 against the selection",
      x(withTerm).includes("exemplar_terms_unexpected") && x(empty).length === 0 && named,
      `@08 with a term: ${x(withTerm).join(", ") || "no exemplar check"}, empty @08: ${x(empty).join(", ") || "no exemplar check"}, `
        + `the review note ${named ? "names" : "does not name"} the selection`);
  } catch (e) {
    add("rank_exemplars checks", false, `stopped: ${e.code ? `SQLSTATE ${e.code} ` : ""}${e.message}`);
  } finally {
    if (owned) {
      await client.query("ROLLBACK");
    } else {
      await client.query("ROLLBACK TO SAVEPOINT x32_verify");
      await client.query("RELEASE SAVEPOINT x32_verify");
    }
  }
  return checks;
}

// Both ALWAYS triggers of a table, with the expected timing, events and function, and no WHEN clause or column list.
async function guardTriggers(client, table, fn, rowName, truncName) {
  const trg = await rows(client, `SELECT t.tgname, t.tgenabled,
                                         (t.tgfoid = to_regprocedure($2) AND t.tgqual IS NULL AND t.tgattr = ''::int2vector
                                          AND ((t.tgname = $3 AND t.tgtype = 27) OR (t.tgname = $4 AND t.tgtype = 34))) AS shape
                                    FROM pg_trigger t WHERE t.tgrelid = to_regclass($1) AND NOT t.tgisinternal ORDER BY 1`, [table, fn, rowName, truncName]);
  const good = trg.filter((t) => t.tgenabled === "A" && t.shape).map((t) => t.tgname);
  return [trg.length === 2 && good.length === 2,
    trg.length ? trg.map((t) => `${t.tgname} ${t.tgenabled === "A" ? "enabled always" : `state ${t.tgenabled}`}${t.shape ? "" : ", unexpected definition"}`).join(", ") : "no trigger"];
}

// Each check is [name, ok, detail]. ok null is information only. airtable: { pat, baseId, fetchImpl } for the F-F10
// checkbox read, read from the repo .env and audit/airtable_links.json when not given.
export async function verify(client, { data = true, airtable = {} } = {}) {
  const checks = [];
  const add = (name, ok, detail) => checks.push([name, ok, detail]);
  const m = readJson("law/manifest.json");

  if (data) {
    const inst = await rows(client, "SELECT instrument, source_sha256, current_to::text AS current_to FROM law.instruments ORDER BY 1");
    const extra = inst.filter((r) => !m.instruments.some((i) => i.instrument === r.instrument));
    add("instruments", extra.length === 0, extra.length ? `rows not in law/: ${extra.map((r) => r.instrument).join(", ")}` : "IRPA and IRPR only");
    for (const i of m.instruments) {
      const r = inst.find((x) => x.instrument === i.instrument);
      add(`${i.instrument} source`, !!r && r.source_sha256 === i.source_sha256,
        r ? `source_sha256 ${r.source_sha256 === i.source_sha256 ? "equals" : "differs from"} law/manifest.json, current to ${r.current_to}` : "no row");
      // The database against the committed files, key by key, not only against itself.
      const file = lawRows(i.instrument);
      const [d] = await rows(client, `
        WITH f AS (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]) AS f(key, h, st))
        SELECT
          (SELECT count(*) FROM law.provisions p LEFT JOIN f USING (key)
            WHERE p.instrument = $4 AND p.status <> 'absent'
              AND (f.h IS DISTINCT FROM p.text_sha256 OR f.st IS DISTINCT FROM p.status))::int AS db_only,
          (SELECT count(*) FROM f LEFT JOIN law.provisions p ON p.key = f.key AND p.status <> 'absent'
            WHERE p.text_sha256 IS DISTINCT FROM f.h OR p.status IS DISTINCT FROM f.st)::int AS file_only,
          (SELECT count(*) FROM law.provisions WHERE instrument = $4 AND status = 'absent')::int AS absent`,
        [file.map((r) => r.key), file.map((r) => r.text_sha256), file.map((r) => r.status), i.instrument]);
      add(`${i.instrument} equals law/`, d.db_only === 0 && d.file_only === 0,
        `${file.length} units in law/, ${d.file_only} missing or different in the database, ${d.db_only} live in the database and not in law/, ${d.absent} absent`);
    }
    const [mm] = await rows(client,
      "SELECT count(*)::int AS n FROM law.provisions p WHERE p.status <> 'absent' AND " +
      "encode(sha256(convert_to(law.provision_text(p.key), 'UTF8')), 'hex') IS DISTINCT FROM p.text_sha256");
    add("rendered hashes", mm.n === 0, `${mm.n} units whose law.provision_text() hashes differently`);

    // Every column of every ref row against the committed files.
    const ref = refRows();
    for (const t of REF_TABLES) {
      const want = ref[t.table];
      const got = await rows(client, `SELECT ${selectCols(t)} FROM ref.${t.table}`);
      const byId = new Map(got.map((r) => [rowId(t, r), r]));
      const differ = want.filter((w) => {
        const g = byId.get(rowId(t, w));
        return !g || t.cols.some((c) => !sameCell(c, g[c], w[c]));
      }).map((w) => rowId(t, w));
      const wantIds = new Set(want.map((w) => rowId(t, w)));
      const dbOnly = got.map((g) => rowId(t, g)).filter((id) => !wantIds.has(id));
      add(`${t.table} equals ref/`, differ.length === 0 && dbOnly.length === 0,
        `${want.length} rows in ${refFile(t)}, every column compared, ${differ.length} missing or different${differ.length ? ` (${differ.slice(0, 5).join(", ")})` : ""}, ` +
        `${dbOnly.length} in the database and not in ref/${dbOnly.length ? ` (${dbOnly.slice(0, 5).join(", ")})` : ""}`);
    }
    const dead = await rows(client, `SELECT v.code, p.status FROM ref.visa_types v JOIN law.provisions p ON p.key = v.governing_provision
                                      WHERE p.status <> 'in_force' ORDER BY 1`);
    add("visa_types governing provisions", dead.length === 0,
      dead.length ? `not in force: ${dead.map((r) => `${r.code} (${r.status})`).join(", ")}` : "every governing_provision is in force in law.provisions");
    const mapDead = await rows(client, `SELECT m.document_type, m.visa_code, m.provision_key, p.status FROM ref.citation_map m
                                         JOIN law.provisions p ON p.key = m.provision_key WHERE p.status <> 'in_force' ORDER BY 1, 2, 3`);
    add("citation_map provisions", mapDead.length === 0,
      mapDead.length ? `not in force: ${mapDead.map((r) => `${r.document_type} ${r.visa_code} ${r.provision_key} (${r.status})`).join(", ")}` : "every mapped provision is in force in law.provisions");

    // The drafting gate over every pair the catalogue defines, and the promise that a refused pair injects nothing.
    const gate = await rows(client, `
      SELECT v.code AS visa_code, d.code AS document_type, g.allowed, g.reason, cardinality(g.provision_keys) AS n,
             (SELECT count(*) FROM ref.citation_context(v.code, d.code))::int AS ctx
        FROM ref.visa_types v CROSS JOIN ref.document_types d
        CROSS JOIN LATERAL ref.drafting_gate(v.code, d.code) g
       WHERE d.restricted_to_visa_code IS NULL OR d.restricted_to_visa_code = v.code`);
    const leaks = gate.filter((g) => (!g.allowed && g.ctx > 0) || (g.allowed && g.ctx !== g.n));
    add("drafting gate injects only what it allows", leaks.length === 0,
      leaks.length ? `context differs from the gate: ${leaks.map((g) => `${g.document_type} ${g.visa_code}`).join(", ")}`
        : `${gate.length} pairs checked, a refused pair returns no context`);
    const reasons = {};
    for (const g of gate) reasons[g.reason] = (reasons[g.reason] || 0) + 1;
    const [st] = await rows(client, `
      SELECT count(*) FILTER (WHERE reviewed_by_licence IS NULL)::int AS unreviewed, count(*)::int AS total FROM ref.citation_map`);
    add("drafting gate", null, `${gate.filter((g) => g.allowed).length} of ${gate.length} pairs allowed (` +
      Object.entries(reasons).map(([r, n]) => `${n} ${r}`).join(", ") + `), ${st.unreviewed} of ${st.total} mapping rows unreviewed`);

    // The prompts registry (X-36.1): every stored template hashes to its template_sha256, read back from the database.
    const prompts = await rows(client, "SELECT stage, version, model, template, template_sha256 FROM ref.prompts ORDER BY 1, 2");
    const badPrompt = prompts.filter((p) => sha256Hex(canonicalJson(p.template)) !== p.template_sha256 || p.model !== p.template.model)
      .map((p) => `${p.stage}@${p.version}`);
    add("prompt hashes", badPrompt.length === 0,
      badPrompt.length ? `stored template does not hash to its template_sha256 or model: ${badPrompt.join(", ")}`
        : `${prompts.length} versions, every stored template recomputes to its SHA-256`);

    checks.push(await syntheticCheck(client, airtable));
    for (const c of await ff10Checks(client)) checks.push(c);
    checks.push(await x32SeedCheck(client, airtable));
    for (const c of await x32Checks(client)) checks.push(c);
  }

  // Every table, sequence, view and function in law, ref and ff13, for every API role, column grants included. Any
  // privilege at all is a FAIL.
  const present = (await rows(client, "SELECT rolname FROM pg_roles WHERE rolname = ANY($1)", [ROLES])).map((r) => r.rolname);
  const objs = await rows(client, `
    SELECT CASE WHEN c.relkind = 'S' THEN 'sequence' ELSE 'table' END AS kind, c.oid::regclass::text AS name FROM pg_class c
     WHERE c.relnamespace::regnamespace::text = ANY($1) AND c.relkind IN ('r', 'v', 'm', 'p', 'S')
    UNION ALL
    SELECT 'function', p.oid::regprocedure::text FROM pg_proc p WHERE p.pronamespace::regnamespace::text = ANY($1)
    ORDER BY 1, 2`, [SCHEMAS]);
  const privileges = async (role) => {
    const hits = [];
    for (const s of SCHEMAS) {
      const [x] = await rows(client, "SELECT has_schema_privilege($1, $2, 'USAGE') AS u, has_schema_privilege($1, $2, 'CREATE') AS c", [role, s]);
      if (x.u) hits.push(`usage on ${s}`);
      if (x.c) hits.push(`create on ${s}`);
    }
    for (const o of objs) {
      const [x] = await rows(client, PRIV_SQL[o.kind], [role, o.name]);
      if (x.h) hits.push(o.name);
    }
    return hits;
  };
  for (const role of ROLES) {
    if (!present.includes(role)) {
      add(`${role} access`, null, "role does not exist here");
      continue;
    }
    const hits = await privileges(role);
    add(`${role} access`, hits.length === 0,
      hits.length ? `has ${hits.join(", ")}` : `none on schemas ${SCHEMAS.join(", ")} and their ${objs.length} tables, sequences and functions`);
  }

  // The Make role: exactly USAGE on ff13 and EXECUTE on the validator, the F-F10 grounding call and the X-32 ranker, no attribute, membership or setting that
  // widens it, and nothing it can use anywhere else (a PUBLIC grant reaches it too).
  const [mr] = await rows(client, `SELECT rolcanlogin, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,
                                          rolconnlimit, rolvaliduntil::text AS until,
                                          (SELECT array_agg(m.roleid::regrole::text) FROM pg_auth_members m WHERE m.member = r.oid) AS member_of
                                     FROM pg_roles r WHERE rolname = $1`, [MAKE_ROLE]);
  if (!mr) {
    add(`${MAKE_ROLE} role`, false, "does not exist, run --push");
  } else {
    const wide = ["rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"].filter((a) => mr[a]);
    add(`${MAKE_ROLE} role`, wide.length === 0 && !mr.member_of && mr.rolconnlimit === 5,
      `${wide.length ? `has ${wide.join(", ")}, ` : ""}member of ${mr.member_of ? mr.member_of.join(", ") : "no role"}, connection limit ${mr.rolconnlimit}, expected 5`);
    add(`${MAKE_ROLE} login`, null, mr.rolcanlogin ? `can log in${mr.until ? `, valid until ${mr.until}` : ""}` : "NOLOGIN, run scripts/law_load/make_role.mjs before Make connects");
    // The role-wide settings, and no per-database override that would replace them.
    const rs = await rows(client, `SELECT s.setdatabase::int AS db, cfg FROM pg_db_role_setting s, unnest(s.setconfig) cfg
                                    WHERE s.setrole = to_regrole($1) ORDER BY 1, 2`, [MAKE_ROLE]);
    const roleWide = rs.filter((r) => r.db === 0).map((r) => r.cfg);
    const perDb = rs.filter((r) => r.db !== 0).map((r) => r.cfg);
    add(`${MAKE_ROLE} timeouts`, perDb.length === 0 && roleWide.length === MAKE_ROLE_SETTINGS.length && MAKE_ROLE_SETTINGS.every((w) => roleWide.includes(w)),
      `${roleWide.join(", ") || "no role-wide setting"}${perDb.length ? `, per-database ${perDb.join(", ")}` : ""}, expected exactly ${MAKE_ROLE_SETTINGS.join(", ")}`);
    const hits = await privileges(MAKE_ROLE);
    const want = ["usage on ff13", ...MAKE_FUNCTIONS];
    add(`${MAKE_ROLE} access`, hits.length === want.length && want.every((w) => hits.includes(w)),
      `has ${hits.join(", ") || "nothing"}, expected exactly ${want.join(", ")}`);
    // Outside law, ref and ff13: a table or sequence counts only where the role also has the schema's USAGE, since
    // a grant it cannot reach is no access (pg_stat_statements grants SELECT to PUBLIC in a schema it cannot use).
    const elsewhere = await rows(client, `
      SELECT c.oid::regclass::text AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f', 'S') AND n.nspname <> ALL($2) AND n.nspname NOT IN ('pg_catalog', 'information_schema')
         AND left(n.nspname, 3) <> 'pg_' AND has_schema_privilege($1, n.oid, 'USAGE')
         AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege($1, c.oid, 'USAGE, SELECT, UPDATE')
                  ELSE has_table_privilege($1, c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                       OR has_any_column_privilege($1, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES') END
       ORDER BY 1`, [MAKE_ROLE, SCHEMAS]);
    add(`${MAKE_ROLE} tables elsewhere`, elsewhere.length === 0,
      elsewhere.length ? `can use ${elsewhere.slice(0, 10).map((r) => r.name).join(", ")}${elsewhere.length > 10 ? ` and ${elsewhere.length - 10} more` : ""}`
        : "no table or sequence it can use (schema USAGE plus a grant) in any non-system schema");
    const fns = await rows(client, `
      SELECT p.oid::regprocedure::text AS name, p.prosecdef, p.prorettype::regtype::text AS rettype, p.proconfig
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname <> ALL($2) AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
         AND has_schema_privilege($1, n.oid, 'USAGE') AND has_function_privilege($1, p.oid, 'EXECUTE')
       ORDER BY p.prosecdef DESC, 1`, [MAKE_ROLE, SCHEMAS]);
    // A trigger or event-trigger function cannot be called directly ("trigger functions can only be called as
    // triggers", measured). Supabase's own public.rls_auto_enable() (the ensure_rls event trigger) is one: it runs as
    // postgres on every CREATE TABLE, temporary tables included, so it is listed as INFO with its search_path.
    const isTrigger = (f) => f.rettype === "trigger" || f.rettype === "event_trigger";
    const definersElsewhere = fns.filter((f) => f.prosecdef && !isTrigger(f)).map((f) => f.name);
    add(`${MAKE_ROLE} definer functions elsewhere`, definersElsewhere.length === 0,
      definersElsewhere.length ? `can execute ${definersElsewhere.slice(0, 10).join(", ")}${definersElsewhere.length > 10 ? ` and ${definersElsewhere.length - 10} more` : ""}`
        : `none it can call, ${fns.filter((f) => !f.prosecdef).length} invoker function(s) it can execute run with its own privileges`);
    const trigDefiners = fns.filter((f) => f.prosecdef && isTrigger(f));
    if (trigDefiners.length) {
      add(`${MAKE_ROLE} trigger definers elsewhere`, null,
        `${trigDefiners.map((f) => `${f.name} (${f.rettype}, ${(f.proconfig || []).join(", ") || "no settings"})`).join(", ")}, not callable directly`);
    }
    const schemas = await rows(client, `
      SELECT n.nspname AS name, has_schema_privilege($1, n.oid, 'CREATE') AS c FROM pg_namespace n
       WHERE n.nspname <> ALL($2) AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
         AND (has_schema_privilege($1, n.oid, 'USAGE') OR has_schema_privilege($1, n.oid, 'CREATE')) ORDER BY 1`, [MAKE_ROLE, SCHEMAS]);
    const creatable = schemas.filter((s) => s.c).map((s) => s.name);
    add(`${MAKE_ROLE} schemas elsewhere`, creatable.length === 0,
      `${creatable.length ? `CREATE on ${creatable.join(", ")}, ` : ""}USAGE on ${schemas.map((s) => s.name).join(", ") || "none"}`);
    const [dbp] = await rows(client, `SELECT has_database_privilege($1, current_database(), 'CREATE') AS c,
                                             has_database_privilege($1, current_database(), 'TEMPORARY') AS t`, [MAKE_ROLE]);
    add(`${MAKE_ROLE} database privileges`, !dbp.c,
      `CREATE ${dbp.c ? "yes" : "no"}, TEMPORARY ${dbp.t ? "yes (through PUBLIC, harmless while every law, ref and ff13 function lists pg_temp last and no table it reaches grants TRIGGER)" : "no"}`);
    // Large objects persist outside any schema. Make only executes the validator, so the role never owns one, and on
    // Supabase postgres cannot revoke PUBLIC EXECUTE on the lo_* functions, so ownership is the check.
    const [lo] = await rows(client, `
      SELECT count(*) FILTER (WHERE m.lomowner = to_regrole($1))::int AS owned,
             count(*) FILTER (WHERE m.lomowner <> to_regrole($1) AND EXISTS (
               SELECT 1 FROM aclexplode(m.lomacl) a WHERE a.grantee IN (0, to_regrole($1)::oid)))::int AS granted,
             current_setting('lo_compat_privileges') AS compat
        FROM pg_largeobject_metadata m`, [MAKE_ROLE]);
    add(`${MAKE_ROLE} large objects`, lo.owned === 0 && lo.granted === 0 && lo.compat === "off",
      `${lo.owned} owned, ${lo.granted} granted to it or to PUBLIC, lo_compat_privileges ${lo.compat}, expected 0, 0 and off`);
    const [lf] = await rows(client, "SELECT has_function_privilege($1, 'pg_catalog.lo_from_bytea(oid,bytea)', 'EXECUTE') AS x", [MAKE_ROLE]);
    add(`${MAKE_ROLE} large-object functions`, null, lf.x
      ? "EXECUTE on lo_create, lo_from_bytea, lo_put and lo_get through PUBLIC, not revocable by postgres on Supabase, so any large object it owns FAILs above"
      : "no EXECUTE on the lo_* functions");
  }
  // Every function in law, ref and ff13 runs with search_path pg_catalog, pg_temp, because the validator runs them as
  // the owner and an empty path searches pg_temp first (review 2026-11-03). Only the three Make functions are definers.
  const fcfg = await rows(client, `SELECT p.oid::regprocedure::text AS name, p.prosecdef, p.proconfig FROM pg_proc p
                                    WHERE p.pronamespace::regnamespace::text = ANY($1) ORDER BY 1`, [SCHEMAS]);
  const badPath = fcfg.filter((f) => JSON.stringify(f.proconfig || []) !== JSON.stringify([SEARCH_PATH])).map((f) => f.name);
  add("function search_path", badPath.length === 0,
    badPath.length ? `not exactly ${SEARCH_PATH}: ${badPath.join(", ")}` : `all ${fcfg.length} functions set ${SEARCH_PATH} and nothing else`);
  const definers = fcfg.filter((f) => f.prosecdef).map((f) => f.name);
  add("Make function definers", definers.length === MAKE_FUNCTIONS.length && MAKE_FUNCTIONS.every((f) => definers.includes(f)),
    `security definer: ${definers.join(", ") || "none"}, expected exactly ${MAKE_FUNCTIONS.join(", ")}`);
  // Both triggers ENABLE ALWAYS (they fire under session_replication_role = replica), with the expected timing,
  // events and function, and no WHEN clause or column list.
  add("ledger append-only", ...await guardTriggers(client, "ff13.validations", "ff13.validations_append_only()", "validations_append_only", "validations_no_truncate"));
  add("groundings append-only", ...await guardTriggers(client, "ff13.groundings", "ff13.groundings_append_only()", "groundings_append_only", "groundings_no_truncate"));
  add("test records retired, never deleted", ...await guardTriggers(client, "ref.test_records", "ref.test_records_retire_only()", "test_records_retire_only", "test_records_no_truncate"));
  add("selections append-only", ...await guardTriggers(client, "ff13.selections", "ff13.selections_append_only()", "selections_append_only", "selections_no_truncate"));
  add("TEST seeds retired, never deleted", ...await guardTriggers(client, "ref.exemplar_test_seeds", "ref.exemplar_test_seeds_retire_only()",
    "exemplar_test_seeds_retire_only", "exemplar_test_seeds_no_truncate"));
  // The prompts registry's versions are immutable the same way (X-36.1).
  const ptrg = await rows(client, `SELECT t.tgname, t.tgenabled,
                                          (t.tgfoid = to_regprocedure('ref.prompts_immutable()') AND t.tgqual IS NULL AND t.tgattr = ''::int2vector
                                           AND ((t.tgname = 'prompts_immutable' AND t.tgtype = 27) OR (t.tgname = 'prompts_no_truncate' AND t.tgtype = 34))) AS shape
                                     FROM pg_trigger t WHERE t.tgrelid = to_regclass('ref.prompts') AND NOT t.tgisinternal ORDER BY 1`);
  const pgood = ptrg.filter((t) => t.tgenabled === "A" && t.shape).map((t) => t.tgname);
  add("prompt versions immutable", ptrg.length === 2 && pgood.length === 2,
    ptrg.length ? ptrg.map((t) => `${t.tgname} ${t.tgenabled === "A" ? "enabled always" : `state ${t.tgenabled}`}${t.shape ? "" : ", unexpected definition"}`).join(", ") : "no trigger");
  const [lr] = await rows(client, "SELECT count(*)::int AS n, max(validated_at)::text AS last FROM ff13.validations");
  add("ledger rows", null, `${lr.n} validation row(s)${lr.last ? `, last ${lr.last}` : ""}`);
  const [gr] = await rows(client, `SELECT count(*)::int AS n, count(*) FILTER (WHERE gate_mode = 'test')::int AS t, max(grounded_at)::text AS last
                                     FROM ff13.groundings`);
  add("grounding rows", null, `${gr.n} grounding row(s), ${gr.t} in test mode${gr.last ? `, last ${gr.last}` : ""}`);
  const [sr] = await rows(client, `SELECT count(*)::int AS n, count(*) FILTER (WHERE exemplar_record_id IS NOT NULL)::int AS p,
                                          count(*) FILTER (WHERE gate_mode = 'test')::int AS t, max(selected_at)::text AS last FROM ff13.selections`);
  add("selection rows", null, `${sr.n} selection row(s), ${sr.p} with a pick, ${sr.t} in test mode${sr.last ? `, last ${sr.last}` : ""}`);

  // Owners and grants, column and sequence grants included.
  const acl = await rows(client, `
    SELECT 'schema ' || n.nspname AS obj, n.nspowner::regrole::text AS owner,
           (SELECT array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
              FROM aclexplode(n.nspacl) a WHERE a.grantee <> n.nspowner) AS grantees, NULL::bool AS rls
      FROM pg_namespace n WHERE n.nspname = ANY($1)
    UNION ALL
    SELECT CASE c.relkind WHEN 'S' THEN 'sequence ' ELSE 'table ' END || c.relnamespace::regnamespace::text || '.' || c.relname, c.relowner::regrole::text,
           (SELECT array_agg(DISTINCT CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE g.grantee::regrole::text END)
              FROM (SELECT a.grantee FROM aclexplode(c.relacl) a
                    UNION SELECT a.grantee FROM pg_attribute t, aclexplode(t.attacl) a WHERE t.attrelid = c.oid AND t.attnum > 0) g
             WHERE g.grantee <> c.relowner),
           CASE WHEN c.relkind = 'r' THEN c.relrowsecurity END
      FROM pg_class c WHERE c.relnamespace::regnamespace::text = ANY($1) AND c.relkind IN ('r', 'S')
    UNION ALL
    SELECT 'function ' || p.pronamespace::regnamespace::text || '.' || p.proname, p.proowner::regrole::text,
           (SELECT array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
              FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee <> p.proowner), NULL
      FROM pg_proc p WHERE p.pronamespace::regnamespace::text = ANY($1)
    ORDER BY 1`, [SCHEMAS]);
  const owners = new Set(acl.map((r) => r.owner));
  add("owner", owners.size === 1 && owners.has("postgres"), `${SCHEMAS.join(", ")} objects owned by ${[...owners].join(", ")}`);
  for (const s of SCHEMAS) {
    if (!acl.some((r) => r.obj === `schema ${s}`)) add(`schema ${s}`, false, "does not exist, run --push");
  }
  for (const r of acl) {
    const g = r.grantees || [];
    const want = EXPECTED_GRANTS[r.obj] || [];
    const same = g.length === want.length && want.every((w) => g.includes(w));
    add(`${r.obj} grants`, same, g.length ? `granted to ${g.join(", ")}${same ? "" : `, expected ${want.join(", ") || "owner only"}`}` : want.length ? `owner only, expected ${want.join(", ")}` : "owner only");
    if (r.rls !== null) add(`${r.obj} RLS`, r.rls === true, r.rls ? "enabled, no policy needed" : "disabled");
  }
  const defacl = await rows(client, "SELECT count(*)::int AS n FROM pg_default_acl WHERE defaclnamespace::regnamespace::text = ANY($1)", [SCHEMAS]);
  add(`default privileges scoped to ${SCHEMAS.join(", ")}`, defacl[0].n === 0, `${defacl[0].n} entries`);

  // Any pgrst.db_schemas setting on the authenticator role, for every database, so a per-database override that
  // lists law cannot hide behind a role-wide one. Hosted Supabase usually sets none here (the dashboard holds it).
  const pgrst = await rows(client, `
    SELECT cfg FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole, unnest(s.setconfig) cfg
     WHERE r.rolname = 'authenticator' AND cfg LIKE 'pgrst.db_schemas=%'`);
  if (pgrst.length) {
    const lists = pgrst.map((r) => r.cfg.slice(r.cfg.indexOf("=") + 1).split(",").map((s) => s.trim()));
    add("Data API exposed schemas", !lists.some((l) => SCHEMAS.some((s) => l.includes(s))), lists.map((l) => l.join(", ")).join(" | "));
  } else {
    add("Data API exposed schemas", null, "no override on the authenticator role, check Project Settings, Data API, Exposed schemas");
  }
  const evt = await rows(client, "SELECT evtname FROM pg_event_trigger ORDER BY 1");
  add("event triggers", null, evt.map((r) => r.evtname).join(", ") || "none");
  const hist = await rows(client, "SELECT to_regclass('supabase_migrations.schema_migrations') IS NOT NULL AS has");
  const versions = committedMigrations().map((f) => f.split("_")[0]);
  if (hist[0].has) {
    const got = (await rows(client, "SELECT version FROM supabase_migrations.schema_migrations")).map((r) => r.version);
    const missing = versions.filter((v) => !got.includes(v));
    add("migration history", missing.length === 0, missing.length ? `not recorded: ${missing.join(", ")}` : `${versions.join(", ")} recorded`);
  } else {
    add("migration history", null, "no supabase_migrations table here");
  }
  return checks;
}

function committedMigrations() {
  return execFileSync("git", ["ls-tree", "--name-only", "HEAD", `${MIGRATIONS_DIR}/`], { cwd: ROOT })
    .toString().split("\n").filter((p) => p.endsWith(".sql")).map((p) => path.posix.basename(p));
}

function npxCli() {
  const p = path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npx-cli.js");
  if (!fs.existsSync(p)) throw new Refusal("npx-cli.js not found next to node");
  return p;
}

function push(config, { dryRun, local }) {
  // A real target gets the committed HEAD. A local rehearsal gets the working tree, to test a migration before
  // it is committed.
  const files = local
    ? fs.readdirSync(path.join(ROOT, MIGRATIONS_DIR)).filter((f) => f.endsWith(".sql")).sort()
    : committedMigrations();
  const read = (f) => local
    ? fs.readFileSync(path.join(ROOT, MIGRATIONS_DIR, f))
    : execFileSync("git", ["show", `HEAD:${MIGRATIONS_DIR}/${f}`], { cwd: ROOT });
  if (!files.length) throw new Refusal(`no migrations in ${MIGRATIONS_DIR}`);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "immi-os-push-"));
  try {
    const dir = path.join(work, "supabase", "migrations");
    fs.mkdirSync(dir, { recursive: true });
    for (const f of files) {
      fs.writeFileSync(path.join(dir, f), read(f));
    }
    const dbUrl = `postgresql://${encodeURIComponent(config.user)}@${config.host}:${config.port}/${encodeURIComponent(config.database)}`;
    const env = { ...process.env, SUPABASE_TELEMETRY_DISABLED: "1", PGPASSWORD: config.password };
    for (const k of [...ENV_KEYS, ...AIRTABLE_KEYS]) delete env[k];
    if (local) {
      env.PGSSLMODE = "disable";
    } else {
      env.PGSSLMODE = "verify-full";
      env.PGSSLROOTCERT = config.caPath;
    }
    console.log(`push ${files.join(", ")} from ${local ? "the working tree" : "HEAD"} with ${SUPABASE_CLI}${dryRun ? " (dry run)" : ""}`);
    const args = [npxCli(), "--yes", SUPABASE_CLI, "db", "push", "--db-url", dbUrl, "--workdir", work, dryRun ? "--dry-run" : "--yes"];
    const r = spawnSync(process.execPath, args, { cwd: work, env, stdio: "inherit" });
    if (r.error) throw r.error;
    return r.status === 0 ? 0 : 1;
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

function report(checks) {
  let failed = 0;
  for (const [name, ok, detail] of checks) {
    const tag = ok === null ? "INFO" : ok ? "PASS" : "FAIL";
    if (ok === false) failed++;
    console.log(`${tag.padEnd(4)}  ${name}: ${detail}`);
  }
  return failed;
}

async function main(argv) {
  const { mode, dryRun } = parseArgs(argv);
  const local = process.env.LAW_LOAD_LOCAL === "1";
  const config = connectionConfig(readEnv(), { local });
  // A local rehearsal may test uncommitted changes. A real target only ever gets committed files.
  if (!local && (mode === "--push" || mode === "--check" || mode === "--load")) gitClean();
  console.log(`target ${config.host}:${config.port}/${config.database}${local ? " (local, no TLS)" : " (TLS verified against SUPABASE_DB_CA)"}`);
  if (mode === "--push") return push(config, { dryRun, local });
  const seed = mode === "--check" || mode === "--load" ? seedSql() : null;
  const ref = seed ? refRows() : null;

  const { caPath, ...pgConfig } = config;
  const client = new pg.Client(pgConfig);
  let lost = null;
  client.on("error", (e) => { lost = e; });
  await client.connect();
  try {
    await client.query("SET statement_timeout = '15min'");
    const [info] = await rows(client, "SELECT current_setting('server_version') AS v");
    // Every table the load and verify touch, so a database one migration behind is refused with a reason instead of
    // crashing halfway through verify (review 2026-11-02).
    const tables = ["law.provisions", ...REF_TABLES.map((t) => `ref.${t.table}`), "ff13.validations", "ff13.groundings", "ff13.selections"];
    const exist = await rows(client, "SELECT t AS name, to_regclass(t) IS NOT NULL AS ok FROM unnest($1::text[]) t", [tables]);
    console.log(`PASS  connection: ${local ? "plaintext to localhost" : "TLS verified"}, password accepted, Postgres ${info.v}`);
    if (mode === "--ping") {
      console.log(`INFO  ${exist.map((e) => `${e.name} ${e.ok ? "exists" : "does not exist yet"}`).join(", ")}`);
      return 0;
    }
    const missing = exist.filter((e) => !e.ok).map((e) => e.name);
    if (missing.length) throw new Refusal(`${missing.join(", ")} ${missing.length > 1 ? "do" : "does"} not exist. Run --push first`);
    if (seed) {
      const t = Date.now();
      try {
        await client.query(seed.head);
        await upsertRef(client, ref);
        await client.query(seed.tail);
        const problems = await refGate(client, ref);
        if (problems.length) {
          await client.query("ROLLBACK");
          for (const p of problems) console.log(`FAIL  ref gate: ${p}`);
          console.log("FAIL  load: the ref gate refused it. Rolled back, nothing committed");
          return 1;
        }
        await client.query(mode === "--check" ? "ROLLBACK" : "COMMIT");
      } catch (e) {
        if (!lost && typeof e.code === "string" && /^[0-9A-Z]{5}$/.test(e.code)) {
          await client.query("ROLLBACK").catch(() => {});
          console.log(`FAIL  load: ${e.message} (SQLSTATE ${e.code}). Rolled back, nothing committed`);
          return 1;
        }
        console.log(`FAIL  load: connection lost (${(lost || e).message}). Commit state unknown, run --verify-only`);
        return 3;
      }
      console.log(`${mode === "--check" ? "PASS  check: the full law and ref load, their constraints and gates ran, then rolled back" : "PASS  load: law and ref committed after the constraints and both gates"} (${Date.now() - t} ms)`);
    }
    const failed = report(await verify(client, { data: mode !== "--check" }));
    console.log(failed ? `${failed} check(s) failed` : "all checks passed");
    return failed ? 1 : 0;
  } finally {
    await client.end().catch(() => {});
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(e instanceof Refusal ? `refused: ${e.message}` : `error: ${e.message}`);
      process.exit(2);
    },
  );
}
