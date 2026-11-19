// X-36.1 regression suite: the prompts registry on PGlite (Postgres 18), with the committed migrations, law/ and ref/
// loaded the way load.mjs loads them. The prompt templates are product text with mappings unfilled, no client data.
//
//   cd scripts/law_load && node --test prompts.test.mjs

import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { seedSql, refRows, upsertRef, refGate, canonicalJson, sha256Hex } from "./load.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MIG = path.join(ROOT, "supabase", "migrations");
let db;
let ref;
const client = () => ({ query: (sql, params) => db.query(sql, params ?? []) });
const q = async (sql, params = []) => (await db.query(sql, params)).rows;
const clone = (x) => JSON.parse(JSON.stringify(x));

// Runs a load of the given ref data inside a transaction that is rolled back, and returns the gate's problems.
async function gateFor(data) {
  await db.exec("BEGIN");
  try {
    await upsertRef(client(), data);
    await db.exec("SET CONSTRAINTS ALL IMMEDIATE");
    return await refGate(client(), data);
  } finally {
    await db.exec("ROLLBACK");
  }
}

before(async () => {
  db = await PGlite.create();
  await db.exec("CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;");
  for (const f of fs.readdirSync(MIG).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(fs.readFileSync(path.join(MIG, f), "utf8"));
  }
  ref = refRows();
  const seed = seedSql();
  await db.exec(seed.head);
  await upsertRef(client(), ref);
  await db.exec(seed.tail);
  assert.deepEqual(await refGate(client(), ref), []);
  await db.exec("COMMIT");
});

test("the registry equals ref/ and every hash agrees between Python and JS", async () => {
  const rows = await q("SELECT stage, version, model, template, template_sha256 FROM ref.prompts ORDER BY 1, 2");
  assert.equal(rows.length, ref.prompts.length);
  for (const r of ref.prompts) {
    // template_sha256 was written by scripts/prompt_registry.py (Python), and the JS canonical form must give the same digest.
    assert.equal(sha256Hex(canonicalJson(r.template)), r.template_sha256, `${r.stage}@${r.version}`);
    const g = rows.find((x) => x.stage === r.stage && x.version === r.version);
    assert.ok(g, `${r.stage}@${r.version} loaded`);
    assert.equal(canonicalJson(g.template), canonicalJson(r.template), `${r.stage}@${r.version} template round-trips through jsonb`);
    assert.equal(sha256Hex(canonicalJson(g.template)), g.template_sha256);
  }
  const b = await q("SELECT count(*)::int AS n FROM ref.prompt_bindings");
  assert.equal(b[0].n, ref.prompt_bindings.length);
});

test("a registered version cannot be updated, deleted or truncated, also in replica mode", async () => {
  const [{ stage, version }] = ref.prompts;
  for (const mode of ["origin", "replica"]) {
    await db.exec(`SET session_replication_role = ${mode}`);
    try {
      await assert.rejects(q("UPDATE ref.prompts SET description = 'Something else entirely' WHERE stage = $1 AND version = $2", [stage, version]), /immutable/);
      await assert.rejects(q("DELETE FROM ref.prompts WHERE stage = $1 AND version = $2", [stage, version]), /immutable/);
      await assert.rejects(q("TRUNCATE ref.prompts CASCADE"), /immutable/);
    } finally {
      await db.exec("RESET session_replication_role");
    }
  }
});

test("the loader refuses an edited version and keeps the stored one", async () => {
  const data = clone(ref);
  data.prompts[0].template.system = `${data.prompts[0].template.system} (edited)`;
  data.prompts[0].template_sha256 = sha256Hex(canonicalJson(data.prompts[0].template));
  const problems = await gateFor(data);
  assert.ok(problems.some((p) => p.includes("differ from the registered version") && p.includes(`${data.prompts[0].stage} | 1`)), problems.join("\n"));
  const [stored] = await q("SELECT template_sha256 FROM ref.prompts WHERE stage = $1 AND version = 1", [data.prompts[0].stage]);
  assert.equal(stored.template_sha256, ref.prompts[0].template_sha256);
});

test("the loader refuses a version dropped from the file, a wrong hash and a model that is not the template's", async () => {
  const dropped = clone(ref);
  const gone = dropped.prompts.pop();
  dropped.prompt_bindings = dropped.prompt_bindings.filter((b) => !(b.stage === gone.stage && b.version === gone.version));
  assert.ok((await gateFor(dropped)).some((p) => p.includes("prompts in the database and not in") && p.includes(gone.stage)));

  const hash = clone(ref);
  hash.prompts.push({ ...clone(ref.prompts[0]), version: 2, template_sha256: "0".repeat(64) });
  assert.ok((await gateFor(hash)).some((p) => p.includes("template_sha256 or model does not match")));

  // A model column that is not the template's model is refused by the table itself (CHECK), before the gate runs.
  const model = clone(ref);
  model.prompts.push({ ...clone(ref.prompts[0]), version: 2, model: "claude-other-model" });
  await db.exec("BEGIN");
  try {
    await assert.rejects(upsertRef(client(), model), (e) => e.code === "23514");
  } finally {
    await db.exec("ROLLBACK");
  }
});

test("a new version loads beside the old one, and the binding moves to it", async () => {
  const data = clone(ref);
  const v2 = clone(ref.prompts[0]);
  v2.version = 2;
  v2.template.system = `${v2.template.system} (v2)`;
  v2.template_sha256 = sha256Hex(canonicalJson(v2.template));
  data.prompts.push(v2);
  const bind = data.prompt_bindings.find((b) => b.stage === v2.stage);
  bind.version = 2;
  await db.exec("BEGIN");
  try {
    await upsertRef(client(), data);
    await db.exec("SET CONSTRAINTS ALL IMMEDIATE");
    assert.deepEqual(await refGate(client(), data), []);
    const versions = await q("SELECT version FROM ref.prompts WHERE stage = $1 ORDER BY 1", [v2.stage]);
    assert.deepEqual(versions.map((r) => r.version), [1, 2]);
    const [b] = await q("SELECT version FROM ref.prompt_bindings WHERE scenario_id = $1 AND module_id = $2", [bind.scenario_id, bind.module_id]);
    assert.equal(b.version, 2);
  } finally {
    await db.exec("ROLLBACK");
  }
});

test("a binding to an unregistered version is refused by the foreign key", async () => {
  const data = clone(ref);
  data.prompt_bindings[0].version = 99;
  await db.exec("BEGIN");
  try {
    await assert.rejects(upsertRef(client(), data), (e) => e.code === "23503");
  } finally {
    await db.exec("ROLLBACK");
  }
});

test("the API roles hold nothing on the registry", async () => {
  for (const role of ["anon", "authenticated", "service_role"]) {
    for (const t of ["ref.prompts", "ref.prompt_bindings"]) {
      const [x] = await q("SELECT has_table_privilege($1, $2, 'SELECT, INSERT, UPDATE, DELETE') AS h", [role, t]);
      assert.equal(x.h, false, `${role} on ${t}`);
    }
  }
  const [p] = await q("SELECT proconfig FROM pg_proc WHERE oid = 'ref.prompts_immutable()'::regprocedure");
  assert.deepEqual(p.proconfig, ["search_path=pg_catalog, pg_temp"]);
});

test("review: a second version with the same template is refused by the table", async () => {
  const data = clone(ref);
  data.prompts.push({ ...clone(ref.prompts[0]), version: 2 });
  await db.exec("BEGIN");
  try {
    await assert.rejects(upsertRef(client(), data), (e) => e.code === "23505");
  } finally {
    await db.exec("ROLLBACK");
  }
});

test("review: verify reads a BIGINT scenario_id beyond 2^31 - 1 without crashing", async () => {
  const { verify } = await import("./load.mjs");
  await db.exec("BEGIN");
  try {
    const [b] = ref.prompt_bindings;
    await q("INSERT INTO ref.prompt_bindings (scenario_id, module_id, stage, version) VALUES (3000000000, $1, $2, $3)", [b.module_id, b.stage, b.version]);
    const checks = await verify(client());
    const row = checks.find(([name]) => name === "prompt_bindings equals ref/");
    assert.ok(row, "the bindings row is reported");
    assert.equal(row[1], false, "the extra binding is a FAIL, not a crash");
    assert.match(row[2], /3000000000/);
  } finally {
    await db.exec("ROLLBACK");
  }
});
