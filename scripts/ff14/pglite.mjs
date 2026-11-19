// F-F14 development database: PGlite (Postgres 18) with the committed migrations, law/ and ref/, loaded the way
// scripts/law_load loads them (ff13_2.test.mjs). A throwaway in-memory database, so its one COMMIT (the seed) commits
// nothing anywhere else. For the harness's tests and --dry-run only, never for a reported result: the decision is "the
// same Supabase functions", and PGlite may differ from the live server in regex and collation behaviour.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { refRows, refGate, seedSql, upsertRef } from "../law_load/load.mjs";
import { ROOT } from "./chain.mjs";
import { LAW_LOAD } from "./db.mjs";
import { Refusal } from "./iml.mjs";

export async function pgliteClient() {
  const { PGlite } = await import(pathToFileURL(path.join(LAW_LOAD, "node_modules", "@electric-sql", "pglite", "dist", "index.js")).href);
  const db = await PGlite.create();
  await db.exec(`CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;
                 CREATE ROLE authenticator NOINHERIT;`);
  const mig = path.join(ROOT, "supabase", "migrations");
  for (const f of fs.readdirSync(mig).filter((f) => f.endsWith(".sql")).sort()) await db.exec(fs.readFileSync(path.join(mig, f), "utf8"));
  const client = { query: (sql, params) => db.query(sql, params ?? []), end: () => db.close(), pglite: db };
  const seed = seedSql();
  const ref = refRows();
  await db.exec(seed.head);
  await upsertRef(client, ref);
  await db.exec(seed.tail);
  const problems = await refGate(client, ref);
  if (problems.length) throw new Refusal(`PGlite ref gate: ${problems.join("; ")}`);
  await db.exec("COMMIT");
  return client;
}
