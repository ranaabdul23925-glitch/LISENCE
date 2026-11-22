"use strict";

// ShopPOS license server -- SQLite to PostgreSQL migration utility.
//
// Safely copies a SQLite license database (sql.js/WASM file) into a fresh or
// empty PostgreSQL database. Designed for the intended future
// Supabase/PostgreSQL architecture while the SQLite service remains active.
//
// Safety guarantees:
//  * The source SQLite database is opened read-only and is NEVER modified.
//  * All PostgreSQL writes run inside a single transaction; on any failure
//    the transaction is rolled back so PostgreSQL is left unchanged.
//  * A dry-run mode reports what would be migrated without writing anything.
//  * Validation runs before and after migration: required source tables,
//    duplicate key values that would violate PostgreSQL unique constraints,
//    and post-migration row counts.
//
// Prerequisites (documented, not assumed):
//  * The `pg` package (node-postgres) installed.
//  * A running PostgreSQL server reachable via POSTGRES_DATABASE_URL.
//  * An empty or fresh target database (the utility does not create databases).

const { Pool } = require("pg");
const fs = require("node:fs");
const path = require("node:path");

// Tables migrated, in foreign-key-safe order (parents before children).
const MIGRATION_TABLES = [
  "shops",
  "plans",
  "licenses",
  "payments",
  "gateway_events",
  "payment_events",
  "license_logs"
];
// Tables required to exist in the source SQLite database.
const REQUIRED_SOURCE_TABLES = ["shops", "licenses", "license_logs", "plans", "payments", "payment_events", "gateway_events"];
// Columns that must be unique in PostgreSQL (and are checked for duplicates
// in the source before migration).
const UNIQUE_COLUMNS = {
  shops: ["local_shop_id"],
  licenses: ["key_hash"],
  payments: ["reference_key", "provider_transaction_id"]
};

function initializeSqlJs() {
  return require("sql.js");
}

function readWasmbinary() {
  const wasmBinary = fs.readFileSync(require.resolve("sql.js/dist/sql-wasm.wasm"));
  return wasmBinary;
}

// Open a SQLite database file read-only and return the sql.js database handle.
async function openSqliteReadOnly(sqlitePath) {
  if (!fs.existsSync(sqlitePath)) throw new Error(`SQLite database was not found: ${sqlitePath}`);
  const SQL = await initializeSqlJs();
  const wasmBinary = readWasmbinary();
  const SQLLib = await SQL({ wasmBinary });
  const bytes = fs.readFileSync(sqlitePath);
  const db = new SQLLib.Database(bytes, { readonly: true });
  return { SQLLib, db };
}

function tableNames(db) {
  const result = db.exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
  return (result[0]?.values ?? []).map(row => row[0]);
}

function allRows(db, table) {
  const result = db.exec(`SELECT * FROM ${table}`);
  const columns = (result[0]?.columns ?? []);
  const rows = (result[0]?.values ?? []).map(values => {
    const row = {};
    for (let i = 0; i < columns.length; i += 1) row[columns[i]] = values[i];
    return row;
  });
  return { columns, rows };
}

function sqlLiteral(value) {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "NULL";
  const text = String(value).replace(/'/g, "''");
  return `'${text}'`;
}

function insertSql(table, columns, row) {
  const values = columns.map(col => sqlLiteral(row[col]));
  return `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${values.join(", ")});`;
}

function validateDuplicates(sourceDb) {
  const problems = [];
  for (const [table, columns] of Object.entries(UNIQUE_COLUMNS)) {
    if (!tableNames(sourceDb).includes(table)) continue;
    for (const column of columns) {
      // NULL values are allowed and not considered duplicates.
      const rows = sourceDb.exec(
        `SELECT ${column}, COUNT(*) AS n FROM ${table} WHERE ${column} IS NOT NULL GROUP BY ${column} HAVING COUNT(*) > 1`
      );
      const duplicates = (rows[0]?.values ?? []).map(values => ({ value: values[0], count: values[1] }));
      for (const dup of duplicates) {
        problems.push({ table, column, value: dup.value, count: dup.count });
      }
    }
  }
  return problems;
}

function validateSource(sourceDb) {
  const names = new Set(tableNames(sourceDb));
  const missing = REQUIRED_SOURCE_TABLES.filter(name => !names.has(name));
  if (missing.length > 0) {
    throw new Error(`SQLite source is missing required tables: ${missing.join(", ")}.`);
  }
  const duplicates = validateDuplicates(sourceDb);
  if (duplicates.length > 0) {
    const summary = duplicates.map(d => `${d.table}.${d.column}='${d.value}' (${d.count} rows)`).join("; ");
    throw new Error(`Duplicate values would violate PostgreSQL unique constraints: ${summary}.`);
  }
  return { tableCount: names.size, duplicates };
}

// Migrate a SQLite license database into PostgreSQL.
//
// Options:
//   sqlitePath   - path to the source SQLite database file (read-only)
//   databaseUrl  - PostgreSQL connection string
//   dryRun       - if true, validate and report without writing to PostgreSQL
//   onProgress   - optional callback({ table, rows, phase })
//
// Returns a migration report.
async function migrateSqliteToPostgres({
  sqlitePath,
  databaseUrl,
  dryRun = false,
  onProgress = () => {}
} = {}) {
  if (!sqlitePath || typeof sqlitePath !== "string") {
    throw new Error("A source SQLite database path is required.");
  }
  if (!dryRun && (!databaseUrl || typeof databaseUrl !== "string")) {
    throw new Error("A PostgreSQL database URL is required.");
  }

  const { db: sourceDb } = await openSqliteReadOnly(sqlitePath);
  try {
    validateSource(sourceDb);

    const snapshot = {};
    for (const table of MIGRATION_TABLES) {
      if (!tableNames(sourceDb).includes(table)) continue;
      snapshot[table] = allRows(sourceDb, table);
      onProgress({ table, phase: "read", rows: snapshot[table].rows.length });
    }

    const report = {
      source: sqlitePath,
      target: databaseUrl || null,
      dryRun,
      tables: {},
      duplicates: validateDuplicates(sourceDb),
      startedAt: new Date().toISOString()
    };

    if (dryRun) {
      for (const table of MIGRATION_TABLES) {
        const data = snapshot[table];
        if (!data) continue;
        report.tables[table] = { rows: data.rows.length, columns: data.columns, wouldMigrate: true };
      }
      report.completedAt = new Date().toISOString();
      report.wouldMigrate = true;
      return report;
    }

    const pool = new Pool({ connectionString: databaseUrl });
    try {
      await pool.query("BEGIN");
      try {
        // Ensure the target schema exists (idempotent migrations).
        // Run each migration in its own transaction to match the adapter.
        for (const file of ["001_initial.sql", "002_plans_and_payments.sql", "003_license_and_shop_columns.sql", "004_indexes.sql"]) {
          await pool.query("BEGIN");
          await pool.query(fs.readFileSync(path.join(__dirname, "migrations", file), "utf8"));
          await pool.query("COMMIT");
        }

        for (const table of MIGRATION_TABLES) {
          const data = snapshot[table];
          if (!data) continue;
          for (const row of data.rows) {
            await pool.query(insertSql(table, data.columns, row));
          }
          report.tables[table] = { rows: data.rows.length, columns: data.columns, migrated: true };
          onProgress({ table, phase: "migrated", rows: data.rows.length });
        }

        // Post-migration validation: row counts must match the source.
        for (const table of MIGRATION_TABLES) {
          const data = snapshot[table];
          if (!data) continue;
          const { rows } = await pool.query(`SELECT COUNT(*) AS count FROM ${table}`);
          const count = Number(rows[0].count);
          if (count !== data.rows.length) {
            throw new Error(`Row count mismatch for ${table}: source ${data.rows.length}, target ${count}.`);
          }
          report.tables[table].verifiedCount = count;
        }

        await pool.query("COMMIT");
        report.committed = true;
      } catch (error) {
        try { await pool.query("ROLLBACK"); } catch {}
        report.committed = false;
        report.error = error instanceof Error ? error.message : String(error);
        throw error;
      }
    } finally {
      await pool.end();
    }

    report.completedAt = new Date().toISOString();
    report.wouldMigrate = false;
    return report;
  } finally {
    sourceDb.close();
  }
}

// Exported for testing and reuse. The adapter module itself remains the
// authoritative runtime implementation.
module.exports = {
  migrateSqliteToPostgres,
  openSqliteReadOnly,
  tableNames,
  allRows,
  validateSource,
  validateDuplicates,
  insertSql,
  sqlLiteral,
  MIGRATION_TABLES,
  REQUIRED_SOURCE_TABLES
};
