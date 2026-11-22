#!/usr/bin/env node
"use strict";

// ShopPOS license server -- SQLite to PostgreSQL migration CLI.
//
// Copies a SQLite license database (sql.js/WASM file) into an empty PostgreSQL
// database. The SQLite source is opened read-only and is NEVER modified.
//
// Usage:
//   node sqlite-migrate.cjs --sqlite <path> [--database-url <url>] [--dry-run]
//
// The database URL may also be supplied via POSTGRES_DATABASE_URL. A dry run
// validates and reports without writing anything and does not need a URL.
//
// Only `--dry-run` is supported as a flag here; no database name is accepted on
// the command line and no URL is ever echoed back to the caller.

const { migrateSqliteToPostgres } = require("./sqlite-to-postgres.cjs");

function parseArgs(argv) {
  const options = { dryRun: false, sqlitePath: undefined, databaseUrl: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--sqlite") {
      options.sqlitePath = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--sqlite=")) {
      options.sqlitePath = arg.slice("--sqlite=".length);
    } else if (arg === "--database-url") {
      options.databaseUrl = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--database-url=")) {
      options.databaseUrl = arg.slice("--database-url=".length);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (!options.sqlitePath) {
    throw new Error("A source SQLite path is required: --sqlite <path>.");
  }
  const databaseUrl = options.databaseUrl || process.env.POSTGRES_DATABASE_URL;
  if (!options.dryRun && !databaseUrl) {
    throw new Error("A PostgreSQL database URL is required: --database-url <url> or POSTGRES_DATABASE_URL.");
  }

  const report = await migrateSqliteToPostgres({
    sqlitePath: options.sqlitePath,
    databaseUrl,
    dryRun: options.dryRun,
    onProgress: ({ table, rows, phase }) => {
      console.log(`  ${phase} ${table}: ${rows} rows`);
    }
  });

  console.log(report.dryRun ? "Dry run complete; nothing was written." : "Migration committed.");
  console.log(`Tables: ${Object.keys(report.tables).length}`);
  return report;
}

if (require.main === module) {
  main().catch(error => {
    console.error(`Migration failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs };