#!/usr/bin/env node
// Report what the Diamond Dust redenomination would change, or apply it.
// The server applies it on its own at start; this is for a dry run against a copy.
//   node bin/redenominate-dd.js [path/to/dustforge.db] [--apply]
const path = require('path');
const Database = require('better-sqlite3');
const { migrate } = require(path.join(__dirname, '..', 'dd_redenominate'));

const args = process.argv.slice(2);
const dbPath = args.find(a => !a.startsWith('--')) || process.env.DB_PATH || './data/dustforge.db';
const db = new Database(dbPath, { fileMustExist: true });
const r = migrate(db, { dryRun: !args.includes('--apply'), log: console.log });
if (r.already) console.log('already applied:', r.already.applied_at, r.already.report);
db.close();
