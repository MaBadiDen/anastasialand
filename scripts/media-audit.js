#!/usr/bin/env node
/*
  Media audit: list files present on disk but missing in DB and vice versa.
  - Scans public/videos
  - Compares with videos.filename in SQLite
*/
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3');

function dbPath() {
  const root = __dirname + '/..';
  const dataDb = path.join(root, 'data', 'users.db');
  const legacyDb = path.join(root, 'users.db');
  if (fs.existsSync(dataDb)) return dataDb;
  if (fs.existsSync(legacyDb)) return legacyDb;
  return dataDb; // default future path
}

const db = new sqlite3.Database(dbPath());
const vidsDir = path.join(__dirname, '..', 'public', 'videos');

function listFiles(dir) {
  try { return fs.readdirSync(dir).filter(f => fs.statSync(path.join(dir,f)).isFile()); } catch { return []; }
}

function main() {
  const files = new Set(listFiles(vidsDir));
  db.all('SELECT filename FROM videos', [], (err, rows) => {
    const known = new Set((rows || []).map(r => String(r.filename)));
    const onDiskNotInDb = Array.from(files).filter(f => !known.has(f));
    const inDbNotOnDisk = Array.from(known).filter(f => !files.has(f));
    console.log(JSON.stringify({ onDiskNotInDb, inDbNotOnDisk }, null, 2));
    db.close();
  });
}

main();
