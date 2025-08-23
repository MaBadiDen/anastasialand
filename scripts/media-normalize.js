#!/usr/bin/env node
/*
  Media filename normalizer: ensures filenames in public/videos and DB are normalized.
  - Normalizes Unicode to NFC and lowercases extensions.
  - Optionally slugifies basename (ASCII) if --slug is provided.
  - Dry run by default; use --apply to perform renames and DB updates.
  - Handles collisions by appending short hash.
*/
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');

function dbPath() {
  const root = __dirname + '/..';
  const dataDb = path.join(root, 'data', 'users.db');
  const legacyDb = path.join(root, 'users.db');
  if (fs.existsSync(dataDb)) return dataDb;
  if (fs.existsSync(legacyDb)) return legacyDb;
  return dataDb; // default future path
}

const vidsDir = path.join(__dirname, '..', 'public', 'videos');
const args = new Set(process.argv.slice(2));
const APPLY = args.has('--apply');
const SLUG = args.has('--slug');

function normalizeName(name) {
  const nfc = name.normalize('NFC');
  const ext = path.extname(nfc).toLowerCase();
  const base = path.basename(nfc, ext);
  if (!SLUG) return base + ext;
  const slug = base
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '') // strip diacritics
    .replace(/[^a-zA-Z0-9\-_.]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .toLowerCase();
  return (slug || 'file') + ext;
}

function shortHash(s) {
  return crypto.createHash('md5').update(s).digest('hex').slice(0,8);
}

function listFiles(dir) {
  try { return fs.readdirSync(dir).filter(f => fs.statSync(path.join(dir,f)).isFile()); } catch { return []; }
}

function ensureUnique(target, occupied) {
  if (!occupied.has(target)) return target;
  const ext = path.extname(target);
  const base = path.basename(target, ext);
  let i = 1;
  let cand = `${base}-${shortHash(base)}${ext}`;
  while (occupied.has(cand)) {
    i++;
    cand = `${base}-${i}-${shortHash(base+i)}${ext}`;
  }
  return cand;
}

function main() {
  if (!fs.existsSync(vidsDir)) {
    console.error('No videos dir:', vidsDir);
    process.exit(1);
  }
  const db = new sqlite3.Database(dbPath());
  const files = listFiles(vidsDir);
  db.all('SELECT id, filename FROM videos', [], (err, rows) => {
    if (err) { console.error('DB error', err.message || err); process.exit(2); }
    const diskSet = new Set(files);
    const dbByName = new Map(rows.map(r => [String(r.filename), Number(r.id)]));
    const occupied = new Set(files);
    const changes = [];

    // Propose renames for disk files first
    for (const f of files) {
      const norm = normalizeName(f);
      if (norm !== f) {
        const unique = ensureUnique(norm, occupied);
        if (unique !== f) {
          changes.push({ kind: 'disk', from: f, to: unique });
          occupied.add(unique);
          occupied.delete(f);
        }
      }
    }
    // Propose DB filename updates (if DB has names not matching normalized)
    for (const [name, id] of dbByName.entries()) {
      const norm = normalizeName(name);
      if (norm !== name) {
        const unique = ensureUnique(norm, occupied);
        if (unique !== name) {
          changes.push({ kind: 'db', id, from: name, to: unique });
          occupied.add(unique);
          occupied.delete(name);
        }
      }
    }

    // Merge paired disk+db renames to keep linkage in sync
    const byFrom = new Map(changes.map(c => [c.from + '|' + c.kind, c]));
    const merged = [];
    for (const ch of changes) {
      if (ch.kind === 'disk') {
        const dbChange = byFrom.get(ch.from + '|db');
        if (dbChange) {
          merged.push({ kind: 'both', id: dbChange.id, from: ch.from, to: ch.to });
        } else if (dbByName.has(ch.from)) {
          merged.push({ kind: 'both', id: dbByName.get(ch.from), from: ch.from, to: ch.to });
        } else {
          merged.push(ch);
        }
      } else if (ch.kind === 'db') {
        const diskChange = byFrom.get(ch.from + '|disk');
        if (!diskChange) merged.push(ch);
      }
    }

    // Deduplicate by (from->to)
    const seen = new Set();
    const plan = [];
    for (const m of merged) {
      const key = `${m.kind}|${m.from}|${m.to}|${m.id||''}`;
      if (!seen.has(key)) { seen.add(key); plan.push(m); }
    }

    if (!APPLY) {
      console.log(JSON.stringify({ dryRun: true, applyHint: 'run with --apply to rename', count: plan.length, plan }, null, 2));
      db.close();
      return;
    }

    // Apply
    db.serialize(() => {
      db.run('BEGIN');
      try {
        for (const step of plan) {
          if (step.kind === 'disk' || step.kind === 'both') {
            const src = path.join(vidsDir, step.from);
            const dst = path.join(vidsDir, step.to);
            if (fs.existsSync(src)) fs.renameSync(src, dst);
          }
          if (step.kind === 'db' || step.kind === 'both') {
            db.run('UPDATE videos SET filename = ? WHERE ' + (step.id ? 'id = ?' : 'filename = ?'), step.id ? [step.to, step.id] : [step.to, step.from]);
          }
        }
        db.run('COMMIT', (commitErr) => {
          if (commitErr) {
            console.error('Commit failed', commitErr.message || commitErr);
            db.run('ROLLBACK');
            process.exit(3);
          } else {
            console.log(JSON.stringify({ dryRun: false, applied: plan.length }));
            db.close();
          }
        });
      } catch (e) {
        console.error('Apply failed', e && e.message || e);
        try { db.run('ROLLBACK'); } catch {}
        process.exit(4);
      }
    });
  });
}

main();
