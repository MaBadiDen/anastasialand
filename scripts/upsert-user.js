// Usage: node scripts/upsert-user.js <username> <password> [role] [email]
// Inserts a new user or updates existing user's password and role.
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

async function main() {
  const [,, usernameArg, passwordArg, roleArg, emailArg] = process.argv;
  if (!usernameArg || !passwordArg) {
    console.error('Usage: node scripts/upsert-user.js <username> <password> [role] [email]');
    process.exit(1);
  }
  const username = String(usernameArg);
  const password = String(passwordArg);
  const role = (roleArg ? String(roleArg) : 'user').toLowerCase();
  const email = emailArg ? String(emailArg) : null;

  // Resolve DB path similar to src/db.ts
  const rootDir = path.join(__dirname, '..');
  const dataDir = path.join(rootDir, 'data');
  try { fs.mkdirSync(dataDir, { recursive: true }); } catch {}
  const dataDbPath = path.join(dataDir, 'users.db');
  const legacyDbPath = path.join(rootDir, 'users.db');
  const dbPath = fs.existsSync(dataDbPath) ? dataDbPath : (fs.existsSync(legacyDbPath) ? legacyDbPath : dataDbPath);
  const db = new sqlite3.Database(dbPath);
  try {
    const hash = await bcrypt.hash(password, 10);
    const exists = await new Promise((resolve, reject) => {
      db.get('SELECT username FROM users WHERE LOWER(username) = LOWER(?)', [username], (err, row) => {
        if (err) return reject(err);
        resolve(!!row);
      });
    });

    if (exists) {
      await new Promise((resolve, reject) => {
        db.run('UPDATE users SET passwordHash = ?, role = COALESCE(?, role), email = COALESCE(?, email) WHERE LOWER(username) = LOWER(?)', [hash, role, email, username], function(err){
          if (err) return reject(err);
          console.log('Updated user:', username, 'changes:', this.changes);
          resolve();
        });
      });
    } else {
      await new Promise((resolve, reject) => {
        db.run('INSERT INTO users (username, passwordHash, role, email) VALUES (?, ?, ?, ?)', [username, hash, role, email], function(err){
          if (err) return reject(err);
          console.log('Inserted user:', username, 'with role:', role);
          resolve();
        });
      });
    }
  } catch (e) {
    console.error('Failed:', e);
    process.exit(1);
  } finally {
    db.close();
  }
}

main();
