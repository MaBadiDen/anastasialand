const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('users.db');
db.all('SELECT username, role, email FROM users', [], (e, rows) => {
  if (e) { console.error('DB error:', e); process.exit(1); }
  console.log('USERS:', rows);
  process.exit(0);
});
