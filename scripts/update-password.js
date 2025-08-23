// Usage: node scripts/update-password.js <username> <newPassword>
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');

async function main() {
  const [,, usernameArg, newPassword] = process.argv;
  if (!usernameArg || !newPassword) {
    console.error('Usage: node scripts/update-password.js <username> <newPassword>');
    process.exit(1);
  }
  const username = usernameArg.toString();
  const db = new sqlite3.Database('users.db');
  try {
    const hash = await bcrypt.hash(newPassword, 10);
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET passwordHash = ? WHERE LOWER(username) = LOWER(?)',
        [hash, username],
        function (err) {
          if (err) return reject(err);
          console.log('Rows updated:', this.changes);
          resolve();
        }
      );
    });
  } catch (e) {
    console.error('Failed:', e);
    process.exit(1);
  } finally {
    db.close();
  }
}

main();
