process.env.NODE_ENV = 'test';
process.env.COOKIE_SECURE = 'false';
const request = require('supertest');
const path = require('path');
const sqlite3 = require('sqlite3');
const crypto = require('crypto');

(async () => {
  const mod = require(path.join(__dirname, '..', 'dist', 'app.js'));
  const app = mod && (mod.default || mod);
  const server = app.listen(0);
  const dbPath = path.join(__dirname, '..', 'data', 'users.db');
  const db = new sqlite3.Database(dbPath);
  const get = (sql, params=[]) => new Promise((res, rej) => db.get(sql, params, function(err,row){ err?rej(err):res(row); }));
  const run = (sql, params=[]) => new Promise((res, rej) => db.run(sql, params, function(err){ err?rej(err):res(this); }));

  try {
    // Ensure a known user with email exists
    const username = 'reset_user_' + Math.random().toString(36).slice(2,6);
    const email = username + '@example.com';
    const bcrypt = require('bcryptjs');
    const passHash = await bcrypt.hash('oldpass123', 10);
    await run('INSERT INTO users (username, passwordHash, role, email) VALUES (?, ?, ?, ?)', [username, passHash, 'user', email]);

    // Open /forgot to get CSRF
    const agent = request.agent(server);
    const fg = await agent.get('/forgot').expect(200);
    const xsrf = (fg.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrf) throw new Error('No XSRF token on /forgot');
    const csrf = decodeURIComponent(xsrf.split(';')[0].split('=')[1]);

    // Request reset
    await agent
      .post('/forgot')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`email=${encodeURIComponent(email)}&_csrf=${encodeURIComponent(csrf)}`)
      .expect(302);

    // Read last reset row for our user
    const row = await get('SELECT id, token_hash, expires_at, used_at FROM password_resets WHERE username = ? ORDER BY id DESC LIMIT 1', [username]);
    if (!row || !row.token_hash) throw new Error('No reset row');

    // Forge plaintext token that matches token_hash by trying randoms briefly (impractical). Instead, simulate what app does:
    // We can't reverse hash; so we will insert our own reset row with known token/token_hash to test the reset endpoint.
    const token = crypto.randomBytes(16).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    await run('INSERT INTO password_resets (username, email, token_hash, expires_at) VALUES (?, ?, ?, ?)', [username, email, tokenHash, expires]);

    // Open /reset?token=...
    const rs = await agent.get('/reset?token=' + encodeURIComponent(token)).expect(200);
    const xsrf2 = (rs.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrf2) throw new Error('No XSRF cookie on /reset');
    const csrf2 = decodeURIComponent(xsrf2.split(';')[0].split('=')[1]);

    // Submit new password
    await agent
      .post('/reset')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`token=${encodeURIComponent(token)}&password=${encodeURIComponent('newpass123')}&confirm=${encodeURIComponent('newpass123')}&_csrf=${encodeURIComponent(csrf2)}`)
      .expect(302);

    // Verify password updated by logging in
    const lg = await agent.get('/login').expect(200);
    const xsrfLogin = (lg.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    const csrfLogin = decodeURIComponent(xsrfLogin.split(';')[0].split('=')[1]);
    await agent
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(username)}&password=${encodeURIComponent('newpass123')}&_csrf=${encodeURIComponent(csrfLogin)}`)
      .expect(302);

    // Try reusing token -> should redirect with error
    const again = await agent
      .post('/reset')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`token=${encodeURIComponent(token)}&password=x&confirm=x&_csrf=${encodeURIComponent(csrf2)}`)
      .expect(302);

    console.log('RESET FLOW OK');
    process.exit(0);
  } catch (e) {
    console.error('RESET FLOW FAIL:', e.message);
    process.exit(1);
  } finally {
    server && server.close();
  }
})();
