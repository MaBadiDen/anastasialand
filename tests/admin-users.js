process.env.NODE_ENV = 'test';
process.env.COOKIE_SECURE = 'false';
const request = require('supertest');
const path = require('path');
const sqlite3 = require('sqlite3');

(async () => {
  const mod = require(path.join(__dirname, '..', 'dist', 'app.js'));
  const app = mod && (mod.default || mod);
  const server = app.listen(0);
  const dbPath = path.join(__dirname, '..', 'data', 'users.db');
  const db = new sqlite3.Database(dbPath);
  const get = (sql, params=[]) => new Promise((res, rej) => db.get(sql, params, function(err,row){ err?rej(err):res(row); }));
  const all = (sql, params=[]) => new Promise((res, rej) => db.all(sql, params, function(err,rows){ err?rej(err):res(rows); }));
  const run = (sql, params=[]) => new Promise((res, rej) => db.run(sql, params, function(err){ err?rej(err):res(this); }));
  try {
    // Admin session
    const admin = request.agent(server);
    const loginPage = await admin.get('/login').expect(200);
    const xsrfLogin = (loginPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrfLogin) throw new Error('No XSRF cookie');
    const loginToken = decodeURIComponent(xsrfLogin.split(';')[0].split('=')[1]);
    await admin
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=TrueMaBadi&password=12344321&_csrf=${encodeURIComponent(loginToken)}`)
      .expect(302);

    // Open admin users page to get CSRF for CRUD
    const usersPage = await admin.get('/admin/users').expect(200);
    const xsrfUsers = (usersPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrfUsers) throw new Error('No XSRF token for users');
    const csrf = decodeURIComponent(xsrfUsers.split(';')[0].split('=')[1]);

    // 1) Create a new user
    const uname = 'crud_test_user_' + Math.random().toString(36).slice(2,8);
    await admin
      .post('/admin/users/create')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(uname)}&password=${encodeURIComponent('p@ssw0rd')}&email=${encodeURIComponent(uname+'@example.com')}&role=user&_csrf=${encodeURIComponent(csrf)}`)
      .expect(302);
    const created = await get('SELECT username, role, email FROM users WHERE username = ?', [uname]);
    if (!created || created.role !== 'user') throw new Error('Create failed');

    // 2) Update email and role to lecturer
    const newEmail = uname + '+2@example.com';
    await admin
      .post('/admin/users/update')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(uname)}&email=${encodeURIComponent(newEmail)}&role=lecturer&_csrf=${encodeURIComponent(csrf)}`)
      .expect(302);
    const updated = await get('SELECT role, email FROM users WHERE username = ?', [uname]);
    if (!updated || updated.role !== 'lecturer' || updated.email !== newEmail) throw new Error('Update failed');

    // 3) Update password optionally
    await admin
      .post('/admin/users/update')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(uname)}&email=${encodeURIComponent(newEmail)}&role=lecturer&password=${encodeURIComponent('newpass123')}&_csrf=${encodeURIComponent(csrf)}`)
      .expect(302);

    // 4) Try self-demote guard (admin cannot demote self)
    await admin.get('/admin/users').expect(200); // refresh CSRF
    const usersPage2 = await admin.get('/admin/users').expect(200);
    const xsrf2 = decodeURIComponent(((usersPage2.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='))||'').split(';')[0].split('=')[1]);
    const selfDemote = await admin
      .post('/admin/users/update')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=TrueMaBadi&email=&role=user&_csrf=${encodeURIComponent(xsrf2)}`)
      .expect(302);
    if (!/warning=/.test(selfDemote.headers.location||'')) throw new Error('Self-demote not blocked');

    // 5) Ensure at least one admin exists guard (attempt to demote last admin)
    const admins = await all("SELECT username FROM users WHERE role='admin'");
    if (admins.length === 1) {
      const lastAdmin = admins[0].username;
      await admin.get('/admin/users').expect(200);
      const page3 = await admin.get('/admin/users').expect(200);
      const xsrf3 = decodeURIComponent(((page3.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='))||'').split(';')[0].split('=')[1]);
      const lastDemote = await admin
        .post('/admin/users/update')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`username=${encodeURIComponent(lastAdmin)}&email=&role=user&_csrf=${encodeURIComponent(xsrf3)}`)
        .expect(302);
      if (!/warning=/.test(lastDemote.headers.location||'')) throw new Error('Last-admin demotion not blocked');
    }

    // 6) Delete created user
    await admin.get('/admin/users').expect(200);
    const usersPage3 = await admin.get('/admin/users').expect(200);
    const xsrfDel = decodeURIComponent(((usersPage3.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='))||'').split(';')[0].split('=')[1]);
    await admin
      .post('/admin/users/delete')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(uname)}&_csrf=${encodeURIComponent(xsrfDel)}`)
      .expect(302);
    const deleted = await get('SELECT 1 FROM users WHERE username = ?', [uname]);
    if (deleted) throw new Error('Delete failed');

    console.log('ADMIN USERS CRUD OK');
    process.exit(0);
  } catch (e) {
    console.error('ADMIN USERS CRUD FAIL:', e.message);
    process.exit(1);
  } finally {
    server && server.close();
  }
})();
