process.env.NODE_ENV = 'test';
process.env.COOKIE_SECURE = 'false';
const request = require('supertest');
const path = require('path');

(async () => {
  const mod = require(path.join(__dirname, '..', 'dist', 'app.js'));
  const app = mod && (mod.default || mod);
  const server = app.listen(0);
  try {
    // 1) Register should reject weak password
    const agent = request.agent(server);
    const regGet = await agent.get('/register').expect(200);
    const xsrf = (regGet.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrf) throw new Error('No XSRF cookie on /register');
    const csrf = decodeURIComponent(xsrf.split(';')[0].split('=')[1]);
    const uname = 'weak_' + Math.random().toString(36).slice(2,8);
    const resWeak = await agent
      .post('/register')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(uname)}&password=${encodeURIComponent('short')}&email=${encodeURIComponent(uname+'@example.com')}&_csrf=${encodeURIComponent(csrf)}`)
      .expect(302);
    if (!/\bwarning=/.test(String(resWeak.headers.location || ''))) {
      throw new Error('Weak password not rejected on register');
    }

    // 2) Register succeeds with strong password
    const strongPass = 'Abcdef12!';
    const resOk = await agent
      .post('/register')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=${encodeURIComponent(uname)}&password=${encodeURIComponent(strongPass)}&email=${encodeURIComponent(uname+'+2@example.com')}&_csrf=${encodeURIComponent(csrf)}`)
      .expect(302);
    if ((resOk.headers.location || '/') !== '/') {
      throw new Error('Strong password register did not redirect home');
    }

    // 3) Change password rejects weak new password
    // Open cabinet to get CSRF
    const cab = await agent.get('/cabinet').expect(200);
    const xsrf2 = (cab.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrf2) throw new Error('No XSRF on /cabinet');
    const csrf2 = decodeURIComponent(xsrf2.split(';')[0].split('=')[1]);
    const resWeakChange = await agent
      .post('/change-password')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`currentPassword=${encodeURIComponent(strongPass)}&newPassword=${encodeURIComponent('short')}&confirmPassword=${encodeURIComponent('short')}&_csrf=${encodeURIComponent(csrf2)}`)
      .expect(302);
    if (!/\/cabinet\?warning=/.test(String(resWeakChange.headers.location || ''))) {
      throw new Error('Weak password not rejected on change-password');
    }

    console.log('PASSWORD POLICY OK');
    process.exit(0);
  } catch (e) {
    console.error('PASSWORD POLICY FAIL:', e.message);
    process.exit(1);
  } finally {
    server && server.close();
  }
})();
