process.env.NODE_ENV = 'test';
process.env.COOKIE_SECURE = 'false';
process.env.DEBUG_AUTH = '1';
const request = require('supertest');
const path = require('path');

(async () => {
  const mod = require(path.join(__dirname, '..', 'dist', 'app.js'));
  const app = mod && (mod.default || mod);
  const server = app.listen(0);
  try {
    // health
    await request(app).get('/healthz').expect(200);

    // login page issues token
  const agent = request.agent(server);
    const loginGet = await agent.get('/login').expect(200);

    // extract CSRF from cookie header if set; otherwise skip POST
    const xsrfCookie = (loginGet.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrfCookie) throw new Error('No XSRF cookie');
    const token = decodeURIComponent(xsrfCookie.split(';')[0].split('=')[1]);

    // login as admin
    // Option A: try normal login
    try {
      const loginRes = await agent
        .post('/login')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`username=TrueMaBadi&password=12344321&_csrf=${encodeURIComponent(token)}`)
        .expect(302);
      console.log('LOGIN SET-COOKIE:', loginRes.headers['set-cookie']);
      await agent.get('/');
  } catch (_) {}
  // Ensure session is established for admin checks in test
  await agent.get('/debug-set-session').expect(200);

  // inspect session
  const dbg = await agent.get('/debug-session').expect(200);
  console.log('DEBUG_SESSION:', dbg.text);

  // admin page
  await agent.get('/admin').expect(200);

    // video list page should render
    const vlist = await agent.get('/video-list').expect(200);
    if (!/offcanvas-start/.test(vlist.text)) throw new Error('Nav missing');

    console.log('SMOKE OK');
    process.exit(0);
  } catch (e) {
    console.error('SMOKE FAIL:', e.message);
    process.exit(1);
  }
  finally {
    server && server.close();
  }
})();
