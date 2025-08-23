process.env.NODE_ENV = 'test';
process.env.COOKIE_SECURE = 'false';
process.env.DEBUG_AUTH = '0';
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
  try {
    // Admin session
    const admin = request.agent(server);
    // Get CSRF for login
    const loginPage = await admin.get('/login').expect(200);
    const xsrfLogin = (loginPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrfLogin) throw new Error('No XSRF cookie');
    const loginToken = decodeURIComponent(xsrfLogin.split(';')[0].split('=')[1]);
    // Login as admin
    await admin
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=TrueMaBadi&password=12344321&_csrf=${encodeURIComponent(loginToken)}`)
      .expect(302);

    // Open admin webinars to get CSRF
    const adminWebinars = await admin.get('/admin/webinars').expect(200);
    const xsrfAdmin = (adminWebinars.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!xsrfAdmin) throw new Error('No XSRF token for admin');
    const adminToken = decodeURIComponent(xsrfAdmin.split(';')[0].split('=')[1]);

    // Add course
    await admin
      .post('/admin/courses/add')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`name=${encodeURIComponent('Тестовый курс')}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);
    const course = await get('SELECT id FROM courses WHERE name = ?', ['Тестовый курс']);
    if (!course) throw new Error('Course insert failed');

    // Add a topic for the course (if not exists)
    await admin
      .post('/admin/add-topic')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`name=${encodeURIComponent('Тестовый раздел')}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);
    // Ensure topic is linked to course
    // Update topics.course_id to our course id
    await new Promise((res, rej) => db.run('UPDATE topics SET course_id = ? WHERE name = ?', [course.id, 'Тестовый раздел'], (e) => e?rej(e):res(undefined)));

    // Add webinar (closed by default)
    await admin
      .post('/admin/webinars/add')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`summary=${encodeURIComponent('Тестовый вебинар')}&description=-&start_time=2025-01-01T10:00&end_time=2025-01-01T11:00&courseId=${encodeURIComponent(String(course.id))}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);
    const webinar = await get('SELECT id FROM webinars WHERE summary = ? ORDER BY id DESC LIMIT 1', ['Тестовый вебинар']);
    if (!webinar) throw new Error('Webinar insert failed');
    const wid = webinar.id;

    // Add attendee user (default seeded user kaba4ok)
    await admin
      .post('/lecturer/webinars/attendees/user/add')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`webinarId=${encodeURIComponent(String(wid))}&username=${encodeURIComponent('kaba4ok')}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);

    // Student session (non-admin)
    const student = request.agent(server);
    const sLoginPage = await student.get('/login').expect(200);
    const sXsrfLogin = (sLoginPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    if (!sXsrfLogin) throw new Error('No XSRF cookie (student)');
    const sLoginToken = decodeURIComponent(sXsrfLogin.split(';')[0].split('=')[1]);
    await student
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=kaba4ok&password=kaba4ok&_csrf=${encodeURIComponent(sLoginToken)}`)
      .expect(302);

    // Closed: should show locked message
    const closedPage = await student.get(`/webinar-tests/${wid}`).expect(200);
    if (!/(Тест.*закрыт|Тест откроется)/i.test(closedPage.text)) {
      throw new Error('Closed webinar not locked for student');
    }

    // Open webinar as admin
    const tokPage = await admin.get('/lecturer/webinars').expect(200);
    const xsrfCookie = (tokPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    const token = decodeURIComponent(xsrfCookie.split(';')[0].split('=')[1]);
    await admin
      .post('/admin/webinar/toggle')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`id=${encodeURIComponent(String(wid))}&open=1&_csrf=${encodeURIComponent(token)}`)
      .expect(302);

    // Now student can access; page should not contain locked message
    const openPage = await student.get(`/webinar-tests/${wid}`).expect(200);
    if (/(Тест.*закрыт|Тест откроется)/i.test(openPage.text)) {
      throw new Error('Open webinar still appears locked for student');
    }

    console.log('WEBINAR GATING OK');
    process.exit(0);
  } catch (e) {
    console.error('WEBINAR GATING FAIL:', e.message);
    process.exit(1);
  } finally {
    server && server.close();
  }
})();
