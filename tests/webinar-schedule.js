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
  const run = (sql, params=[]) => new Promise((res, rej) => db.run(sql, params, function(err){ err?rej(err):res(this); }));
  try {
    // Admin login
    const admin = request.agent(server);
    const loginPage = await admin.get('/login').expect(200);
    const xsrfLogin = (loginPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    const loginToken = decodeURIComponent(xsrfLogin.split(';')[0].split('=')[1]);
    await admin
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=TrueMaBadi&password=12344321&_csrf=${encodeURIComponent(loginToken)}`)
      .expect(302);

    // Ensure a course and webinar exist
    const adminWebinars = await admin.get('/admin/webinars').expect(200);
    const xsrfAdmin = (adminWebinars.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    const adminToken = decodeURIComponent(xsrfAdmin.split(';')[0].split('=')[1]);

    await admin.post('/admin/courses/add')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`name=${encodeURIComponent('Курс расписание')}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);
    await admin.post('/admin/add-topic')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`name=${encodeURIComponent('Раздел расписание')}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);
    const course = await get('SELECT id FROM courses WHERE name = ?', ['Курс расписание']);
    await run('UPDATE topics SET course_id = ? WHERE name = ?', [course.id, 'Раздел расписание']);

    await admin
      .post('/admin/webinars/add')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`summary=${encodeURIComponent('Вебинар расписание')}&description=-&start_time=2025-01-02T10:00&end_time=2025-01-02T11:00&courseId=${encodeURIComponent(String(course.id))}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);
    const webinar = await get('SELECT id FROM webinars WHERE summary = ? ORDER BY id DESC LIMIT 1', ['Вебинар расписание']);
    const wid = webinar.id;

    // Student user becomes attendee
    await admin
      .post('/lecturer/webinars/attendees/user/add')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`webinarId=${encodeURIComponent(String(wid))}&username=${encodeURIComponent('kaba4ok')}&_csrf=${encodeURIComponent(adminToken)}`)
      .expect(302);

    // Schedule open in the past (UTC), student should be allowed
    const schedTokPg = await admin.get('/lecturer/webinars').expect(200);
    const xsrfSched = (schedTokPg.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    const schedToken = decodeURIComponent(xsrfSched.split(';')[0].split('=')[1]);
    const pastIso = new Date(Date.now() - 5 * 60 * 1000).toISOString().slice(0,16); // yyyy-MM-ddTHH:mm (local interpreted)
    await admin
      .post('/lecturer/webinar/schedule-open')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`id=${encodeURIComponent(String(wid))}&when=${encodeURIComponent(pastIso)}&_csrf=${encodeURIComponent(schedToken)}`)
      .expect(302);

    // Student login
    const student = request.agent(server);
    const sLoginPage = await student.get('/login').expect(200);
    const sXsrfLogin = (sLoginPage.headers['set-cookie'] || []).find(c => c.startsWith('XSRF-TOKEN='));
    const sLoginToken = decodeURIComponent(sXsrfLogin.split(';')[0].split('=')[1]);
    await student
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=kaba4ok&password=kaba4ok&_csrf=${encodeURIComponent(sLoginToken)}`)
      .expect(302);

    const openPage = await student.get(`/webinar-tests/${wid}`).expect(200);
    if (/(Тест.*закрыт|Тест откроется)/i.test(openPage.text)) {
      throw new Error('Scheduled open did not unlock test');
    }

    console.log('WEBINAR SCHEDULE OK');
    process.exit(0);
  } catch (e) {
    console.error('WEBINAR SCHEDULE FAIL:', e.message);
    process.exit(1);
  } finally {
    server && server.close();
  }
})();
