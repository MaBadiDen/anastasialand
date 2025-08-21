import express from 'express';
import path from 'path';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import { db } from './db';
import multer from 'multer';
import fs from 'fs';
import nodemailer from 'nodemailer';

// Расширяем тип сессии
declare module 'express-session' {
    interface SessionData {
        user?: string;
        role?: string;
        message?: string;
    }
}

const app = express();
const port = 3000;

// Middleware для авторизации
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

// Middleware для проверки роли администратора
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (req.session.role !== 'admin') {
        return res.status(403).send('Доступ разрешён только администраторам');
    }
    next();
}

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, '../public/public')));
app.use('/videos', requireAuth, express.static(path.join(__dirname, '../public/videos')));

app.use((req, res, next) => {
    const publicPaths = ['/login', '/register', '/forgot'];
    if (publicPaths.includes(req.path) || req.path.startsWith('/public')) {
        return next();
    }
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
});

// Страница регистрации
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/public/register.html'));
});
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    db.get('SELECT username FROM users WHERE username = ?', [username], async (err, row) => {
        if (row) {
            return res.redirect('/register?error=Пользователь уже зарегистрирован');
        }
        const passwordHash = await bcrypt.hash(password, 10);
        db.run(
            'INSERT INTO users (username, passwordHash, role, email) VALUES (?, ?, ?, ?)',
            [username, passwordHash, 'user', email],
            (err) => {
                if (err) return res.redirect('/register?error=Ошибка регистрации');
                res.redirect('/login');
            }
        );
    });
});

// Страница входа
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/public/login.html'));
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT passwordHash, role FROM users WHERE username = ?', [username], async (err, row: { passwordHash?: string, role?: string } | undefined) => {
        if (!row || !row.passwordHash) {
            return res.redirect('/login?error=Неверное имя пользователя или пароль');
        }
        const isMatch = await bcrypt.compare(password, row.passwordHash);
        if (!isMatch) {
            return res.redirect('/login?error=Неверное имя пользователя или пароль');
        }
        req.session.user = username;
        req.session.role = row.role;
        res.redirect('/');
    });
});

// Главная страница
app.get('/', requireAuth, (req, res) => {
    const username = req.session.user;
    res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Обучающий сайт</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <span class="navbar-brand mx-auto mb-0 h1">Обучающий сайт</span>
            <div class="d-flex ms-auto align-items-center">
                <span class="me-2">${username}</span>
                <a href="/cabinet" class="btn btn-outline-secondary">Личный кабинет</a>
            </div>
        </div>
    </nav>
    <div class="container py-4">
        <h1 class="mb-4 text-center">Добро пожаловать!</h1>
        <div class="d-flex flex-column align-items-center gap-3">
            <a href="/videos.html" class="btn btn-primary btn-lg w-50">Видео</a>
            <a href="/presentations.html" class="btn btn-success btn-lg w-50">Презентации</a>
            <a href="/tests.html" class="btn btn-info btn-lg w-50">Тесты</a>
        </div>
    </div>
</body>
</html>
    `);
});

// Личный кабинет
app.get('/cabinet', requireAuth, (req, res) => {
    const isAdmin = req.session.role === 'admin';
    const message = req.session.message || '';
    req.session.message = undefined;
    const username = req.session.user;
    res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Личный кабинет</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <a href="/" class="btn btn-outline-primary me-3">Главное меню</a>
            <span class="navbar-brand mx-auto mb-0 h1">Обучающий сайт</span>
            <div class="d-flex ms-auto align-items-center">
                <span class="me-2">${username}</span>
            </div>
        </div>
    </nav>
    <div class="container py-4">
        <h1 class="mb-4">Личный кабинет</h1>
        <p>Здравствуйте, ${username}!</p>
        <div class="mb-3">
            <a href="/logout" class="btn btn-danger me-2">Выйти</a>
            ${isAdmin ? '<a href="/admin" class="btn btn-warning">Админпанель</a>' : ''}
        </div>
        <hr>
        <h4>Смена пароля</h4>
        ${message ? `<div class="alert alert-info">${message}</div>` : ''}
        <form method="POST" action="/change-password" class="mb-3" style="max-width:400px;">
            <div class="mb-2">
                <label for="currentPassword" class="form-label">Текущий пароль</label>
                <input type="password" class="form-control" id="currentPassword" name="currentPassword" required>
            </div>
            <div class="mb-2">
                <label for="newPassword" class="form-label">Новый пароль</label>
                <input type="password" class="form-control" id="newPassword" name="newPassword" required>
            </div>
            <div class="mb-2">
                <label for="confirmPassword" class="form-label">Повторите новый пароль</label>
                <input type="password" class="form-control" id="confirmPassword" name="confirmPassword" required>
            </div>
            <button type="submit" class="btn btn-success">Сменить пароль</button>
        </form>
    </div>
</body>
</html>
    `);
});

app.post('/change-password', requireAuth, async (req, res) => {
    const username = req.session.user;
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) {
        req.session.message = 'Пожалуйста, заполните все поля.';
        return res.redirect('/cabinet');
    }
    if (newPassword !== confirmPassword) {
        req.session.message = 'Новые пароли не совпадают.';
        return res.redirect('/cabinet');
    }
    db.get('SELECT passwordHash FROM users WHERE username = ?', [username], async (err, row: { passwordHash?: string } | undefined) => {
        if (err || !row || !row.passwordHash) {
            req.session.message = 'Ошибка пользователя.';
            return res.redirect('/cabinet');
        }
        const isMatch = await bcrypt.compare(currentPassword, row.passwordHash);
        if (!isMatch) {
            req.session.message = 'Текущий пароль неверен.';
            return res.redirect('/cabinet');
        }
        const newHash = await bcrypt.hash(newPassword, 10);
        db.run('UPDATE users SET passwordHash = ? WHERE username = ?', [newHash, username], (err) => {
            if (err) {
                req.session.message = 'Ошибка при смене пароля.';
            } else {
                req.session.message = 'Пароль успешно изменён!';
            }
            return res.redirect('/cabinet');
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Видео
app.get('/videos.html', requireAuth, (req, res) => {
    const username = req.session.user;
    db.all('SELECT * FROM videos ORDER BY topic, title', (err, videos: Array<{ topic: string; title: string; filename: string }>) => {
        if (err) return res.send('Ошибка загрузки видео');
        // Группировка по тематикам
        const topics: { [key: string]: Array<{ topic: string; title: string; filename: string }> } = {};
        videos.forEach(v => {
            if (!topics[v.topic]) topics[v.topic] = [];
            topics[v.topic].push(v);
        });
        let htmlVideos = '';
        for (const topic in topics) {
            htmlVideos += `<h3 class="mt-4 mb-3">${topic}</h3>`;
            htmlVideos += '<div class="accordion" id="accordion-' + topic.replace(/[^a-zA-Z0-9]/g, '') + '">';
            topics[topic].forEach((video, idx) => {
                const vidId = `vid${topic.replace(/[^a-zA-Z0-9]/g, '')}-${idx}`;
                htmlVideos += `
<div class="accordion-item">
    <h2 class="accordion-header" id="heading-${vidId}">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${vidId}" aria-expanded="false" aria-controls="collapse-${vidId}">
            ${video.title}
        </button>
    </h2>
    <div id="collapse-${vidId}" class="accordion-collapse collapse" aria-labelledby="heading-${vidId}" data-bs-parent="#accordion-${topic.replace(/[^a-zA-Z0-9]/g, '')}">
        <div class="accordion-body">
            <video src="/videos/${video.filename}" controls style="width:100%;max-width:600px;"></video>
        </div>
    </div>
</div>
`;
            });
            htmlVideos += '</div>';
        }
        res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Обучающие видео</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .accordion-button { transition: background 0.2s; }
        .accordion-body { transition: max-height 0.4s; }
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <a href="/" class="btn btn-outline-primary me-3">Главное меню</a>
            <span class="navbar-brand mx-auto mb-0 h1">Обучающий сайт</span>
            <div class="d-flex ms-auto align-items-center">
                <span class="me-2">${username}</span>
                <a href="/cabinet" class="btn btn-outline-secondary">Личный кабинет</a>
            </div>
        </div>
    </nav>
    <div class="container py-4">
        <h1 class="mb-4">Обучающие видео</h1>
        ${htmlVideos}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        `);
    });
});

// Презентации
app.get('/presentations.html', requireAuth, (req, res) => {
    const username = req.session.user;
    res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Презентации</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <a href="/" class="btn btn-outline-primary me-3">Главное меню</a>
            <span class="navbar-brand mx-auto mb-0 h1">Обучающий сайт</span>
            <div class="d-flex ms-auto align-items-center">
                <span class="me-2">${username}</span>
                <a href="/cabinet" class="btn btn-outline-secondary">Личный кабинет</a>
            </div>
        </div>
    </nav>
    <div class="container py-4">
        <h1 class="mb-4">Презентации</h1>
        <div class="alert alert-info">Здесь скоро появятся презентации.</div>
    </div>
</body>
</html>
    `);
});

// Тесты
app.get('/tests.html', requireAuth, (req, res) => {
    const username = req.session.user;
    res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Тесты</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <a href="/" class="btn btn-outline-primary me-3">Главное меню</a>
            <span class="navbar-brand mx-auto mb-0 h1">Обучающий сайт</span>
            <div class="d-flex ms-auto align-items-center">
                <span class="me-2">${username}</span>
                <a href="/cabinet" class="btn btn-outline-secondary">Личный кабинет</a>
            </div>
        </div>
    </nav>
    <div class="container py-4">
        <h1 class="mb-4">Тесты</h1>
        <div class="alert alert-info">Здесь скоро появятся тесты.</div>
    </div>
</body>
</html>
    `);
});

// Админка и видео CRUD
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
    const username = req.session.user;
    res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Админ-панель</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <a href="/" class="btn btn-outline-primary me-3">Главное меню</a>
            <span class="navbar-brand mx-auto mb-0 h1">Обучающий сайт</span>
            <div class="d-flex ms-auto align-items-center">
                <span class="me-2">${username}</span>
                <a href="/cabinet" class="btn btn-outline-secondary">Личный кабинет</a>
            </div>
        </div>
    </nav>
    <div class="container py-4">
        <h1 class="mb-4">Админ-панель</h1>
        <button class="btn btn-warning mb-3" onclick="window.location.href='/video-list'">Редактирование видео</button>
    </div>
</body>
</html>
    `);
});
app.get('/api/videos', requireAuth, requireAdmin, (req, res) => {
    db.all('SELECT * FROM videos', (err, rows) => {
        if (err) return res.json([]);
        res.json(rows);
    });
});
app.post('/admin/edit-video/:id', requireAuth, requireAdmin, (req, res) => {
    const id = req.params.id;
    const { title, topic } = req.body;
    db.run(
        'UPDATE videos SET title = ?, topic = ? WHERE id = ?',
        [title, topic, id],
        (err) => {
            if (err) return res.status(500).send('Ошибка редактирования');
            res.sendStatus(200);
        }
    );
});
app.delete('/admin/delete-video/:id', requireAuth, requireAdmin, (req, res) => {
    const id = req.params.id;
    db.get('SELECT filename FROM videos WHERE id = ?', [id], (err, row: { filename?: string } | undefined) => {
        if (!row || !row.filename) return res.status(404).send('Видео не найдено');
        const filePath = path.join(__dirname, '../public/videos', row.filename);
        db.run('DELETE FROM videos WHERE id = ?', [id], (err) => {
            if (err) return res.status(500).send('Ошибка удаления из базы');
            fs.unlink(filePath, () => {
                res.sendStatus(200);
            });
        });
    });
});
app.get('/video-list', requireAuth, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, '../public/video-list.html'));
});
const upload = multer({
    dest: path.join(__dirname, '../public/videos')
});
app.post('/admin/upload-video', requireAuth, requireAdmin, upload.single('video'), (req, res) => {
    const { title, topic } = req.body;
    if (!req.file || !req.file.filename) {
        return res.status(400).send('Файл видео не загружен');
    }
    const filename = req.file.filename;
    db.run(
        'INSERT INTO videos (title, filename, topic) VALUES (?, ?, ?)',
        [title, filename, topic || 'Без темы'],
        (err) => {
            res.redirect('/admin');
        }
    );
});

// Восстановление пароля
app.get('/forgot', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/public/forgot.html'));
});
app.post('/forgot', (req, res) => {
    const { email } = req.body;
    db.get('SELECT username, email FROM users WHERE email = ?', [email], async (err, user: { username?: string, email?: string } | undefined) => {
        if (!user || !user.email) {
            return res.redirect('/forgot?error=Пользователь с таким email не найден');
        }
        const tempPassword = Math.random().toString(36).slice(-8);
        const passwordHash = await bcrypt.hash(tempPassword, 10);
        db.run('UPDATE users SET passwordHash = ? WHERE email = ?', [passwordHash, email], (err) => {
            if (err) return res.redirect('/forgot?error=Ошибка восстановления');
            const mailOptions = {
                from: 'denistc@mail.ru',
                to: email,
                subject: 'Восстановление пароля',
                text: `Ваш временный пароль: ${tempPassword}`
            };
            (nodemailer.createTransport({
                host: 'smtp.mail.ru',
                port: 465,
                secure: true,
                auth: {
                    user: 'denistc@mail.ru',
                    pass: 'i60SaEpwa4apKNEsMQte'
                }
            })).sendMail(
                mailOptions,
                (error: Error | null, info: any) => {
                    if (error) {
                        return res.redirect('/forgot?error=Ошибка отправки письма');
                    }
                    res.redirect('/login?error=Вам на почту отправлен временный пароль');
                }
            );
        });
    });
});

app.listen(port, () => {
    console.log(`Сайт запущен: http://localhost:${port}`);
});