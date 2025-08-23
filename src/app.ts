import express from 'express';
import path from 'path';
import session from 'express-session';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import { hashPassword, verifyPassword, isArgon2Hash } from './security/passwords';
import nodemailer from 'nodemailer';
import fs from 'fs';
import dotenv from 'dotenv';
import helmet from 'helmet';
// Safe dynamic require for compression to avoid build-time issues if package/types are missing
// Use type any to avoid TS complaining when types aren't present
let compression: any;
try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    compression = require('compression');
} catch {
    compression = () => (_req: express.Request, _res: express.Response, next: express.NextFunction) => next();
}
import crypto from 'crypto';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import connectSqlite3 from 'connect-sqlite3';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';
import { db, logAdminAction } from './db';
import { validateBody, loginSchema, registerSchema, forgotSchema, changePasswordSchema, topicSchema, deleteTopicSchema, videoMetaSchema, auditClearSchema, upsertVideoTestSchema, deleteVideoTestSchema, updateVideoTestSchema, requestResetSchema, resetPasswordSchema, courseSchema, lecturerAccessSchema, webinarToggleSchema, webinarAddSchema, groupSchema, groupIdSchema, groupMembershipSchema, groupRenameSchema, webinarAttendeeUserSchema, webinarAttendeeGroupSchema, upsertWebinarTestSchema, updateWebinarTestSchema, deleteWebinarTestSchema, adminCreateUserSchema, adminUpdateUserSchema, adminDeleteUserSchema } from './middleware/validators';
import { sampleTest } from './tests';
import { requireAuth, requireAdmin, requireLecturer, isLecturer } from './middleware/auth';
import userRouter from './routes/user';
import { config } from './config';

dotenv.config();
const app = express();
// Global cookie security toggle: set COOKIE_SECURE=false to allow cookies over HTTP in local prod
const IS_PROD = config.isProd;
const IS_TEST = config.isTest;
const COOKIE_SECURE = config.cookieSecure;
const SQLiteStore = connectSqlite3(session);
// Views (EJS) located at project-root /views
app.set('views', path.join(__dirname, '..', 'views'));
app.set('view engine', 'ejs');
// Process-level error handlers to avoid silent crashes
process.on('unhandledRejection', (reason: any) => {
    console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err: any) => {
    console.error('Uncaught Exception:', err);
});
// Extra diagnostics for unexpected exits/signals
process.on('exit', (code) => {
    try { console.error('[process.exit] code=', code); } catch {}
});
['SIGINT','SIGTERM'].forEach((sig) => {
    try {
        process.on(sig as NodeJS.Signals, () => {
            try { console.error('[signal]', sig, 'received'); } catch {}
        });
    } catch {}
});
// Body parsers
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(express.json({ limit: '200kb' }));
// Security & logging
app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            fontSrc: ["'self'", 'data:'],
            imgSrc: ["'self'", 'data:'],
            mediaSrc: ["'self'"],
            connectSrc: ["'self'"],
            frameAncestors: ["'self'"],
        }
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' }
}));
// HTTP compression for HTML/CSS/JS/EJS responses
app.use(compression());
// Additional hardening headers not covered above
app.use((req, res, next) => {
    // Tighten browser features
    res.setHeader('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
    // HSTS only when using secure cookies and production
    if (IS_PROD && COOKIE_SECURE) {
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    }
    next();
});
app.use(morgan('dev'));
app.use(cookieParser());
// Trust proxy if behind reverse proxy (e.g., Heroku/NGINX)
if (config.trustProxy) {
    app.set('trust proxy', 1);
}
// CSRF protection: store secret in httpOnly cookie; send readable token separately on GET pages
const csrfProtection = csurf({ cookie: { sameSite: 'lax', httpOnly: true, secure: COOKIE_SECURE } });

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }); // generic
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }); // IP-based
// Username+IP based limiter for POST /login; successful requests are skipped
const loginByUserLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    keyGenerator: (req: any /* express.Request */) => {
        const u = (req.body?.username || '').toString().trim().toLowerCase();
        return `${req.ip}|${u}`;
    }
});
const registerLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const forgotLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    rolling: config.session.rolling,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: COOKIE_SECURE,
        // Convert hours to ms
        maxAge: Math.max(15 * 60 * 1000, (config.session.ttlHours || 24) * 60 * 60 * 1000)
    },
    store: IS_TEST ? undefined as any : new SQLiteStore({ db: 'sessions.sqlite', dir: path.join(__dirname, '../data') })
}));
// Expose common locals for EJS templates (after session is initialized)
app.use((req, res, next) => {
    res.locals.username = req.session?.user || '';
    res.locals.isAdmin = req.session?.role === 'admin';
    (res.locals as any).role = req.session?.role || '';
    (res.locals as any).assetVersion = config.assetVersion;
    next();
});
// Protect direct access to public/index.html and disable automatic index at '/'
app.get('/', requireAuth, (req: express.Request, res: express.Response) => {
    const username = req.session.user || '';
    const isAdmin = (req.session.role === 'admin');
    res.render('home', { username, isAdmin });
});
// Resolve video storage directory (env override enables persistent disk mounts in prod)
const VIDEO_DIR = process.env.VIDEO_DIR || path.join(__dirname, '../public/videos');
try { fs.mkdirSync(VIDEO_DIR, { recursive: true }); } catch {}

// Server-side gating for video files based on progress
function checkVideoUnlocked(req: express.Request, res: express.Response, next: express.NextFunction) {
    try {
        const username = req.session.user as string;
        if (!username) return res.status(401).send('Требуется вход');
        // Extract requested filename
        const p = (req.path || '').split('/');
        const raw = p[p.length - 1] || '';
        const filename = decodeURIComponent(raw);
        if (!filename) return res.status(404).send('Не найдено');
        // Lookup video by filename
        db.get('SELECT id, topic FROM videos WHERE filename = ?', [filename], (e: any, video: any) => {
            if (e) return res.status(500).send('Ошибка базы');
            if (!video) {
                // Unknown file: do not serve
                return res.status(404).send('Видео не найдено');
            }
            // Determine index within topic order (by custom position, then id)
            db.all('SELECT id FROM videos WHERE topic = ? ORDER BY position ASC, id ASC', [video.topic], (e2: any, rows: Array<{id:number}>) => {
                if (e2 || !rows || rows.length === 0) return res.status(404).send('Видео не найдено');
                const idx = rows.findIndex(r => r.id === video.id);
                if (idx < 0) return res.status(404).send('Видео не найдено');
                db.get('SELECT unlockedCount FROM user_progress WHERE username = ? AND topic = ?', [username, video.topic], (e3: any, prog: any) => {
                    if (e3) return res.status(500).send('Ошибка прогресса');
                    const unlocked = prog ? Number(prog.unlockedCount) : 1;
                    if (idx < unlocked) {
                        return next();
                    } else {
                        res.status(403).send('<div style="font-family:sans-serif;padding:2rem">Доступ закрыт. Пройдите тест предыдущего видео, чтобы открыть это. <a href="/videos.html">К списку видео</a></div>');
                    }
                });
            });
        });
    } catch (err) {
        return res.status(500).send('Ошибка');
    }
}
// Apply gating and then serve from both current and legacy folders
app.use('/videos', requireAuth, checkVideoUnlocked);
app.use('/videos', express.static(VIDEO_DIR));
// Note: root static will be mounted later, after dynamic routes, to avoid shadowing pages like /videos.html
// Routers
app.use(userRouter);
// Типы сессии (user, role, message)
declare module 'express-session' {
    interface SessionData {
        user?: string;
        role?: string;
        message?: string;
    }
}
// --- end of typings augmentation ---

// Optional session debug
if (process.env.DEBUG_AUTH === '1') {
    app.get('/debug-session', (req: express.Request, res: express.Response) => {
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify({ sid: (req as any).sessionID, user: req.session.user, role: req.session.role, cookie: req.headers.cookie || '' }, null, 2));
    });
    app.get('/debug-set-session', (req: express.Request, res: express.Response) => {
        req.session.user = 'TrueMaBadi';
        req.session.role = 'admin';
        req.session.save(() => {
            res.json({ ok: true, user: req.session.user, role: req.session.role });
        });
    });
}


app.post('/change-password', requireAuth, csrfProtection, validateBody(changePasswordSchema, '/cabinet'), async (req: express.Request, res: express.Response) => {
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
    const isMatch = await verifyPassword(currentPassword, row.passwordHash);
        if (!isMatch) {
            req.session.message = 'Текущий пароль неверен.';
            return res.redirect('/cabinet');
        }
    const newHash = await hashPassword(newPassword);
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

app.get('/logout', (req: express.Request, res: express.Response) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Админпанель
app.get('/admin', requireAuth, requireAdmin, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.render('admin/index');
});
// Журнал действий администратора (просмотр)
app.get('/admin/audit', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const qUser = (req.query.user as string) || '';
    const qAction = (req.query.action as string) || '';
    const qDays = Number(req.query.days || 0);
    const where: string[] = [];
    const params: any[] = [];
    if (qUser) { where.push('username = ?'); params.push(qUser); }
    if (qAction) { where.push('action = ?'); params.push(qAction); }
    if (qDays > 0) { where.push('created_at >= datetime("now", ? )'); params.push('-' + qDays + ' days'); }
    const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
    const sql = 'SELECT id, username, action, entity, entity_id, created_at FROM admin_audit' + whereSql + ' ORDER BY id DESC LIMIT 200';
    db.all(sql, params, (err, rows: any[]) => {
        if (err) return res.status(500).send('Ошибка загрузки журнала');
    const csrfToken = (req as any).csrfToken();
    const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
    res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
        res.render('admin/audit', { rows: rows || [], qUser, qAction, qDays, csrfToken, warning });
    });
});
// Журнал действий администратора
// Личный кабинет
app.get('/cabinet', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const isAdmin = req.session.role === 'admin';
    const message = req.session.message || '';
    req.session.message = undefined;
    const username = req.session.user || '';
    const csrfToken = (req as any).csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    res.render('cabinet', { username, isAdmin, message, csrfToken });
});

// CSV export for audit log
app.get('/admin/audit.csv', requireAuth, requireAdmin, (req: express.Request, res: express.Response) => {
        const qUser = (req.query.user as string) || '';
        const qAction = (req.query.action as string) || '';
        const qDays = Number(req.query.days || 0);
        const where: string[] = [];
        const params: any[] = [];
        if (qUser) { where.push('username = ?'); params.push(qUser); }
        if (qAction) { where.push('action = ?'); params.push(qAction); }
        if (qDays > 0) { where.push('created_at >= datetime("now", ? )'); params.push('-' + qDays + ' days'); }
        const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
        const sql = 'SELECT id, username, action, entity, entity_id, created_at FROM admin_audit' + whereSql + ' ORDER BY id DESC LIMIT 10000';
        db.all(sql, params, (err, rows: any[]) => {
                if (err) return res.status(500).send('Ошибка экспорта');
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.setHeader('Content-Disposition', 'attachment; filename="audit.csv"');
                const header = 'id,username,action,entity,entity_id,created_at\n';
                const body = (rows || []).map(r => [r.id, r.username, r.action, r.entity, r.entity_id, r.created_at]
                        .map(v => (v == null ? '' : String(v).replace(/"/g, '""')))
                        .map(v => '"' + v + '"').join(',')).join('\n');
                res.send('\uFEFF' + header + body);
        });
});

app.post('/admin/audit/clear', requireAuth, requireAdmin, csrfProtection, validateBody(auditClearSchema, '/admin/audit'), (req: express.Request, res: express.Response) => {
    const { mode, days } = req.body as { mode: 'all' | 'days'; days?: number };
    if (mode === 'all') {
        db.run('DELETE FROM admin_audit', [], (err) => {
            return res.redirect('/admin/audit');
        });
    } else {
        const cutoff = '-' + Number(days) + ' days';
        db.run('DELETE FROM admin_audit WHERE created_at < datetime("now", ?)', [cutoff], (err) => {
            return res.redirect('/admin/audit');
        });
    }
});

// Admin: Users list and per-user progress control
app.get('/admin/users', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    db.all('SELECT username, role, COALESCE(email, "") as email FROM users ORDER BY role DESC, username ASC', (err, users: Array<{username:string; role:string; email?:string}>) => {
        if (err) return res.status(500).send('Ошибка загрузки пользователей');
        const csrfToken = (req as any).csrfToken();
        res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
    const message = typeof req.query.message === 'string' ? req.query.message : '';
    res.render('admin/users', { users: users || [], csrfToken, warning, message });
    });
});

// Admin: create user
app.post('/admin/users/create', requireAuth, requireAdmin, csrfProtection, validateBody(adminCreateUserSchema, '/admin/users'), async (req: express.Request, res: express.Response) => {
    const { username, password, email, role } = req.body as any;
    try {
    const hash = await hashPassword(password);
        db.run('INSERT INTO users (username, passwordHash, role, email) VALUES (?, ?, ?, ?)', [username, hash, role, email || null], (err) => {
            if (err) {
                const msg = (String(err.message || '')).toLowerCase().includes('constraint') || String(err.message || '').includes('SQLITE_CONSTRAINT')
                    ? 'Пользователь с таким логином уже существует'
                    : 'Не удалось создать пользователя';
                return res.redirect('/admin/users?warning=' + encodeURIComponent(msg));
            }
            logAdminAction(req.session.user || 'unknown', 'create_user', 'users', username);
            return res.redirect('/admin/users?message=' + encodeURIComponent('Пользователь создан'));
        });
    } catch (e) {
        return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось создать пользователя'));
    }
});

// Admin: update user (role/email/password)
app.post('/admin/users/update', requireAuth, requireAdmin, csrfProtection, validateBody(adminUpdateUserSchema, '/admin/users'), async (req: express.Request, res: express.Response) => {
    const { username, email, role, password } = req.body as any;
    const doPass = typeof password === 'string' && password.trim().length >= 6;
    try {
        // Prevent self-demotion
        if ((req.session.user || '').toLowerCase() === String(username).toLowerCase() && role !== 'admin') {
            return res.redirect('/admin/users?warning=' + encodeURIComponent('Нельзя понижать собственную роль'));
        }
        db.get('SELECT role FROM users WHERE LOWER(username) = LOWER(?)', [username], async (e0: any, row: any) => {
            if (e0) return res.redirect('/admin/users?warning=' + encodeURIComponent('Ошибка загрузки пользователя'));
            if (!row) return res.redirect('/admin/users?warning=' + encodeURIComponent('Пользователь не найден'));
            // Prevent demoting last admin
            if (String(row.role || 'user') === 'admin' && role !== 'admin') {
                db.get('SELECT COUNT(*) AS cnt FROM users WHERE role = "admin"', [], async (e1: any, c: any) => {
                    if (e1) return res.redirect('/admin/users?warning=' + encodeURIComponent('Ошибка проверки ролей'));
                    if (c && Number(c.cnt) <= 1) {
                        return res.redirect('/admin/users?warning=' + encodeURIComponent('Нельзя понижать последнего администратора'));
                    }
                    // proceed update
                    try {
                        if (doPass) {
                            const hash = await hashPassword(password);
                            db.run('UPDATE users SET email = ?, role = ?, passwordHash = ? WHERE LOWER(username) = LOWER(?)', [email || null, role, hash, username], (err) => {
                                if (err) return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
                                logAdminAction(req.session.user || 'unknown', 'update_user', 'users', username);
                                return res.redirect('/admin/users?message=' + encodeURIComponent('Изменения сохранены'));
                            });
                        } else {
                            db.run('UPDATE users SET email = ?, role = ? WHERE LOWER(username) = LOWER(?)', [email || null, role, username], (err) => {
                                if (err) return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
                                logAdminAction(req.session.user || 'unknown', 'update_user', 'users', username);
                                return res.redirect('/admin/users?message=' + encodeURIComponent('Изменения сохранены'));
                            });
                        }
                    } catch {
                        return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
                    }
                });
            } else {
                // proceed without last-admin restriction
                try {
                    if (doPass) {
                        const hash = await hashPassword(password);
                        db.run('UPDATE users SET email = ?, role = ?, passwordHash = ? WHERE LOWER(username) = LOWER(?)', [email || null, role, hash, username], (err) => {
                            if (err) return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
                            logAdminAction(req.session.user || 'unknown', 'update_user', 'users', username);
                            return res.redirect('/admin/users?message=' + encodeURIComponent('Изменения сохранены'));
                        });
                    } else {
                        db.run('UPDATE users SET email = ?, role = ? WHERE LOWER(username) = LOWER(?)', [email || null, role, username], (err) => {
                            if (err) return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
                            logAdminAction(req.session.user || 'unknown', 'update_user', 'users', username);
                            return res.redirect('/admin/users?message=' + encodeURIComponent('Изменения сохранены'));
                        });
                    }
                } catch {
                    return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
                }
            }
        });
    } catch (e) {
        return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось сохранить изменения'));
    }
});

// Admin: delete user
app.post('/admin/users/delete', requireAuth, requireAdmin, csrfProtection, validateBody(adminDeleteUserSchema, '/admin/users'), (req: express.Request, res: express.Response) => {
    const { username } = req.body as any;
    if ((req.session.user || '').toLowerCase() === String(username).toLowerCase()) {
        return res.redirect('/admin/users?warning=' + encodeURIComponent('Нельзя удалить себя'));
    }
    db.get('SELECT role FROM users WHERE LOWER(username) = LOWER(?)', [username], (e0: any, row: any) => {
        if (e0) return res.redirect('/admin/users?warning=' + encodeURIComponent('Ошибка загрузки пользователя'));
        if (!row) return res.redirect('/admin/users?warning=' + encodeURIComponent('Пользователь не найден'));
        if (String(row.role || 'user') === 'admin') {
            db.get('SELECT COUNT(*) AS cnt FROM users WHERE role = "admin"', [], (e1: any, c: any) => {
                if (e1) return res.redirect('/admin/users?warning=' + encodeURIComponent('Ошибка проверки ролей'));
                if (c && Number(c.cnt) <= 1) {
                    return res.redirect('/admin/users?warning=' + encodeURIComponent('Нельзя удалять последнего администратора'));
                }
                db.run('DELETE FROM users WHERE LOWER(username) = LOWER(?)', [username], (err) => {
                    if (err) return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось удалить пользователя'));
                    logAdminAction(req.session.user || 'unknown', 'delete_user', 'users', username);
                    return res.redirect('/admin/users?message=' + encodeURIComponent('Пользователь удалён'));
                });
            });
        } else {
            db.run('DELETE FROM users WHERE LOWER(username) = LOWER(?)', [username], (err) => {
                if (err) return res.redirect('/admin/users?warning=' + encodeURIComponent('Не удалось удалить пользователя'));
                logAdminAction(req.session.user || 'unknown', 'delete_user', 'users', username);
                return res.redirect('/admin/users?message=' + encodeURIComponent('Пользователь удалён'));
            });
        }
    });
});
    // Admin: Groups management page
    app.get('/admin/groups', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
        res.setHeader('Cache-Control', 'no-store');
        const csrfToken = (req as any).csrfToken();
        db.serialize(() => {
            db.all('SELECT id, name FROM groups ORDER BY name', [], (e1: any, groups: any[]) => {
                if (e1) return res.status(500).send('Ошибка загрузки групп');
                db.all('SELECT username FROM users ORDER BY username', [], (e2: any, users: any[]) => {
                    if (e2) return res.status(500).send('Ошибка загрузки пользователей');
                    db.all('SELECT ug.username, ug.group_id, g.name AS group_name FROM user_groups ug JOIN groups g ON g.id = ug.group_id ORDER BY ug.username, g.name', [], (e3: any, members: any[]) => {
                        if (e3) return res.status(500).send('Ошибка загрузки участников');
                        res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
                        res.render('admin/groups', { csrfToken, groups: groups || [], users: users || [], members: members || [] });
                    });
                });
            });
        });
    });

    // Admin: create group
    app.post('/admin/groups/add', requireAuth, requireAdmin, csrfProtection, validateBody(groupSchema, '/admin/groups'), (req: express.Request, res: express.Response) => {
        const { name } = req.body as any;
        db.run('INSERT OR IGNORE INTO groups (name) VALUES (?)', [name], (err) => {
            if (!err) logAdminAction(req.session.user || 'unknown', 'add_group', 'groups', name);
            res.redirect('/admin/groups');
        });
    });

    // Admin: delete group
    app.post('/admin/groups/delete', requireAuth, requireAdmin, csrfProtection, validateBody(groupIdSchema, '/admin/groups'), (req: express.Request, res: express.Response) => {
        const { id } = req.body as any;
        db.run('DELETE FROM groups WHERE id = ?', [id], (err) => {
            if (!err) logAdminAction(req.session.user || 'unknown', 'delete_group', 'groups', String(id));
            res.redirect('/admin/groups');
        });
    });

    // Admin: group details (JSON) for modal
    app.get('/admin/groups/:id', requireAuth, requireAdmin, (req: express.Request, res: express.Response) => {
        const id = Number(req.params.id);
        const wantsJson = typeof req.headers['accept'] === 'string' && (req.headers['accept'] as string).includes('application/json');
        if (!Number.isFinite(id)) return res.status(wantsJson ? 400 : 404).json({ ok: false, error: 'Некорректный ID' });
        db.get('SELECT id, name FROM groups WHERE id = ?', [id], (e0: any, group: any) => {
            if (e0 || !group) return res.status(404).json({ ok: false, error: 'Группа не найдена' });
            db.all('SELECT username FROM user_groups WHERE group_id = ? ORDER BY username', [id], (e1: any, members: any[]) => {
                if (e1) return res.status(500).json({ ok: false });
                const memberSet = new Set((members || []).map((m: any) => m.username));
                db.all('SELECT username FROM users ORDER BY username', [], (e2: any, users: any[]) => {
                    if (e2) return res.status(500).json({ ok: false });
                    const available = (users || []).filter((u: any) => !memberSet.has(u.username));
                    res.json({ ok: true, group, members: members || [], availableUsers: available });
                });
            });
        });
    });

    // Admin: rename group
    app.post('/admin/groups/rename', requireAuth, requireAdmin, csrfProtection, validateBody(groupRenameSchema, '/admin/groups'), (req: express.Request, res: express.Response) => {
        const { id, name } = req.body as any;
        const wantsJson = typeof req.headers['accept'] === 'string' && (req.headers['accept'] as string).includes('application/json');
        db.run('UPDATE groups SET name = ? WHERE id = ?', [name, id], (err) => {
            if (!err) logAdminAction(req.session.user || 'unknown', 'rename_group', 'groups', String(id));
            if (wantsJson) {
                return res.status(err ? 500 : 200).json({ ok: !err, group: { id, name } });
            }
            res.redirect('/admin/groups');
        });
    });

    // Admin: add user to group
    app.post('/admin/groups/members/add', requireAuth, requireAdmin, csrfProtection, validateBody(groupMembershipSchema, '/admin/groups'), (req: express.Request, res: express.Response) => {
        const { username, groupId } = req.body as any;
        const wantsJson = typeof req.headers['accept'] === 'string' && (req.headers['accept'] as string).includes('application/json');
        db.run('INSERT OR IGNORE INTO user_groups (username, group_id) VALUES (?, ?)', [username, groupId], (err) => {
            if (!err) logAdminAction(req.session.user || 'unknown', 'add_user_to_group', 'user_groups', username + ':' + groupId);
            if (!wantsJson) return res.redirect('/admin/groups');
            // Return updated membership lists
            db.all('SELECT username FROM user_groups WHERE group_id = ? ORDER BY username', [groupId], (e1:any, members:any[]) => {
                if (e1) return res.status(500).json({ ok: false });
                const memberSet = new Set((members||[]).map((m:any)=>m.username));
                db.all('SELECT username FROM users ORDER BY username', [], (e2:any, users:any[]) => {
                    if (e2) return res.status(500).json({ ok: false });
                    const available = (users||[]).filter((u:any)=> !memberSet.has(u.username));
                    res.json({ ok: true, members: members||[], availableUsers: available });
                });
            });
        });
    });

    // Admin: remove user from group
    app.post('/admin/groups/members/remove', requireAuth, requireAdmin, csrfProtection, validateBody(groupMembershipSchema, '/admin/groups'), (req: express.Request, res: express.Response) => {
        const { username, groupId } = req.body as any;
        const wantsJson = typeof req.headers['accept'] === 'string' && (req.headers['accept'] as string).includes('application/json');
        db.run('DELETE FROM user_groups WHERE username = ? AND group_id = ?', [username, groupId], (err) => {
            if (!err) logAdminAction(req.session.user || 'unknown', 'remove_user_from_group', 'user_groups', username + ':' + groupId);
            if (!wantsJson) return res.redirect('/admin/groups');
            db.all('SELECT username FROM user_groups WHERE group_id = ? ORDER BY username', [groupId], (e1:any, members:any[]) => {
                if (e1) return res.status(500).json({ ok: false });
                const memberSet = new Set((members||[]).map((m:any)=>m.username));
                db.all('SELECT username FROM users ORDER BY username', [], (e2:any, users:any[]) => {
                    if (e2) return res.status(500).json({ ok: false });
                    const available = (users||[]).filter((u:any)=> !memberSet.has(u.username));
                    res.json({ ok: true, members: members||[], availableUsers: available });
                });
            });
        });
    });

app.get('/admin/user/:username/progress', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const u = (req.params.username || '').toString();
    db.all('SELECT name FROM topics ORDER BY name ASC', (e1, topics: Array<{name:string}>) => {
        if (e1) return res.status(500).send('Ошибка загрузки разделов');
        const names = (topics || []).map(t => ({ name: t.name }));
        const selected = typeof req.query.topic === 'string' ? req.query.topic : (names[0]?.name || '');
        db.get('SELECT unlockedCount FROM user_progress WHERE username = ? AND topic = ?', [u, selected], (e2, row: any) => {
            const totalQuery = 'SELECT COUNT(*) as total FROM videos WHERE topic = ?';
            db.get(totalQuery, [selected], (e3, totalRow: any) => {
                const total = Number(totalRow?.total || 0);
                const unlockedCount = Number(row?.unlockedCount || 1);
                const passed = Math.max(0, Math.min(total, unlockedCount - 1));
                const csrfToken = (req as any).csrfToken();
                res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
                const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
                res.render('admin/user-progress', { username: u, topics: names, topic: selected, passed, csrfToken, warning });
            });
        });
    });
});

app.post('/admin/user-progress/mark', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = (req.body?.username || '').toString();
    const topic = (req.body?.topic || '').toString();
    const op = (req.body?.op || '').toString(); // 'inc' | 'dec'
    if (!username || !topic || !/(inc|dec)/.test(op)) return res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress?topic=' + encodeURIComponent(topic) + '&warning=' + encodeURIComponent('Некорректные данные'));
    db.all('SELECT id FROM videos WHERE topic = ? ORDER BY position, id', [topic], (e1, vids: any[]) => {
        if (e1) return res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress?topic=' + encodeURIComponent(topic) + '&warning=' + encodeURIComponent('Ошибка'));
        const total = (vids||[]).length;
        db.get('SELECT unlockedCount, lastWatchedIndex FROM user_progress WHERE username = ? AND topic = ?', [username, topic], (e2, row: any) => {
            const current = row ? Number(row.unlockedCount) : 1;
            let next = current + (op === 'inc' ? 1 : -1);
            const minAllowed = 1;
            const maxAllowed = Math.max(1, total + 1);
            if (next < minAllowed) next = minAllowed;
            if (next > maxAllowed) next = maxAllowed;
            const last = row ? Number(row.lastWatchedIndex) : -1;
            const newLast = Math.min(last, Math.min(total - 1, next - 1));
            db.run('INSERT INTO user_progress (username, topic, unlockedCount, lastWatchedIndex) VALUES (?, ?, ?, ?) ON CONFLICT(username, topic) DO UPDATE SET unlockedCount = excluded.unlockedCount, lastWatchedIndex = excluded.lastWatchedIndex', [username, topic, next, newLast], (e3) => {
                if (e3) return res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress?topic=' + encodeURIComponent(topic) + '&warning=' + encodeURIComponent('Ошибка'));
                logAdminAction(req.session.user || 'unknown', 'admin_mark_user_progress', 'user_progress', username + ':' + topic + '->' + next);
                res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress');
            });
        });
    });
});

app.post('/admin/user-progress/set', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = (req.body?.username || '').toString();
    const topic = (req.body?.topic || '').toString();
    const requestedPassed = Number((req.body?.passed || ''));
    if (!username || !topic || !Number.isFinite(requestedPassed)) return res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress?topic=' + encodeURIComponent(topic) + '&warning=' + encodeURIComponent('Некорректные данные'));
    db.all('SELECT id FROM videos WHERE topic = ? ORDER BY position, id', [topic], (e1, vids: any[]) => {
        if (e1) return res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress?topic=' + encodeURIComponent(topic) + '&warning=' + encodeURIComponent('Ошибка'));
    const total = (vids||[]).length;
    const minPassed = 0;
    const maxPassed = Math.max(0, total);
    const normalizedPassed = Math.max(minPassed, Math.min(maxPassed, requestedPassed));
    const next = normalizedPassed + 1; // unlockedCount
        db.get('SELECT lastWatchedIndex FROM user_progress WHERE username = ? AND topic = ?', [username, topic], (e2, row: any) => {
            const last = row ? Number(row.lastWatchedIndex) : -1;
            const newLast = Math.min(last, Math.min(total - 1, next - 1));
            db.run('INSERT INTO user_progress (username, topic, unlockedCount, lastWatchedIndex) VALUES (?, ?, ?, ?) ON CONFLICT(username, topic) DO UPDATE SET unlockedCount = excluded.unlockedCount, lastWatchedIndex = excluded.lastWatchedIndex', [username, topic, next, newLast], (e3) => {
                if (e3) return res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress?topic=' + encodeURIComponent(topic) + '&warning=' + encodeURIComponent('Ошибка'));
                logAdminAction(req.session.user || 'unknown', 'admin_set_user_progress', 'user_progress', username + ':' + topic + '->' + next);
                res.redirect('/admin/user/' + encodeURIComponent(username) + '/progress');
            });
        });
    });
});

// Аутентификация
app.get('/login', authLimiter, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    res.sendFile(path.join(__dirname, '../public/login.html'));
});
app.post('/login', loginLimiter, loginByUserLimiter, csrfProtection, validateBody(loginSchema, '/login'), async (req: express.Request, res: express.Response) => {
    const delay = (ms: number) => new Promise(r => setTimeout(r, ms));
    const { username, password } = req.body as { username: string; password: string };
    db.get('SELECT username, passwordHash, role FROM users WHERE username = ?', [username], async (err, row: { username?: string, passwordHash?: string, role?: string } | undefined) => {
        if (err || !row || !row.passwordHash) {
            await delay(350);
            return res.redirect('/login?error=Неверные данные');
        }
        const ok = await verifyPassword(password, row.passwordHash);
        if (!ok) {
            await delay(350);
            return res.redirect('/login?error=Неверные данные');
        }
        // Opportunistic upgrade: if legacy bcrypt, rehash with Argon2
        if (!isArgon2Hash(row.passwordHash)) {
            try {
                const upgraded = await hashPassword(password);
                db.run('UPDATE users SET passwordHash = ? WHERE username = ?', [upgraded, row.username], () => {});
            } catch {}
        }
        // Regenerate session to prevent fixation
        req.session.regenerate((regenErr) => {
            if (regenErr) {
                return res.redirect('/login?error=' + encodeURIComponent('Ошибка входа, попробуйте ещё раз'));
            }
            req.session.user = row.username!;
            req.session.role = row.role || 'user';
            if (config.debugAuth) {
                try { console.log('[LOGIN] COOKIE_SECURE=', COOKIE_SECURE, 'user=', req.session.user, 'role=', req.session.role); } catch {}
            }
            // Ensure session is persisted before redirecting
            req.session.save((saveErr) => {
                if (saveErr) {
                    return res.redirect('/login?error=' + encodeURIComponent('Ошибка входа, попробуйте ещё раз'));
                }
                if (config.debugAuth) {
                    try { console.log('[LOGIN] Set-Cookie header just before redirect:', res.getHeader('Set-Cookie')); } catch {}
                }
                res.redirect('/');
            });
        });
    });
});

// Регистрация
app.get('/register', authLimiter, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    res.sendFile(path.join(__dirname, '../public/register.html'));
});
app.post('/register', registerLimiter, csrfProtection, validateBody(registerSchema, '/register'), async (req: express.Request, res: express.Response) => {
    const { username, password, email } = req.body as { username: string; password: string; email: string };
    db.get('SELECT 1 FROM users WHERE username = ? OR email = ?', [username, email], async (err, row: any) => {
        if (err) return res.redirect('/register?error=Ошибка базы данных');
        if (row) return res.redirect('/register?error=Имя или email уже заняты');
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, passwordHash, role, email) VALUES (?, ?, ?, ?)', [username, hash, 'user', email], (insErr) => {
            if (insErr) return res.redirect('/register?error=Ошибка регистрации');
            req.session.user = username;
            req.session.role = 'user';
            res.redirect('/');
        });
    });
});

// Восстановление пароля
app.get('/forgot', authLimiter, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    res.sendFile(path.join(__dirname, '../public/forgot.html'));
});
app.post('/forgot', forgotLimiter, csrfProtection, validateBody(requestResetSchema, '/forgot'), (req: express.Request, res: express.Response) => {
    const { email } = req.body as { email: string };
    db.get('SELECT username, email FROM users WHERE email = ?', [email], async (err, user: { username?: string, email?: string } | undefined) => {
        // Всегда отвечаем одинаково, чтобы не раскрывать наличие пользователя
        const genericOk = () => res.redirect('/login?error=' + encodeURIComponent('Если такой email зарегистрирован, мы отправили ссылку для сброса.'));
        if (!user || !user.email) {
            return genericOk();
        }
    // Сгенерировать криптостойкий токен и сохранить только его хэш
        const tokenBuf = crypto.randomBytes(32);
        const token = tokenBuf.toString('base64url');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    // Сохраняем только hash
    db.run('INSERT INTO password_resets (username, email, token_hash, expires_at) VALUES (?, ?, ?, ?)', [user.username, email, tokenHash, expiresAt], (insErr) => {
            if (insErr) return genericOk();
            const baseUrl = config.publicUrl;
            const link = `${baseUrl}/reset?token=${encodeURIComponent(token)}`;
            const mailOptions = {
                from: config.smtp.user,
                to: email,
                subject: 'Сброс пароля',
                text: `Для сброса пароля перейдите по ссылке: ${link}\nСсылка действует 1 час.`
            };
            const isProd = config.isProd;
            const smtpReady = !!(config.smtp.user && config.smtp.pass && config.smtp.host);
            if (!isProd || !smtpReady) {
                return genericOk();
            }
            (mailTransport()).sendMail(mailOptions, (error: Error | null) => {
                if (error) {
                    console.error('Mail send failed:', error?.message || error);
                    return genericOk();
                } else {
                    return genericOk();
                }
            });
        });
    });
});

// Reset password - open form
app.get('/reset', csrfProtection, (req: express.Request, res: express.Response) => {
    const token = (req.query.token || '').toString();
    if (!token) return res.redirect('/login?error=' + encodeURIComponent('Некорректная ссылка'));
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    db.get('SELECT username, expires_at, used_at FROM password_resets WHERE token_hash = ?', [tokenHash], (e, row: any) => {
        if (e || !row) return res.redirect('/login?error=' + encodeURIComponent('Ссылка недействительна'));
        const expired = new Date(row.expires_at).getTime() < Date.now();
        const used = !!row.used_at;
        if (expired || used) return res.redirect('/login?error=' + encodeURIComponent('Ссылка недействительна или просрочена'));
    const csrfToken = (req as any).csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
        res.render('reset-password', { csrfToken, token, error: '' });
    });
});

// Reset password - submit new password
app.post('/reset', csrfProtection, validateBody(resetPasswordSchema, '/login'), async (req: express.Request, res: express.Response) => {
    const { token, password } = req.body as { token: string; password: string; confirm: string };
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    db.get('SELECT username, expires_at, used_at FROM password_resets WHERE token_hash = ?', [tokenHash], async (e, row: any) => {
        if (e || !row) return res.redirect('/login?error=' + encodeURIComponent('Ссылка недействительна'));
        const expired = new Date(row.expires_at).getTime() < Date.now();
        const used = !!row.used_at;
        if (expired || used) return res.redirect('/login?error=' + encodeURIComponent('Ссылка недействительна или просрочена'));
    const hash = await hashPassword(password);
    db.serialize(() => {
            db.run('BEGIN');
            db.run('UPDATE users SET passwordHash = ? WHERE username = ?', [hash, row.username]);
            db.run('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?', [tokenHash]);
            db.run('COMMIT', (commitErr) => {
                if (commitErr) return res.redirect('/login?error=' + encodeURIComponent('Ошибка сохранения пароля'));
                res.redirect('/login?error=' + encodeURIComponent('Пароль изменён. Войдите с новым паролем.'));
            });
        });
    });
});

// Видео
app.get('/videos.html', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const username = req.session.user || '';
    const user = req.session.user || '';
    db.all('SELECT id, title, filename, topic FROM videos ORDER BY topic, position ASC, id ASC', (err, videos: Array<{ id: number; topic: string; title: string; filename: string }>) => {
        if (err) return res.send('Ошибка загрузки видео');
        const grouped: { [key: string]: Array<{ id: number; title: string; filename: string; topic: string }> } = {};
        (videos || []).forEach(v => {
            if (!grouped[v.topic]) grouped[v.topic] = [];
            grouped[v.topic].push(v);
        });
        db.all('SELECT topic, unlockedCount, lastWatchedIndex FROM user_progress WHERE username = ?', [user], (perr, rows: Array<{ topic: string; unlockedCount: number; lastWatchedIndex: number }>) => {
            const progress: Record<string, { unlockedCount: number; lastWatchedIndex: number }> = {};
            (rows || []).forEach(r => progress[r.topic] = { unlockedCount: r.unlockedCount, lastWatchedIndex: r.lastWatchedIndex });
            const topics = Object.keys(grouped).map(name => ({ name, videos: grouped[name] }));
            res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
            const isAdmin = (req.session.role === 'admin');
            res.render('videos', { username, topics, progress, isAdmin });
        });
    });
});

// Презентации
app.get('/presentations.html', requireAuth, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.render('presentations');
});

// Тесты по вебинарам: показывает вебинары курса, где пользователь участник (напрямую или через группу),
// и разрешает перейти к /tests.html?topic=... только когда tests_open=1 (админ может всегда)
app.get('/webinar-tests', requireAuth, (req: express.Request, res: express.Response) => {
        res.setHeader('Cache-Control', 'no-store');
        const username = req.session.user as string;
        const isAdmin = (req.session.role === 'admin');
        // Подтянуть вебинары, где пользователь участник (прямо или через группу), вместе с названием курса и первой темой курса
        const sql = `
            SELECT w.id, w.summary, w.start_time, w.end_time, w.tests_open, w.tests_open_at, w.course_id, c.name AS course_name,
                         (SELECT t.name FROM topics t WHERE t.course_id = w.course_id ORDER BY t.name LIMIT 1) AS topic_name
            FROM webinars w
            JOIN courses c ON c.id = w.course_id
            WHERE 
                EXISTS (SELECT 1 FROM webinar_attendees wa WHERE wa.webinar_id = w.id AND wa.username = ?)
                OR EXISTS (
                    SELECT 1 FROM webinar_attendee_groups wag
                    JOIN user_groups ug ON ug.group_id = wag.group_id
                    WHERE wag.webinar_id = w.id AND ug.username = ?
                )
            -- Order by start_time DESC with NULLs last in SQLite-compatible way
            ORDER BY (w.start_time IS NULL) ASC, w.start_time DESC, w.id DESC
            LIMIT 200`;
        db.all(sql, [username, username], (err, rows: any[]) => {
                if (err) return res.status(500).send('Ошибка загрузки вебинаров');
                const webinars = (rows || []).map(r => ({
                        id: Number(r.id),
                        summary: r.summary,
                        start_time: r.start_time,
                        end_time: r.end_time,
                        tests_open: !!r.tests_open || (!!r.tests_open_at && new Date(r.tests_open_at).getTime() <= Date.now()),
                        next_open_at: r.tests_open ? null : (r.tests_open_at || null),
                        course_id: Number(r.course_id),
                        course_name: r.course_name,
                        topic_name: r.topic_name
                }));
                res.render('webinar-tests', { username, isAdmin, webinars });
        });
});

// Вебинары: открытие/закрытие тестов (лектор/админ)
app.post('/admin/webinar/toggle', requireAuth, requireLecturer, csrfProtection, validateBody(webinarToggleSchema, '/admin/webinars'), (req: express.Request, res: express.Response) => {
    const { id, open } = req.body as any;
    const who = req.session.user || 'unknown';
    const ensureAccess = (cb: () => void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [id], (e: any, w: any) => {
            if (e || !w) return res.redirect('/admin/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2: any, ok: any) => {
                if (e2 || !ok) return res.redirect('/admin/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('UPDATE webinars SET tests_open = ?, opened_by = ?, opened_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE opened_at END WHERE id = ?', [open, open ? who : null, open, id], (err) => {
            if (!err) logAdminAction(who, open ? 'webinar_open_tests' : 'webinar_close_tests', 'webinars', String(id));
            res.redirect('/admin/webinars');
        });
    });
});

// Запуск тестов конкретного вебинара (лекции) с проверкой доступа и флага открытости
app.get('/webinar-tests/:id', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const username = req.session.user as string;
    const isAdmin = (req.session.role === 'admin');
    const wid = Number(req.params.id);
    if (!Number.isFinite(wid)) return res.status(400).send('Некорректный вебинар');
    db.get('SELECT id, summary, tests_open, tests_open_at FROM webinars WHERE id = ?', [wid], (e:any, w:any) => {
        if (e || !w) return res.status(404).send('Вебинар не найден');
        const title = w.summary || 'Тест вебинара';
        const scheduledAtMs = w.tests_open_at ? new Date(w.tests_open_at).getTime() : 0;
        const isScheduledOpen = !!w.tests_open_at && scheduledAtMs <= Date.now();
        const proceed = () => {
            const runQuery = () => {
                db.all('SELECT question, options_json, answer FROM webinar_tests WHERE webinar_id = ? ORDER BY position, id', [wid], (e2:any, rows:any[]) => {
                    if (e2 && String(e2.message||'').includes('no such table')) {
                        // Создать таблицу на лету и повторить
                        db.serialize(() => {
                            db.run(`CREATE TABLE IF NOT EXISTS webinar_tests (id INTEGER PRIMARY KEY AUTOINCREMENT, webinar_id INTEGER NOT NULL, question TEXT NOT NULL, options_json TEXT NOT NULL, answer INTEGER NOT NULL, position INTEGER NOT NULL DEFAULT 0, FOREIGN KEY (webinar_id) REFERENCES webinars(id) ON DELETE CASCADE)`);
                            db.run('CREATE INDEX IF NOT EXISTS idx_webinar_tests_web_pos ON webinar_tests(webinar_id, position, id)', [], () => runQuery());
                        });
                        return;
                    }
                    const test = (rows || []).map(r => ({ question: r.question, options: JSON.parse(r.options_json || '[]'), answer: Number(r.answer) }));
                    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
                    if (!test || test.length === 0) {
                        return res.render('webinar-test-run', { username, isAdmin, title, test: [], error: 'Для этой лекции тест пока не добавлен.' });
                    }
                    res.render('webinar-test-run', { username, isAdmin, title, test, error: '' });
                });
            };
            runQuery();
        };
    if (isAdmin || w.tests_open || isScheduledOpen) {
            // Проверить, что пользователь — участник этого вебинара (прямо или через группу), если не админ
            if (isAdmin) return proceed();
            db.get('SELECT 1 FROM webinar_attendees WHERE webinar_id = ? AND username = ? LIMIT 1', [wid, username], (aErr:any, aRow:any) => {
                if (aErr) return res.status(500).send('Ошибка');
                if (aRow) return proceed();
                db.get('SELECT 1 FROM webinar_attendee_groups wag JOIN user_groups ug ON ug.group_id = wag.group_id WHERE wag.webinar_id = ? AND ug.username = ? LIMIT 1', [wid, username], (gErr:any, gRow:any) => {
                    if (gErr || !gRow) return res.status(403).send('Доступ запрещён');
                    return proceed();
                });
            });
        } else {
            const whenText = w.tests_open_at ? ('Тест откроется: ' + new Date(w.tests_open_at).toLocaleString()) : 'Тест закрыт преподавателем.';
            return res.render('webinar-test-run', { username, isAdmin, title, test: [], error: whenText });
        }
    });
});

// Lecturer toggle mirrors admin but redirects back to lecturer panel
app.post('/lecturer/webinar/toggle', requireAuth, requireLecturer, csrfProtection, validateBody(webinarToggleSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const { id, open } = req.body as any;
    const who = req.session.user || 'unknown';
    const ensureAccess = (cb: () => void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [id], (e: any, w: any) => {
            if (e || !w) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2: any, ok: any) => {
                if (e2 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('UPDATE webinars SET tests_open = ?, opened_by = ?, opened_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE opened_at END WHERE id = ?', [open, open ? who : null, open, id], (err) => {
            if (!err) logAdminAction(who, open ? 'webinar_open_tests' : 'webinar_close_tests', 'webinars', String(id));
            res.redirect('/lecturer/webinars');
        });
    });
});

// Lecturer: schedule automatic open
app.post('/lecturer/webinar/schedule-open', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const webinarId = Number((req.body as any).id);
    const when = ((req.body as any).when || '').toString(); // 'YYYY-MM-DDTHH:mm'
    if (!Number.isFinite(webinarId) || !when) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Некорректные данные'));
    const ensureAccess = (cb:()=>void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e:any, w:any) => {
            if (e || !w) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                cb();
            });
        });
    };
    ensureAccess(() => {
        // Interpret input as local time, convert to UTC ISO without milliseconds
    const toUtcIso = (s: string) => {
            try {
                const base = s.length <= 16 ? s + ':00' : s; // add seconds
                const d = new Date(base);
                // If Date parsing fails or yields invalid date, fallback to raw
                if (isNaN(d.getTime())) return base;
        // Convert local time to UTC and keep trailing 'Z'
        return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0,19) + 'Z';
            } catch { return s; }
        };
        const whenIso = toUtcIso(when);
        db.run('UPDATE webinars SET tests_open_at = ? WHERE id = ?', [whenIso, webinarId], (err) => {
            if (!err) logAdminAction(who, 'schedule_webinar_open', 'webinars', String(webinarId));
            res.redirect('/lecturer/webinars');
        });
    });
});

// Lecturer: clear schedule
app.post('/lecturer/webinar/schedule-clear', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const webinarId = Number((req.body as any).id);
    if (!Number.isFinite(webinarId)) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Некорректные данные'));
    const ensureAccess = (cb:()=>void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e:any, w:any) => {
            if (e || !w) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('UPDATE webinars SET tests_open_at = NULL WHERE id = ?', [webinarId], (err) => {
            if (!err) logAdminAction(who, 'clear_schedule_webinar_open', 'webinars', String(webinarId));
            res.redirect('/lecturer/webinars');
        });
    });
});

// Админ/Лектор: список вебинаров и форма добавления
app.get('/admin/webinars', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const username = req.session.user as string;
    const isAdmin = req.session.role === 'admin';
    const csrfToken = (req as any).csrfToken();
    const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
    const savedForm = (req.session as any).webinarForm || {};
    (req.session as any).webinarForm = undefined;
    const loadForCourseIds = (courseIds: number[]|null) => {
        const courseSql = isAdmin || !courseIds ? 'SELECT id, name FROM courses ORDER BY name' : `SELECT id, name FROM courses WHERE id IN (${courseIds.map(()=>'?').join(',')}) ORDER BY name`;
        const courseParams: any[] = isAdmin || !courseIds ? [] : courseIds;
        db.all(courseSql, courseParams, (e1:any, courses:any[]) => {
            if (e1) return res.status(500).send('Ошибка загрузки курсов');
            const webSql = isAdmin || !courseIds
                ? 'SELECT id, summary, description, start_time, end_time, tests_open, course_id FROM webinars ORDER BY (start_time IS NULL) ASC, start_time DESC, id DESC'
                : `SELECT id, summary, description, start_time, end_time, tests_open, course_id FROM webinars WHERE course_id IN (${courseIds.map(()=>'?').join(',')}) ORDER BY (start_time IS NULL) ASC, start_time DESC, id DESC`;
            const webParams = isAdmin || !courseIds ? [] : courseParams;
            db.all(webSql, webParams, (e3:any, webinars:any[]) => {
                if (e3) return res.status(500).send('Ошибка загрузки вебинаров');
                res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
                res.render('admin/webinars', { csrfToken, courses: courses||[], webinars: webinars||[], isAdmin, warning, savedForm });
            });
        });
    };
    if (isAdmin) {
        loadForCourseIds(null);
    } else {
        db.all('SELECT course_id FROM lecturer_courses WHERE username = ?', [username], (e:any, rows:any[]) => {
            const ids = (rows||[]).map(r=>Number(r.course_id)).filter(n=>Number.isFinite(n));
            if (ids.length === 0) return res.render('admin/webinars', { csrfToken, courses: [], webinars: [], isAdmin, warning, savedForm });
            loadForCourseIds(ids);
        });
    }
});

app.post('/admin/webinars/add', requireAuth, requireLecturer, csrfProtection, validateBody(webinarAddSchema, '/admin/webinars', { preserveForm: { key: 'webinarForm', pick: ['summary','description','start_time','end_time','courseId'] } }), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { summary, description, start_time, end_time, courseId } = req.body as any;
    const enforceAccess = (cb: ()=>void) => {
        if (req.session.role === 'admin') return cb();
        const cid = Number(courseId);
        db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, cid], (e2:any, ok:any)=>{
            if (e2 || !ok) return res.redirect('/admin/webinars?warning=' + encodeURIComponent('Нет доступа'));
            cb();
        });
    };
    enforceAccess(() => {
        db.run('INSERT INTO webinars (summary, description, start_time, end_time, course_id) VALUES (?, ?, ?, ?, ?)', [summary, description || null, start_time || null, end_time || null, courseId], (err) => {
            if (!err) logAdminAction(who, 'add_webinar', 'webinars', summary);
            res.redirect('/admin/webinars');
        });
    });
});

// Lecturer panel: landing redirects to webinars list
app.get('/lecturer', requireAuth, requireLecturer, (req: express.Request, res: express.Response) => {
    res.redirect('/lecturer/webinars');
});

// Lecturer webinars: same data load as admin but renders lecturer view and scopes to lecturer courses
app.get('/lecturer/webinars', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const username = req.session.user as string;
    const isAdmin = req.session.role === 'admin';
    const csrfToken = (req as any).csrfToken();
    const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
    const savedForm = (req.session as any).webinarForm || {};
    (req.session as any).webinarForm = undefined;
    const render = (courses:any[], webinars:any[]) => {
        res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
        // Also load users/groups and current attendees for UI
        db.all('SELECT id, name FROM groups ORDER BY name', [], (gErr:any, groups:any[]) => {
            db.all('SELECT username FROM users ORDER BY username', [], (uErr:any, users:any[]) => {
                const ids = (webinars||[]).map((w:any)=>Number(w.id)).filter((n:number)=>Number.isFinite(n));
                if (ids.length === 0) {
                    return res.render('lecturer/webinars', { csrfToken, courses, webinars, isAdmin, groups: groups||[], users: users||[], attendeeUsersByWebinar: {}, attendeeGroupsByWebinar: {}, warning, savedForm });
                }
                const ph = ids.map(()=>'?').join(',');
                db.all(`SELECT webinar_id, username FROM webinar_attendees WHERE webinar_id IN (${ph})`, ids, (e1:any, rows1:any[]) => {
                    const attendeeUsersByWebinar: Record<number, string[]> = {};
                    (rows1||[]).forEach(r=>{
                        const wid = Number(r.webinar_id);
                        (attendeeUsersByWebinar[wid] ||= []).push(r.username);
                    });
                    db.all(`SELECT wag.webinar_id, wag.group_id, g.name AS group_name FROM webinar_attendee_groups wag JOIN groups g ON g.id = wag.group_id WHERE wag.webinar_id IN (${ph})`, ids, (e2:any, rows2:any[]) => {
                        const attendeeGroupsByWebinar: Record<number, Array<{id:number; name:string}>> = {};
                        (rows2||[]).forEach(r=>{
                            const wid = Number(r.webinar_id);
                            (attendeeGroupsByWebinar[wid] ||= []).push({ id: Number(r.group_id), name: r.group_name });
                        });
                        res.render('lecturer/webinars', { csrfToken, courses, webinars, isAdmin, groups: groups||[], users: users||[], attendeeUsersByWebinar, attendeeGroupsByWebinar, warning, savedForm });
                    });
                });
            });
        });
    };
    const loadForCourseIds = (courseIds: number[]|null) => {
        const courseSql = isAdmin || !courseIds ? 'SELECT id, name FROM courses ORDER BY name' : `SELECT id, name FROM courses WHERE id IN (${courseIds.map(()=>'?').join(',')}) ORDER BY name`;
        const courseParams: any[] = isAdmin || !courseIds ? [] : courseIds;
        db.all(courseSql, courseParams, (e1:any, courses:any[]) => {
            if (e1) return res.status(500).send('Ошибка загрузки курсов');
            const webSql = isAdmin || !courseIds
                ? 'SELECT id, summary, description, start_time, end_time, tests_open, course_id FROM webinars ORDER BY (start_time IS NULL) ASC, start_time DESC, id DESC'
                : `SELECT id, summary, description, start_time, end_time, tests_open, course_id FROM webinars WHERE course_id IN (${courseIds.map(()=>'?').join(',')}) ORDER BY (start_time IS NULL) ASC, start_time DESC, id DESC`;
            const webParams = isAdmin || !courseIds ? [] : courseParams;
            db.all(webSql, webParams, (e3:any, webinars:any[]) => {
                if (e3) return res.status(500).send('Ошибка загрузки вебинаров');
                return render(courses, webinars);
            });
        });
    };
    if (isAdmin) {
        loadForCourseIds(null);
    } else {
        db.all('SELECT course_id FROM lecturer_courses WHERE username = ?', [username], (e:any, rows:any[]) => {
            const ids = (rows||[]).map(r=>Number(r.course_id)).filter(n=>Number.isFinite(n));
            if (ids.length === 0) return res.render('lecturer/webinars', { csrfToken, courses: [], webinars: [], isAdmin, warning, savedForm });
            loadForCourseIds(ids);
        });
    }
});

// Lecturer create webinar mirrors admin but redirects back to lecturer
app.post('/lecturer/webinars/add', requireAuth, requireLecturer, csrfProtection, validateBody(webinarAddSchema, '/lecturer/webinars', { preserveForm: { key: 'webinarForm', pick: ['summary','description','start_time','end_time','courseId'] } }), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { summary, description, start_time, end_time, courseId } = req.body as any;
    const enforceAccess = (cb: ()=>void) => {
        if (req.session.role === 'admin') return cb();
        const cid = Number(courseId);
        db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, cid], (e2:any, ok:any)=>{
            if (e2 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
            cb();
        });
    };
    enforceAccess(() => {
        db.run('INSERT INTO webinars (summary, description, start_time, end_time, course_id) VALUES (?, ?, ?, ?, ?)', [summary, description || null, start_time || null, end_time || null, courseId], (err) => {
            if (!err) logAdminAction(who, 'add_webinar', 'webinars', summary);
            res.redirect('/lecturer/webinars');
        });
    });
});

// Lecturer: manage webinar tests page
app.get('/lecturer/webinar-tests/:webinarId', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const who = req.session.user as string;
    const isAdmin = req.session.role === 'admin';
    const webinarId = Number(req.params.webinarId);
    if (!Number.isFinite(webinarId)) return res.status(400).send('Некорректный вебинар');
    const ensureAccess = (cb:()=>void) => {
        if (isAdmin) return cb();
        db.get('SELECT course_id, summary FROM webinars WHERE id = ?', [webinarId], (e:any, w:any) => {
            if (e || !w) return res.status(404).send('Вебинар не найден');
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.status(403).send('Нет доступа к курсу');
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.get('SELECT id, summary FROM webinars WHERE id = ?', [webinarId], (e:any, webinar:any) => {
            if (e || !webinar) return res.status(404).send('Вебинар не найден');
            db.all('SELECT id, question, options_json, answer, position FROM webinar_tests WHERE webinar_id = ? ORDER BY position, id', [webinarId], (e2:any, tests:any[]) => {
                const csrfToken = (req as any).csrfToken();
                res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
                res.render('lecturer/webinar-tests', { webinar, tests: tests || [], csrfToken });
            });
        });
    });
});

// Lecturer: add webinar test
app.post('/lecturer/webinar-tests/upsert', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (typeof req.body?.options === 'string') {
        (req.body as any).options = (req.body.options as string).split(/\r?\n/).map((s:string)=>s.trim()).filter(Boolean);
    }
    next();
}, validateBody(upsertWebinarTestSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { webinarId, question, options, answer, position } = req.body as any;
    const ensureAccess = (cb:()=>void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e:any, w:any) => {
            if (e || !w) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                cb();
            });
        });
    };
    ensureAccess(() => {
        const optionsJson = JSON.stringify(options);
        db.run('INSERT INTO webinar_tests (webinar_id, question, options_json, answer, position) VALUES (?, ?, ?, ?, ?)', [webinarId, question, optionsJson, answer, position ?? 0], (err) => {
            if (!err) logAdminAction(who, 'lecturer_add_webinar_test', 'webinar_tests', String(webinarId));
            res.redirect('/lecturer/webinar-tests/' + webinarId);
        });
    });
});

// Lecturer: update webinar test
app.post('/lecturer/webinar-tests/update', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (typeof req.body?.options === 'string') {
        (req.body as any).options = (req.body.options as string).split(/\r?\n/).map((s:string)=>s.trim()).filter(Boolean);
    }
    next();
}, validateBody(updateWebinarTestSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { id, webinarId, question, options, answer, position } = req.body as any;
    const ensureAccess = (cb:()=>void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e:any, w:any) => {
            if (e || !w) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                cb();
            });
        });
    };
    ensureAccess(() => {
        const optionsJson = JSON.stringify(options);
        db.run('UPDATE webinar_tests SET question = ?, options_json = ?, answer = ?, position = ? WHERE id = ?', [question, optionsJson, answer, position ?? 0, id], (e) => {
            if (!e) logAdminAction(who, 'lecturer_update_webinar_test', 'webinar_tests', String(id));
            res.redirect('/lecturer/webinar-tests/' + webinarId);
        });
    });
});

// Lecturer: delete webinar test
app.post('/lecturer/webinar-tests/delete', requireAuth, requireLecturer, csrfProtection, validateBody(deleteWebinarTestSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const id = Number((req.body as any).id);
    db.get('SELECT webinar_id FROM webinar_tests WHERE id = ?', [id], (e:any, row:any) => {
        if (e || !row) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Тест не найден'));
        const webinarId = Number(row.webinar_id);
        const ensureAccess = (cb:()=>void) => {
            if (req.session.role === 'admin') return cb();
            db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e2:any, w:any) => {
                if (e2 || !w) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
                db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e3:any, ok:any) => {
                    if (e3 || !ok) return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа к курсу'));
                    cb();
                });
            });
        };
        ensureAccess(() => {
            db.run('DELETE FROM webinar_tests WHERE id = ?', [id], (de:any) => {
                if (!de) logAdminAction(who, 'lecturer_delete_webinar_test', 'webinar_tests', String(id));
                res.redirect('/lecturer/webinar-tests/' + webinarId);
            });
        });
    });
});

// Lecturer: manage webinar attendees (users)
app.post('/lecturer/webinars/attendees/user/add', requireAuth, requireLecturer, csrfProtection, validateBody(webinarAttendeeUserSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { webinarId, username } = req.body as any;
    const wantsJSON = (req as any).xhr || (req.get('accept') || '').includes('application/json');
    // Ensure lecturer owns access to this webinar via its course
    const ensureAccess = (cb: () => void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e: any, w: any) => {
            if (e || !w) {
                if (wantsJSON) return res.status(404).json({ ok: false, message: 'Вебинар не найден' });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            }
            const cid = Number(w.course_id);
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, cid], (e2: any, ok: any) => {
                if (e2 || !ok) {
                    if (wantsJSON) return res.status(403).json({ ok: false, message: 'Нет доступа' });
                    return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа'));
                }
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('INSERT OR IGNORE INTO webinar_attendees (webinar_id, username) VALUES (?, ?)', [webinarId, username], (err) => {
            if (err) {
                if (wantsJSON) return res.status(500).json({ ok: false });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Ошибка добавления пользователя'));
            }
            logAdminAction(who, 'lecturer_add_attendee', 'webinar_attendees', webinarId + ':' + username);
            if (wantsJSON) return res.json({ ok: true, kind: 'user', username });
            res.redirect('/lecturer/webinars');
        });
    });
});

app.post('/lecturer/webinars/attendees/user/remove', requireAuth, requireLecturer, csrfProtection, validateBody(webinarAttendeeUserSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { webinarId, username } = req.body as any;
    const wantsJSON = (req as any).xhr || (req.get('accept') || '').includes('application/json');
    const ensureAccess = (cb: () => void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e: any, w: any) => {
            if (e || !w) {
                if (wantsJSON) return res.status(404).json({ ok: false, message: 'Вебинар не найден' });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            }
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2: any, ok: any) => {
                if (e2 || !ok) {
                    if (wantsJSON) return res.status(403).json({ ok: false, message: 'Нет доступа' });
                    return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа'));
                }
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('DELETE FROM webinar_attendees WHERE webinar_id = ? AND username = ?', [webinarId, username], (err) => {
            if (err) {
                if (wantsJSON) return res.status(500).json({ ok: false });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Ошибка удаления пользователя'));
            }
            logAdminAction(who, 'lecturer_remove_attendee', 'webinar_attendees', webinarId + ':' + username);
            if (wantsJSON) return res.json({ ok: true, kind: 'user', username });
            res.redirect('/lecturer/webinars');
        });
    });
});

// Lecturer: manage webinar attendees by groups
app.post('/lecturer/webinars/attendees/group/add', requireAuth, requireLecturer, csrfProtection, validateBody(webinarAttendeeGroupSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { webinarId, groupId } = req.body as any;
    const wantsJSON = (req as any).xhr || (req.get('accept') || '').includes('application/json');
    const ensureAccess = (cb: () => void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e: any, w: any) => {
            if (e || !w) {
                if (wantsJSON) return res.status(404).json({ ok: false, message: 'Вебинар не найден' });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            }
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2: any, ok: any) => {
                if (e2 || !ok) {
                    if (wantsJSON) return res.status(403).json({ ok: false, message: 'Нет доступа' });
                    return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа'));
                }
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('INSERT OR IGNORE INTO webinar_attendee_groups (webinar_id, group_id) VALUES (?, ?)', [webinarId, groupId], (err) => {
            if (err) {
                if (wantsJSON) return res.status(500).json({ ok: false });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Ошибка добавления группы'));
            }
            logAdminAction(who, 'lecturer_add_attendee_group', 'webinar_attendee_groups', webinarId + ':' + groupId);
            if (wantsJSON) {
                db.get('SELECT name FROM groups WHERE id = ?', [groupId], (ge:any, grow:any)=>{
                    const groupName = grow?.name || undefined;
                    return res.json({ ok: true, kind: 'group', groupId: Number(groupId), groupName });
                });
                return;
            }
            res.redirect('/lecturer/webinars');
        });
    });
});
app.post('/lecturer/webinars/attendees/group/remove', requireAuth, requireLecturer, csrfProtection, validateBody(webinarAttendeeGroupSchema, '/lecturer/webinars'), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { webinarId, groupId } = req.body as any;
    const wantsJSON = (req as any).xhr || (req.get('accept') || '').includes('application/json');
    const ensureAccess = (cb: () => void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [webinarId], (e: any, w: any) => {
            if (e || !w) {
                if (wantsJSON) return res.status(404).json({ ok: false, message: 'Вебинар не найден' });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Вебинар не найден'));
            }
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2: any, ok: any) => {
                if (e2 || !ok) {
                    if (wantsJSON) return res.status(403).json({ ok: false, message: 'Нет доступа' });
                    return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Нет доступа'));
                }
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.run('DELETE FROM webinar_attendee_groups WHERE webinar_id = ? AND group_id = ?', [webinarId, groupId], (err) => {
            if (err) {
                if (wantsJSON) return res.status(500).json({ ok: false });
                return res.redirect('/lecturer/webinars?warning=' + encodeURIComponent('Ошибка удаления группы'));
            }
            logAdminAction(who, 'lecturer_remove_attendee_group', 'webinar_attendee_groups', webinarId + ':' + groupId);
            if (wantsJSON) {
                db.get('SELECT name FROM groups WHERE id = ?', [groupId], (ge:any, grow:any) => {
                    const groupName = grow?.name || undefined;
                    return res.json({ ok: true, kind: 'group', groupId: Number(groupId), groupName });
                });
                return;
            }
            res.redirect('/lecturer/webinars');
        });
    });
});

// Страница тестов
app.get('/tests.html', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    const topic = typeof req.query.topic === 'string' ? req.query.topic : undefined;
    const isAdmin = (req.session.role === 'admin');
    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    if (!topic) {
        // Если тема не указана, и есть открытые вебинары, взять ближайший открытый и выбрать первый раздел его курса
        db.get('SELECT course_id FROM webinars WHERE tests_open = 1 ORDER BY start_time DESC LIMIT 1', [], (e:any, w:any) => {
            if (!w?.course_id) return res.render('tests', { username, test: [], topic: undefined, error: 'Раздел не указан.', isAdmin });
            db.get('SELECT name FROM topics WHERE course_id = ? ORDER BY name LIMIT 1', [w.course_id], (e2:any, trow:any) => {
                const tname = trow?.name as string | undefined;
                if (!tname) return res.render('tests', { username, test: [], topic: undefined, error: 'Раздел не указан.', isAdmin });
                // безопасный HTTP-редирект вместо внутреннего вызова роутера
                return res.redirect('/tests.html?topic=' + encodeURIComponent(tname));
            });
        });
        return;
    }
    // If tests are controlled by webinars, ensure user is an attendee of an open webinar for this topic
    db.get('SELECT id FROM webinars WHERE tests_open = 1 AND course_id = (SELECT course_id FROM topics WHERE name = ?) ORDER BY start_time DESC LIMIT 1', [topic], (weErr:any, wrow:any) => {
        if (weErr) return res.render('tests', { username, test: [], topic, error: 'Ошибка проверки доступа к тестам.', isAdmin });
        if (!wrow) {
            return res.render('tests', { username, test: [], topic, error: 'Тесты закрыты преподавателем.', isAdmin });
        }
        const wid = Number(wrow.id);
        if (!isAdmin) {
            // Check attendee list: direct users or via groups
            db.get('SELECT 1 AS ok FROM webinar_attendees WHERE webinar_id = ? AND username = ? LIMIT 1', [wid, username], (aErr:any, aRow:any) => {
                if (aErr) return res.render('tests', { username, test: [], topic, error: 'Ошибка проверки доступа к тестам.', isAdmin });
                if (!aRow) {
                    db.get('SELECT 1 AS ok FROM webinar_attendee_groups wag JOIN user_groups ug ON ug.group_id = wag.group_id WHERE wag.webinar_id = ? AND ug.username = ? LIMIT 1', [wid, username], (gErr:any, gRow:any) => {
                        if (gErr || !gRow) {
                            return res.render('tests', { username, test: [], topic, error: 'Тесты доступны только участникам вебинара.', isAdmin });
                        }
                        // Attendee via group OK -> continue to load tests
                        return loadTestsForTopic();
                    });
                } else {
                    // Direct attendee OK -> continue to load tests
                    return loadTestsForTopic();
                }
            });
        } else {
            // Admin bypass
            return loadTestsForTopic();
        }
        function loadTestsForTopic() {
            // Find first unlocked video in this topic and load its tests
            db.all('SELECT id FROM videos WHERE topic = ? ORDER BY position ASC, id ASC', [topic], (e, vids: Array<{id:number}>) => {
            if (e || (vids||[]).length === 0) return res.render('tests', { username, test: [], topic, error: 'Для этого раздела нет видео.', isAdmin });
                const videoIds = vids.map(v => v.id);
                db.get('SELECT unlockedCount FROM user_progress WHERE username = ? AND topic = ?', [username, topic], (e2, row: any) => {
                    const unlockedCount = row ? Number(row.unlockedCount) : 1;
                    const targetVideoId = videoIds[Math.min(unlockedCount - 1, videoIds.length - 1)];
                    db.all('SELECT question, options_json, answer FROM video_tests WHERE video_id = ? ORDER BY position, id', [targetVideoId], (e3, tests: any[]) => {
                        if (e3 || !tests || tests.length === 0) return res.render('tests', { username, test: [], topic, error: 'Для текущего видео тест ещё не добавлен.', isAdmin });
                        const prepared = tests.map(t => ({ question: t.question, options: JSON.parse(t.options_json || '[]'), answer: Number(t.answer) }));
                        res.render('tests', { username, test: prepared, topic, error: undefined, isAdmin });
                    });
                });
            });
        }
    });
});

// Progress APIs
app.post('/api/progress/watch', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    const { topic, index } = req.body as { topic?: string; index?: number };
    if (!topic || typeof index !== 'number') return res.status(400).json({ ok: false });
    db.get('SELECT unlockedCount, lastWatchedIndex FROM user_progress WHERE username = ? AND topic = ?', [username, topic], (err, row: any) => {
        if (err) return res.status(500).json({ ok: false });
        const unlocked = row ? Number(row.unlockedCount) : 1;
        const last = row ? Number(row.lastWatchedIndex) : -1;
        if (index > last) {
            const newLast = index;
            db.run('INSERT INTO user_progress (username, topic, unlockedCount, lastWatchedIndex) VALUES (?, ?, ?, ?) ON CONFLICT(username, topic) DO UPDATE SET lastWatchedIndex = excluded.lastWatchedIndex', [username, topic, unlocked, newLast], (e2) => {
                if (e2) return res.status(500).json({ ok: false });
                res.json({ ok: true });
            });
        } else {
            res.json({ ok: true });
        }
    });
});
app.post('/api/progress/test-pass', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    const { topic } = req.body as { topic?: string };
    if (!topic) return res.status(400).json({ ok: false });
    // Determine total videos in this topic to cap unlock
    db.all('SELECT id FROM videos WHERE topic = ? ORDER BY position ASC, id ASC', [topic], (err, rows: any[]) => {
        if (err) return res.status(500).json({ ok: false });
        const total = (rows || []).length;
        db.get('SELECT unlockedCount FROM user_progress WHERE username = ? AND topic = ?', [username, topic], (gerr, row: any) => {
            if (gerr) return res.status(500).json({ ok: false });
            const current = row ? Number(row.unlockedCount) : 1;
            const maxAllowed = Math.max(1, total + 1);
            const next = Math.min(current + 1, maxAllowed);
            db.run('INSERT INTO user_progress (username, topic, unlockedCount, lastWatchedIndex) VALUES (?, ?, ?, ?) ON CONFLICT(username, topic) DO UPDATE SET unlockedCount = excluded.unlockedCount', [username, topic, next, -1], (uerr) => {
                if (uerr) return res.status(500).json({ ok: false });
                res.json({ ok: true, unlockedCount: next });
            });
        });
    });
});

// (Home route is defined above to render EJS template)
app.get('/api/videos', requireAuth, requireAdmin, (req: express.Request, res: express.Response) => {
    db.all('SELECT * FROM videos', (err, rows) => {
        if (err) return res.json([]);
        res.json(rows);
    });
});

// Lightweight endpoint to refresh CSRF cookie for AJAX flows
app.get('/api/csrf', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
    res.json({ ok: true });
});

// Notifications APIs
app.get('/api/notifications/unread-count', requireAuth, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    db.get('SELECT COUNT(*) AS c FROM notifications WHERE username = ? AND read_at IS NULL', [username], (err, row: any) => {
        if (err) return res.json({ count: 0 });
        res.json({ count: Number(row?.c || 0) });
    });
});
app.get('/api/notifications', requireAuth, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    db.all('SELECT id, title, body, created_at, read_at FROM notifications WHERE username = ? ORDER BY created_at DESC, id DESC LIMIT 50', [username], (err, rows: any[]) => {
        if (err) return res.json([]);
        res.json(rows || []);
    });
});
app.post('/api/notifications/:id/read', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false });
    db.run('UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?', [id, username], (err) => {
        if (err) return res.status(500).json({ ok: false });
        res.json({ ok: true });
    });
});
// Notifications: mark all as read
app.post('/api/notifications/read-all', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    db.run('UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE username = ? AND read_at IS NULL', [username], function (this: any, err) {
        if (err) return res.status(500).json({ ok: false });
        const affected = Number(this && this.changes || 0);
        res.json({ ok: true, affected });
    });
});
// Notifications: clear all
app.post('/api/notifications/clear-all', requireAuth, csrfProtection, (req: express.Request, res: express.Response) => {
    const username = req.session.user as string;
    db.run('DELETE FROM notifications WHERE username = ?', [username], function (this: any, err) {
        if (err) return res.status(500).json({ ok: false });
        const affected = Number(this && this.changes || 0);
        res.json({ ok: true, affected });
    });
});
// Helper: seed a test notification (admin only)
app.post('/admin/notifications/seed', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const { username, title, body } = req.body as any;
    if (!username || !title) return res.redirect('/admin?warning=' + encodeURIComponent('Укажите пользователя и заголовок'));
    createNotificationAndMaybeEmail(username, title, body || '').then(() => res.redirect('/admin')).catch(() => res.redirect('/admin?warning=' + encodeURIComponent('Ошибка добавления уведомления')));
});

// Webinar attendees flattened users (direct + via groups)
app.get('/api/webinars/:id/attendees/users', requireAuth, requireLecturer, (req: express.Request, res: express.Response) => {
    const wid = Number(req.params.id);
    if (!Number.isFinite(wid)) return res.status(400).json([]);
    const who = req.session.user as string;
    const ensureAccess = (cb:()=>void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [wid], (e:any, w:any) => {
            if (e || !w) return res.status(404).json([]);
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.status(403).json([]);
                cb();
            });
        });
    };
    ensureAccess(() => {
        const result = new Set<string>();
        db.all('SELECT username FROM webinar_attendees WHERE webinar_id = ?', [wid], (e1:any, rows1:any[]) => {
            if (!e1) (rows1||[]).forEach(r=>result.add(String(r.username)));
            db.all('SELECT ug.username FROM webinar_attendee_groups wag JOIN user_groups ug ON ug.group_id = wag.group_id WHERE wag.webinar_id = ?', [wid], (e2:any, rows2:any[]) => {
                if (!e2) (rows2||[]).forEach(r=>result.add(String(r.username)));
                res.json(Array.from(result));
            });
        });
    });
});

// Send notifications for diff between baseline and current attendees when modal closes
app.post('/api/webinars/:id/attendees/notify-diff', requireAuth, requireLecturer, csrfProtection, (req: express.Request, res: express.Response) => {
    const wid = Number(req.params.id);
    if (!Number.isFinite(wid)) return res.status(400).json({ ok:false });
    const who = req.session.user as string;
    const baselineRaw = (req.body as any).snapshot as string | undefined;
    let baseline: string[] = [];
    try { baseline = JSON.parse(baselineRaw || '[]'); if (!Array.isArray(baseline)) baseline = []; } catch { baseline = []; }
    const ensureAccess = (cb:()=>void) => {
        if (req.session.role === 'admin') return cb();
        db.get('SELECT course_id FROM webinars WHERE id = ?', [wid], (e:any, w:any) => {
            if (e || !w) return res.status(404).json({ ok:false });
            db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, w.course_id], (e2:any, ok:any) => {
                if (e2 || !ok) return res.status(403).json({ ok:false });
                cb();
            });
        });
    };
    ensureAccess(() => {
        db.get('SELECT summary, start_time FROM webinars WHERE id = ?', [wid], (we:any, wrow:any) => {
            const summary = wrow?.summary || 'Вебинар';
            const when = wrow?.start_time || '';
            const curr = new Set<string>();
            db.all('SELECT username FROM webinar_attendees WHERE webinar_id = ?', [wid], (e1:any, rows1:any[]) => {
                if (!e1) (rows1||[]).forEach(r=>curr.add(String(r.username)));
                db.all('SELECT ug.username FROM webinar_attendee_groups wag JOIN user_groups ug ON ug.group_id = wag.group_id WHERE wag.webinar_id = ?', [wid], (e2:any, rows2:any[]) => {
                    if (!e2) (rows2||[]).forEach(r=>curr.add(String(r.username)));
                    const base = new Set<string>(baseline.filter(u=>typeof u==='string'));
                    const added: string[] = []; const removed: string[] = [];
                    curr.forEach(u => { if (!base.has(u)) added.push(u); });
                    base.forEach(u => { if (!curr.has(u)) removed.push(u); });
                    // Insert notifications
                    const tasks: Array<Promise<void>> = [];
                    added.forEach(u => tasks.push(createNotificationAndMaybeEmail(u, 'Вас добавили в вебинар', summary + (when ? (' — ' + when) : ''))));
                    removed.forEach(u => tasks.push(createNotificationAndMaybeEmail(u, 'Вас удалили из вебинара', summary + (when ? (' — ' + when) : ''))));
                    Promise.all(tasks).then(()=>res.json({ ok:true, added: added.length, removed: removed.length }));
                });
            });
        });
    });
});
app.post('/admin/edit-video/:id', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const id = req.params.id;
    let { title, topic } = req.body as { title: string; topic: string };
    topic = (topic || '').trim();
    const position = Number((req.body as any).position ?? 0);
    db.run(
        'UPDATE videos SET title = ?, topic = ?, position = ? WHERE id = ?',
        [title, topic, Number.isFinite(position) && position >= 0 ? position : 0, id],
        (err) => {
            if (err) return res.redirect('/video-list?warning=' + encodeURIComponent('Ошибка редактирования'));
            logAdminAction(req.session.user || 'unknown', 'edit_video', 'videos', String(id));
            res.redirect('/video-list');
        }
    );
});
app.get('/video-list', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const activeTopic = typeof req.query.topic === 'string' ? req.query.topic : '';
    db.all('SELECT id, name FROM topics ORDER BY name', (err, topicsRaw: Array<{id:number; name:string}>) => {
        if (err) return res.send('Ошибка загрузки разделов');
        db.all('SELECT v.id, v.title, v.topic, v.filename, v.position, (SELECT COUNT(*) FROM video_tests t WHERE t.video_id = v.id) AS testCount FROM videos v ORDER BY v.topic ASC, v.position ASC, v.id ASC', (err2, videosRaw: Array<{id:number; title:string; topic:string; filename:string; position:number; testCount:number}>) => {
            if (err2) return res.send('Ошибка загрузки видео');
            const topicsTable = (topicsRaw || []).map(t => ({ id: t.id, name: t.name }));
            const videosByTopic: Record<string, Array<{id:number; title:string; filename:string; position:number; testCount:number}>> = {};
            (videosRaw || []).forEach(v => {
                (videosByTopic[v.topic] ||= []).push({ id: v.id, title: v.title, filename: v.filename, position: v.position, testCount: Number((v as any).testCount || 0) });
            });
            // Union topics from table and from videos
            const namesFromVideos = Object.keys(videosByTopic);
            const nameSet = new Set<string>([...topicsTable.map(t => t.name), ...namesFromVideos]);
            const topics = Array.from(nameSet).sort((a,b)=> a.localeCompare(b, 'ru')).map(name => {
                const found = topicsTable.find(t => t.name === name);
                return found ? { id: found.id, name } : { name } as any;
            });
        const csrfToken = (req as any).csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
            const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
            const error = typeof req.query.error === 'string' ? req.query.error : '';
            res.render('admin/video-list', { topics, videosByTopic, csrfToken, activeTopic, warning, error });
        });
    });
});

// Admin: manage tests for a specific video
app.get('/admin/video-tests/:videoId', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const videoId = Number(req.params.videoId);
    if (!Number.isFinite(videoId)) return res.status(400).send('Некорректный ID видео');
    db.get('SELECT id, title, topic FROM videos WHERE id = ?', [videoId], (e, video: any) => {
        if (e || !video) return res.status(404).send('Видео не найдено');
        db.all('SELECT id, question, options_json, answer, position FROM video_tests WHERE video_id = ? ORDER BY position, id', [videoId], (e2, tests: any[]) => {
            if (e2) return res.status(500).send('Ошибка загрузки тестов');
            const csrfToken = (req as any).csrfToken();
            res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
            const warning = typeof req.query.warning === 'string' ? req.query.warning : '';
            res.render('admin/video-tests', { video, tests: tests || [], csrfToken, warning });
        });
    });
});
app.post('/admin/video-tests/upsert', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response, next: express.NextFunction) => {
    // Parse options from newline textarea to array before validation
    if (typeof req.body?.options === 'string') {
        req.body.options = (req.body.options as string).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    }
    next();
}, validateBody(upsertVideoTestSchema, '/video-list'), (req: express.Request, res: express.Response) => {
    const { videoId, question, options, answer, position } = req.body as { videoId: number; question: string; options: string[]; answer: number; position?: number };
    const optionsJson = JSON.stringify(options);
    db.run('INSERT INTO video_tests (video_id, question, options_json, answer, position) VALUES (?, ?, ?, ?, ?)', [videoId, question, optionsJson, answer, position ?? 0], (err) => {
        if (err) return res.redirect('/admin/video-tests/' + videoId + '?warning=' + encodeURIComponent('Ошибка сохранения'));
        logAdminAction(req.session.user || 'unknown', 'add_video_test', 'video_tests', String(videoId));
        res.redirect('/admin/video-tests/' + videoId);
    });
});
app.post('/admin/video-tests/delete', requireAuth, requireAdmin, csrfProtection, validateBody(deleteVideoTestSchema, '/video-list'), (req: express.Request, res: express.Response) => {
    const id = (req.body as any).id as number;
    db.get('SELECT video_id FROM video_tests WHERE id = ?', [id], (e, row: any) => {
        if (e || !row) return res.redirect('/video-list?warning=' + encodeURIComponent('Тест не найден'));
        const videoId = row.video_id;
        db.run('DELETE FROM video_tests WHERE id = ?', [id], (e2) => {
            if (e2) return res.redirect('/admin/video-tests/' + videoId + '?warning=' + encodeURIComponent('Ошибка удаления'));
            logAdminAction(req.session.user || 'unknown', 'delete_video_test', 'video_tests', String(id));
            res.redirect('/admin/video-tests/' + videoId);
        });
    });
});
app.post('/admin/video-tests/update', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (typeof req.body?.options === 'string') {
        req.body.options = (req.body.options as string).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    }
    next();
}, validateBody(updateVideoTestSchema, '/video-list'), (req: express.Request, res: express.Response) => {
    const { id, videoId, question, options, answer, position } = req.body as { id: number; videoId: number; question: string; options: string[]; answer: number; position?: number };
    const optionsJson = JSON.stringify(options);
    db.run('UPDATE video_tests SET question = ?, options_json = ?, answer = ?, position = ? WHERE id = ?', [question, optionsJson, answer, position ?? 0, id], (e) => {
        if (e) return res.redirect('/admin/video-tests/' + videoId + '?warning=' + encodeURIComponent('Ошибка сохранения'));
        logAdminAction(req.session.user || 'unknown', 'update_video_test', 'video_tests', String(id));
        res.redirect('/admin/video-tests/' + videoId);
    });
});
const upload = multer({
    dest: VIDEO_DIR,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
    fileFilter: (req, file, cb) => {
        const ok = /^video\//.test(file.mimetype) || /(mp4|webm|ogg)$/i.test(file.originalname);
        if (ok) return cb(null, true);
        return cb(new Error('Недопустимый тип файла'));
    }
});
// Note: For multipart/form-data, parse with multer BEFORE csrfProtection so the token in body is readable
app.post('/admin/upload-video', requireAuth, requireAdmin, upload.single('video'), csrfProtection, validateBody(videoMetaSchema, '/video-list', { cleanupFileOnFail: true }), (req: express.Request, res: express.Response) => {
    const { title, position } = req.body as { title: string; topic: string; position?: number };
    const topicRaw = (req.body as any).topic as string;
    const topic = (topicRaw || 'Без темы').trim();
    if (!req.file || !req.file.filename) {
        return res.redirect('/video-list?warning=' + encodeURIComponent('Файл видео не загружен'));
    }
    const filename = req.file.filename;
    const pos = Number(position ?? 0);
    db.run(
        'INSERT INTO videos (title, filename, topic, position) VALUES (?, ?, ?, ?)',
    [title, filename, topic, Number.isFinite(pos) && pos >= 0 ? pos : 0],
        (err) => {
            if (err) return res.redirect('/video-list?error=Ошибка загрузки видео');
            logAdminAction(req.session.user || 'unknown', 'upload_video', 'videos', filename);
            res.redirect('/video-list?topic=' + encodeURIComponent(topic));
        }
    );
});

// Лектор: загрузка видео только в доступные курсы/темы
app.post('/lecturer/upload-video', requireAuth, requireLecturer, upload.single('video'), csrfProtection, validateBody(videoMetaSchema, '/video-list', { cleanupFileOnFail: true }), (req: express.Request, res: express.Response) => {
    const who = req.session.user as string;
    const { title, position } = req.body as { title: string; topic: string; position?: number };
    const topicRaw = (req.body as any).topic as string;
    const topic = (topicRaw || 'Без темы').trim();
    // Check access: lecturer has access to the course of this topic
    db.get('SELECT t.id as topic_id, t.course_id FROM topics t WHERE TRIM(t.name) = TRIM(?)', [topic], (e:any, row:any) => {
        if (e || !row) return res.redirect('/video-list?warning=' + encodeURIComponent('Нет доступа к разделу'));
        db.get('SELECT 1 FROM lecturer_courses WHERE username = ? AND course_id = ?', [who, row.course_id], (e2:any, ok:any) => {
            if (e2 || !ok) return res.redirect('/video-list?warning=' + encodeURIComponent('Нет доступа к курсу'));
            if (!req.file || !req.file.filename) return res.redirect('/video-list?warning=' + encodeURIComponent('Файл видео не загружен'));
            const filename = req.file.filename;
            const pos = Number(position ?? 0);
            db.run('INSERT INTO videos (title, filename, topic, position) VALUES (?, ?, ?, ?)', [title, filename, topic, Number.isFinite(pos) && pos >= 0 ? pos : 0], (err) => {
                if (err) return res.redirect('/video-list?error=Ошибка загрузки видео');
                logAdminAction(who, 'lecturer_upload_video', 'videos', filename);
                res.redirect('/video-list?topic=' + encodeURIComponent(topic));
            });
        });
    });
});

// Админ: управление курсами и доступом лекторов
app.post('/admin/courses/add', requireAuth, requireAdmin, csrfProtection, validateBody(courseSchema, '/admin'), (req: express.Request, res: express.Response) => {
    const { name } = req.body as any;
    db.run('INSERT OR IGNORE INTO courses (name) VALUES (?)', [name], (err) => {
        if (!err) logAdminAction(req.session.user || 'unknown', 'add_course', 'courses', name);
        res.redirect('/admin');
    });
});
app.post('/admin/lecturers/grant', requireAuth, requireAdmin, csrfProtection, validateBody(lecturerAccessSchema, '/admin'), (req: express.Request, res: express.Response) => {
    const { username, courseId } = req.body as any;
    db.run('INSERT OR IGNORE INTO lecturer_courses (username, course_id) VALUES (?, ?)', [username, courseId], (err) => {
        if (!err) logAdminAction(req.session.user || 'unknown', 'grant_lecturer_course', 'lecturer_courses', username + ':' + courseId);
        res.redirect('/admin');
    });
});
app.post('/admin/lecturers/revoke', requireAuth, requireAdmin, csrfProtection, validateBody(lecturerAccessSchema, '/admin'), (req: express.Request, res: express.Response) => {
    const { username, courseId } = req.body as any;
    db.run('DELETE FROM lecturer_courses WHERE username = ? AND course_id = ?', [username, courseId], (err) => {
        if (!err) logAdminAction(req.session.user || 'unknown', 'revoke_lecturer_course', 'lecturer_courses', username + ':' + courseId);
        res.redirect('/admin');
    });
});

// Admin: Courses and lecturer bindings management page
app.get('/admin/courses', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const csrfToken = (req as any).csrfToken();
    db.all('SELECT id, name FROM courses ORDER BY name', [], (e1:any, courses:any[]) => {
        if (e1) return res.status(500).send('Ошибка загрузки курсов');
        db.all("SELECT lc.username, lc.course_id, c.name AS course_name FROM lecturer_courses lc JOIN courses c ON c.id = lc.course_id ORDER BY lc.username, c.name", [], (e2:any, bindings:any[]) => {
            if (e2) return res.status(500).send('Ошибка загрузки назначений');
            db.all("SELECT username FROM users WHERE role = 'lecturer' ORDER BY username", [], (e3:any, lecturers:any[]) => {
                if (e3) return res.status(500).send('Ошибка загрузки списка лекторов');
                res.cookie('XSRF-TOKEN', csrfToken, { sameSite: 'lax', secure: COOKIE_SECURE, httpOnly: false });
                res.render('admin/courses', { csrfToken, courses: courses || [], lecturers: lecturers || [], bindings: bindings || [] });
            });
        });
    });
});

// Multer error handler (must be after routes using multer)
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err) {
        if (err.code === 'LIMIT_FILE_SIZE' || err.message === 'Недопустимый тип файла') {
            return res.redirect('/video-list?warning=' + encodeURIComponent(err.code === 'LIMIT_FILE_SIZE' ? 'Файл слишком большой' : err.message));
        }
        if (err.code === 'EBADCSRFTOKEN') {
            // Clean up uploaded file if CSRF failed after multer saved it
            if ((req as any).file && (req as any).file.path) {
                try { fs.unlinkSync((req as any).file.path); } catch {}
            }
            // Clear CSRF cookie and session (best-effort)
            try { res.clearCookie('XSRF-TOKEN'); } catch {}
            // Redirect back to the GET page to re-issue a fresh token
            const ref = (req.headers.referer && typeof req.headers.referer === 'string') ? req.headers.referer : '/';
            const target = new URL(ref, 'http://localhost');
            const url = target.pathname + target.search;
            return res.redirect(url + (url.includes('?') ? '&' : '?') + 'error=' + encodeURIComponent('Сессия истекла. Обновите страницу и попробуйте снова.'));
        }
    }
    next(err);
});

app.post('/admin/delete-video/:id', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const id = req.params.id;
    db.get('SELECT filename FROM videos WHERE id = ?', [id], (err, row: { filename?: string } | undefined) => {
    if (!row || !row.filename) return res.redirect('/video-list?warning=' + encodeURIComponent('Видео не найдено'));
    const filePath = path.join(VIDEO_DIR, row.filename);
        db.run('DELETE FROM videos WHERE id = ?', [id], (err2) => {
            if (err2) return res.redirect('/video-list?warning=' + encodeURIComponent('Ошибка удаления из базы'));
            fs.unlink(filePath, () => res.redirect('/video-list'));
            logAdminAction(req.session.user || 'unknown', 'delete_video', 'videos', String(id));
        });
    });
});

// Управление разделами
app.post('/admin/add-topic', requireAuth, requireAdmin, csrfProtection, validateBody(topicSchema, '/video-list'), (req: express.Request, res: express.Response) => {
    const name = (req.body?.name || '').toString().trim();
    db.run('INSERT OR IGNORE INTO topics (name) VALUES (?)', [name], (err) => {
        if (err) return res.redirect('/video-list?warning=Ошибка добавления раздела');
    logAdminAction(req.session.user || 'unknown', 'add_topic', 'topics', name);
    res.redirect('/video-list?topic=' + encodeURIComponent(name));
    });
});
app.post('/admin/delete-topic', requireAuth, requireAdmin, csrfProtection, validateBody(deleteTopicSchema, '/video-list'), (req: express.Request, res: express.Response) => {
    const id = Number(req.body?.id);
    // Find topic name first
    db.get('SELECT name FROM topics WHERE id = ?', [id], (e0, trow: any) => {
        if (e0 || !trow) return res.redirect('/video-list?warning=' + encodeURIComponent('Раздел не найден'));
        const topicName = trow.name as string;
        // Collect videos under this topic
    const topicKey = (topicName || '').trim();
    db.all('SELECT id, filename FROM videos WHERE TRIM(topic) = TRIM(?)', [topicKey], (e1, vids: Array<{id:number; filename:string}>) => {
            if (e1) return res.redirect('/video-list?warning=' + encodeURIComponent('Ошибка загрузки видео раздела'));
            const files = (vids || []).map(v => v.filename);
            db.serialize(() => {
                db.run('BEGIN');
        db.run('DELETE FROM videos WHERE TRIM(topic) = TRIM(?)', [topicKey]);
        db.run('DELETE FROM user_progress WHERE TRIM(topic) = TRIM(?)', [topicKey]);
                db.run('DELETE FROM topics WHERE id = ?', [id]);
                db.run('COMMIT', (commitErr) => {
                    if (commitErr) return res.redirect('/video-list?warning=' + encodeURIComponent('Ошибка удаления раздела'));
                    // Delete files asynchronously (best-effort)
                    try {
                        files.forEach(fn => {
                            try { fs.unlink(path.join(VIDEO_DIR, fn), ()=>{}); } catch {}
                        });
                    } catch {}
                    logAdminAction(req.session.user || 'unknown', 'delete_topic', 'topics', String(id));
                    (vids || []).forEach(v => logAdminAction(req.session.user || 'unknown', 'delete_video', 'videos', String(v.id)));
                    res.redirect('/video-list');
                });
            });
        });
    });
});

// Unified deletion: by id (preferred) or by name when no row exists in topics.
app.post('/admin/delete-topic-any', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const rawId = (req.body?.id ?? '').toString().trim();
    const rawName = (req.body?.name ?? '').toString().trim();
    const id = rawId ? Number(rawId) : NaN;
    const finish = (ok: boolean, msg?: string) => res.redirect('/video-list' + (ok ? '' : ('?warning=' + encodeURIComponent(msg || 'Ошибка удаления раздела'))));
    const performDeleteByName = (topicName: string) => {
        const topicKey = (topicName || '').trim();
        db.all('SELECT id, filename FROM videos WHERE TRIM(topic) = TRIM(?)', [topicKey], (e1, vids: Array<{id:number; filename:string}>) => {
            if (e1) return finish(false, 'Ошибка загрузки видео раздела');
            const files = (vids || []).map(v => v.filename);
            db.serialize(() => {
                db.run('BEGIN');
                db.run('DELETE FROM videos WHERE TRIM(topic) = TRIM(?)', [topicKey]);
                db.run('DELETE FROM user_progress WHERE TRIM(topic) = TRIM(?)', [topicKey]);
                db.run('DELETE FROM topics WHERE TRIM(name) = TRIM(?)', [topicKey]);
                db.run('COMMIT', (commitErr) => {
                    if (commitErr) return finish(false, 'Ошибка удаления раздела');
                    try {
                        files.forEach(fn => { try { fs.unlink(path.join(VIDEO_DIR, fn), ()=>{}); } catch {} });
                    } catch {}
                    logAdminAction(req.session.user || 'unknown', 'delete_topic_any', 'topics', topicKey);
                    (vids || []).forEach(v => logAdminAction(req.session.user || 'unknown', 'delete_video', 'videos', String(v.id)));
                    return finish(true);
                });
            });
        });
    };
    if (!isNaN(id)) {
        db.get('SELECT name FROM topics WHERE id = ?', [id], (e0, trow: any) => {
            if (e0 || !trow) return finish(false, 'Раздел не найден');
            performDeleteByName(trow.name as string);
        });
    } else if (rawName) {
        performDeleteByName(rawName);
    } else {
        return finish(false, 'Не указан раздел');
    }
});

// Save positions after drag-and-drop reorder within a topic
app.post('/admin/videos/reorder', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    const topic = (req.body?.topic || '').toString();
    const ids = Array.isArray((req.body as any).ids) ? (req.body as any).ids.map((n: any) => Number(n)).filter((n: number) => Number.isFinite(n)) : [];
    if (!topic || ids.length === 0) return res.status(400).json({ ok: false });
    // Transactional update to keep ordering consistent
    db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        let failed = false;
        ids.forEach((id: number, index: number) => {
            if (failed) return;
            db.run('UPDATE videos SET position = ? WHERE id = ? AND topic = ?', [index, id, topic], (err) => {
                if (err && !failed) {
                    failed = true;
                    db.run('ROLLBACK', () => res.status(500).json({ ok: false }));
                }
            });
        });
        if (!failed) {
            db.run('COMMIT', (commitErr) => {
                if (commitErr) return res.status(500).json({ ok: false });
                res.json({ ok: true });
            });
        }
    });
});

// Cleanup orphan records: videos whose topic is not in topics, and progress for non-existent topics
app.post('/admin/videos/cleanup-orphans', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    db.serialize(() => {
        db.run('BEGIN');
        db.all('SELECT id, filename FROM videos WHERE TRIM(topic) NOT IN (SELECT TRIM(name) FROM topics)', [], (e, rows: Array<{id:number; filename:string}>) => {
            const files = (rows || []).map(r => r.filename);
            db.run('DELETE FROM videos WHERE TRIM(topic) NOT IN (SELECT TRIM(name) FROM topics)');
            db.run('DELETE FROM user_progress WHERE TRIM(topic) NOT IN (SELECT TRIM(name) FROM topics)');
            db.run('COMMIT', (commitErr) => {
                if (!commitErr) {
                    try {
                        const base = path.join(__dirname, '../public/videos');
                        files.forEach(fn => { try { fs.unlink(path.join(base, fn), ()=>{}); } catch {} });
                    } catch {}
                    logAdminAction(req.session.user || 'unknown', 'cleanup_orphans', 'videos', String((rows||[]).length));
                }
                return res.redirect('/video-list');
            });
        });
    });
});

// Cleanup orphan tests: questions pointing to non-existing videos
app.post('/admin/tests/cleanup-orphans', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    db.serialize(() => {
        db.run('BEGIN');
        db.get('SELECT COUNT(1) AS cnt FROM video_tests WHERE video_id NOT IN (SELECT id FROM videos)', [], (e: any, row: any) => {
            const count = Number(row?.cnt || 0);
            db.run('DELETE FROM video_tests WHERE video_id NOT IN (SELECT id FROM videos)');
            db.run('COMMIT', (commitErr) => {
                if (!commitErr) {
                    logAdminAction(req.session.user || 'unknown', 'cleanup_orphans', 'video_tests', String(count));
                }
                return res.redirect('/video-list');
            });
        });
    });
});

// (removed duplicate /forgot routes)
const port = config.port;
// Liveness/readiness probe
app.get('/healthz', (req: express.Request, res: express.Response) => {
    db.get('SELECT 1 as ok', [], (err) => {
        res.status(err ? 500 : 200).json({ ok: !err, uptime: process.uptime() });
    });
});
// Only start the listener when run directly (not when required by tests)
if (require.main === module) {
    const server = app.listen(port, () => {
        console.log('Сайт запущен: http://localhost:' + port);
    });
    try {
        server.on('error', (e: any) => {
            console.error('[server.error]', e?.code || e?.message || e);
        });
    } catch {}
}

// --- helpers ---
let __mailTransport: any | null = null;
function mailTransport() {
    if (__mailTransport) return __mailTransport;
    __mailTransport = nodemailer.createTransport({
        host: config.smtp.host,
        port: Number(config.smtp.port),
        secure: config.smtp.secure,
        pool: true,
        maxConnections: Number(config.smtp.maxConnections),
        maxMessages: Number(config.smtp.maxMessages),
        auth: {
            user: config.smtp.user,
            pass: config.smtp.pass
        },
        tls: {
            // allow self-signed in dev if explicitly asked
            rejectUnauthorized: config.smtp.tlsRejectUnauthorized
        }
    });
    return __mailTransport;
}

// Create in-app notification and, if SMTP configured in production and email exists, send it by email too
function createNotificationAndMaybeEmail(username: string, title: string, body: string): Promise<void> {
    return new Promise<void>((resolve) => {
        try {
            db.run('INSERT INTO notifications (username, title, body) VALUES (?, ?, ?)', [username, title, body || null], (insErr) => {
                // Fire-and-forget email sending; don't fail the whole op if email fails
                const isProd = config.isProd;
                const smtpReady = !!(config.smtp.user && config.smtp.pass && config.smtp.host);
                if (!isProd || !smtpReady) { return resolve(); }
                db.get('SELECT email FROM users WHERE username = ?', [username], (e:any, row:any) => {
                    const to = (row && row.email) ? String(row.email) : '';
                    if (!to) return resolve();
                    const mailOptions = { from: config.smtp.user, to, subject: title || 'Уведомление', text: body || '' };
                    try {
                        (mailTransport()).sendMail(mailOptions, () => resolve());
                    } catch {
                        resolve();
                    }
                });
            });
        } catch {
            resolve();
        }
    });
}

// Maintenance: cleanup expired or used password reset tokens (daily)
if (require.main === module) {
    setInterval(() => {
        try {
            db.run('DELETE FROM password_resets WHERE (expires_at < datetime("now")) OR used_at IS NOT NULL');
        } catch {}
    }, 24 * 60 * 60 * 1000);
}

// Admin-triggered cleanup endpoint
app.post('/admin/password-resets/cleanup', requireAuth, requireAdmin, csrfProtection, (req: express.Request, res: express.Response) => {
    db.run('DELETE FROM password_resets WHERE (expires_at < datetime("now")) OR used_at IS NOT NULL', [], (err) => {
        if (err) return res.redirect('/admin/audit?warning=' + encodeURIComponent('Ошибка очистки токенов'));
        logAdminAction(req.session.user || 'unknown', 'cleanup_password_resets', 'password_resets', 'all');
        res.redirect('/admin/audit');
    });
});

export function escapeHtml(s: string) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Mount static after routes so it doesn't shadow dynamic EJS pages
app.use(express.static(path.join(__dirname, '../public'), {
    index: false,
    setHeaders: (res, filePath) => {
        try {
            if (/\.html$/i.test(filePath)) {
                res.setHeader('Cache-Control', 'no-store');
            } else if (/\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm)$/i.test(filePath)) {
                res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
            }
        } catch {}
    }
}));

// 404 handler
app.use((req, res) => {
    res.status(404).send('<div style="font-family:sans-serif;padding:2rem">Страница не найдена (404). <a href="/">На главную</a></div>');
});

// 500 handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).send('<div style="font-family:sans-serif;padding:2rem">Внутренняя ошибка сервера (500).</div>');
});

export default app;
