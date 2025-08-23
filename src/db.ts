import sqlite3 from 'sqlite3';
import fs from 'fs';
import path from 'path';
sqlite3.verbose();

// Resolve database path: ALWAYS use persistent data/users.db (mounted on Render)
const rootDir = path.join(__dirname, '..');
const dataDir = path.join(rootDir, 'data');
try { fs.mkdirSync(dataDir, { recursive: true }); } catch {}
const dataDbPath = path.join(dataDir, 'users.db');
const legacyDbPath = path.join(rootDir, 'users.db');
// One-time migration: if legacy DB exists in project root and data DB doesn't, move/copy it to data
try {
    if (!fs.existsSync(dataDbPath) && fs.existsSync(legacyDbPath)) {
        try {
            fs.renameSync(legacyDbPath, dataDbPath);
        } catch {
            // Fallback to copy if rename across devices is not possible
            try {
                const buf = fs.readFileSync(legacyDbPath);
                fs.writeFileSync(dataDbPath, buf);
            } catch {}
        }
    }
} catch {}
const dbPath = dataDbPath;
try { if (process.env.DEBUG_AUTH === '1') console.error('[DB] Using SQLite at', dbPath); } catch {}

export const db = new sqlite3.Database(dbPath);

// Pragmas for performance and reliability
db.serialize(() => {
    db.run('PRAGMA foreign_keys = ON');
    db.run('PRAGMA journal_mode = WAL');
    db.run('PRAGMA synchronous = NORMAL');
});

// Создание и миграции для users в сериализованном порядке
import { hashPassword } from './security/passwords';
db.serialize(() => {
    // Базовая таблица
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            passwordHash TEXT NOT NULL
        )
    `);
    // Миграции колонок
    db.run(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`, (err) => {
        if (err && !String(err.message || '').includes('duplicate column name')) {
            console.error('Ошибка при добавлении столбца role:', err.message);
        }
    });
    db.run(`ALTER TABLE users ADD COLUMN email TEXT`, (err) => {
        if (err && !String(err.message || '').includes('duplicate column name')) {
            console.error('Ошибка при добавлении столбца email:', err.message);
        }
    });
    // Дефолтные пользователи и правки после того, как гарантированно есть нужные колонки
    (async () => {
        try {
            const adminHash = await hashPassword('12344321');
            const userHash = await hashPassword('kaba4ok');
            db.run('INSERT OR IGNORE INTO users (username, passwordHash, role) VALUES (?, ?, ?)', ['TrueMaBadi', adminHash, 'admin']);
            db.run('INSERT OR IGNORE INTO users (username, passwordHash, role) VALUES (?, ?, ?)', ['kaba4ok', userHash, 'user']);
            db.run('UPDATE users SET email = ? WHERE username = ?', ['kaba4ok.den@gmail.com', 'TrueMaBadi']);
            db.run('UPDATE users SET role = ? WHERE username = ?', ['admin', 'TrueMaBadi']);

            // One-time admin bootstrap from env (useful on Render after fresh disk)
            const envAdmin = (process.env.BOOTSTRAP_ADMIN_USERNAME || '').trim();
            const envPass = (process.env.BOOTSTRAP_ADMIN_PASSWORD || '').trim();
            const envEmail = (process.env.BOOTSTRAP_ADMIN_EMAIL || '').trim();
            if (envAdmin && envPass) {
                try {
                    const hash = await hashPassword(envPass);
                    db.run('INSERT OR IGNORE INTO users (username, passwordHash, role, email) VALUES (?, ?, ?, ?)', [envAdmin, hash, 'admin', envEmail || null]);
                } catch (ee) {
                    try { console.error('[bootstrap-admin] failed:', (ee as any)?.message || ee); } catch {}
                }
            }
        } catch (e) {
            console.error('Ошибка инициализации пользователей:', (e as any)?.message || e);
        }
    })();
});

// videos: создание и миграции последовательно
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            filename TEXT NOT NULL,
            topic TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0
        )
    `);
    // На случай апгрейда старой БД без position
    db.run(`ALTER TABLE videos ADD COLUMN position INTEGER NOT NULL DEFAULT 0`, (err) => {
        if (err && !String(err.message || '').includes('duplicate column name')) {
            console.error('Ошибка при добавлении столбца position в videos:', err.message);
        }
    });
});

// Разделы (темы) для видео
db.run(`
    CREATE TABLE IF NOT EXISTS topics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )
`);

// Курсы и привязка тем к курсам, а также доступ лекторов — выполняем последовательно
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    `);
    // Add course_id to topics for hierarchical structure (nullable for backward compat)
    db.run(`ALTER TABLE topics ADD COLUMN course_id INTEGER`, (err) => {
        if (err && !String(err.message || '').includes('duplicate column name')) {
            console.error('Ошибка при добавлении столбца course_id в topics:', err.message);
        }
    });
    // Assign default course to existing topics if empty
    db.run(`INSERT OR IGNORE INTO courses (id, name) VALUES (1, 'Общий')`);
    db.run(`UPDATE topics SET course_id = 1 WHERE course_id IS NULL`);

    // Доступ лекторов к курсам
    db.run(`
        CREATE TABLE IF NOT EXISTS lecturer_courses (
            username TEXT NOT NULL,
            course_id INTEGER NOT NULL,
            PRIMARY KEY (username, course_id),
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_lecturer_courses_user ON lecturer_courses(username)');
});

// Аудит действий администратора
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            entity TEXT,
            entity_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// Тесты для видео
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS video_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            video_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            options_json TEXT NOT NULL,
            answer INTEGER NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(video_id) REFERENCES videos(id) ON DELETE CASCADE
        )
    `);
});

// Прогресс пользователя по разделам (видео)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS user_progress (
            username TEXT NOT NULL,
            topic TEXT NOT NULL,
            unlockedCount INTEGER NOT NULL DEFAULT 1,
            lastWatchedIndex INTEGER NOT NULL DEFAULT -1,
            PRIMARY KEY (username, topic)
        )
    `);
});

// Helpful indexes
db.serialize(() => {
    db.run('CREATE INDEX IF NOT EXISTS idx_videos_topic_pos ON videos(topic, position, id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_video_tests_video_pos ON video_tests(video_id, position, id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_user_progress_username ON user_progress(username)');
    db.run('CREATE INDEX IF NOT EXISTS idx_admin_audit_user_action_time ON admin_audit(username, action, created_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_topics_course ON topics(course_id, name)');
});

// Группы пользователей и членства
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS user_groups (
            username TEXT NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (username, group_id),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups(username)');
});

// Password reset tokens: store only token_hash (no plaintext tokens)
db.serialize(() => {
    // Create table if not exists (new schema uses token_hash only)
    db.run(`
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT,
            token_hash TEXT,
            expires_at DATETIME NOT NULL,
            used_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(username, expires_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash)');

    // Legacy migration: if a legacy 'token' column exists, rebuild table without it
    db.all("PRAGMA table_info(password_resets)", [], (e: any, cols: Array<any>) => {
        if (e) return; // best-effort
        const hasTokenCol = Array.isArray(cols) && cols.some((c: any) => String(c.name) === 'token');
        if (!hasTokenCol) return;
        db.serialize(() => {
            db.run('BEGIN');
            db.run(`
                CREATE TABLE IF NOT EXISTS password_resets_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    email TEXT,
                    token_hash TEXT,
                    expires_at DATETIME NOT NULL,
                    used_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `);
            db.run(
                'INSERT INTO password_resets_new (id, username, email, token_hash, expires_at, used_at, created_at) ' +
                'SELECT id, username, email, token_hash, expires_at, used_at, created_at FROM password_resets',
                [],
                (insErr) => {
                    if (insErr) {
                        db.run('ROLLBACK');
                        return;
                    }
                    db.run('DROP TABLE password_resets', [], (dropErr) => {
                        if (dropErr) {
                            db.run('ROLLBACK');
                            return;
                        }
                        db.run('ALTER TABLE password_resets_new RENAME TO password_resets', [], (renErr) => {
                            if (renErr) {
                                db.run('ROLLBACK');
                                return;
                            }
                            db.run('CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(username, expires_at)');
                            db.run('CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash)');
                            db.run('COMMIT');
                        });
                    });
                }
            );
        });
    });
});

// Вебинары (для гугл календаря и открытия тестов)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS webinars (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_event_id TEXT,
            summary TEXT,
            description TEXT,
            start_time DATETIME,
            end_time DATETIME,
            course_id INTEGER,
            topic_id INTEGER,
            tests_open INTEGER NOT NULL DEFAULT 0,
            opened_by TEXT,
            opened_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE SET NULL,
            FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE SET NULL
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_webinars_time ON webinars(start_time, end_time)');
    db.run('CREATE INDEX IF NOT EXISTS idx_webinars_open ON webinars(tests_open)');
    // Add scheduled auto-open time for webinars
    db.run(`ALTER TABLE webinars ADD COLUMN tests_open_at DATETIME`, (err) => {
        if (err && !String(err.message || '').includes('duplicate column name')) {
            console.error('Ошибка при добавлении столбца tests_open_at в webinars:', err.message);
        }
    });

    // Attendees per webinar: direct users and by groups
    db.run(`
        CREATE TABLE IF NOT EXISTS webinar_attendees (
            webinar_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            PRIMARY KEY (webinar_id, username),
            FOREIGN KEY (webinar_id) REFERENCES webinars(id) ON DELETE CASCADE
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_webinar_attendees_web ON webinar_attendees(webinar_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_webinar_attendees_user ON webinar_attendees(username)');

    db.run(`
        CREATE TABLE IF NOT EXISTS webinar_attendee_groups (
            webinar_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (webinar_id, group_id),
            FOREIGN KEY (webinar_id) REFERENCES webinars(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_webinar_attendee_groups_web ON webinar_attendee_groups(webinar_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_webinar_attendee_groups_group ON webinar_attendee_groups(group_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id)');
});

// Тесты для вебинаров (лекций)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS webinar_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webinar_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            options_json TEXT NOT NULL,
            answer INTEGER NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (webinar_id) REFERENCES webinars(id) ON DELETE CASCADE
        )
    `);
    db.run('CREATE INDEX IF NOT EXISTS idx_webinar_tests_web_pos ON webinar_tests(webinar_id, position, id)');
});

export function logAdminAction(username: string, action: string, entity?: string, entityId?: string) {
    db.run('INSERT INTO admin_audit (username, action, entity, entity_id) VALUES (?, ?, ?, ?)', [username, action, entity || null, entityId || null]);
}

    // Уведомления для пользователей
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                read_at DATETIME
            )
        `);
        db.run('CREATE INDEX IF NOT EXISTS idx_notifications_user_time ON notifications(username, created_at DESC)');
        db.run('CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(username, read_at)');
    });