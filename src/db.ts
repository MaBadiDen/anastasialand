import sqlite3 from 'sqlite3';
sqlite3.verbose();

export const db = new sqlite3.Database('users.db');

// Сначала создаём таблицу, если её нет
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        passwordHash TEXT NOT NULL
    )
`);

// Затем пробуем добавить столбец role, если его нет
db.run(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
        console.error('Ошибка при добавлении столбца role:', err.message);
    }
});

// Затем пробуем добавить столбец email, если его нет
db.run(`ALTER TABLE users ADD COLUMN email TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
        console.error('Ошибка при добавлении столбца email:', err.message);
    }
});

// Добавляем пользователей вручную при запуске (один раз)
import bcrypt from 'bcryptjs';

async function addDefaultUsers() {
    const adminHash = await bcrypt.hash('12344321', 10);
    const userHash = await bcrypt.hash('kaba4ok', 10);

    db.run(
        'INSERT OR IGNORE INTO users (username, passwordHash, role) VALUES (?, ?, ?)', 
        ['TrueMaBadi', adminHash, 'admin']
    );
    db.run(
        'INSERT OR IGNORE INTO users (username, passwordHash, role) VALUES (?, ?, ?)', 
        ['kaba4ok', userHash, 'user']
    );
}

addDefaultUsers();

// Добавляем/обновляем почту для пользователя TrueMaBadi
db.run(
    'UPDATE users SET email = ? WHERE username = ?',
    ['kaba4ok.den@gmail.com', 'TrueMaBadi']
);

db.run(`
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        topic TEXT NOT NULL
    )
`);