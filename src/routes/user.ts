import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { db, logAdminAction } from '../db';
import { requireAuth, requireAdmin } from '../middleware/auth';
import { csrfProtection } from '../middleware/csrf';

const userRouter = Router();

userRouter.get('/user-list', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    res.cookie('XSRF-TOKEN', (req as any).csrfToken(), { sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
    db.all('SELECT username, email, role FROM users ORDER BY username', (err: Error | null, usersRaw: any) => {
        if (err) return res.send('Ошибка загрузки пользователей');
        const users = usersRaw as Array<{username: string, email: string, role: string}>;
    const warn = (req.query.warning as string) || '';
    const errMsg = (req.query.error as string) || '';
    res.send(`<!DOCTYPE html><html lang='ru'><head><meta charset='UTF-8'><title>Редактирование пользователей</title><link href='/vendor/bootstrap/bootstrap.min.css' rel='stylesheet'></head><body class='bg-light'>
        <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom mb-4">
            <div class="container-fluid">
                <a href="/admin" class="btn btn-outline-primary me-3">Админпанель</a>
                <span class="navbar-brand mx-auto mb-0 h1">Пользователи</span>
                <a href="/" class="btn btn-outline-secondary ms-auto">Главное меню</a>
            </div>
        </nav>
    <div class='container py-4'><h1 class='mb-4'>Редактирование пользователей</h1>
    ${warn ? `<div class="alert alert-warning">${warn}</div>` : ''}
    ${errMsg ? `<div class="alert alert-danger">${errMsg}</div>` : ''}
        <table class='table table-bordered bg-white'>
            <thead><tr><th>Имя</th><th>Email</th><th>Роль</th><th>Пароль</th><th>Действия</th></tr></thead>
            <tbody>
                ${users.map(u => `
                    <tr>
                        <form method='POST' action='/admin/edit-user/${u.username}' class='d-flex'>
                            <td><input type='text' name='username' value='${u.username}' class='form-control' required></td>
                            <td><input type='email' name='email' value='${u.email || ''}' class='form-control' required></td>
                            <td>${u.role}</td>
                            <td><input type='password' name='password' placeholder='Новый пароль' class='form-control'></td>
                            <td><button type='submit' class='btn btn-sm btn-primary'>Сохранить</button></td>
                        </form>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        </div>
        <script>(function(){
          function getCookie(n){return document.cookie.split('; ').find(r=>r.startsWith(n+'='))?.split('=')[1];}
          var t=getCookie('XSRF-TOKEN'); if(!t) return;
          document.querySelectorAll("form[method='POST']").forEach(function(f){
            if(!f.querySelector("input[name='_csrf']")){
              var i=document.createElement('input'); i.type='hidden'; i.name='_csrf'; i.value=decodeURIComponent(t); f.appendChild(i);
            }
          });
        })();</script>
    <script src="/vendor/bootstrap/bootstrap.bundle.min.js"></script>
        </body></html>`);
    });
});

userRouter.post('/admin/edit-user/:id', requireAuth, requireAdmin, csrfProtection, async (req: Request, res: Response) => {
    const usernameOld = req.params.id;
    const { username, email, password } = req.body;
    let query = 'UPDATE users SET username = ?, email = ?';
    let params: any[] = [username, email];
    if (password && password.length > 0) {
        const passwordHash = await bcrypt.hash(password, 10);
        query += ', passwordHash = ?';
        params.push(passwordHash);
    }
    query += ' WHERE username = ?';
    params.push(usernameOld);
    db.run(query, params, (err: Error | null) => {
        if (err) return res.redirect('/user-list?error=Ошибка сохранения');
    logAdminAction(req.session.user || 'unknown', 'edit_user', 'users', username);
        res.redirect('/user-list');
    });
});

export default userRouter;
