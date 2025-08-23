import csurf from 'csurf';

export const csrfProtection = csurf({
  cookie: {
    sameSite: 'lax',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
});
