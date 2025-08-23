declare module 'connect-sqlite3' {
  import session from 'express-session';
  const init: (session: typeof import('express-session')) => any;
  export default init;
}
