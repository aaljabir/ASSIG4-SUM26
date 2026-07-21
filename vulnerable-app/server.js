'use strict';

/*
 * CampusSwap — Patched Server
 * ===========================
 *
 * Security fixes included:
 *
 * [V1] SQL Injection
 *      - Login and search now use parameterized SQL statements.
 *
 * [V2] Stored XSS supporting protections
 *      - Content-Security-Policy added.
 *      - Session cookie uses HttpOnly.
 *      - The main output-escaping fix must also be applied in views.js.
 *
 * [V3] Cross-Site Request Forgery
 *      - Each session receives a random CSRF token.
 *      - Wallet transfers require a valid CSRF token.
 *      - Session cookie uses SameSite=Strict.
 */

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

const { db, createSchema } = require('./db');
const V = require('./views');

createSchema();

const app = express();
const PORT = process.env.PORT || 3000;

/*
 * Parse cookies and HTML form submissions.
 */
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

/*
 * Content-Security-Policy
 *
 * Inline JavaScript is not permitted because script-src only permits scripts
 * loaded from the same application origin.
 */
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'"
    ].join('; ')
  );

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');

  next();
});

/*
 * Serve application CSS and other public files.
 */
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Session handling
// ---------------------------------------------------------------------------

/*
 * In-memory session store:
 *
 * sid -> {
 *   userId,
 *   username,
 *   csrf
 * }
 *
 * This is suitable for the local coursework application. A real production
 * system would normally use a persistent session store.
 */
const sessions = new Map();

/**
 * Uses a constant-time comparison for two hexadecimal security tokens.
 *
 * The format and length checks are performed first because
 * crypto.timingSafeEqual requires buffers of identical length.
 */
function safeTokenEqual(submittedToken, storedToken) {
  if (
    typeof submittedToken !== 'string' ||
    typeof storedToken !== 'string'
  ) {
    return false;
  }

  const tokenPattern = /^[a-f0-9]{64}$/i;

  if (
    !tokenPattern.test(submittedToken) ||
    !tokenPattern.test(storedToken)
  ) {
    return false;
  }

  const submittedBuffer = Buffer.from(submittedToken, 'hex');
  const storedBuffer = Buffer.from(storedToken, 'hex');

  if (submittedBuffer.length !== storedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(submittedBuffer, storedBuffer);
}

/**
 * Creates a new session for a successfully authenticated user.
 */
function startSession(res, user) {
  const sid = crypto.randomBytes(24).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');

  sessions.set(sid, {
    userId: user.id,
    username: user.username,
    csrf: csrfToken
  });

  res.cookie('sid', sid, {
    path: '/',
    httpOnly: true,
    sameSite: 'strict',

    /*
     * localhost normally uses HTTP during the assignment.
     * Setting Secure only in production allows the local application to work.
     */
    secure: process.env.NODE_ENV === 'production'
  });
}

/**
 * Loads the current session from the sid cookie.
 */
app.use((req, res, next) => {
  const sid = req.cookies.sid;

  req.session =
    sid && sessions.has(sid)
      ? sessions.get(sid)
      : null;

  req.sid = sid || null;

  next();
});

/**
 * Returns the authenticated database user or null.
 */
function currentUser(req) {
  if (!req.session) {
    return null;
  }

  return (
    db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(req.session.userId) || null
  );
}

// ---------------------------------------------------------------------------
// Home
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  const items = db
    .prepare(`
      SELECT
        items.id,
        items.title,
        items.description,
        items.price,
        users.username AS seller
      FROM items
      JOIN users ON users.id = items.seller_id
      ORDER BY items.id DESC
    `)
    .all();

  res.send(
    V.renderHome({
      session: req.session,
      items,
      flash: req.query.msg
    })
  );
});

// ---------------------------------------------------------------------------
// Search — SQL injection fixed
// ---------------------------------------------------------------------------

app.get('/search', (req, res) => {
  const q =
    typeof req.query.q === 'string'
      ? req.query.q
      : '';

  let rows = [];

  try {
    /*
     * The search text is supplied through a placeholder. It cannot alter the
     * structure of the SQL query.
     */
    rows = db
      .prepare(`
        SELECT id, title, price
        FROM items
        WHERE title LIKE ?
      `)
      .all(`%${q}%`);
  } catch (error) {
    console.error('Search query failed:', error.message);
    rows = [];
  }

  res.send(
    V.renderSearch({
      session: req.session,
      q,
      rows
    })
  );
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

app.get('/login', (req, res) => {
  res.send(
    V.renderLogin({
      session: req.session,
      error: req.query.error
    })
  );
});

app.post('/login', (req, res) => {
  const username =
    typeof req.body.username === 'string'
      ? req.body.username.trim()
      : '';

  const password =
    typeof req.body.password === 'string'
      ? req.body.password
      : '';

  let user = null;

  try {
    /*
     * Both values are passed separately from the SQL statement.
     */
    user = db
      .prepare(`
        SELECT *
        FROM users
        WHERE username = ?
          AND password = ?
      `)
      .get(username, password);
  } catch (error) {
    console.error('Login query failed:', error.message);
    user = null;
  }

  if (!user) {
    return res.send(
      V.renderLogin({
        session: req.session,
        error: 'Invalid username or password.'
      })
    );
  }

  startSession(res, user);

  return res.redirect(
    '/?msg=' +
      encodeURIComponent(`Welcome back, ${user.username}!`)
  );
});

app.get('/register', (req, res) => {
  res.send(
    V.renderRegister({
      session: req.session,
      error: req.query.error
    })
  );
});

app.post('/register', (req, res) => {
  const username =
    typeof req.body.username === 'string'
      ? req.body.username.trim()
      : '';

  const password =
    typeof req.body.password === 'string'
      ? req.body.password
      : '';

  if (!username || !password) {
    return res.send(
      V.renderRegister({
        session: req.session,
        error: 'Username and password are required.'
      })
    );
  }

  try {
    const info = db
      .prepare(`
        INSERT INTO users (username, password, credits)
        VALUES (?, ?, 100)
      `)
      .run(username, password);

    startSession(res, {
      id: info.lastInsertRowid,
      username
    });

    return res.redirect(
      '/?msg=' +
        encodeURIComponent(
          'Account created. You have 100 starter credits.'
        )
    );
  } catch (error) {
    return res.send(
      V.renderRegister({
        session: req.session,
        error: 'That username is taken.'
      })
    );
  }
});

app.post('/logout', (req, res) => {
  if (req.sid) {
    sessions.delete(req.sid);
  }

  res.clearCookie('sid', {
    path: '/',
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  });

  res.redirect('/');
});

// ---------------------------------------------------------------------------
// Item details and comments
// ---------------------------------------------------------------------------

app.get('/item/:id', (req, res) => {
  const item = db
    .prepare(`
      SELECT
        items.*,
        users.username AS seller
      FROM items
      JOIN users ON users.id = items.seller_id
      WHERE items.id = ?
    `)
    .get(req.params.id);

  if (!item) {
    return res.status(404).send(
      V.layout({
        title: 'Not found',
        session: req.session,
        body: '<h1>Item not found</h1>'
      })
    );
  }

  const comments = db
    .prepare(`
      SELECT *
      FROM comments
      WHERE item_id = ?
      ORDER BY id ASC
    `)
    .all(item.id);

  return res.send(
    V.renderItem({
      session: req.session,
      item,
      comments,
      flash: req.query.msg
    })
  );
});

app.post('/item/:id/comment', (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.redirect('/login');
  }

  const body =
    typeof req.body.body === 'string'
      ? req.body.body
      : '';

  if (!body.trim()) {
    return res.redirect(
      `/item/${encodeURIComponent(req.params.id)}?msg=` +
        encodeURIComponent('Comment cannot be empty.')
    );
  }

  /*
   * The database may safely store the original comment text. The important
   * Stored-XSS fix is contextual output encoding in views.js:
   *
   *     ${esc(c.body)}
   *
   * instead of:
   *
   *     ${c.body}
   */
  db.prepare(`
    INSERT INTO comments (item_id, author, body)
    VALUES (?, ?, ?)
  `).run(req.params.id, user.username, body);

  return res.redirect(
    `/item/${encodeURIComponent(req.params.id)}?msg=` +
      encodeURIComponent('Comment posted.')
  );
});

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

app.get('/wallet', (req, res) => {
  const me = currentUser(req);

  if (!me) {
    return res.redirect('/login');
  }

  const transfers = db
    .prepare(`
      SELECT *
      FROM transfers
      WHERE from_user = ?
         OR to_user = ?
      ORDER BY id DESC
      LIMIT 20
    `)
    .all(me.username, me.username);

  /*
   * views.js must accept this csrf value and place it in the transfer form:
   *
   * <input type="hidden" name="_csrf" value="${esc(csrf)}">
   */
  return res.send(
    V.renderWallet({
      session: req.session,
      me,
      transfers,
      flash: req.query.msg,
      csrf: req.session.csrf
    })
  );
});

app.post('/wallet/transfer', (req, res) => {
  const me = currentUser(req);

  if (!me) {
    return res.redirect('/login');
  }

  /*
   * Validate the token before performing any state-changing action.
   */
  const submittedToken =
    typeof req.body._csrf === 'string'
      ? req.body._csrf
      : '';

  const storedToken =
    req.session && typeof req.session.csrf === 'string'
      ? req.session.csrf
      : '';

  if (!safeTokenEqual(submittedToken, storedToken)) {
    return res
      .status(403)
      .send('CSRF token missing or invalid.');
  }

  const to =
    typeof req.body.to === 'string'
      ? req.body.to.trim()
      : '';

  const amount = Number.parseInt(req.body.amount, 10);

  if (!to || !Number.isInteger(amount) || amount <= 0) {
    return res.redirect(
      '/wallet?msg=' +
        encodeURIComponent(
          'Enter a valid recipient and amount.'
        )
    );
  }

  const recipient = db
    .prepare(`
      SELECT *
      FROM users
      WHERE username = ?
    `)
    .get(to);

  if (!recipient) {
    return res.redirect(
      '/wallet?msg=' +
        encodeURIComponent(`No such user: ${to}`)
    );
  }

  if (recipient.id === me.id) {
    return res.redirect(
      '/wallet?msg=' +
        encodeURIComponent(
          'You cannot send credits to yourself.'
        )
    );
  }

  /*
   * Read the sender again immediately before the transaction so the balance
   * check uses current database information.
   */
  const freshSender = db
    .prepare('SELECT * FROM users WHERE id = ?')
    .get(me.id);

  if (!freshSender || freshSender.credits < amount) {
    return res.redirect(
      '/wallet?msg=' +
        encodeURIComponent('Not enough credits.')
    );
  }

  const performTransfer = db.transaction(() => {
    /*
     * The additional credits condition protects against an invalid negative
     * balance if the balance changes before this statement executes.
     */
    const debitResult = db
      .prepare(`
        UPDATE users
        SET credits = credits - ?
        WHERE id = ?
          AND credits >= ?
      `)
      .run(amount, freshSender.id, amount);

    if (debitResult.changes !== 1) {
      throw new Error('Sender balance changed before transfer.');
    }

    const creditResult = db
      .prepare(`
        UPDATE users
        SET credits = credits + ?
        WHERE id = ?
      `)
      .run(amount, recipient.id);

    if (creditResult.changes !== 1) {
      throw new Error('Recipient could not be credited.');
    }

    db.prepare(`
      INSERT INTO transfers (from_user, to_user, amount)
      VALUES (?, ?, ?)
    `).run(
      freshSender.username,
      recipient.username,
      amount
    );
  });

  try {
    performTransfer();
  } catch (error) {
    console.error('Wallet transfer failed:', error.message);

    return res.redirect(
      '/wallet?msg=' +
        encodeURIComponent(
          'The transfer could not be completed. Please try again.'
        )
    );
  }

  return res.redirect(
    '/wallet?msg=' +
      encodeURIComponent(
        `Sent ${amount} credits to ${recipient.username}.`
      )
  );
});

// ---------------------------------------------------------------------------
// Start application
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(
    `CampusSwap (SECURED build) running at http://localhost:${PORT}`
  );

  console.log(
    'Run "npm run seed" first if you have not seeded the database.'
  );
});