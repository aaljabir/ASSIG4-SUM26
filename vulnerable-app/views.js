'use strict';

/*
 * CampusSwap - secured view helpers
 * ---------------------------------
 *
 * Security updates:
 * 1. Stored comments are escaped before being inserted into HTML.
 * 2. The wallet transfer form includes the session CSRF token.
 */

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout({ title, session, body }) {
  const nav = session
    ? `
      <span class="who">
        Signed in as <strong>${esc(session.username)}</strong>
      </span>
      <a href="/wallet">Wallet</a>
      <form method="POST" action="/logout" class="inline">
        <button class="link" type="submit">Log out</button>
      </form>
    `
    : `
      <a href="/login">Log in</a>
      <a href="/register">Register</a>
    `;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <title>${esc(title)} · CampusSwap</title>

  <link rel="stylesheet" href="/styles.css">
</head>

<body>
  <div class="warnbar">
    ⚠ Local coursework application only. Do not deploy on a public server.
  </div>

  <header class="topbar">
    <a class="brand" href="/">
      Campus<span>Swap</span>
    </a>

    <nav>
      ${nav}
    </nav>
  </header>

  <main>
    ${body}
  </main>

  <footer>
    CampusSwap · a fictional student marketplace for coursework
  </footer>
</body>
</html>`;
}

function renderHome({ session, items, flash }) {
  const cards = items
    .map(
      (item) => `
        <a class="card" href="/item/${encodeURIComponent(item.id)}">
          <h3>${esc(item.title)}</h3>
          <p class="desc">${esc(item.description)}</p>
          <p class="price">${esc(item.price)} credits</p>
          <p class="seller">seller: ${esc(item.seller)}</p>
        </a>
      `
    )
    .join('');

  return layout({
    title: 'Marketplace',
    session,

    body: `
      ${flash ? `<p class="flash">${esc(flash)}</p>` : ''}

      <section class="hero">
        <h1>Buy and sell around campus.</h1>

        <p>
          Trade textbooks, gadgets, and dorm gear with other students
          using CampusSwap credits.
        </p>

        <form class="search" method="GET" action="/search">
          <input
            name="q"
            placeholder="Search items…"
            aria-label="Search items"
          >

          <button type="submit">Search</button>
        </form>
      </section>

      <section class="grid">
        ${cards}
      </section>
    `
  });
}

function renderSearch({ session, q, rows }) {
  const list = rows.length
    ? rows
        .map(
          (row) => `
            <li>
              <strong>${esc(row.title)}</strong>
              — ${esc(row.price)} credits
            </li>
          `
        )
        .join('')
    : '<li class="muted">No items matched.</li>';

  return layout({
    title: 'Search',
    session,

    body: `
      <p>
        <a href="/">← Back to marketplace</a>
      </p>

      <h1>Results for “${esc(q)}”</h1>

      <ul class="results">
        ${list}
      </ul>
    `
  });
}

function renderItem({ session, item, comments, flash }) {
  /*
   * Stored-XSS fix:
   * The comment body is passed through esc() before insertion into HTML.
   */
  const commentHtml = comments
    .map(
      (comment) => `
        <li class="comment">
          <span class="author">${esc(comment.author)}</span>
          <span class="when">${esc(comment.created)}</span>

          <div class="cbody">${esc(comment.body)}</div>
        </li>
      `
    )
    .join('');

  const commentForm = session
    ? `
      <form
        method="POST"
        action="/item/${encodeURIComponent(item.id)}/comment"
        class="commentform"
      >
        <textarea
          name="body"
          rows="3"
          placeholder="Ask a question or leave a note…"
          required
        ></textarea>

        <button type="submit">Post comment</button>
      </form>
    `
    : `
      <p class="muted">
        <a href="/login">Log in</a> to leave a comment.
      </p>
    `;

  return layout({
    title: item.title,
    session,

    body: `
      <p>
        <a href="/">← Back to marketplace</a>
      </p>

      ${flash ? `<p class="flash">${esc(flash)}</p>` : ''}

      <article class="detail">
        <h1>${esc(item.title)}</h1>

        <p class="price big">
          ${esc(item.price)} credits
        </p>

        <p class="desc">
          ${esc(item.description)}
        </p>

        <p class="seller">
          Sold by ${esc(item.seller)}
        </p>
      </article>

      <section class="comments">
        <h2>Comments</h2>

        <ul class="commentlist">
          ${
            commentHtml ||
            '<li class="muted">No comments yet.</li>'
          }
        </ul>

        ${commentForm}
      </section>
    `
  });
}

function renderLogin({ session, error }) {
  return layout({
    title: 'Log in',
    session,

    body: `
      <div class="formwrap">
        <h1>Log in</h1>

        ${error ? `<p class="error">${esc(error)}</p>` : ''}

        <form method="POST" action="/login">
          <label>
            Username

            <input
              name="username"
              autocomplete="username"
              required
            >
          </label>

          <label>
            Password

            <input
              name="password"
              type="password"
              autocomplete="current-password"
              required
            >
          </label>

          <button type="submit">Log in</button>
        </form>

        <p class="muted">
          Demo account:
          <code>alice</code> /
          <code>sunshine22</code>
        </p>
      </div>
    `
  });
}

function renderRegister({ session, error }) {
  return layout({
    title: 'Register',
    session,

    body: `
      <div class="formwrap">
        <h1>Create an account</h1>

        ${error ? `<p class="error">${esc(error)}</p>` : ''}

        <form method="POST" action="/register">
          <label>
            Username

            <input
              name="username"
              autocomplete="username"
              required
            >
          </label>

          <label>
            Password

            <input
              name="password"
              type="password"
              autocomplete="new-password"
              required
            >
          </label>

          <button type="submit">Register</button>
        </form>
      </div>
    `
  });
}

function renderWallet({
  session,
  me,
  transfers,
  flash,
  csrf
}) {
  const history = transfers.length
    ? transfers
        .map(
          (transfer) => `
            <li>
              ${esc(transfer.from_user)}
              →
              ${esc(transfer.to_user)}:

              <strong>${esc(transfer.amount)}</strong>
              credits

              <span class="when">
                ${esc(transfer.created)}
              </span>
            </li>
          `
        )
        .join('')
    : '<li class="muted">No transfers yet.</li>';

  return layout({
    title: 'Wallet',
    session,

    body: `
      <div class="wallet">
        <h1>Your wallet</h1>

        ${flash ? `<p class="flash">${esc(flash)}</p>` : ''}

        <p class="balance">
          Balance:
          <strong>${esc(me.credits)}</strong>
          credits
        </p>

        <h2>Send credits</h2>

        <form
          method="POST"
          action="/wallet/transfer"
          class="transferform"
        >
          <input
            type="hidden"
            name="_csrf"
            value="${esc(csrf)}"
          >

          <label>
            To (username)

            <input
              name="to"
              autocomplete="off"
              required
            >
          </label>

          <label>
            Amount

            <input
              name="amount"
              type="number"
              min="1"
              step="1"
              required
            >
          </label>

          <button type="submit">Send</button>
        </form>

        <h2>History</h2>

        <ul class="history">
          ${history}
        </ul>
      </div>
    `
  });
}

module.exports = {
  esc,
  layout,
  renderHome,
  renderSearch,
  renderItem,
  renderLogin,
  renderRegister,
  renderWallet
};