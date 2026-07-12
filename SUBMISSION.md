# Submission checklist — Assignment 4

Submit on Canvas: **the URL of your Git repository only.** No zip, no files.

## Before you push
- [ ] `npm run seed && npm start` works from a clean clone of `vulnerable-app/`.
- [ ] `exploits/sqli.sh` performs the **auth bypass** and the **UNION exfil**.
- [ ] `exploits/xss-payload.txt` contains a working stored-XSS payload + notes.
- [ ] `exploits/csrf-poc.html` moves a victim's credits against the *original* app.
- [ ] Against your **fixed** app, all three exploits fail
      (`SAFE: 3 / 3` from `verify.sh`).
- [ ] Legitimate login, commenting, and transfers still work.
- [ ] `WRITEUP.md` is filled in (use the template below).
- [ ] `node_modules/` and `data/*.db` are **not** committed (`.gitignore` handles this).

## Make your own repo (don't push to the starter)
```bash
# after cloning the starter and doing your work:
rm -rf .git
git init
git add -A
git commit -m "CYSE 411 A4 - CampusSwap patched + exploits"
# create an empty repo on GitHub, then:
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```
Then paste the repo URL into Canvas.

---

## `WRITEUP.md` template (copy this into a file named WRITEUP.md)

```markdown
# Assignment 4 Write-up — <your name>

## V1 — SQL Injection
- Exploit (login bypass): <payload> — why it worked in one sentence.
- Exploit (UNION exfil): <payload> — what data you recovered.
- Fix: <what you changed in /login and /search> (mention bcrypt only if you did the bonus).

## V2 — Stored XSS
- Exploit: <payload> — where it was stored, who it affected.
- Fix: <encoding change> + <the CSP header you added> + <HttpOnly>.
- One sentence: why CSP helps even if you miss an escaping bug.

## V3 — CSRF
- Exploit: <how csrf-poc.html works> — why the cookie was enough.
- Fix: <the token mechanism> + <SameSite change>.
- One sentence: why the attacker cannot forge a valid token.

## Time spent
<hours> — anything that took longer than expected?
```
