# Assignment 4 Write-up — aaljabir

## Overview

For this assignment, I examined CampusSwap from two perspectives. First, I used the deliberately insecure application as an attacker to confirm that its weaknesses were practically exploitable. I then changed only the relevant security-sensitive sections so the same attacks stopped working while normal marketplace functions continued to operate.

## V1 — SQL Injection

### Authentication Bypass

The login bypass used the following username:

```text
quartermaster' -- 
```

The password field could contain any value. The single quotation mark ended the username string, while the SQL comment sequence caused the database to ignore the password condition. This allowed access to the quartermaster account without knowing its password.

### UNION-Based Disclosure

The search payload was:

```text
zzz%' UNION SELECT id, username || '::' || password, credits FROM users -- 
```

The original search query expected three columns. I therefore created a UNION query with three compatible values: user ID, combined username and password, and credit balance. This caused user information to appear among ordinary search results.

### Remediation

I replaced dynamically assembled SQL strings with prepared statements. Both the login values and the search term are now passed through `?` placeholders. The database therefore handles these values strictly as data rather than interpreting them as SQL syntax.

Normal login and normal item searching still function after this change.

## V2 — Stored Cross-Site Scripting

### Exploit

I submitted the following comment:

```html
<script>alert('CampusSwap stored-XSS proof')</script>
```

The application stored the comment and later inserted it directly into the item page. As a result, the browser executed the content whenever another user visited that listing. A second local-only demonstration showed that the readable session cookie could also be accessed through `document.cookie`.

### Remediation

I changed the comment rendering expression from raw output to `esc(comment.body)`. HTML control characters are now encoded, so the browser displays malicious markup rather than executing it.

I also introduced a Content-Security-Policy that restricts scripts and other resources to the CampusSwap origin. Finally, the session cookie now uses the `HttpOnly` option, preventing client-side JavaScript from reading it.

CSP provides a second defensive boundary: even if another output-encoding mistake appears later, the browser is instructed not to execute inline scripts.

## V3 — Cross-Site Request Forgery

### Exploit

My proof-of-concept page contained a hidden form that automatically submitted a transfer of 37 credits to Mallory. When Alice visited that external page while authenticated, her browser included the CampusSwap session cookie with the request. The original server considered the cookie sufficient proof that Alice had approved the transfer.

### Remediation

Each newly created session now receives a cryptographically random CSRF token. The wallet form includes that token in a hidden `_csrf` field. Before processing a transfer, the server validates the submitted token against the token stored in the authenticated session.

I also configured the session cookie with `SameSite: 'strict'`, which further restricts cross-site cookie transmission.

The external attack page cannot create a valid token because it cannot read the secret value embedded in a same-origin CampusSwap page. Legitimate transfers still work because the real wallet form receives the correct token.

## Verification

Before the patches, the supplied verification script reported:

```text
EXPLOITABLE: 3 / 3
```

After applying the fixes, reseeding the database, and restarting the server, the script reported:

```text
SAFE: 3 / 3
```

I also manually confirmed that standard login, item comments, searching, and wallet transfers remained operational.
