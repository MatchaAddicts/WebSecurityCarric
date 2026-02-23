# Vegetarian Juice Shop

An intentionally vulnerable web application for security testing and training, inspired by OWASP Juice Shop.

**WARNING: This application is intentionally vulnerable. Do NOT deploy in production environments!**

## Overview

Vegetarian Juice Shop is a modern web application for a fictional vegetarian juice company. It contains **35+ intentional security vulnerabilities** spanning all **OWASP Top 10:2025** categories, with a built-in **scoreboard** and **challenge tracking system** for individual users.

## Features

- Full e-commerce juice shop (products, cart, orders, reviews)
- 35+ security challenges across all OWASP Top 10:2025 categories
- Individual user scoreboard with progress tracking
- Global leaderboard with rankings
- Flag-based challenge verification (`VJS{...}` format)
- Category-based challenge grouping
- Difficulty levels (Easy/Medium/Hard with point values)
- Hint system for each challenge
- Real-time challenge solve notifications

## OWASP Top 10:2025 Vulnerability Categories

| OWASP 2025 | Category | Challenges | Description |
|------------|----------|------------|-------------|
| **A01:2025** | Broken Access Control | 6 | IDOR, admin bypass, CSRF, SSRF, forged reviews, privilege escalation |
| **A02:2025** | Security Misconfiguration | 5 | Verbose errors, path traversal, default creds, hidden pages, XXE |
| **A03:2025** | Software Supply Chain Failures | 3 | Outdated deps, exposed lockfile, prototype pollution (**NEW in 2025**) |
| **A04:2025** | Cryptographic Failures | 3 | MD5 hashing, exposed API docs/secrets, weak JWT secret |
| **A05:2025** | Injection | 8 | SQL injection (3), XSS (3), null byte, NoSQL-style injection |
| **A06:2025** | Insecure Design | 3 | Unrestricted file upload, mass assignment, race condition |
| **A07:2025** | Authentication Failures | 3 | Weak password, JWT none algorithm, broken password reset |
| **A08:2025** | Software & Data Integrity Failures | 1 | Client-side price tampering, unsigned data |
| **A09:2025** | Security Logging & Alerting Failures | 1 | No rate limiting, no failed login alerts |
| **A10:2025** | Mishandling of Exceptional Conditions | 3 | Negative quantities, type confusion, integer overflow (**NEW in 2025**) |

## Quick Start

### Using Node.js

```bash
npm install
npm start
```

Open http://localhost:3000

### Using Docker

```bash
docker build -t vegetarian-juice-shop .
docker run -p 3000:3000 vegetarian-juice-shop
```

### Using Docker Compose

```bash
# Vulnerable instance only
docker-compose up

# With clean/remediated instance for comparison
docker-compose --profile clean up
```

- Vulnerable instance: http://localhost:3000
- Clean instance: http://localhost:3001

## Scoring System

- **Easy challenges (1 star):** 100 points each
- **Medium challenges (2 stars):** 200 points each
- **Hard challenges (3 stars):** 300 points each

Flags follow the format: `VJS{flag_content_here}`

## API Endpoints

| Endpoint | Description | OWASP |
|----------|-------------|-------|
| `POST /api/auth/login` | Login (SQLi, no rate limiting) | A05, A09 |
| `GET /api/products/search?q=` | Search (SQLi, reflected XSS) | A05 |
| `GET /api/users/profile/:id` | Profile (IDOR, password hash exposure) | A01, A04 |
| `PUT /api/users/profile` | Update profile (mass assignment, prototype pollution) | A06, A03 |
| `POST /api/users/wallet/topup` | Wallet (no auth on user_id, integer overflow) | A01, A10 |
| `POST /api/orders` | Create order (negative qty, no balance check) | A10, A06 |
| `POST /api/reviews` | Post review (stored XSS, forged user) | A05, A01 |
| `GET /api/files/download?file=` | Download (path traversal) | A02 |
| `POST /api/files/import-xml` | Import XML (XXE) | A02 |
| `POST /api/coupons/apply` | Apply coupon (race condition, NoSQL injection) | A06, A05 |
| `GET /api-docs` | API documentation (exposed secrets) | A04 |
| `GET /api/dependencies` | Dependency info (supply chain) | A03 |
| `POST /api/validate` | Validation (type confusion) | A10 |
| `GET /api/scoreboard` | Global leaderboard | - |
| `GET /api/scoreboard/user/:id` | Individual progress | - |
| `POST /api/challenges/verify` | Submit a flag | - |

## Tech Stack

- **Backend:** Node.js, Express.js
- **Database:** SQLite3 (better-sqlite3)
- **Frontend:** Vanilla HTML/CSS/JavaScript
- **Auth:** JWT (intentionally weak)
- **Container:** Docker

## Project Structure

```
vegetarian-juice-shop/
├── server/
│   ├── app.js              # Main Express application
│   ├── db/
│   │   ├── schema.js       # Database schema
│   │   └── seed.js         # Seed data (users, products, challenges)
│   ├── middleware/
│   │   └── auth.js         # JWT auth (intentionally weak)
│   └── routes/
│       ├── auth.js          # Authentication (SQLi, no rate limiting)
│       ├── products.js      # Products (SQLi search)
│       ├── users.js         # Users (IDOR, mass assignment, prototype pollution)
│       ├── orders.js        # Orders (SQLi, negative qty)
│       ├── reviews.js       # Reviews (stored XSS, forged user)
│       ├── feedback.js      # Feedback (XSS)
│       ├── files.js         # File ops (upload, path traversal, XXE)
│       ├── coupons.js       # Coupons (race condition, NoSQL injection)
│       ├── admin.js         # Admin (broken access control)
│       ├── scoreboard.js    # Scoreboard system
│       └── challenges.js    # Challenge tracking and flag verification
├── frontend/
│   ├── index.html           # SPA shell (DOM XSS)
│   ├── css/style.css        # Styles
│   └── js/
│       ├── app.js           # App logic, navigation
│       ├── api.js           # API client
│       └── pages.js         # Page renderers
├── Dockerfile
├── docker-compose.yml
└── package.json
```

## License

MIT - For educational and security testing purposes only.
