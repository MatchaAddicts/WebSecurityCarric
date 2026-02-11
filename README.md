# Vegetarian Juice Shop

An intentionally vulnerable web application for security testing and training, inspired by OWASP Juice Shop.

**WARNING: This application is intentionally vulnerable. Do NOT deploy in production environments!**

## Overview

Vegetarian Juice Shop is a modern web application for a fictional vegetarian juice company. It contains **28+ intentional security vulnerabilities** spanning the OWASP Top 10 categories, with a built-in **scoreboard** and **challenge tracking system** for individual users.

## Features

- Full e-commerce juice shop (products, cart, orders, reviews)
- 28+ security challenges across OWASP Top 10 categories
- Individual user scoreboard with progress tracking
- Global leaderboard with rankings
- Flag-based challenge verification (`VJS{...}` format)
- Category-based challenge grouping
- Difficulty levels (Easy/Medium/Hard with point values)
- Hint system for each challenge
- Real-time challenge solve notifications

## Vulnerability Categories

| Category | Count | OWASP |
|----------|-------|-------|
| SQL Injection | 3 | A03:2021 |
| Cross-Site Scripting (XSS) | 3 | A03:2021 |
| Broken Access Control (IDOR) | 4 | A01:2021 |
| Authentication Failures | 3 | A07:2021 |
| Security Misconfiguration | 3 | A05:2021 |
| Cryptographic Failures | 3 | A02:2021 |
| SSRF | 1 | A10:2021 |
| XXE | 1 | A05:2021 |
| File Upload | 1 | A04:2021 |
| CSRF | 1 | A01:2021 |
| Mass Assignment | 1 | A04:2021 |
| Race Condition | 1 | A04:2021 |
| Reconnaissance | 1 | A05:2021 |
| Null Byte Injection | 1 | A03:2021 |
| NoSQL-style Injection | 1 | A03:2021 |

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

| Endpoint | Description |
|----------|-------------|
| `GET /api-docs` | API documentation (vulnerable: exposed) |
| `POST /api/auth/login` | Login (vulnerable: SQLi) |
| `GET /api/products/search?q=` | Search (vulnerable: SQLi, reflected XSS) |
| `GET /api/users/profile/:id` | Profile (vulnerable: IDOR) |
| `PUT /api/users/profile` | Update profile (vulnerable: mass assignment) |
| `POST /api/reviews` | Post review (vulnerable: stored XSS, forged user) |
| `GET /api/files/download?file=` | Download (vulnerable: path traversal) |
| `GET /api/scoreboard` | Global leaderboard |
| `GET /api/scoreboard/user/:id` | Individual progress |
| `POST /api/challenges/verify` | Submit a flag |

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
│       ├── auth.js          # Authentication (SQLi, weak reset)
│       ├── products.js      # Products (SQLi search)
│       ├── users.js         # Users (IDOR, mass assignment)
│       ├── orders.js        # Orders (SQLi)
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
