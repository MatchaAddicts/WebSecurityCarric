const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const { getDb } = require('./db/schema');
const { JWT_SECRET } = require('./middleware/auth');

// Initialize database and seed if empty
const db = getDb();
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  console.log('Empty database detected, seeding...');
  require('./db/seed');
}

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY: CORS misconfiguration - allows all origins
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// VULNERABILITY: A03:2025 Supply Chain - Serve package files (lockfile exposure)
app.use(express.static(path.join(__dirname, '..')));

// VULNERABILITY: Expose server info in headers
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Express 4.18.2');
  res.setHeader('Server', 'Vegetarian-Juice-Shop/1.0 (Node.js)');
  next();
});

// --- Auto-solve middleware: automatically marks challenges solved when flags appear in responses ---

// Deep-scan any object for VJS{...} flag patterns
function extractFlags(obj) {
  const flags = [];
  const scan = (val) => {
    if (!val) return;
    if (typeof val === 'string') {
      const matches = val.match(/VJS\{[^}]+\}/g);
      if (matches) flags.push(...matches);
    } else if (Array.isArray(val)) {
      val.forEach(scan);
    } else if (typeof val === 'object') {
      Object.values(val).forEach(scan);
    }
  };
  scan(obj);
  return [...new Set(flags)];
}

// Resolve user ID from JWT header, req.user, or response body (login case)
function resolveUserId(req, body) {
  if (req.user && req.user.id) return req.user.id;

  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.id) return decoded.id;
    } catch (e) {}
    try {
      const parts = token.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      if (header.alg === 'none' || header.alg === 'None') {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        if (payload.id) return payload.id;
      }
    } catch (e) {}
  }

  // Login case: user ID is in the response body
  if (body && body.user && body.user.id) return body.user.id;

  return null;
}

// Intercept res.json() to auto-solve challenges when flags are returned
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = function(body) {
    try {
      // Collect flags from response body + any set by middleware (e.g. jwt_none detection)
      const flags = extractFlags(body);
      if (req._detectedFlags) flags.push(...req._detectedFlags);
      const uniqueFlags = [...new Set(flags)];

      if (uniqueFlags.length > 0) {
        const userId = resolveUserId(req, body);
        if (userId) {
          const db = getDb();
          const solved = [];
          for (const flag of uniqueFlags) {
            try {
              const challenge = db.prepare('SELECT id, name, difficulty FROM challenges WHERE flag = ?').get(flag);
              if (challenge) {
                const existing = db.prepare('SELECT id FROM user_challenges WHERE user_id = ? AND challenge_id = ?').get(userId, challenge.id);
                if (!existing) {
                  db.prepare('INSERT INTO user_challenges (user_id, challenge_id, flag_submitted) VALUES (?, ?, ?)').run(userId, challenge.id, flag);
                  solved.push({ name: challenge.name, points: challenge.difficulty * 100 });
                }
              }
            } catch (e) {}
          }
          // Attach auto-solved info so the client can show notifications
          if (solved.length > 0 && typeof body === 'object' && body !== null) {
            body._auto_solved = solved;
          }
        }
      }
    } catch (e) {}
    return originalJson(body);
  };
  next();
});

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/products', require('./routes/products'));
app.use('/api/users', require('./routes/users'));
app.use('/api/orders', require('./routes/orders'));
app.use('/api/reviews', require('./routes/reviews'));
app.use('/api/feedback', require('./routes/feedback'));
app.use('/api/scoreboard', require('./routes/scoreboard'));
app.use('/api/challenges', require('./routes/challenges'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/files', require('./routes/files'));
app.use('/api/coupons', require('./routes/coupons'));

// VULNERABILITY: A03:2025 Supply Chain - package-lock.json accessible
app.get('/package-lock.json', (req, res) => {
  const lockfilePath = path.join(__dirname, '..', 'package-lock.json');
  res.json({
    flag: 'VJS{l0ckf1l3_3xp0s3d}',
    message: 'You found the exposed lockfile! This reveals exact dependency versions.',
    hint: 'Run npm audit against these versions to find known CVEs.',
    lockfile_path: lockfilePath
  });
});

// VULNERABILITY: A03:2025 Supply Chain - npm audit info
app.get('/api/dependencies', (req, res) => {
  const pkg = require('../package.json');
  res.json({
    flag: 'VJS{vuln3r4bl3_d3ps_f0und}',
    dependencies: pkg.dependencies,
    note: 'Several of these packages have known CVEs. The application uses md5 for password hashing, an outdated multer, and xml2js with XXE risks.',
    vulnerable_packages: [
      { name: 'md5', issue: 'MD5 is cryptographically broken, should use bcrypt/argon2' },
      { name: 'multer', issue: 'v1.x has known vulnerabilities, should upgrade to v2.x' },
      { name: 'xml2js', issue: 'XXE risks if not properly configured' },
      { name: 'jsonwebtoken', issue: 'Using weak secret and accepting "none" algorithm' }
    ]
  });
});

// VULNERABILITY: A10:2025 - Type confusion endpoint
app.post('/api/validate', (req, res) => {
  const { value, expected_type } = req.body;

  // VULNERABILITY: No type checking - processes whatever is sent
  try {
    let result;
    if (expected_type === 'number') {
      // Doesn't actually verify it's a number
      result = value + 1;
    } else if (expected_type === 'string') {
      result = value.toUpperCase();
    } else {
      result = value;
    }

    const response = { result, input_type: typeof value, expected_type };

    // Detect type confusion
    if (typeof value !== expected_type) {
      response.flag = 'VJS{typ3_c0nfus10n_3rr0r}';
      response.note = `Expected ${expected_type} but received ${typeof value}`;
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({
      error: err.message,
      flag: 'VJS{typ3_c0nfus10n_3rr0r}',
      note: `Type confusion caused error: expected ${expected_type} but got ${typeof value}`,
      stack: err.stack
    });
  }
});

// VULNERABILITY: A01:2025 - SSRF via URL preview feature
app.post('/api/preview-url', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const result = { url, preview: `Preview of: ${url}` };

  // VULNERABILITY: No URL validation - allows internal resource access
  if (/localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254|file:|internal|metadata/i.test(url)) {
    result.flag = 'VJS{ssrf_1nt3rn4l_4cc3ss}';
    result.message = 'SSRF detected! Internal resource access attempted.';
    result.internal_data = { db_host: 'localhost:5432', redis: 'redis://internal:6379', secret_key: JWT_SECRET };
  }

  res.json(result);
});

// VULNERABILITY: Unprotected API documentation
app.get('/api-docs', (req, res) => {
  const { getDb } = require('./db/schema');
  const db = getDb();
  // Auto-solve the challenge when someone accesses this
  res.json({
    flag: 'VJS{3xp0s3d_4p1_d0cs}',
    name: 'Vegetarian Juice Shop API',
    version: '1.0.0',
    endpoints: {
      auth: {
        'POST /api/auth/login': 'Login with email and password',
        'POST /api/auth/register': 'Register a new user',
        'POST /api/auth/reset-password': 'Reset password (insecure)',
      },
      products: {
        'GET /api/products': 'List all products',
        'GET /api/products/search?q=': 'Search products (vulnerable to SQLi)',
        'GET /api/products/:id': 'Get product details',
      },
      users: {
        'GET /api/users/profile/:id': 'Get user profile (IDOR)',
        'PUT /api/users/profile': 'Update profile (mass assignment)',
        'POST /api/users/wallet/topup': 'Top up wallet (no auth check on user_id)',
      },
      orders: {
        'GET /api/orders/:id': 'Get order details (SQLi)',
        'POST /api/orders': 'Create order',
      },
      reviews: {
        'GET /api/reviews/product/:id': 'Get reviews for product',
        'POST /api/reviews': 'Create review (stored XSS, forged user)',
      },
      files: {
        'POST /api/files/upload': 'Upload file (unrestricted)',
        'GET /api/files/download?file=': 'Download file (path traversal)',
        'POST /api/files/import-xml': 'Import XML (XXE)',
      },
      ssrf: {
        'POST /api/preview-url': 'Preview URL content (SSRF)',
      },
      admin: {
        'GET /api/admin/dashboard': 'Admin dashboard (broken access)',
        'GET /api/admin/users': 'List all users',
      },
      coupons: {
        'POST /api/coupons/apply': 'Apply coupon (race condition, NoSQL injection)',
      },
      scoreboard: {
        'GET /api/scoreboard': 'View scoreboard',
        'GET /api/scoreboard/user/:id': 'User progress',
      },
      challenges: {
        'GET /api/challenges': 'List all challenges',
        'POST /api/challenges/verify': 'Submit a flag',
      }
    },
    database: 'SQLite3 (better-sqlite3)',
    jwt_info: 'HS256 with secret key',
    debug_note: 'JWT_SECRET=vegetarian-juice-secret-key'
  });
});

// VULNERABILITY: robots.txt reveals hidden paths
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *
Disallow: /api-docs
Disallow: /admin
Disallow: /secret-dev-page
Disallow: /api/admin
Disallow: /ftp
`);
});

// VULNERABILITY: Hidden developer page
app.get('/secret-dev-page', (req, res) => {
  res.json({
    flag: 'VJS{r0b0ts_txt_s3cr3t}',
    message: 'Congratulations! You found the secret developer page!',
    dev_notes: [
      'TODO: Remove default admin account (admin@vegetarian-juice.shop / admin123)',
      'TODO: Switch from MD5 to bcrypt',
      'TODO: Add CSRF tokens',
      'TODO: Fix SQL injection in search',
      'TODO: Sanitize review inputs',
      'JWT Secret: vegetarian-juice-secret-key',
      'Backup DB account: wurstbot@vegetarian-juice.shop / VeggieBot2024!'
    ]
  });
});

// VULNERABILITY: Verbose error handling that leaks information
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    flag: 'VJS{v3rb0s3_3rr0r_l34k}',
    db_path: require('./db/schema').DB_PATH,
    node_version: process.version,
    platform: process.platform,
    env: process.env.NODE_ENV || 'development'
  });
});

// SPA fallback - serve index.html for all non-API routes
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
  } else {
    res.status(404).json({ error: 'Endpoint not found' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  ╔══════════════════════════════════════════════════════╗
  ║       Vegetarian Juice Shop v1.0.0                   ║
  ║       Running on http://0.0.0.0:${PORT}                ║
  ║                                                      ║
  ║  WARNING: This application is intentionally          ║
  ║  vulnerable! Do NOT deploy in production!            ║
  ╚══════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
