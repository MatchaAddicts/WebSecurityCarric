const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const { getDb } = require('./db/schema');
const { JWT_SECRET, optionalAuth } = require('./middleware/auth');
const { solveChallenge, _doSolve } = require('./utils/challengeSolver');

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

// --- Challenge auto-solve middleware ---
// Resolves pending solves (for unauthenticated routes like login)
// and attaches challenge-solved notifications to responses.

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

  if (body && body.user && body.user.id) return body.user.id;
  return null;
}

app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = function(body) {
    try {
      // Complete pending solves (e.g. login route where user wasn't known at detection time)
      if (req._pendingSolves && req._pendingSolves.length > 0) {
        const userId = resolveUserId(req, body);
        if (userId) {
          for (const key of req._pendingSolves) {
            _doSolve(userId, key, req);
          }
        }
      }

      // Attach solved challenge notifications to response
      if (req._challengesSolved && req._challengesSolved.length > 0 && typeof body === 'object' && body !== null) {
        body._challenge_solved = req._challengesSolved;
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
app.get('/package-lock.json', optionalAuth, (req, res) => {
  solveChallenge(req, 'exposed_lockfile');
  const lockfilePath = path.join(__dirname, '..', 'package-lock.json');
  res.json({
    message: 'You found the exposed lockfile! This reveals exact dependency versions.',
    hint: 'Run npm audit against these versions to find known CVEs.',
    lockfile_path: lockfilePath
  });
});

// VULNERABILITY: A03:2025 Supply Chain - npm audit info
app.get('/api/dependencies', optionalAuth, (req, res) => {
  solveChallenge(req, 'outdated_deps');
  const pkg = require('../package.json');
  res.json({
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
app.post('/api/validate', optionalAuth, (req, res) => {
  const { value, expected_type } = req.body;

  try {
    let result;
    if (expected_type === 'number') {
      result = value + 1;
    } else if (expected_type === 'string') {
      result = value.toUpperCase();
    } else {
      result = value;
    }

    const response = { result, input_type: typeof value, expected_type };

    if (typeof value !== expected_type) {
      solveChallenge(req, 'type_confusion');
      response.note = `Expected ${expected_type} but received ${typeof value}`;
    }

    res.json(response);
  } catch (err) {
    solveChallenge(req, 'type_confusion');
    res.status(500).json({
      error: err.message,
      note: `Type confusion caused error: expected ${expected_type} but got ${typeof value}`,
      stack: err.stack
    });
  }
});

// VULNERABILITY: A01:2025 - SSRF via URL preview feature
app.post('/api/preview-url', optionalAuth, (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const result = { url, preview: `Preview of: ${url}` };

  if (/localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254|file:|internal|metadata/i.test(url)) {
    solveChallenge(req, 'ssrf_basic');
    result.message = 'Internal resource access attempted.';
    result.internal_data = { db_host: 'localhost:5432', redis: 'redis://internal:6379', secret_key: JWT_SECRET };
  }

  res.json(result);
});

// VULNERABILITY: Unprotected API documentation
app.get('/api-docs', optionalAuth, (req, res) => {
  solveChallenge(req, 'exposed_api');
  res.json({
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
        'POST /api/challenges/solve': 'Report a solved challenge (client-side detection)',
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
app.get('/secret-dev-page', optionalAuth, (req, res) => {
  solveChallenge(req, 'hidden_page');
  res.json({
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
  solveChallenge(req, 'error_disclosure');
  res.status(500).json({
    error: err.message,
    stack: err.stack,
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
