const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const cors = require('cors');

const { getDb } = require('./db/schema');

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

// VULNERABILITY: Expose server info in headers
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Express 4.18.2');
  res.setHeader('Server', 'Vegetarian-Juice-Shop/1.0 (Node.js)');
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
