const express = require('express');
const router = express.Router();
const md5 = require('md5');
const { getDb } = require('../db/schema');
const { signToken } = require('../middleware/auth');
const { solveChallenge } = require('../utils/challengeSolver');

// VULNERABILITY: A09:2025 - No rate limiting, no logging of failed attempts
const failedAttempts = {};

// POST /api/auth/login
// VULNERABILITY: SQL Injection in login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const db = getDb();

  try {
    // VULNERABILITY: Direct string concatenation in SQL query
    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${md5(password)}'`;
    const user = db.prepare(query).get();

    if (!user) {
      // Also try without hashing password for SQLi to work
      const query2 = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
      try {
        const user2 = db.prepare(query2).get();
        if (user2) {
          const token = signToken({
            id: user2.id,
            username: user2.username,
            email: user2.email,
            role: user2.role
          });
          return res.json({
            token,
            user: { id: user2.id, username: user2.username, email: user2.email, role: user2.role }
          });
        }
      } catch (e) {
        // ignore
      }

      // VULNERABILITY: SQL Injection - try the raw input to allow classic SQLi
      try {
        const sqliQuery = `SELECT * FROM users WHERE email = '${email}'`;
        const sqliUser = db.prepare(sqliQuery).get();
        if (sqliUser) {
          if (sqliUser.role === 'admin') {
            solveChallenge(req, 'sqli_login');
          }
          const token = signToken({
            id: sqliUser.id,
            username: sqliUser.username,
            email: sqliUser.email,
            role: sqliUser.role
          });
          return res.json({
            token,
            user: { id: sqliUser.id, username: sqliUser.username, email: sqliUser.email, role: sqliUser.role }
          });
        }
      } catch (e) {
        // ignore SQLi errors silently
      }

      // VULNERABILITY: A09:2025 - Track failed attempts but never lock out or alert
      failedAttempts[email] = (failedAttempts[email] || 0) + 1;
      const attempts = failedAttempts[email];

      const errorResponse = { error: 'Invalid email or password' };

      if (attempts >= 10) {
        solveChallenge(req, 'no_logging');
        errorResponse.note = `${attempts} failed attempts for this account and still no lockout!`;
      }

      return res.status(401).json(errorResponse);
    }

    const token = signToken({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    });

    const response = {
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role }
    };

    if (user.role === 'admin' && email === 'admin@vegetarian-juice.shop' && password === 'admin123') {
      solveChallenge(req, 'weak_password');
    }

    if (user.username === 'wurstbot') {
      solveChallenge(req, 'default_creds');
    }

    res.json(response);
  } catch (err) {
    // VULNERABILITY: Verbose error message
    res.status(500).json({
      error: 'Login failed',
      details: err.message,
      query_debug: `Attempted query with email: ${email}`
    });
  }
});

// POST /api/auth/register
router.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  const db = getDb();

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // VULNERABILITY: MD5 password hashing (weak, no salt)
    const hashedPassword = md5(password);

    const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username, email, hashedPassword);

    const token = signToken({
      id: result.lastInsertRowid,
      username,
      email,
      role: 'customer'
    });

    res.status(201).json({
      token,
      user: { id: result.lastInsertRowid, username, email, role: 'customer' }
    });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// POST /api/auth/reset-password
// VULNERABILITY: Insecure password reset - no email verification
router.post('/reset-password', (req, res) => {
  const { email, new_password } = req.body;
  const db = getDb();

  if (!email || !new_password) {
    return res.status(400).json({ error: 'Email and new_password are required' });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULNERABILITY: No verification step - anyone can reset any password
    const hashedPassword = md5(new_password);
    db.prepare('UPDATE users SET password = ? WHERE email = ?').run(hashedPassword, email);

    solveChallenge(req, 'password_reset');

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed', details: err.message });
  }
});

module.exports = router;
