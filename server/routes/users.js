const express = require('express');
const router = express.Router();
const md5 = require('md5');
const { getDb } = require('../db/schema');
const { verifyToken, optionalAuth } = require('../middleware/auth');
const { solveChallenge } = require('../utils/challengeSolver');

// GET /api/users/profile/:id
// VULNERABILITY: IDOR - no authorization check, any user can view any profile
router.get('/profile/:id', optionalAuth, (req, res) => {
  const db = getDb();
  try {
    // VULNERABILITY: Returns sensitive data including password hash
    const user = db.prepare('SELECT id, username, email, role, wallet_balance, profile_image, created_at, password FROM users WHERE id = ?').get(req.params.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const response = { user };

    // Detect IDOR: user accessing someone else's profile
    if (req.user && req.user.id !== parseInt(req.params.id)) {
      solveChallenge(req, 'idor_profile');
    }

    // VULNERABILITY: Password hash exposed
    if (user.password) {
      solveChallenge(req, 'md5_passwords');
      response.password_hash_info = {
        algorithm: 'MD5',
        hash: user.password
      };
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/users/profile
// VULNERABILITY: Mass Assignment - accepts all fields including role
router.put('/profile', verifyToken, (req, res) => {
  const db = getDb();
  const userId = req.user.id;

  try {
    const fields = req.body;
    const setClauses = [];
    const values = [];

    // VULNERABILITY: A03:2025 Supply Chain - Prototype Pollution
    const pollutionDetected = fields['__proto__'] !== undefined ||
      fields['constructor'] !== undefined ||
      fields['prototype'] !== undefined;

    for (const [key, value] of Object.entries(fields)) {
      if (key !== 'id' && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
        setClauses.push(`${key} = ?`);
        values.push(value);
      }
    }

    if (setClauses.length === 0 && !pollutionDetected) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    if (setClauses.length > 0) {
      values.push(userId);
      const query = `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`;
      db.prepare(query).run(...values);
    }

    const updated = db.prepare('SELECT id, username, email, role, wallet_balance FROM users WHERE id = ?').get(userId);

    const response = { user: updated, message: 'Profile updated' };

    if (fields.role === 'admin') {
      solveChallenge(req, 'mass_assign');
    }

    if (pollutionDetected) {
      solveChallenge(req, 'prototype_pollution');
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({ error: err.message, details: err.message });
  }
});

// POST /api/users/wallet/topup
// VULNERABILITY: No proper auth check on target user_id
router.post('/wallet/topup', verifyToken, (req, res) => {
  const { user_id, amount } = req.body;
  const db = getDb();

  const targetUserId = user_id || req.user.id;

  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  try {
    db.prepare('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?').run(amount, targetUserId);
    const user = db.prepare('SELECT id, username, wallet_balance FROM users WHERE id = ?').get(targetUserId);

    const response = { user, message: `Wallet topped up by $${amount}` };

    if (targetUserId !== req.user.id) {
      solveChallenge(req, 'horizontal_priv');
    }

    const origin = req.headers.origin || '';
    const host = req.headers.host || '';
    if (!origin || !origin.includes(host)) {
      solveChallenge(req, 'csrf_wallet');
    }

    if (amount > 1000000 || amount === Number.MAX_SAFE_INTEGER || !Number.isFinite(amount)) {
      solveChallenge(req, 'overflow_wallet');
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULNERABILITY: List all users (information disclosure)
router.get('/', (req, res) => {
  const db = getDb();
  try {
    const users = db.prepare('SELECT id, username, email, role, wallet_balance, created_at FROM users').all();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
