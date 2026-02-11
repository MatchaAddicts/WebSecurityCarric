const express = require('express');
const router = express.Router();
const md5 = require('md5');
const { getDb } = require('../db/schema');
const { verifyToken, optionalAuth } = require('../middleware/auth');

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
      response.flag = 'VJS{1d0r_pr0f1le_4cc3ss}';
    }

    // VULNERABILITY: Password hash exposed
    if (user.password) {
      response.password_hash_info = {
        algorithm: 'MD5',
        hash: user.password,
        flag: 'VJS{md5_n0_s4lt_cr4ck}'
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
    // VULNERABILITY: Directly spread all body fields into update
    const fields = req.body;
    const setClauses = [];
    const values = [];

    for (const [key, value] of Object.entries(fields)) {
      if (key !== 'id') { // Only protect id from modification
        setClauses.push(`${key} = ?`);
        values.push(value);
      }
    }

    if (setClauses.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(userId);
    const query = `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`;
    db.prepare(query).run(...values);

    const updated = db.prepare('SELECT id, username, email, role, wallet_balance FROM users WHERE id = ?').get(userId);

    const response = { user: updated, message: 'Profile updated' };

    // Check if role was changed to admin
    if (fields.role === 'admin') {
      response.flag = 'VJS{m4ss_4ss1gn_r0l3}';
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

  // VULNERABILITY: Uses user_id from body, not from token
  const targetUserId = user_id || req.user.id;

  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  try {
    db.prepare('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?').run(amount, targetUserId);
    const user = db.prepare('SELECT id, username, wallet_balance FROM users WHERE id = ?').get(targetUserId);

    const response = { user, message: `Wallet topped up by $${amount}` };

    // VULNERABILITY: Horizontal privilege escalation detected
    if (targetUserId !== req.user.id) {
      response.flag = 'VJS{h0r1z0nt4l_pr1v_3sc}';
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
