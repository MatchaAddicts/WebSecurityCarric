const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken, optionalAuth } = require('../middleware/auth');
const { solveChallenge } = require('../utils/challengeSolver');

// GET /api/reviews/product/:id
router.get('/product/:id', (req, res) => {
  const db = getDb();
  try {
    const reviews = db.prepare(`
      SELECT r.*, u.username FROM reviews r
      LEFT JOIN users u ON r.user_id = u.id
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `).all(req.params.id);

    // VULNERABILITY: Reviews contain raw HTML (stored XSS)
    res.json(reviews);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/reviews
// VULNERABILITY: Stored XSS + Forged User ID (IDOR)
router.post('/', verifyToken, (req, res) => {
  const { product_id, rating, comment, user_id } = req.body;
  const db = getDb();

  if (!product_id || !comment) {
    return res.status(400).json({ error: 'product_id and comment are required' });
  }

  try {
    // VULNERABILITY: Uses user_id from body instead of token (forged review)
    const actualUserId = user_id || req.user.id;

    // VULNERABILITY: No HTML sanitization - allows stored XSS
    const stmt = db.prepare('INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)');
    const result = stmt.run(product_id, actualUserId, rating || 5, comment);

    const response = {
      id: result.lastInsertRowid,
      product_id,
      user_id: actualUserId,
      rating: rating || 5,
      comment,
      message: 'Review posted'
    };

    if (comment.includes('<script') || comment.includes('onerror') || comment.includes('onload') || comment.includes('javascript:')) {
      solveChallenge(req, 'xss_stored');
    }

    if (user_id && user_id !== req.user.id) {
      solveChallenge(req, 'forged_review');
    }

    res.status(201).json(response);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/reviews/:id
router.delete('/:id', verifyToken, (req, res) => {
  const db = getDb();
  try {
    // VULNERABILITY: No ownership check
    db.prepare('DELETE FROM reviews WHERE id = ?').run(req.params.id);
    res.json({ message: 'Review deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
