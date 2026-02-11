const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { optionalAuth } = require('../middleware/auth');

// GET /api/feedback
router.get('/', (req, res) => {
  const db = getDb();
  try {
    const feedback = db.prepare('SELECT f.*, u.username FROM feedback f LEFT JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC').all();
    res.json(feedback);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/feedback
// VULNERABILITY: No authentication required, XSS in message
router.post('/', optionalAuth, (req, res) => {
  const { subject, message, rating } = req.body;
  const db = getDb();

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  try {
    const userId = req.user?.id || null;
    // VULNERABILITY: No input sanitization
    const stmt = db.prepare('INSERT INTO feedback (user_id, subject, message, rating) VALUES (?, ?, ?, ?)');
    const result = stmt.run(userId, subject || 'No subject', message, rating || 3);

    res.status(201).json({
      id: result.lastInsertRowid,
      message: 'Feedback submitted',
      subject,
      content: message
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
