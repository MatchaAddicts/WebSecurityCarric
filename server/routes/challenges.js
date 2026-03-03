const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken, optionalAuth } = require('../middleware/auth');
const { solveChallenge, drainNotifications } = require('../utils/challengeSolver');

// GET /api/challenges
// List all challenges with solve status for current user
router.get('/', optionalAuth, (req, res) => {
  const db = getDb();

  try {
    const challenges = db.prepare(`
      SELECT
        c.id,
        c.key,
        c.name,
        c.description,
        c.category,
        c.difficulty,
        c.hint,
        c.owasp_category,
        c.tutorial_url
      FROM challenges c
      ORDER BY c.category, c.difficulty
    `).all();

    let solvedKeys = new Set();
    if (req.user) {
      const solved = db.prepare(`
        SELECT c.key FROM user_challenges uc
        JOIN challenges c ON uc.challenge_id = c.id
        WHERE uc.user_id = ?
      `).all(req.user.id);
      solvedKeys = new Set(solved.map(s => s.key));
    }
    // Also check session-based solves (anonymous users)
    if (req.sessionId) {
      const sessionSolved = db.prepare(`
        SELECT c.key FROM user_challenges uc
        JOIN challenges c ON uc.challenge_id = c.id
        WHERE uc.session_id = ? AND uc.user_id IS NULL
      `).all(req.sessionId);
      for (const s of sessionSolved) {
        solvedKeys.add(s.key);
      }
    }

    const result = challenges.map(ch => ({
      ...ch,
      solved: solvedKeys.has(ch.key),
      stars: '★'.repeat(ch.difficulty) + '☆'.repeat(3 - ch.difficulty),
      points: ch.difficulty * 100
    }));

    // Group by category
    const grouped = {};
    for (const ch of result) {
      if (!grouped[ch.category]) {
        grouped[ch.category] = [];
      }
      grouped[ch.category].push(ch);
    }

    res.json({
      challenges: result,
      grouped,
      total: challenges.length,
      solved: solvedKeys.size
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/challenges/solve
// Client-side challenge detection (e.g. DOM XSS, Reflected XSS)
// These are detected in the browser and reported to the server.
router.post('/solve', verifyToken, (req, res) => {
  const { key } = req.body;

  if (!key) {
    return res.status(400).json({ error: 'Challenge key is required' });
  }

  // Only allow client-side detectable challenges
  const clientChallenges = ['xss_dom', 'xss_reflected'];
  if (!clientChallenges.includes(key)) {
    return res.status(400).json({ error: 'This challenge cannot be solved via client report' });
  }

  solveChallenge(req, key);
  res.json({ message: 'Challenge detection reported' });
});

// POST /api/challenges/restart
// Reset all challenge progress (no auth required)
router.post('/restart', (req, res) => {
  const db = getDb();

  try {
    const deleted = db.prepare('DELETE FROM user_challenges').run();

    res.json({
      message: 'All challenge progress has been reset',
      challenges_cleared: deleted.changes
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/challenges/my-progress
router.get('/my-progress', verifyToken, (req, res) => {
  const db = getDb();

  try {
    const solved = db.prepare(`
      SELECT c.*, uc.solved_at
      FROM user_challenges uc
      JOIN challenges c ON uc.challenge_id = c.id
      WHERE uc.user_id = ?
      ORDER BY uc.solved_at DESC
    `).all(req.user.id);

    const totalChallenges = db.prepare('SELECT COUNT(*) as count FROM challenges').get();
    const totalScore = solved.reduce((sum, s) => sum + (s.difficulty * 100), 0);

    res.json({
      solved,
      total_solved: solved.length,
      total_challenges: totalChallenges.count,
      total_score: totalScore,
      progress_percent: Math.round((solved.length / totalChallenges.count) * 100)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/challenges/notifications
// Poll endpoint: returns and clears any pending solve notifications for this session.
router.get('/notifications', (req, res) => {
  const notifications = drainNotifications(req.sessionId);
  res.json({ notifications });
});

module.exports = router;
