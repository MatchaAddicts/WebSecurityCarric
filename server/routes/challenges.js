const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken, optionalAuth } = require('../middleware/auth');

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

// POST /api/challenges/verify
// Submit a flag to solve a challenge
router.post('/verify', verifyToken, (req, res) => {
  const { flag } = req.body;
  const db = getDb();

  if (!flag) {
    return res.status(400).json({ error: 'Flag is required' });
  }

  try {
    // Find challenge by flag
    const challenge = db.prepare('SELECT * FROM challenges WHERE flag = ?').get(flag);

    if (!challenge) {
      return res.status(400).json({
        error: 'Invalid flag',
        message: 'The submitted flag does not match any challenge.'
      });
    }

    // Check if already solved
    const existing = db.prepare('SELECT * FROM user_challenges WHERE user_id = ? AND challenge_id = ?').get(
      req.user.id, challenge.id
    );

    if (existing) {
      return res.json({
        message: 'Challenge already solved!',
        challenge: {
          name: challenge.name,
          category: challenge.category,
          difficulty: challenge.difficulty,
          points: challenge.difficulty * 100
        },
        already_solved: true
      });
    }

    // Record the solve
    db.prepare('INSERT INTO user_challenges (user_id, challenge_id, flag_submitted) VALUES (?, ?, ?)').run(
      req.user.id, challenge.id, flag
    );

    // Get updated stats
    const solvedCount = db.prepare('SELECT COUNT(*) as count FROM user_challenges WHERE user_id = ?').get(req.user.id);
    const totalChallenges = db.prepare('SELECT COUNT(*) as count FROM challenges').get();
    const totalScore = db.prepare(`
      SELECT COALESCE(SUM(c.difficulty * 100), 0) as score
      FROM user_challenges uc
      JOIN challenges c ON uc.challenge_id = c.id
      WHERE uc.user_id = ?
    `).get(req.user.id);

    res.json({
      message: `Congratulations! You solved "${challenge.name}"!`,
      challenge: {
        name: challenge.name,
        category: challenge.category,
        difficulty: challenge.difficulty,
        points: challenge.difficulty * 100,
        owasp_category: challenge.owasp_category
      },
      stats: {
        challenges_solved: solvedCount.count,
        total_challenges: totalChallenges.count,
        total_score: totalScore.score,
        progress_percent: Math.round((solvedCount.count / totalChallenges.count) * 100)
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

module.exports = router;
