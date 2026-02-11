const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { optionalAuth } = require('../middleware/auth');

// GET /api/scoreboard
// Public scoreboard showing all users' progress
router.get('/', (req, res) => {
  const db = getDb();

  try {
    // Get all users with their solved challenge count and total score
    const leaderboard = db.prepare(`
      SELECT
        u.id,
        u.username,
        COUNT(uc.id) as challenges_solved,
        COALESCE(SUM(c.difficulty * 100), 0) as total_score,
        MAX(uc.solved_at) as last_solve
      FROM users u
      LEFT JOIN user_challenges uc ON u.id = uc.user_id
      LEFT JOIN challenges c ON uc.challenge_id = c.id
      GROUP BY u.id
      HAVING challenges_solved > 0
      ORDER BY total_score DESC, last_solve ASC
    `).all();

    // Get total challenges info
    const totalChallenges = db.prepare('SELECT COUNT(*) as count FROM challenges').get();
    const maxScore = db.prepare('SELECT SUM(difficulty * 100) as max_score FROM challenges').get();

    // Category breakdown
    const categories = db.prepare(`
      SELECT
        category,
        COUNT(*) as total,
        difficulty
      FROM challenges
      GROUP BY category
      ORDER BY category
    `).all();

    res.json({
      leaderboard: leaderboard.map((entry, index) => ({
        rank: index + 1,
        ...entry,
        progress_percent: Math.round((entry.challenges_solved / totalChallenges.count) * 100)
      })),
      stats: {
        total_challenges: totalChallenges.count,
        max_possible_score: maxScore.max_score || 0,
        total_players: leaderboard.length,
        categories
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/scoreboard/user/:id
// Individual user's detailed progress
router.get('/user/:id', optionalAuth, (req, res) => {
  const db = getDb();
  const userId = req.params.id;

  try {
    const user = db.prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get solved challenges
    const solved = db.prepare(`
      SELECT
        c.id,
        c.key,
        c.name,
        c.category,
        c.difficulty,
        c.owasp_category,
        uc.solved_at
      FROM user_challenges uc
      JOIN challenges c ON uc.challenge_id = c.id
      WHERE uc.user_id = ?
      ORDER BY uc.solved_at DESC
    `).all(userId);

    // Get all challenges to show unsolved
    const allChallenges = db.prepare(`
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

    const solvedIds = new Set(solved.map(s => s.id));

    // Category progress
    const categoryProgress = {};
    for (const ch of allChallenges) {
      if (!categoryProgress[ch.category]) {
        categoryProgress[ch.category] = { total: 0, solved: 0, challenges: [] };
      }
      categoryProgress[ch.category].total++;
      const isSolved = solvedIds.has(ch.id);
      if (isSolved) {
        categoryProgress[ch.category].solved++;
      }
      categoryProgress[ch.category].challenges.push({
        ...ch,
        solved: isSolved,
        solved_at: isSolved ? solved.find(s => s.id === ch.id)?.solved_at : null
      });
    }

    const totalScore = solved.reduce((sum, s) => sum + (s.difficulty * 100), 0);
    const maxScore = allChallenges.reduce((sum, c) => sum + (c.difficulty * 100), 0);

    res.json({
      user: {
        ...user,
        total_score: totalScore,
        max_score: maxScore,
        challenges_solved: solved.length,
        total_challenges: allChallenges.length,
        progress_percent: Math.round((solved.length / allChallenges.length) * 100),
        completion_by_difficulty: {
          easy: {
            solved: solved.filter(s => s.difficulty === 1).length,
            total: allChallenges.filter(c => c.difficulty === 1).length,
          },
          medium: {
            solved: solved.filter(s => s.difficulty === 2).length,
            total: allChallenges.filter(c => c.difficulty === 2).length,
          },
          hard: {
            solved: solved.filter(s => s.difficulty === 3).length,
            total: allChallenges.filter(c => c.difficulty === 3).length,
          }
        }
      },
      recent_solves: solved.slice(0, 10),
      category_progress: categoryProgress
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/scoreboard/stats
// Overall platform statistics
router.get('/stats', (req, res) => {
  const db = getDb();

  try {
    const totalPlayers = db.prepare('SELECT COUNT(DISTINCT user_id) as count FROM user_challenges').get();
    const totalSolves = db.prepare('SELECT COUNT(*) as count FROM user_challenges').get();
    const totalChallenges = db.prepare('SELECT COUNT(*) as count FROM challenges').get();

    // Most solved challenges
    const popularChallenges = db.prepare(`
      SELECT c.name, c.category, c.difficulty, COUNT(uc.id) as solve_count
      FROM challenges c
      LEFT JOIN user_challenges uc ON c.id = uc.challenge_id
      GROUP BY c.id
      ORDER BY solve_count DESC
      LIMIT 10
    `).all();

    // Category distribution
    const categoryDist = db.prepare(`
      SELECT category, COUNT(*) as count, AVG(difficulty) as avg_difficulty
      FROM challenges
      GROUP BY category
    `).all();

    // Difficulty distribution
    const difficultyDist = db.prepare(`
      SELECT difficulty, COUNT(*) as count
      FROM challenges
      GROUP BY difficulty
      ORDER BY difficulty
    `).all();

    res.json({
      total_players: totalPlayers.count,
      total_solves: totalSolves.count,
      total_challenges: totalChallenges.count,
      popular_challenges: popularChallenges,
      category_distribution: categoryDist,
      difficulty_distribution: difficultyDist
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
