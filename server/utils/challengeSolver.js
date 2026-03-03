const { getDb } = require('../db/schema');

/**
 * Solve a challenge for the current user.
 * If req.user is set, solves immediately. Otherwise queues for the response middleware.
 */
function solveChallenge(req, challengeKey) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      // Queue for the response middleware to resolve user from response body
      req._pendingSolves = req._pendingSolves || [];
      req._pendingSolves.push(challengeKey);
      return null;
    }
    return _doSolve(userId, challengeKey, req);
  } catch (e) {
    return null;
  }
}

function _doSolve(userId, challengeKey, req) {
  try {
    const db = getDb();
    const challenge = db.prepare('SELECT id, name, difficulty FROM challenges WHERE key = ?').get(challengeKey);
    if (!challenge) return null;

    const existing = db.prepare('SELECT id FROM user_challenges WHERE user_id = ? AND challenge_id = ?').get(userId, challenge.id);
    if (existing) return null;

    db.prepare('INSERT INTO user_challenges (user_id, challenge_id, flag_submitted) VALUES (?, ?, ?)').run(userId, challenge.id, 'auto-detected');

    req._challengesSolved = req._challengesSolved || [];
    req._challengesSolved.push({ name: challenge.name, points: challenge.difficulty * 100 });

    return { name: challenge.name, points: challenge.difficulty * 100 };
  } catch (e) {
    return null;
  }
}

module.exports = { solveChallenge, _doSolve };
