const { getDb } = require('../db/schema');

/**
 * Solve a challenge for the current user or session.
 * If req.user is set, solves immediately.
 * If only req.sessionId is set, solves against the session.
 * Otherwise queues for the response middleware.
 */
function solveChallenge(req, challengeKey) {
  try {
    const userId = req.user?.id;
    if (userId) {
      return _doSolve(userId, challengeKey, req);
    }
    if (req.sessionId) {
      return _doSolveSession(req.sessionId, challengeKey, req);
    }
    // Queue for the response middleware to resolve user from response body
    req._pendingSolves = req._pendingSolves || [];
    req._pendingSolves.push(challengeKey);
    return null;
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

function _doSolveSession(sessionId, challengeKey, req) {
  try {
    const db = getDb();
    const challenge = db.prepare('SELECT id, name, difficulty FROM challenges WHERE key = ?').get(challengeKey);
    if (!challenge) return null;

    const existing = db.prepare('SELECT id FROM user_challenges WHERE session_id = ? AND challenge_id = ?').get(sessionId, challenge.id);
    if (existing) return null;

    db.prepare('INSERT INTO user_challenges (session_id, challenge_id, flag_submitted) VALUES (?, ?, ?)').run(sessionId, challenge.id, 'auto-detected');

    req._challengesSolved = req._challengesSolved || [];
    req._challengesSolved.push({ name: challenge.name, points: challenge.difficulty * 100 });

    return { name: challenge.name, points: challenge.difficulty * 100 };
  } catch (e) {
    return null;
  }
}

/**
 * Merge session-based solves into a user account.
 * Called on login/register so anonymous progress is preserved.
 */
function mergeSessionSolves(sessionId, userId) {
  try {
    const db = getDb();
    const sessionSolves = db.prepare('SELECT challenge_id FROM user_challenges WHERE session_id = ? AND user_id IS NULL').all(sessionId);
    for (const solve of sessionSolves) {
      const existing = db.prepare('SELECT id FROM user_challenges WHERE user_id = ? AND challenge_id = ?').get(userId, solve.challenge_id);
      if (!existing) {
        db.prepare('UPDATE user_challenges SET user_id = ?, session_id = NULL WHERE session_id = ? AND challenge_id = ?').run(userId, sessionId, solve.challenge_id);
      } else {
        // User already has this solve, remove the duplicate session one
        db.prepare('DELETE FROM user_challenges WHERE session_id = ? AND challenge_id = ? AND user_id IS NULL').run(sessionId, solve.challenge_id);
      }
    }
  } catch (e) {
    // Silently fail
  }
}

module.exports = { solveChallenge, _doSolve, _doSolveSession, mergeSessionSolves };
