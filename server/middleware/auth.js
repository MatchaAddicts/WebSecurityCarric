const jwt = require('jsonwebtoken');

// VULNERABILITY: Weak JWT secret, hardcoded
const JWT_SECRET = 'vegetarian-juice-secret-key';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
}

// VULNERABILITY: JWT "none" algorithm not properly rejected
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.token;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // VULNERABILITY: accepts "none" algorithm
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());

    if (header.alg === 'none' || header.alg === 'None') {
      // Intentionally accept none algorithm
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      req.user = payload;
      return next();
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token', details: err.message });
  }
}

function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.token;

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());

    if (header.alg === 'none' || header.alg === 'None') {
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      req.user = payload;
      return next();
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    req.user = null;
    next();
  }
}

// VULNERABILITY: Admin check only looks at JWT claim, doesn't verify against DB
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

module.exports = { signToken, verifyToken, optionalAuth, requireAdmin, JWT_SECRET };
