const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { optionalAuth } = require('../middleware/auth');
const { solveChallenge } = require('../utils/challengeSolver');

// GET /api/products
router.get('/', (req, res) => {
  const db = getDb();
  try {
    const products = db.prepare('SELECT * FROM products WHERE is_active = 1').all();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/products/search?q=
// VULNERABILITY: SQL Injection in search
router.get('/search', optionalAuth, (req, res) => {
  const { q } = req.query;
  const db = getDb();

  if (!q) {
    return res.json([]);
  }

  try {
    // VULNERABILITY: Direct string concatenation enables UNION-based SQLi
    const query = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;
    const products = db.prepare(query).all();

    const response = { results: products };

    if (q.toLowerCase().includes('union') && q.toLowerCase().includes('select')) {
      solveChallenge(req, 'sqli_search');
    }

    // VULNERABILITY: Reflected XSS - query echoed back
    response.query = q;
    response.message = `Found ${products.length} results for "${q}"`;

    res.json(response);
  } catch (err) {
    // VULNERABILITY: Error message reveals SQL structure
    res.status(500).json({
      error: 'Search failed',
      details: err.message,
      attempted_query: `SELECT * FROM products WHERE name LIKE '%${q}%'`
    });
  }
});

// GET /api/products/:id
router.get('/:id', (req, res) => {
  const db = getDb();
  try {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
