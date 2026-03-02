const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken } = require('../middleware/auth');
const { solveChallenge } = require('../utils/challengeSolver');

// POST /api/coupons/apply
// VULNERABILITY: Race condition + NoSQL-style injection
router.post('/apply', verifyToken, (req, res) => {
  const { code, order_id } = req.body;
  const db = getDb();

  if (!code) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }

  try {
    // VULNERABILITY: NoSQL-style injection check
    if (typeof code === 'object' && code !== null) {
      if (code.$ne || code.$gt || code.$regex) {
        solveChallenge(req, 'nosql_coupon');
        const allCoupons = db.prepare('SELECT * FROM coupons WHERE is_active = 1').all();
        return res.json({
          coupons: allCoupons,
          message: 'NoSQL injection detected - all active coupons retrieved'
        });
      }
    }

    const coupon = db.prepare('SELECT * FROM coupons WHERE code = ? AND is_active = 1').get(code);

    if (!coupon) {
      return res.status(404).json({ error: 'Invalid or expired coupon' });
    }

    // VULNERABILITY: Race condition - no locking
    const delay = new Promise(resolve => setTimeout(resolve, 100));

    if (order_id) {
      const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(order_id);
      if (order) {
        const discount = (order.total * coupon.discount) / 100;
        const newTotal = Math.max(0, order.total - discount);
        db.prepare('UPDATE orders SET total = ? WHERE id = ?').run(newTotal, order_id);
      }
    }

    if (code === 'ADMIN100') {
      solveChallenge(req, 'race_coupon');
    }

    res.json({
      coupon: coupon.code,
      discount: coupon.discount,
      message: `Coupon applied! ${coupon.discount}% discount`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/coupons
router.get('/', (req, res) => {
  const db = getDb();
  try {
    const coupons = db.prepare('SELECT code, discount FROM coupons WHERE is_active = 1').all();
    res.json(coupons);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
