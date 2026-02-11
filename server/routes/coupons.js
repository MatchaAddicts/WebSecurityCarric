const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken } = require('../middleware/auth');

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
      // Simulated NoSQL operator injection
      if (code.$ne || code.$gt || code.$regex) {
        const allCoupons = db.prepare('SELECT * FROM coupons WHERE is_active = 1').all();
        return res.json({
          flag: 'VJS{n0sql_0p3r4t0r_1nj}',
          coupons: allCoupons,
          message: 'NoSQL injection detected - all active coupons retrieved'
        });
      }
    }

    const coupon = db.prepare('SELECT * FROM coupons WHERE code = ? AND is_active = 1').get(code);

    if (!coupon) {
      return res.status(404).json({ error: 'Invalid or expired coupon' });
    }

    // VULNERABILITY: Race condition - no locking, coupon can be applied multiple times
    // Simulate a slow operation to make race condition exploitable
    const delay = new Promise(resolve => setTimeout(resolve, 100));

    // Apply discount to order if order_id provided
    if (order_id) {
      const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(order_id);
      if (order) {
        const discount = (order.total * coupon.discount) / 100;
        const newTotal = Math.max(0, order.total - discount);
        db.prepare('UPDATE orders SET total = ? WHERE id = ?').run(newTotal, order_id);
      }
    }

    res.json({
      coupon: coupon.code,
      discount: coupon.discount,
      message: `Coupon applied! ${coupon.discount}% discount`,
      flag: code === 'ADMIN100' ? 'VJS{r4c3_c0nd1t10n_c0up0n}' : undefined
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/coupons
router.get('/', (req, res) => {
  const db = getDb();
  try {
    // VULNERABILITY: Lists all active coupons (information disclosure)
    const coupons = db.prepare('SELECT code, discount FROM coupons WHERE is_active = 1').all();
    res.json(coupons);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
