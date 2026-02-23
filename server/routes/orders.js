const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken, optionalAuth } = require('../middleware/auth');

// GET /api/orders/:id
// VULNERABILITY: SQL Injection in order lookup
router.get('/:id', optionalAuth, (req, res) => {
  const db = getDb();
  const orderId = req.params.id;

  try {
    // VULNERABILITY: String concatenation in SQL
    const query = `SELECT o.*, u.username, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = '${orderId}'`;
    const order = db.prepare(query).get();

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Get order items
    const items = db.prepare('SELECT oi.*, p.name as product_name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?').all(order.id);

    const response = { order, items };

    // Detect SQLi attempt
    if (orderId.includes("'") || orderId.toLowerCase().includes('union') || orderId.toLowerCase().includes('or')) {
      response.flag = 'VJS{0rder_sql1_exf1ltr4t10n}';
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({
      error: 'Order lookup failed',
      details: err.message,
      query_hint: `Query used string concatenation for order id: ${orderId}`
    });
  }
});

// POST /api/orders
router.post('/', verifyToken, (req, res) => {
  const db = getDb();
  const { items, address, coupon_code } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Items array is required' });
  }

  try {
    let total = 0;
    const validItems = [];

    for (const item of items) {
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(item.product_id);
      if (!product) continue;

      // VULNERABILITY: No stock check, negative quantities allowed
      const qty = item.quantity || 1;
      total += product.price * qty;
      validItems.push({ ...item, price: product.price, quantity: qty });
    }

    // Apply coupon if provided
    let discount = 0;
    if (coupon_code) {
      const coupon = db.prepare('SELECT * FROM coupons WHERE code = ? AND is_active = 1').get(coupon_code);
      if (coupon) {
        discount = (total * coupon.discount) / 100;
        total = Math.max(0, total - discount);
      }
    }

    // VULNERABILITY: No check if user has sufficient wallet balance
    const orderResult = db.prepare('INSERT INTO orders (user_id, total, address) VALUES (?, ?, ?)').run(
      req.user.id, total, address || 'Not provided'
    );

    for (const item of validItems) {
      db.prepare('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)').run(
        orderResult.lastInsertRowid, item.product_id, item.quantity, item.price
      );
    }

    // Deduct from wallet (but no check if balance is sufficient)
    db.prepare('UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?').run(total, req.user.id);

    const response = {
      order_id: orderResult.lastInsertRowid,
      total,
      discount,
      items: validItems,
      message: 'Order placed successfully'
    };

    // VULNERABILITY: A10:2025 - Negative quantities allowed (exceptional conditions)
    const hasNegativeQty = validItems.some(i => i.quantity < 0);
    if (hasNegativeQty) {
      response.flag = 'VJS{n3g4t1v3_qu4nt1ty_cr3d1t}';
    }

    // VULNERABILITY: A08:2025 - Client-submitted prices accepted without DB verification
    if (req.body.items && req.body.items.some(i => i.price !== undefined)) {
      response.flag_integrity = 'VJS{d4t4_1nt3gr1ty_f41l}';
    }

    res.status(201).json(response);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/orders
router.get('/', verifyToken, (req, res) => {
  const db = getDb();
  try {
    // VULNERABILITY: Returns all orders for the user, but doesn't properly scope
    const orders = db.prepare('SELECT * FROM orders WHERE user_id = ?').all(req.user.id);
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
