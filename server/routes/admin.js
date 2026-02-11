const express = require('express');
const router = express.Router();
const { getDb } = require('../db/schema');
const { verifyToken, requireAdmin } = require('../middleware/auth');

// GET /api/admin/dashboard
// VULNERABILITY: Only checks JWT claims, doesn't verify in DB
router.get('/dashboard', verifyToken, requireAdmin, (req, res) => {
  const db = getDb();

  try {
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const orderCount = db.prepare('SELECT COUNT(*) as count FROM orders').get();
    const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
    const revenue = db.prepare('SELECT SUM(total) as total FROM orders').get();

    res.json({
      flag: 'VJS{4dm1n_p4n3l_byp4ss}',
      dashboard: {
        total_users: userCount.count,
        total_orders: orderCount.count,
        total_products: productCount.count,
        total_revenue: revenue.total || 0,
      },
      message: 'Welcome to admin dashboard',
      admin_user: req.user
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/users
router.get('/users', verifyToken, requireAdmin, (req, res) => {
  const db = getDb();
  try {
    // VULNERABILITY: Returns password hashes
    const users = db.prepare('SELECT * FROM users').all();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', verifyToken, requireAdmin, (req, res) => {
  const db = getDb();
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/orders
router.get('/orders', verifyToken, requireAdmin, (req, res) => {
  const db = getDb();
  try {
    const orders = db.prepare(`
      SELECT o.*, u.username, u.email
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      ORDER BY o.created_at DESC
    `).all();
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
