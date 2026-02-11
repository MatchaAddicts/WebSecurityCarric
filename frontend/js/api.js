// API Client for Vegetarian Juice Shop
const API = {
  baseUrl: '',

  getToken() {
    return localStorage.getItem('vjs_token');
  },

  setToken(token) {
    localStorage.setItem('vjs_token', token);
  },

  getUser() {
    const user = localStorage.getItem('vjs_user');
    return user ? JSON.parse(user) : null;
  },

  setUser(user) {
    localStorage.setItem('vjs_user', JSON.stringify(user));
  },

  clearAuth() {
    localStorage.removeItem('vjs_token');
    localStorage.removeItem('vjs_user');
  },

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      const data = await response.json();

      // Auto-detect flags in responses
      if (data.flag) {
        showNotification(`Flag found: ${data.flag}`, 'flag');
        autoSubmitFlag(data.flag);
      }
      if (data.flag_bonus) {
        showNotification(`Bonus flag found: ${data.flag_bonus}`, 'flag');
        autoSubmitFlag(data.flag_bonus);
      }

      if (!response.ok) {
        throw { status: response.status, ...data };
      }

      return data;
    } catch (err) {
      if (err.status) throw err;
      throw { error: 'Network error', details: err.message };
    }
  },

  // Auth
  async login(email, password) {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  },

  async register(username, email, password) {
    return this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password })
    });
  },

  async resetPassword(email, new_password) {
    return this.request('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ email, new_password })
    });
  },

  // Products
  async getProducts() {
    return this.request('/api/products');
  },

  async searchProducts(query) {
    return this.request(`/api/products/search?q=${encodeURIComponent(query)}`);
  },

  async getProduct(id) {
    return this.request(`/api/products/${id}`);
  },

  // Users
  async getProfile(id) {
    return this.request(`/api/users/profile/${id}`);
  },

  async updateProfile(data) {
    return this.request('/api/users/profile', {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  },

  async topupWallet(user_id, amount) {
    return this.request('/api/users/wallet/topup', {
      method: 'POST',
      body: JSON.stringify({ user_id, amount })
    });
  },

  async listUsers() {
    return this.request('/api/users');
  },

  // Reviews
  async getReviews(productId) {
    return this.request(`/api/reviews/product/${productId}`);
  },

  async postReview(product_id, rating, comment, user_id) {
    const body = { product_id, rating, comment };
    if (user_id) body.user_id = user_id;
    return this.request('/api/reviews', {
      method: 'POST',
      body: JSON.stringify(body)
    });
  },

  // Orders
  async getOrders() {
    return this.request('/api/orders');
  },

  async getOrder(id) {
    return this.request(`/api/orders/${id}`);
  },

  async createOrder(items, address, coupon_code) {
    return this.request('/api/orders', {
      method: 'POST',
      body: JSON.stringify({ items, address, coupon_code })
    });
  },

  // Feedback
  async getFeedback() {
    return this.request('/api/feedback');
  },

  async postFeedback(subject, message, rating) {
    return this.request('/api/feedback', {
      method: 'POST',
      body: JSON.stringify({ subject, message, rating })
    });
  },

  // Coupons
  async applyCoupon(code, order_id) {
    return this.request('/api/coupons/apply', {
      method: 'POST',
      body: JSON.stringify({ code, order_id })
    });
  },

  // Scoreboard
  async getScoreboard() {
    return this.request('/api/scoreboard');
  },

  async getUserScoreboard(userId) {
    return this.request(`/api/scoreboard/user/${userId}`);
  },

  async getScoreboardStats() {
    return this.request('/api/scoreboard/stats');
  },

  // Challenges
  async getChallenges() {
    return this.request('/api/challenges');
  },

  async verifyFlag(flag) {
    return this.request('/api/challenges/verify', {
      method: 'POST',
      body: JSON.stringify({ flag })
    });
  },

  async getMyProgress() {
    return this.request('/api/challenges/my-progress');
  },

  // Admin
  async getAdminDashboard() {
    return this.request('/api/admin/dashboard');
  },

  async getAdminUsers() {
    return this.request('/api/admin/users');
  },

  // Files
  async uploadFile(fileData, filename) {
    const token = this.getToken();
    const response = await fetch('/api/files/upload', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Filename': filename,
        'Content-Type': 'application/octet-stream'
      },
      body: fileData
    });
    return response.json();
  },

  async downloadFile(filename) {
    return this.request(`/api/files/download?file=${encodeURIComponent(filename)}`);
  },

  async importXml(xmlData) {
    const token = this.getToken();
    const response = await fetch('/api/files/import-xml', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/xml'
      },
      body: xmlData
    });
    return response.json();
  }
};
