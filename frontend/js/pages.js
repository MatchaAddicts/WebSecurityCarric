// Page Renderers for Vegetarian Juice Shop

// ==================== HOME PAGE ====================
function renderHome() {
  const user = API.getUser();
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <div class="hero">
      <h1>🥬🥤 Vegetarian Juice Shop</h1>
      <p>The most intentionally vulnerable vegetarian juice shop on the internet. Test your security skills and climb the scoreboard!</p>
      <div style="display:flex; gap:1rem; justify-content:center; flex-wrap:wrap;">
        <button class="btn btn-accent" onclick="navigate('products')">Browse Juices</button>
        <button class="btn btn-secondary" onclick="navigate('challenges')">View Challenges</button>
        <button class="btn btn-primary" onclick="navigate('scoreboard')">Scoreboard</button>
      </div>
    </div>

    <div class="grid-3">
      <div class="card stat-card">
        <div class="stat-value" id="home-challenges">--</div>
        <div class="stat-label">Security Challenges</div>
      </div>
      <div class="card stat-card">
        <div class="stat-value" id="home-categories">--</div>
        <div class="stat-label">OWASP Categories</div>
      </div>
      <div class="card stat-card">
        <div class="stat-value" id="home-players">--</div>
        <div class="stat-label">Active Players</div>
      </div>
    </div>

    ${user ? `
      <div class="card mt-2">
        <div class="card-header">Your Progress</div>
        <div id="home-progress">Loading...</div>
      </div>
    ` : `
      <div class="card mt-2 text-center">
        <h3>Get Started</h3>
        <p class="mt-1">Create an account or login to start solving challenges and tracking your progress.</p>
        <div class="mt-2">
          <button class="btn btn-primary" onclick="navigate('register')">Register</button>
          <button class="btn btn-secondary" onclick="navigate('login')">Login</button>
        </div>
      </div>
    `}

    <div class="card mt-2">
      <div class="card-header">OWASP Top 10:2025 Vulnerability Categories</div>
      <div class="grid-2 mt-1">
        <div><span class="category-tag cat-access">A01</span> Broken Access Control (incl. SSRF, CSRF)</div>
        <div><span class="category-tag cat-misc">A02</span> Security Misconfiguration</div>
        <div><span class="category-tag cat-supply">A03</span> Software Supply Chain Failures <span style="color:var(--accent); font-size:0.7rem;">NEW</span></div>
        <div><span class="category-tag cat-crypto">A04</span> Cryptographic Failures</div>
        <div><span class="category-tag cat-injection">A05</span> Injection (SQL, XSS, NoSQL)</div>
        <div><span class="category-tag cat-other">A06</span> Insecure Design</div>
        <div><span class="category-tag cat-auth">A07</span> Authentication Failures</div>
        <div><span class="category-tag cat-other">A08</span> Software &amp; Data Integrity Failures</div>
        <div><span class="category-tag cat-other">A09</span> Security Logging &amp; Alerting Failures</div>
        <div><span class="category-tag cat-exceptional">A10</span> Mishandling of Exceptional Conditions <span style="color:var(--accent); font-size:0.7rem;">NEW</span></div>
      </div>
    </div>
  `;

  // Load stats
  API.getScoreboardStats().then(stats => {
    document.getElementById('home-challenges').textContent = stats.total_challenges;
    document.getElementById('home-categories').textContent = stats.category_distribution?.length || 0;
    document.getElementById('home-players').textContent = stats.total_players;
  }).catch(() => {});

  if (user) {
    API.getMyProgress().then(progress => {
      const el = document.getElementById('home-progress');
      if (el) {
        el.innerHTML = `
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${progress.progress_percent}%">${progress.progress_percent}%</div>
          </div>
          <p class="mt-1">${progress.total_solved} / ${progress.total_challenges} challenges solved | Score: ${progress.total_score} pts</p>
        `;
      }
    }).catch(() => {});
  }
}

// ==================== PRODUCTS PAGE ====================
async function renderProducts() {
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <h2 class="mb-2">Our Juices & Smoothies</h2>
    <div class="search-container">
      <input type="text" id="search-input" class="form-control" placeholder="Search products..." onkeydown="if(event.key==='Enter') searchProducts()" />
      <button class="btn btn-primary" onclick="searchProducts()">Search</button>
    </div>
    <div id="search-results"></div>
    <div id="products-grid" class="grid">Loading...</div>
  `;

  try {
    const products = await API.getProducts();
    const grid = document.getElementById('products-grid');
    grid.innerHTML = products.map(p => `
      <div class="product-card">
        <div class="product-image">${getProductEmoji(p.category)}</div>
        <div class="product-info">
          <div class="product-name">${p.name}</div>
          <div class="product-description">${p.description || ''}</div>
          <div class="flex-between">
            <span class="product-price">$${p.price.toFixed(2)}</span>
            <span class="category-tag cat-other">${p.category}</span>
          </div>
          <div class="product-actions">
            <button class="btn btn-primary btn-sm" onclick='addToCart(${JSON.stringify({id: p.id, name: p.name, price: p.price})})'>Add to Cart</button>
            <button class="btn btn-secondary btn-sm" onclick="navigate('product', {id: ${p.id}})">Details</button>
          </div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    document.getElementById('products-grid').innerHTML = `<p>Error loading products: ${err.error || err.message}</p>`;
  }
}

async function searchProducts() {
  const query = document.getElementById('search-input').value;
  if (!query) return;

  const resultsDiv = document.getElementById('search-results');
  try {
    const data = await API.searchProducts(query);
    // VULNERABILITY: XSS - message contains unescaped query
    resultsDiv.innerHTML = `
      <div class="card">
        <p>${data.message}</p>
        ${data.results && data.results.length > 0 ? `
          <div class="grid mt-1">
            ${data.results.map(p => `
              <div class="product-card">
                <div class="product-info">
                  <div class="product-name">${p.name}</div>
                  <div class="product-price">$${(p.price || 0).toFixed ? p.price.toFixed(2) : p.price}</div>
                </div>
              </div>
            `).join('')}
          </div>
        ` : '<p class="mt-1">No results found.</p>'}
      </div>
    `;

    // Client-side detection: reflected XSS
    if (query.includes('<script') || query.includes('onerror') || query.includes('javascript:')) {
      reportClientChallenge('xss_reflected');
    }
  } catch (err) {
    resultsDiv.innerHTML = `<div class="card" style="border-left: 4px solid var(--danger);">
      <p><strong>Error:</strong> ${err.details || err.error || 'Search failed'}</p>
      ${err.attempted_query ? `<p style="font-family:monospace; font-size:0.8rem;">Query: ${err.attempted_query}</p>` : ''}
    </div>`;
  }
}

// ==================== PRODUCT DETAIL PAGE ====================
async function renderProductDetail(productId) {
  const content = document.getElementById('app-content');

  try {
    const product = await API.getProduct(productId);
    const reviews = await API.getReviews(productId);

    content.innerHTML = `
      <button class="btn btn-secondary mb-2" onclick="navigate('products')">Back to Products</button>
      <div class="grid-2">
        <div class="card">
          <div class="product-image" style="height:300px; border-radius:var(--radius);">${getProductEmoji(product.category)}</div>
        </div>
        <div class="card">
          <h2>${product.name}</h2>
          <p class="mt-1">${product.description || 'No description available.'}</p>
          <p class="product-price mt-2">$${product.price.toFixed(2)}</p>
          <p class="mt-1">Category: <span class="category-tag cat-other">${product.category}</span></p>
          <p>Stock: ${product.stock} available</p>
          <button class="btn btn-primary mt-2" onclick='addToCart(${JSON.stringify({id: product.id, name: product.name, price: product.price})})'>Add to Cart</button>
        </div>
      </div>

      <div class="card mt-2">
        <div class="card-header">Reviews (${reviews.length})</div>
        <div id="reviews-list">
          ${reviews.length > 0 ? reviews.map(r => `
            <div class="review-item">
              <div class="flex-between">
                <span class="review-author">${r.username || 'Anonymous'}</span>
                <span class="review-rating">${'★'.repeat(r.rating)}${'☆'.repeat(5 - r.rating)}</span>
              </div>
              <!-- VULNERABILITY: Stored XSS - raw HTML rendering -->
              <div class="review-comment">${r.comment}</div>
            </div>
          `).join('') : '<p>No reviews yet. Be the first to review!</p>'}
        </div>
      </div>

      ${API.getToken() ? `
        <div class="card mt-2">
          <div class="card-header">Write a Review</div>
          <div class="form-group">
            <label>Rating</label>
            <select id="review-rating" class="form-control">
              <option value="5">★★★★★ (5)</option>
              <option value="4">★★★★☆ (4)</option>
              <option value="3">★★★☆☆ (3)</option>
              <option value="2">★★☆☆☆ (2)</option>
              <option value="1">★☆☆☆☆ (1)</option>
            </select>
          </div>
          <div class="form-group">
            <label>Comment</label>
            <textarea id="review-comment" class="form-control" placeholder="Write your review..."></textarea>
          </div>
          <button class="btn btn-primary" onclick="postReview(${product.id})">Submit Review</button>
        </div>
      ` : '<p class="mt-2">Login to write a review.</p>'}
    `;
  } catch (err) {
    content.innerHTML = `<p>Error loading product: ${err.error || err.message}</p>`;
  }
}

async function postReview(productId) {
  const rating = document.getElementById('review-rating').value;
  const comment = document.getElementById('review-comment').value;

  if (!comment) {
    showNotification('Please write a comment', 'warning');
    return;
  }

  try {
    await API.postReview(productId, parseInt(rating), comment);
    showNotification('Review posted!');
    renderProductDetail(productId);
  } catch (err) {
    showNotification(err.error || 'Failed to post review', 'error');
  }
}

// ==================== LOGIN PAGE ====================
function renderLogin() {
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <div class="auth-container">
      <div class="card">
        <div class="card-header">Login</div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" id="login-email" class="form-control" placeholder="your@email.com" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="login-password" class="form-control" placeholder="Your password" onkeydown="if(event.key==='Enter') doLogin()" />
        </div>
        <button class="btn btn-primary btn-block" onclick="doLogin()">Login</button>
        <p class="mt-2 text-center" style="font-size:0.85rem;">
          Don't have an account? <a href="#" onclick="navigate('register')">Register</a>
        </p>
        <hr style="margin: 1rem 0;" />
        <p style="font-size:0.8rem; color:var(--text-light);">Forgot password? <a href="#" onclick="showResetForm()">Reset here</a></p>
        <div id="reset-form" style="display:none;" class="mt-1">
          <div class="form-group">
            <label>Email for reset</label>
            <input type="email" id="reset-email" class="form-control" placeholder="target@email.com" />
          </div>
          <div class="form-group">
            <label>New Password</label>
            <input type="password" id="reset-password" class="form-control" placeholder="New password" />
          </div>
          <button class="btn btn-danger btn-sm" onclick="doResetPassword()">Reset Password</button>
        </div>
      </div>
    </div>
  `;
}

function showResetForm() {
  document.getElementById('reset-form').style.display = 'block';
}

async function doLogin() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  if (!email || !password) {
    showNotification('Please fill in all fields', 'warning');
    return;
  }

  try {
    const data = await API.login(email, password);
    API.setToken(data.token);
    API.setUser(data.user);
    updateAuthUI();
    showNotification(`Welcome back, ${data.user.username}!`);
    navigate('home');
  } catch (err) {
    showNotification(err.error || 'Login failed', 'error');
  }
}

async function doResetPassword() {
  const email = document.getElementById('reset-email').value;
  const password = document.getElementById('reset-password').value;

  try {
    const result = await API.resetPassword(email, password);
    showNotification(result.message);
  } catch (err) {
    showNotification(err.error || 'Reset failed', 'error');
  }
}

// ==================== REGISTER PAGE ====================
function renderRegister() {
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <div class="auth-container">
      <div class="card">
        <div class="card-header">Create Account</div>
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="reg-username" class="form-control" placeholder="Choose a username" />
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" id="reg-email" class="form-control" placeholder="your@email.com" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="reg-password" class="form-control" placeholder="Choose a password" onkeydown="if(event.key==='Enter') doRegister()" />
        </div>
        <button class="btn btn-primary btn-block" onclick="doRegister()">Register</button>
        <p class="mt-2 text-center" style="font-size:0.85rem;">
          Already have an account? <a href="#" onclick="navigate('login')">Login</a>
        </p>
      </div>
    </div>
  `;
}

async function doRegister() {
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;

  if (!username || !email || !password) {
    showNotification('Please fill in all fields', 'warning');
    return;
  }

  try {
    const data = await API.register(username, email, password);
    API.setToken(data.token);
    API.setUser(data.user);
    updateAuthUI();
    showNotification(`Welcome, ${data.user.username}! Account created.`);
    navigate('home');
  } catch (err) {
    showNotification(err.error || 'Registration failed', 'error');
  }
}

// ==================== PROFILE PAGE ====================
async function renderProfile() {
  const content = document.getElementById('app-content');
  const user = API.getUser();

  if (!user) {
    navigate('login');
    return;
  }

  try {
    const profile = await API.getProfile(user.id);
    const progress = await API.getMyProgress();

    content.innerHTML = `
      <h2 class="mb-2">My Profile</h2>
      <div class="grid-2">
        <div class="card">
          <div class="card-header">Account Info</div>
          <p><strong>Username:</strong> ${profile.user.username}</p>
          <p><strong>Email:</strong> ${profile.user.email}</p>
          <p><strong>Role:</strong> ${profile.user.role}</p>
          <p><strong>Member since:</strong> ${new Date(profile.user.created_at).toLocaleDateString()}</p>

          <div class="wallet-display mt-2">
            <div>
              <div style="font-size:0.8rem; opacity:0.8;">Wallet Balance</div>
              <div class="wallet-amount">$${profile.user.wallet_balance.toFixed(2)}</div>
            </div>
            <button class="btn btn-secondary" onclick="walletTopup()">Top Up</button>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Challenge Progress</div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${progress.progress_percent}%">${progress.progress_percent}%</div>
          </div>
          <div class="grid-3 mt-2">
            <div class="stat-card">
              <div class="stat-value" style="font-size:1.5rem;">${progress.total_solved}</div>
              <div class="stat-label">Solved</div>
            </div>
            <div class="stat-card">
              <div class="stat-value" style="font-size:1.5rem;">${progress.total_challenges}</div>
              <div class="stat-label">Total</div>
            </div>
            <div class="stat-card">
              <div class="stat-value" style="font-size:1.5rem;">${progress.total_score}</div>
              <div class="stat-label">Score</div>
            </div>
          </div>
        </div>
      </div>

      <div class="card mt-2">
        <div class="card-header">Update Profile</div>
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="profile-username" class="form-control" value="${profile.user.username}" />
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="text" id="profile-email" class="form-control" value="${profile.user.email}" />
        </div>
        <button class="btn btn-primary" onclick="updateProfile()">Save Changes</button>
      </div>

      <div class="card mt-2">
        <div class="card-header">Recent Solves</div>
        ${progress.solved.length > 0 ? progress.solved.slice(0, 5).map(s => `
          <div style="padding: 0.5rem 0; border-bottom: 1px solid var(--border);">
            <span class="category-tag ${getCategoryClass(s.category)}">${s.category}</span>
            <strong>${s.name}</strong>
            <span style="color:var(--text-light); font-size:0.8rem;"> - ${new Date(s.solved_at).toLocaleString()}</span>
          </div>
        `).join('') : '<p>No challenges solved yet.</p>'}
      </div>

      <div class="card mt-2">
        <div class="card-header">File Upload</div>
        <p style="font-size:0.85rem; color:var(--text-light); margin-bottom:0.5rem;">Upload profile image or documents (jpg, png, gif, pdf, txt, xml)</p>
        <input type="file" id="file-upload" class="form-control" />
        <button class="btn btn-primary mt-1" onclick="uploadFile()">Upload</button>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<p>Error loading profile: ${err.error || err.message}</p>`;
  }
}

async function updateProfile() {
  const username = document.getElementById('profile-username').value;
  const email = document.getElementById('profile-email').value;

  try {
    const result = await API.updateProfile({ username, email });
    showNotification('Profile updated!');
    API.setUser(result.user);
    updateAuthUI();
  } catch (err) {
    showNotification(err.error || 'Update failed', 'error');
  }
}

async function walletTopup() {
  const amount = prompt('Enter top-up amount:');
  if (!amount || isNaN(amount)) return;

  const user = API.getUser();
  try {
    await API.topupWallet(user.id, parseFloat(amount));
    showNotification(`$${amount} added to wallet!`);
    renderProfile();
  } catch (err) {
    showNotification(err.error || 'Top-up failed', 'error');
  }
}

async function uploadFile() {
  const fileInput = document.getElementById('file-upload');
  if (!fileInput.files.length) {
    showNotification('Please select a file', 'warning');
    return;
  }

  const file = fileInput.files[0];
  try {
    const result = await API.uploadFile(file, file.name);
    showNotification(result.message || 'File uploaded!');
    if (result.flag) {
      showNotification(`Flag: ${result.flag}`, 'flag');
    }
  } catch (err) {
    showNotification(err.error || 'Upload failed', 'error');
  }
}

// ==================== CART PAGE ====================
function renderCart() {
  const content = document.getElementById('app-content');
  const total = cart.reduce((sum, item) => sum + item.price, 0);

  content.innerHTML = `
    <h2 class="mb-2">Shopping Cart</h2>
    ${cart.length === 0 ? `
      <div class="card text-center">
        <p>Your cart is empty.</p>
        <button class="btn btn-primary mt-1" onclick="navigate('products')">Browse Products</button>
      </div>
    ` : `
      <div class="card">
        <div class="table-container">
          <table>
            <thead>
              <tr><th>Product</th><th>Price</th><th>Action</th></tr>
            </thead>
            <tbody>
              ${cart.map((item, i) => `
                <tr>
                  <td>${item.name}</td>
                  <td>$${item.price.toFixed(2)}</td>
                  <td><button class="btn btn-danger btn-sm" onclick="removeFromCart(${i})">Remove</button></td>
                </tr>
              `).join('')}
            </tbody>
            <tfoot>
              <tr>
                <td><strong>Total</strong></td>
                <td><strong>$${total.toFixed(2)}</strong></td>
                <td></td>
              </tr>
            </tfoot>
          </table>
        </div>

        <div class="form-group mt-2">
          <label>Coupon Code</label>
          <div class="flex gap-1">
            <input type="text" id="coupon-code" class="form-control" placeholder="Enter coupon code" />
            <button class="btn btn-secondary" onclick="applyCoupon()">Apply</button>
          </div>
        </div>

        <div class="form-group">
          <label>Delivery Address</label>
          <textarea id="order-address" class="form-control" placeholder="Enter delivery address"></textarea>
        </div>

        <button class="btn btn-accent btn-block" onclick="placeOrder()">Place Order ($${total.toFixed(2)})</button>
      </div>
    `}
  `;
}

async function applyCoupon() {
  const code = document.getElementById('coupon-code').value;
  if (!code) return;

  try {
    const result = await API.applyCoupon(code);
    showNotification(result.message);
  } catch (err) {
    showNotification(err.error || 'Invalid coupon', 'error');
  }
}

async function placeOrder() {
  if (cart.length === 0) return;

  if (!API.getToken()) {
    showNotification('Please login to place an order', 'warning');
    navigate('login');
    return;
  }

  const address = document.getElementById('order-address')?.value;
  const coupon = document.getElementById('coupon-code')?.value;
  const items = cart.map(item => ({ product_id: item.id, quantity: 1 }));

  try {
    const result = await API.createOrder(items, address, coupon);
    showNotification(`Order #${result.order_id} placed! Total: $${result.total.toFixed(2)}`);
    cart = [];
    localStorage.removeItem('vjs_cart');
    updateCartCount();
    navigate('orders');
  } catch (err) {
    showNotification(err.error || 'Order failed', 'error');
  }
}

// ==================== ORDERS PAGE ====================
async function renderOrders() {
  const content = document.getElementById('app-content');

  if (!API.getToken()) {
    navigate('login');
    return;
  }

  try {
    const orders = await API.getOrders();
    content.innerHTML = `
      <h2 class="mb-2">My Orders</h2>
      <div class="form-group">
        <label>Look up order by ID</label>
        <div class="flex gap-1">
          <input type="text" id="order-lookup-id" class="form-control" placeholder="Enter order ID" />
          <button class="btn btn-primary" onclick="lookupOrder()">Lookup</button>
        </div>
      </div>
      <div id="order-lookup-result"></div>
      ${orders.length === 0 ? '<div class="card"><p>No orders yet.</p></div>' : `
        <div class="table-container">
          <table>
            <thead>
              <tr><th>Order #</th><th>Total</th><th>Status</th><th>Date</th><th>Action</th></tr>
            </thead>
            <tbody>
              ${orders.map(o => `
                <tr>
                  <td>#${o.id}</td>
                  <td>$${o.total.toFixed(2)}</td>
                  <td>${o.status}</td>
                  <td>${new Date(o.created_at).toLocaleDateString()}</td>
                  <td><button class="btn btn-primary btn-sm" onclick="lookupOrderById(${o.id})">View</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `}
    `;
  } catch (err) {
    content.innerHTML = `<p>Error: ${err.error || err.message}</p>`;
  }
}

async function lookupOrder() {
  const id = document.getElementById('order-lookup-id').value;
  if (!id) return;
  lookupOrderById(id);
}

async function lookupOrderById(id) {
  const resultDiv = document.getElementById('order-lookup-result');
  try {
    const data = await API.getOrder(id);
    resultDiv.innerHTML = `
      <div class="card">
        <div class="card-header">Order #${data.order.id}</div>
        <p><strong>User:</strong> ${data.order.username} (${data.order.email})</p>
        <p><strong>Total:</strong> $${data.order.total}</p>
        <p><strong>Status:</strong> ${data.order.status}</p>
        <p><strong>Address:</strong> ${data.order.address}</p>
        ${data.items ? `
          <h4 class="mt-1">Items:</h4>
          ${data.items.map(i => `<p>${i.product_name} x${i.quantity} - $${i.price}</p>`).join('')}
        ` : ''}
      </div>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div class="card" style="border-left: 4px solid var(--danger);">
      <p><strong>Error:</strong> ${err.details || err.error || 'Lookup failed'}</p>
    </div>`;
  }
}

// ==================== SCOREBOARD PAGE ====================
async function renderScoreboard() {
  const content = document.getElementById('app-content');

  try {
    const [scoreboard, stats] = await Promise.all([
      API.getScoreboard(),
      API.getScoreboardStats()
    ]);

    content.innerHTML = `
      <div class="scoreboard-header">
        <h1>Scoreboard</h1>
        <p>Track your progress solving security challenges</p>
        <div class="grid-3 mt-2" style="max-width:600px; margin:1rem auto 0;">
          <div>
            <div style="font-size:1.8rem; font-weight:bold;">${stats.total_challenges}</div>
            <div style="font-size:0.8rem; opacity:0.8;">Challenges</div>
          </div>
          <div>
            <div style="font-size:1.8rem; font-weight:bold;">${stats.total_players}</div>
            <div style="font-size:0.8rem; opacity:0.8;">Players</div>
          </div>
          <div>
            <div style="font-size:1.8rem; font-weight:bold;">${stats.total_solves}</div>
            <div style="font-size:0.8rem; opacity:0.8;">Total Solves</div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">Leaderboard</div>
        ${scoreboard.leaderboard.length === 0 ? '<p>No solves yet. Be the first!</p>' : `
          <div class="table-container">
            <table>
              <thead>
                <tr><th>Rank</th><th>Player</th><th>Score</th><th>Solved</th><th>Progress</th><th>Last Solve</th></tr>
              </thead>
              <tbody>
                ${scoreboard.leaderboard.map(entry => `
                  <tr>
                    <td>
                      <span class="rank-badge ${entry.rank <= 3 ? 'rank-' + entry.rank : 'rank-other'}">
                        ${entry.rank <= 3 ? ['', '🥇', '🥈', '🥉'][entry.rank] : '#' + entry.rank}
                      </span>
                    </td>
                    <td>
                      <a href="#" onclick="viewUserScoreboard(${entry.id})" style="color:var(--primary-dark); font-weight:bold; text-decoration:none;">
                        ${entry.username}
                      </a>
                    </td>
                    <td><strong>${entry.total_score}</strong> pts</td>
                    <td>${entry.challenges_solved} / ${scoreboard.stats.total_challenges}</td>
                    <td>
                      <div class="progress-bar" style="height:12px;">
                        <div class="progress-fill" style="width:${entry.progress_percent}%; min-width:0; font-size:0;">${entry.progress_percent}%</div>
                      </div>
                    </td>
                    <td style="font-size:0.8rem; color:var(--text-light);">${entry.last_solve ? new Date(entry.last_solve).toLocaleString() : '-'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>

      <div class="grid-2 mt-2">
        <div class="card">
          <div class="card-header">Challenge Categories</div>
          ${stats.category_distribution.map(cat => `
            <div class="flex-between" style="padding: 0.4rem 0; border-bottom: 1px solid var(--border);">
              <span class="category-tag ${getCategoryClass(cat.category)}">${cat.category}</span>
              <span>${cat.count} challenges (avg difficulty: ${cat.avg_difficulty.toFixed(1)})</span>
            </div>
          `).join('')}
        </div>

        <div class="card">
          <div class="card-header">Difficulty Distribution</div>
          ${stats.difficulty_distribution.map(d => `
            <div class="flex-between" style="padding: 0.5rem 0; border-bottom: 1px solid var(--border);">
              <span>${'★'.repeat(d.difficulty)}${'☆'.repeat(3 - d.difficulty)} (Level ${d.difficulty})</span>
              <span><strong>${d.count}</strong> challenges (${d.difficulty * 100} pts each)</span>
            </div>
          `).join('')}
        </div>
      </div>

      <div class="card mt-2">
        <div class="card-header">Most Solved Challenges</div>
        ${stats.popular_challenges.filter(c => c.solve_count > 0).length === 0 ? '<p>No challenges solved yet.</p>' : `
          <div class="table-container">
            <table>
              <thead><tr><th>Challenge</th><th>Category</th><th>Difficulty</th><th>Solves</th></tr></thead>
              <tbody>
                ${stats.popular_challenges.filter(c => c.solve_count > 0).map(c => `
                  <tr>
                    <td>${c.name}</td>
                    <td><span class="category-tag ${getCategoryClass(c.category)}">${c.category}</span></td>
                    <td>${'★'.repeat(c.difficulty)}${'☆'.repeat(3 - c.difficulty)}</td>
                    <td>${c.solve_count}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<p>Error loading scoreboard: ${err.error || err.message}</p>`;
  }
}

async function viewUserScoreboard(userId) {
  const content = document.getElementById('app-content');

  try {
    const data = await API.getUserScoreboard(userId);
    const u = data.user;

    content.innerHTML = `
      <button class="btn btn-secondary mb-2" onclick="navigate('scoreboard')">Back to Scoreboard</button>
      <div class="card">
        <h2>${u.username}'s Profile</h2>
        <div class="grid-3 mt-2">
          <div class="stat-card">
            <div class="stat-value" style="font-size:2rem;">${u.total_score}</div>
            <div class="stat-label">Total Score</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="font-size:2rem;">${u.challenges_solved}/${u.total_challenges}</div>
            <div class="stat-label">Challenges</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="font-size:2rem;">${u.progress_percent}%</div>
            <div class="stat-label">Progress</div>
          </div>
        </div>
        <div class="progress-bar mt-2">
          <div class="progress-fill" style="width:${u.progress_percent}%">${u.progress_percent}%</div>
        </div>
      </div>

      <div class="card mt-2">
        <div class="card-header">Difficulty Breakdown</div>
        <div class="grid-3">
          <div class="text-center">
            <div style="font-size:1.5rem; color:var(--success);">★☆☆</div>
            <p>${u.completion_by_difficulty.easy.solved}/${u.completion_by_difficulty.easy.total}</p>
            <p style="font-size:0.8rem; color:var(--text-light);">Easy</p>
          </div>
          <div class="text-center">
            <div style="font-size:1.5rem; color:var(--warning);">★★☆</div>
            <p>${u.completion_by_difficulty.medium.solved}/${u.completion_by_difficulty.medium.total}</p>
            <p style="font-size:0.8rem; color:var(--text-light);">Medium</p>
          </div>
          <div class="text-center">
            <div style="font-size:1.5rem; color:var(--danger);">★★★</div>
            <p>${u.completion_by_difficulty.hard.solved}/${u.completion_by_difficulty.hard.total}</p>
            <p style="font-size:0.8rem; color:var(--text-light);">Hard</p>
          </div>
        </div>
      </div>

      <div class="card mt-2">
        <div class="card-header">Category Progress</div>
        ${Object.entries(data.category_progress).map(([cat, info]) => `
          <div style="margin-bottom: 1rem;">
            <div class="flex-between">
              <span class="category-tag ${getCategoryClass(cat)}">${cat}</span>
              <span>${info.solved}/${info.total}</span>
            </div>
            <div class="progress-bar mt-1" style="height:8px;">
              <div class="progress-fill" style="width:${Math.round((info.solved / info.total) * 100)}%; min-width:0; font-size:0;"></div>
            </div>
          </div>
        `).join('')}
      </div>

      <div class="card mt-2">
        <div class="card-header">Recent Solves</div>
        ${data.recent_solves.length === 0 ? '<p>No solves yet.</p>' : data.recent_solves.map(s => `
          <div style="padding:0.5rem 0; border-bottom:1px solid var(--border);">
            <span class="category-tag ${getCategoryClass(s.category)}">${s.category}</span>
            <strong>${s.name}</strong>
            <span style="color:var(--text-light); font-size:0.8rem;"> ${new Date(s.solved_at).toLocaleString()}</span>
            <span class="challenge-difficulty" style="float:right;">${'★'.repeat(s.difficulty)} +${s.difficulty * 100}pts</span>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<p>Error: ${err.error || err.message}</p>`;
  }
}

// ==================== CHALLENGES PAGE ====================
async function renderChallenges() {
  const content = document.getElementById('app-content');

  try {
    const data = await API.getChallenges();

    content.innerHTML = `
      <h2 class="mb-1">Security Challenges</h2>
      <p style="color:var(--text-light); margin-bottom:1rem;">Find and exploit vulnerabilities to solve challenges. Challenges are automatically detected when you successfully exploit a vulnerability.</p>

      <div class="flex-between mb-2" style="flex-wrap:wrap; gap:0.5rem;">
        <span>Solved: <strong>${data.solved}</strong> / ${data.total}</span>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
          <button class="btn btn-sm btn-primary" onclick="filterChallenges('all')">All</button>
          <button class="btn btn-sm btn-secondary" onclick="filterChallenges('solved')">Solved</button>
          <button class="btn btn-sm btn-secondary" onclick="filterChallenges('unsolved')">Unsolved</button>
          <button class="btn btn-sm" style="background:var(--danger); color:white;" onclick="restartChallenges()">Restart All</button>
        </div>
      </div>

      ${Object.entries(data.grouped).map(([category, challenges]) => `
        <div class="mb-2">
          <h3>
            <span class="category-tag ${getCategoryClass(category)}">${category}</span>
            (${challenges.filter(c => c.solved).length}/${challenges.length})
          </h3>
          <div class="grid mt-1" id="challenge-group-${category.replace(/\s/g, '-')}">
            ${challenges.map(ch => `
              <div class="challenge-card ${ch.solved ? 'solved' : 'unsolved'}" data-solved="${ch.solved}">
                <div class="flex-between">
                  <div>
                    <div class="challenge-category">${ch.owasp_category || category}</div>
                    <div class="challenge-name">${ch.name}</div>
                  </div>
                  <span class="challenge-status ${ch.solved ? 'status-solved' : 'status-unsolved'}">
                    ${ch.solved ? 'SOLVED' : 'UNSOLVED'}
                  </span>
                </div>
                <div class="challenge-difficulty">${ch.stars} (${ch.points} pts)</div>
                <div class="challenge-description">${ch.description}</div>
                ${ch.hint ? `
                  <details>
                    <summary style="cursor:pointer; color:var(--warning); font-size:0.85rem;">Show Hint</summary>
                    <div class="challenge-hint">${ch.hint}</div>
                  </details>
                ` : ''}
                ${ch.tutorial_url ? `<a href="${ch.tutorial_url}" target="_blank" style="font-size:0.8rem;">Learn more</a>` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      `).join('')}
    `;
  } catch (err) {
    content.innerHTML = `<p>Error loading challenges: ${err.error || err.message}</p>`;
  }
}

function filterChallenges(filter) {
  const cards = document.querySelectorAll('.challenge-card');
  cards.forEach(card => {
    const solved = card.dataset.solved === 'true';
    if (filter === 'all') card.style.display = '';
    else if (filter === 'solved') card.style.display = solved ? '' : 'none';
    else if (filter === 'unsolved') card.style.display = solved ? 'none' : '';
  });
}

// ==================== FEEDBACK PAGE ====================
async function renderFeedback() {
  const content = document.getElementById('app-content');

  try {
    const feedbacks = await API.getFeedback();

    content.innerHTML = `
      <h2 class="mb-2">Customer Feedback</h2>

      <div class="card mb-2">
        <div class="card-header">Submit Feedback</div>
        <div class="form-group">
          <label>Subject</label>
          <input type="text" id="fb-subject" class="form-control" placeholder="Subject" />
        </div>
        <div class="form-group">
          <label>Message</label>
          <textarea id="fb-message" class="form-control" placeholder="Your feedback..."></textarea>
        </div>
        <div class="form-group">
          <label>Rating</label>
          <select id="fb-rating" class="form-control">
            <option value="5">5 - Excellent</option>
            <option value="4">4 - Good</option>
            <option value="3" selected>3 - Average</option>
            <option value="2">2 - Poor</option>
            <option value="1">1 - Terrible</option>
          </select>
        </div>
        <button class="btn btn-primary" onclick="doSubmitFeedback()">Submit</button>
      </div>

      <div class="card">
        <div class="card-header">Recent Feedback (${feedbacks.length})</div>
        ${feedbacks.map(f => `
          <div class="review-item">
            <div class="flex-between">
              <span class="review-author">${f.username || 'Anonymous'}</span>
              <span class="review-rating">${'★'.repeat(f.rating || 0)}${'☆'.repeat(5 - (f.rating || 0))}</span>
            </div>
            <div style="font-weight:600; margin:0.3rem 0;">${f.subject}</div>
            <!-- VULNERABILITY: XSS in feedback message -->
            <div>${f.message}</div>
            <div style="font-size:0.75rem; color:var(--text-light);">${new Date(f.created_at).toLocaleString()}</div>
          </div>
        `).join('')}
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<p>Error: ${err.error || err.message}</p>`;
  }
}

async function doSubmitFeedback() {
  const subject = document.getElementById('fb-subject').value;
  const message = document.getElementById('fb-message').value;
  const rating = parseInt(document.getElementById('fb-rating').value);

  if (!message) {
    showNotification('Please enter a message', 'warning');
    return;
  }

  try {
    await API.postFeedback(subject, message, rating);
    showNotification('Feedback submitted!');
    renderFeedback();
  } catch (err) {
    showNotification(err.error || 'Failed to submit feedback', 'error');
  }
}

// ==================== ADMIN PAGE ====================
async function renderAdmin() {
  const content = document.getElementById('app-content');

  try {
    const dashboard = await API.getAdminDashboard();

    content.innerHTML = `
      <h2 class="mb-2">Admin Dashboard</h2>
      ${dashboard.flag ? `<div class="card" style="background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:white;">
        <p><strong>Flag:</strong> ${dashboard.flag}</p>
      </div>` : ''}

      <div class="grid-3 mt-1">
        <div class="card stat-card">
          <div class="stat-value">${dashboard.dashboard.total_users}</div>
          <div class="stat-label">Total Users</div>
        </div>
        <div class="card stat-card">
          <div class="stat-value">${dashboard.dashboard.total_orders}</div>
          <div class="stat-label">Total Orders</div>
        </div>
        <div class="card stat-card">
          <div class="stat-value">$${dashboard.dashboard.total_revenue.toFixed(2)}</div>
          <div class="stat-label">Revenue</div>
        </div>
      </div>

      <div class="card mt-2">
        <div class="card-header">All Users</div>
        <div id="admin-users">Loading...</div>
      </div>
    `;

    // Load users
    const users = await API.getAdminUsers();
    document.getElementById('admin-users').innerHTML = `
      <div class="table-container">
        <table>
          <thead>
            <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Wallet</th><th>Password Hash</th></tr>
          </thead>
          <tbody>
            ${users.map(u => `
              <tr>
                <td>${u.id}</td>
                <td>${u.username}</td>
                <td>${u.email}</td>
                <td>${u.role}</td>
                <td>$${u.wallet_balance.toFixed(2)}</td>
                <td style="font-family:monospace; font-size:0.75rem;">${u.password}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `
      <div class="card" style="border-left: 4px solid var(--danger);">
        <h3>Access Denied</h3>
        <p>${err.error || 'Admin access required'}</p>
        <p class="mt-1" style="font-size:0.85rem; color:var(--text-light);">Hint: You need admin privileges. Can you forge your way in?</p>
      </div>
    `;
  }
}
