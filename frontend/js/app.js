// Vegetarian Juice Shop - Main App Logic

let cart = JSON.parse(localStorage.getItem('vjs_cart') || '[]');
let _currentPage = 'home';

// Navigation
function navigate(page, params = {}) {
  _currentPage = page;
  const content = document.getElementById('app-content');
  content.innerHTML = '<div class="text-center mt-3"><p>Loading...</p></div>';
  content.className = 'fade-in';

  switch (page) {
    case 'home': renderHome(); break;
    case 'products': renderProducts(); break;
    case 'product': renderProductDetail(params.id); break;
    case 'login': renderLogin(); break;
    case 'register': renderRegister(); break;
    case 'profile': renderProfile(); break;
    case 'cart': renderCart(); break;
    case 'orders': renderOrders(); break;
    case 'scoreboard': renderScoreboard(); break;
    case 'challenges': renderChallenges(); break;
    case 'feedback': renderFeedback(); break;
    case 'admin': renderAdmin(); break;
    default: renderHome();
  }
}

// Auth State Management
function updateAuthUI() {
  const user = API.getUser();
  const userSection = document.getElementById('nav-user-section');
  const authSection = document.getElementById('nav-auth-section');
  const adminLink = document.getElementById('admin-link');

  if (user) {
    userSection.style.display = 'none';
    authSection.style.display = 'inline';
    if (user.role === 'admin') {
      adminLink.style.display = 'inline';
    } else {
      adminLink.style.display = 'none';
    }
  } else {
    userSection.style.display = 'inline';
    authSection.style.display = 'none';
  }

  updateCartCount();
}

function updateCartCount() {
  const countEl = document.getElementById('cart-count');
  if (countEl) {
    countEl.textContent = cart.length;
  }
}

function logout() {
  API.clearAuth();
  document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  cart = [];
  localStorage.removeItem('vjs_cart');
  updateAuthUI();
  navigate('home');
  showNotification('Logged out successfully');
}

// Notifications
function showNotification(message, type = 'success') {
  const bar = document.getElementById('notification-bar');
  const text = document.getElementById('notification-text');
  bar.style.display = 'flex';
  bar.className = `notification-bar ${type}`;
  text.textContent = message;

  setTimeout(() => { bar.style.display = 'none'; }, 6000);
}

function closeNotification() {
  document.getElementById('notification-bar').style.display = 'none';
}

// Report client-side detected challenge to server
async function reportClientChallenge(key) {
  if (!API.getToken()) return;
  try {
    await API.reportChallengeSolved(key);
  } catch (e) {
    // Silently fail
  }
}

// Restart challenges
async function restartChallenges() {
  if (!confirm('Reset ALL challenge progress for every user? This cannot be undone.')) return;

  try {
    const result = await API.restartChallenges();
    showNotification(result.message || 'Challenges restarted');
    renderChallenges();
  } catch (e) {
    showNotification(e.error || 'Failed to restart challenges', 'error');
  }
}

// Cart management
function addToCart(product) {
  cart.push(product);
  localStorage.setItem('vjs_cart', JSON.stringify(cart));
  updateCartCount();
  showNotification(`${product.name} added to cart`);
}

function removeFromCart(index) {
  cart.splice(index, 1);
  localStorage.setItem('vjs_cart', JSON.stringify(cart));
  updateCartCount();
  renderCart();
}

// Product emoji mapping
function getProductEmoji(category) {
  const emojis = {
    'juice': '🥤',
    'smoothie': '🥝',
    'shake': '🫐',
    'elixir': '🧪',
    'bowl': '🥣',
    'latte': '☕',
    'seasonal': '🎄',
    'special': '✨',
    'default': '🥬'
  };
  return emojis[category] || emojis['default'];
}

// Category CSS class (OWASP Top 10:2025)
function getCategoryClass(category) {
  const map = {
    'Broken Access Control': 'cat-access',
    'Security Misconfiguration': 'cat-misc',
    'Supply Chain': 'cat-supply',
    'Cryptographic Failures': 'cat-crypto',
    'Injection': 'cat-injection',
    'Insecure Design': 'cat-design',
    'Authentication Failures': 'cat-auth',
    'Integrity Failures': 'cat-integrity',
    'Logging Failures': 'cat-logging',
    'Exceptional Conditions': 'cat-exceptional',
  };
  return map[category] || 'cat-other';
}

// Challenge solved modal popup
function showChallengeSolvedPopup(name, points) {
  const overlay = document.createElement('div');
  overlay.className = 'challenge-solved-overlay';
  overlay.innerHTML = `
    <div class="challenge-solved-card">
      <div class="solved-icon">&#127937;</div>
      <div class="solved-title">Challenge Solved!</div>
      <div class="solved-name">${name}</div>
      <div class="solved-points">+${points} pts</div>
      <button class="solved-dismiss" onclick="this.closest('.challenge-solved-overlay').remove()">Nice!</button>
    </div>
  `;
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.remove();
  });
  document.body.appendChild(overlay);
}

// Poll for challenge solve notifications (catches solves from direct browser visits, curl, etc.)
let _notificationPollTimer = null;

function startNotificationPolling() {
  if (_notificationPollTimer) return;
  _notificationPollTimer = setInterval(async () => {
    try {
      const resp = await fetch('/api/challenges/notifications');
      const data = await resp.json();
      if (data.notifications && data.notifications.length > 0) {
        for (const ch of data.notifications) {
          showChallengeSolvedPopup(ch.name, ch.points);
        }
        // Auto-refresh challenges page if currently viewing it
        if (_currentPage === 'challenges') {
          renderChallenges();
        }
      }
    } catch (e) {
      // Silently ignore polling errors
    }
  }, 3000);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  updateAuthUI();
  navigate('home');
  startNotificationPolling();
});
