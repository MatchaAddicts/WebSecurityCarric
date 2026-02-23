const { getDb } = require('./schema');
const md5 = require('md5');

function seed() {
  const db = getDb();

  // Clear existing data
  db.exec(`
    DELETE FROM user_challenges;
    DELETE FROM user_files;
    DELETE FROM order_items;
    DELETE FROM orders;
    DELETE FROM cart;
    DELETE FROM reviews;
    DELETE FROM feedback;
    DELETE FROM coupons;
    DELETE FROM challenges;
    DELETE FROM products;
    DELETE FROM users;
  `);

  // --- USERS ---
  const insertUser = db.prepare(`
    INSERT INTO users (username, email, password, role, wallet_balance) VALUES (?, ?, ?, ?, ?)
  `);

  const users = [
    ['admin', 'admin@vegetarian-juice.shop', md5('admin123'), 'admin', 1000.00],
    ['john', 'john@juice.local', md5('password'), 'customer', 100.00],
    ['jane', 'jane@juice.local', md5('qwerty123'), 'customer', 150.00],
    ['bob', 'bob@juice.local', md5('bob2024'), 'customer', 75.50],
    ['alice', 'alice@juice.local', md5('alice!'), 'customer', 200.00],
    ['support', 'support@vegetarian-juice.shop', md5('sup0rt!@#'), 'support', 500.00],
    ['deluxe_member', 'deluxe@juice.local', md5('deluxe'), 'deluxe', 999.99],
    ['bender', 'bender@juice.local', md5('BendMe!'), 'customer', 0.00],
    // Hidden admin account - vulnerability: backdoor account
    ['wurstbot', 'wurstbot@vegetarian-juice.shop', md5('VeggieBot2024!'), 'admin', 99999.00],
  ];

  for (const u of users) {
    insertUser.run(...u);
  }

  // --- PRODUCTS ---
  const insertProduct = db.prepare(`
    INSERT INTO products (name, description, price, image, category, stock) VALUES (?, ?, ?, ?, ?, ?)
  `);

  const products = [
    ['Green Goddess Juice', 'A refreshing blend of kale, spinach, cucumber, and green apple.', 5.99, '/img/green-goddess.png', 'juice', 50],
    ['Tropical Paradise Smoothie', 'Mango, pineapple, coconut milk, and a splash of lime.', 6.49, '/img/tropical.png', 'smoothie', 40],
    ['Beet Bliss', 'Beetroot, carrot, ginger, and a hint of lemon.', 5.49, '/img/beet-bliss.png', 'juice', 60],
    ['Berry Burst Shake', 'Mixed berries, almond milk, and vanilla protein.', 7.99, '/img/berry-burst.png', 'shake', 35],
    ['Carrot Zinger', 'Fresh carrots with turmeric and black pepper.', 4.99, '/img/carrot-zinger.png', 'juice', 70],
    ['Avocado Dream', 'Avocado, banana, spinach, and oat milk.', 8.49, '/img/avocado-dream.png', 'smoothie', 25],
    ['Detox Elixir', 'Lemon, ginger, cayenne pepper, and maple syrup.', 3.99, '/img/detox.png', 'elixir', 100],
    ['Forbidden Fruit Blend', 'A secret recipe made with forbidden ingredients.', 0.00, '/img/forbidden.png', 'special', 1],
    ['Christmas Special Nog', 'Seasonal plant-based eggnog with nutmeg.', 9.99, '/img/nog.png', 'seasonal', 0],
    ['Protein Power Bowl', 'Acai, peanut butter, banana, granola, hemp seeds.', 11.99, '/img/power-bowl.png', 'bowl', 20],
    ['Cucumber Cooler', 'Cucumber, mint, lime, and sparkling water.', 4.49, '/img/cucumber.png', 'juice', 80],
    ['Golden Milk Latte', 'Turmeric, ginger, cinnamon, black pepper, oat milk.', 5.99, '/img/golden-milk.png', 'latte', 45],
    ['Admin Super Juice', 'Only available to admin users. Grants +1000 to wallet.', 0.01, '/img/admin-juice.png', 'special', 999],
  ];

  for (const p of products) {
    insertProduct.run(...p);
  }

  // --- REVIEWS ---
  const insertReview = db.prepare(`
    INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)
  `);

  const reviews = [
    [1, 2, 5, 'Amazing green juice! So refreshing!'],
    [1, 3, 4, 'Great taste but a bit too sweet for me.'],
    [2, 2, 5, 'Best tropical smoothie I have ever had!'],
    [3, 4, 3, 'The beet flavor is quite strong.'],
    [4, 3, 5, 'Love the berry shake!'],
    [5, 5, 4, 'Good carrot juice, could use more ginger.'],
    [7, 2, 5, 'The detox elixir really works!'],
    [6, 4, 4, 'Avocado dream is creamy perfection.'],
  ];

  for (const r of reviews) {
    insertReview.run(...r);
  }

  // --- COUPONS ---
  const insertCoupon = db.prepare(`
    INSERT INTO coupons (code, discount, is_active) VALUES (?, ?, ?)
  `);

  const coupons = [
    ['VEGGIE10', 10.0, 1],
    ['WELCOME20', 20.0, 1],
    ['EXPIRED50', 50.0, 0],
    ['ADMIN100', 100.0, 1],  // Hidden coupon - full discount
    ['NULL', 90.0, 1],       // Tricky coupon code
  ];

  for (const c of coupons) {
    insertCoupon.run(...c);
  }

  // --- CHALLENGES ---
  const insertChallenge = db.prepare(`
    INSERT INTO challenges (key, name, description, category, difficulty, hint, flag, owasp_category, tutorial_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const challenges = [
    // ================================================================
    // OWASP Top 10:2025 Challenges
    // ================================================================

    // A01:2025 - Broken Access Control (includes SSRF, consolidated from A10:2021)
    ['idor_profile', 'IDOR - View Profile', 'Access another user\'s profile by manipulating the user ID parameter.', 'Broken Access Control', 1, 'Try changing the user ID in the API URL.', 'VJS{1d0r_pr0f1le_4cc3ss}', 'A01:2025-Broken Access Control', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
    ['admin_panel', 'Admin Section Access', 'Access the admin panel without being an admin.', 'Broken Access Control', 2, 'The admin panel path might be predictable. Check the JWT token.', 'VJS{4dm1n_p4n3l_byp4ss}', 'A01:2025-Broken Access Control', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
    ['forged_review', 'Forged Review', 'Post a review as a different user by manipulating the request.', 'Broken Access Control', 2, 'The review API trusts the user_id in the request body.', 'VJS{f0rg3d_r3v13w_1d0r}', 'A01:2025-Broken Access Control', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
    ['horizontal_priv', 'Horizontal Privilege Escalation', 'Modify another user\'s cart or wallet balance.', 'Broken Access Control', 3, 'The wallet top-up endpoint doesn\'t verify the user matches the token.', 'VJS{h0r1z0nt4l_pr1v_3sc}', 'A01:2025-Broken Access Control', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
    ['csrf_wallet', 'CSRF Wallet Transfer', 'Perform a cross-site request to transfer wallet balance.', 'Broken Access Control', 2, 'The wallet transfer endpoint has no CSRF protection.', 'VJS{csrf_w4ll3t_dr41n}', 'A01:2025-Broken Access Control', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
    ['ssrf_basic', 'Server-Side Request Forgery', 'Exploit the URL preview feature to access internal resources.', 'Broken Access Control', 3, 'The URL preview feature fetches URLs server-side without validation.', 'VJS{ssrf_1nt3rn4l_4cc3ss}', 'A01:2025-Broken Access Control', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],

    // A02:2025 - Security Misconfiguration (moved up from A05:2021)
    ['error_disclosure', 'Verbose Error Messages', 'Trigger an error that reveals sensitive system information.', 'Security Misconfiguration', 1, 'Try sending unexpected data types to API endpoints.', 'VJS{v3rb0s3_3rr0r_l34k}', 'A02:2025-Security Misconfiguration', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
    ['directory_listing', 'Directory Traversal', 'Access files outside the intended directory using path traversal.', 'Security Misconfiguration', 2, 'The file download endpoint doesn\'t sanitize path characters.', 'VJS{d1r3ct0ry_tr4v3rs4l}', 'A02:2025-Security Misconfiguration', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
    ['default_creds', 'Default Credentials', 'Find and use hidden default/backdoor accounts.', 'Security Misconfiguration', 2, 'Some accounts were created during development and never removed.', 'VJS{d3f4ult_cr3ds_b4ckd00r}', 'A02:2025-Security Misconfiguration', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
    ['hidden_page', 'Hidden Page Discovery', 'Find the secret developer page hidden in the application.', 'Security Misconfiguration', 1, 'Robots.txt might reveal something interesting.', 'VJS{r0b0ts_txt_s3cr3t}', 'A02:2025-Security Misconfiguration', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
    ['xxe_upload', 'XML External Entity', 'Exploit XXE in the XML import feature to read server files.', 'Security Misconfiguration', 3, 'The XML parser processes external entities without restriction.', 'VJS{xx3_f1l3_r34d}', 'A02:2025-Security Misconfiguration', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],

    // A03:2025 - Software Supply Chain Failures (NEW in 2025)
    ['outdated_deps', 'Outdated Dependencies', 'Identify known vulnerable npm packages used by the application.', 'Supply Chain', 1, 'Run npm audit or check package.json for outdated packages with known CVEs.', 'VJS{vuln3r4bl3_d3ps_f0und}', 'A03:2025-Software Supply Chain Failures', 'https://owasp.org/Top10/'],
    ['exposed_lockfile', 'Exposed Lockfile', 'Access the package-lock.json to enumerate exact dependency versions.', 'Supply Chain', 1, 'The server serves static files from the project root. Try fetching the lockfile directly.', 'VJS{l0ckf1l3_3xp0s3d}', 'A03:2025-Software Supply Chain Failures', 'https://owasp.org/Top10/'],
    ['prototype_pollution', 'Prototype Pollution', 'Exploit a prototype pollution vulnerability via the profile update endpoint.', 'Supply Chain', 3, 'Try setting __proto__ or constructor.prototype properties in the JSON body.', 'VJS{pr0t0typ3_p0llut10n}', 'A03:2025-Software Supply Chain Failures', 'https://owasp.org/Top10/'],

    // A04:2025 - Cryptographic Failures (moved from A02:2021)
    ['md5_passwords', 'Weak Password Hashing', 'Discover that passwords are hashed with MD5 (unsalted).', 'Cryptographic Failures', 2, 'Check the /api/users endpoint or look at the database schema.', 'VJS{md5_n0_s4lt_cr4ck}', 'A04:2025-Cryptographic Failures', 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
    ['exposed_api', 'Exposed API Docs', 'Find the unprotected API documentation endpoint that leaks secrets.', 'Cryptographic Failures', 1, 'Try common paths like /api-docs, /swagger, /api/docs.', 'VJS{3xp0s3d_4p1_d0cs}', 'A04:2025-Cryptographic Failures', 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
    ['jwt_secret', 'Weak JWT Secret', 'Discover the JWT signing secret and forge tokens.', 'Cryptographic Failures', 3, 'The JWT secret might be in a common wordlist. Try "secret", "veggie", etc.', 'VJS{w34k_jwt_s3cr3t}', 'A04:2025-Cryptographic Failures', 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],

    // A05:2025 - Injection (moved from A03:2021)
    ['sqli_login', 'Login Bypass', 'Log in as admin without knowing the password using SQL injection.', 'Injection', 1, 'Try some classic SQL injection in the login form.', 'VJS{sql_inject10n_l0gin_byp4ss}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['sqli_search', 'Search Injection', 'Extract hidden product data using SQL injection in the search bar.', 'Injection', 2, 'The search endpoint directly concatenates user input into SQL.', 'VJS{un10n_s3lect_m4ster}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['sqli_order', 'Order Manipulation', 'Use SQL injection in the order lookup to view other users orders.', 'Injection', 3, 'The order lookup uses string concatenation for the SQL WHERE clause.', 'VJS{0rder_sql1_exf1ltr4t10n}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['xss_reflected', 'Reflected XSS', 'Perform a reflected XSS attack via the search functionality.', 'Injection', 1, 'The search query is reflected in the page without sanitization.', 'VJS{r3flect3d_xss_p0p}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['xss_stored', 'Stored XSS', 'Store a persistent XSS payload in a product review.', 'Injection', 2, 'Review comments are rendered as raw HTML.', 'VJS{st0r3d_xss_r3v13w}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['xss_dom', 'DOM-based XSS', 'Exploit a DOM-based XSS vulnerability via URL fragment.', 'Injection', 3, 'Check how the page handles the URL hash/fragment.', 'VJS{d0m_xss_fr4gm3nt}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['null_byte', 'Null Byte Injection', 'Use a null byte to bypass file extension validation.', 'Injection', 3, 'Try appending %00 before the file extension.', 'VJS{null_byt3_1nj3ct}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
    ['nosql_coupon', 'NoSQL-style Injection', 'Bypass coupon validation using NoSQL-style operator injection.', 'Injection', 3, 'Try sending JSON with MongoDB-style operators to the coupon endpoint.', 'VJS{n0sql_0p3r4t0r_1nj}', 'A05:2025-Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],

    // A06:2025 - Insecure Design (moved from A04:2021)
    ['file_upload', 'Unrestricted File Upload', 'Upload a malicious file by bypassing the file type check.', 'Insecure Design', 2, 'The server only checks the file extension, not the MIME type or content.', 'VJS{unr3str1ct3d_upl04d}', 'A06:2025-Insecure Design', 'https://owasp.org/Top10/A04_2021-Insecure_Design/'],
    ['mass_assign', 'Mass Assignment', 'Elevate your role to admin through mass assignment in profile update.', 'Insecure Design', 2, 'The profile update endpoint blindly applies all submitted fields.', 'VJS{m4ss_4ss1gn_r0l3}', 'A06:2025-Insecure Design', 'https://owasp.org/Top10/A04_2021-Insecure_Design/'],
    ['race_coupon', 'Race Condition', 'Apply a coupon multiple times using a race condition.', 'Insecure Design', 3, 'Send multiple concurrent requests to the coupon redemption endpoint.', 'VJS{r4c3_c0nd1t10n_c0up0n}', 'A06:2025-Insecure Design', 'https://owasp.org/Top10/A04_2021-Insecure_Design/'],

    // A07:2025 - Authentication Failures (same position)
    ['weak_password', 'Weak Admin Password', 'Log in to the admin account by guessing or brute-forcing the password.', 'Authentication Failures', 1, 'The admin uses a very common password.', 'VJS{w34k_4dm1n_p4ssw0rd}', 'A07:2025-Authentication Failures', 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
    ['jwt_none', 'JWT None Algorithm', 'Forge a JWT token using the none algorithm to become admin.', 'Authentication Failures', 3, 'Try changing the algorithm in the JWT header to "none".', 'VJS{jwt_n0n3_4lg0_f0rg3}', 'A07:2025-Authentication Failures', 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
    ['password_reset', 'Broken Password Reset', 'Reset another user\'s password through the insecure reset mechanism.', 'Authentication Failures', 2, 'The password reset doesn\'t properly verify the requester\'s identity.', 'VJS{br0k3n_p4ss_r3s3t}', 'A07:2025-Authentication Failures', 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],

    // A08:2025 - Software and Data Integrity Failures
    ['unsigned_jwt', 'Unsigned Data Integrity', 'Tamper with order data after submission by modifying the client-side request.', 'Integrity Failures', 2, 'The server trusts client-submitted price values without verifying against the database.', 'VJS{d4t4_1nt3gr1ty_f41l}', 'A08:2025-Software and Data Integrity Failures', 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'],

    // A09:2025 - Security Logging & Alerting Failures
    ['no_logging', 'Missing Security Logs', 'Perform multiple failed login attempts without triggering any lockout or alert.', 'Logging Failures', 2, 'Brute force the login endpoint. Notice there is no rate limiting or logging of failed attempts.', 'VJS{n0_l0gg1ng_0r_4l3rt}', 'A09:2025-Security Logging and Alerting Failures', 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'],

    // A10:2025 - Mishandling of Exceptional Conditions (NEW in 2025)
    ['negative_quantity', 'Negative Quantity Order', 'Place an order with negative quantities to credit your wallet.', 'Exceptional Conditions', 1, 'Try submitting an order with negative item quantities. The backend does not validate bounds.', 'VJS{n3g4t1v3_qu4nt1ty_cr3d1t}', 'A10:2025-Mishandling of Exceptional Conditions', 'https://owasp.org/Top10/'],
    ['type_confusion', 'Type Confusion', 'Cause unexpected behavior by sending wrong data types to API endpoints.', 'Exceptional Conditions', 2, 'Send an array where a string is expected, or an object where a number is expected.', 'VJS{typ3_c0nfus10n_3rr0r}', 'A10:2025-Mishandling of Exceptional Conditions', 'https://owasp.org/Top10/'],
    ['overflow_wallet', 'Integer Overflow', 'Overflow the wallet balance by topping up with an extremely large number.', 'Exceptional Conditions', 2, 'Try topping up with Number.MAX_SAFE_INTEGER or very large values.', 'VJS{1nt3g3r_0v3rfl0w_w4ll3t}', 'A10:2025-Mishandling of Exceptional Conditions', 'https://owasp.org/Top10/'],
  ];

  for (const c of challenges) {
    insertChallenge.run(...c);
  }

  // --- FEEDBACK ---
  const insertFeedback = db.prepare(`
    INSERT INTO feedback (user_id, subject, message, rating) VALUES (?, ?, ?, ?)
  `);

  const feedbacks = [
    [2, 'Great juice!', 'Loved the Green Goddess. Will order again!', 5],
    [3, 'Delivery issue', 'My order arrived late but the juice was still cold.', 3],
    [null, 'Anonymous feedback', 'Please add more smoothie options.', 4],
  ];

  for (const f of feedbacks) {
    insertFeedback.run(...f);
  }

  console.log('Database seeded successfully!');
  console.log(`  - ${users.length} users created`);
  console.log(`  - ${products.length} products created`);
  console.log(`  - ${reviews.length} reviews created`);
  console.log(`  - ${coupons.length} coupons created`);
  console.log(`  - ${challenges.length} challenges created`);
  console.log(`  - ${feedbacks.length} feedback entries created`);
}

seed();
