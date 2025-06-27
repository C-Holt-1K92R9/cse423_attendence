require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const QRCode = require('qrcode');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MySQLStore = require('express-mysql-session')(session);
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  ssl: { ca: process.env.DB_SSL_CA }
});
const sessionStore = new MySQLStore({}, dbPool);

app.use(cookieParser());
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- Helper Functions ---
const clearAuthCookies = (res) => {
  res.clearCookie('remember_me_token', { path: '/' });
  res.clearCookie('name', { path: '/' });
  res.clearCookie('attended', { path: '/' });
  res.clearCookie('photo_url', { path: '/' });
  res.clearCookie('student_id', { path: '/' });
  res.clearCookie('token', { path: '/' });
};

const getRememberMeUser = async (cookies) => {
  if (!cookies || !cookies.remember_me_token) return null;
  const [selector, validator] = cookies.remember_me_token.split(':');
  if (!selector || !validator) return null;
  const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);
  if (tokenRows.length === 0) return null;
  const authToken = tokenRows[0];
  // Check expiry using Asia/Dhaka timezone
  const nowDhaka = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" }));
  if (new Date(authToken.expires) < nowDhaka) {
    await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
    return null;
  }
  const match = await bcrypt.compare(validator, authToken.hashed_validator);
  if (!match) return null;
  // Explicitly select all columns from users table
  const [userRows] = await dbPool.execute('SELECT * FROM users WHERE Email = ?', [authToken.email]);
  if (userRows.length === 0) return null;
  // Return the full user object
  return userRows[0];
};

const now = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" }));
const dd = String(now.getDate()).padStart(2, '0');
const mm = String(now.getMonth() + 1).padStart(2, '0');
const yyyy = now.getFullYear();
const new_column = `${dd}_${mm}_${yyyy}`;

// --- Passport Google OAuth ---
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  const { id: googleId, displayName: name } = profile;
  const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
  if (!email) return done(new Error("No email found in Google profile"), null);
  const authorizedDomains = ["g.bracu.ac.bd", "bracu.ac.bd"];
  const domain = email.split('@')[1];
  if (!authorizedDomains.includes(domain)) return done(null, false, { message: "Domain is not authorized" });

  try {
    let [rows] = await dbPool.execute(
      'SELECT * FROM users WHERE google_id = ? OR Email = ?',
      [googleId, email]
    );
    let user = rows[0];
    if (!user) {
      let type = domain === "g.bracu.ac.bd" ? 0 : 1;
      const [insertResult] = await dbPool.execute(
        'INSERT INTO users (Name, Email, type, google_id, Photo_url) VALUES (?, ?, ?, ?, ?)',
        [name, email, type, googleId, profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null]
      );
      [rows] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [insertResult.insertId]);
      user = rows[0];
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [id]);
    done(null, rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// --- IP Whitelist Middleware ---
const ALLOWED_IP = process.env.ALLOWED_IP;
const ipWhitelistMiddleware = async (req, res, next) => {
  let requestIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (requestIp && requestIp.includes(',')) requestIp = requestIp.split(',')[0].trim();
  if (requestIp && requestIp.startsWith('::ffff:')) requestIp = requestIp.replace('::ffff:', '');
  console.log('Request IP:', requestIp);
  try {
    const https = require('https');
    console.log('Fetching ISP info for IP:', requestIp);
    // Use ipinfo.io to get ISP info
    https.get(`https://ipinfo.io/${requestIp}/json`, (res2) => {
      let data2 = '';
      res2.on('data', chunk => data2 += chunk);
      res2.on('end', () => {
        try {
          const info = JSON.parse(data2);
          let isp = null;
          if (info.org) {
            // org is usually like "AS15169 Google LLC"
            isp = info.org.split(' ').slice(1).join(' ');
            console.log('IP Address:', requestIp);
            console.log('ISP Provider:', isp);
          } else {
            console.log('IP Address:', requestIp);
            console.log('ISP info not found.');
          }
          if (isp && isp.toLowerCase().includes(process.env.ALLOWED_ISP_NAME.toLowerCase())) {
            return next();
          } else {
            return res.status(403).json({ success: false, message: 'Access denied: This action can only be performed from an authorized ISP.' });
          }
        } catch (parseErr) {
          return res.status(403).json({ success: false, message: 'Access denied: Unable to verify ISP.' });
        }
      });
    }).on('error', err => {
      console.error('Error fetching ISP info:', err.message);
      return res.status(403).json({ success: false, message: 'Access denied: Unable to verify ISP.' });
    });
  } catch (error) {
    res.status(403).json({ success: false, message: 'Access denied: Unable to verify ISP.' });
  }
};

// --- Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?message=Domain is not Authorized!', session: false }),
  async (req, res) => {
    const user = req.user;
    try {
      const selector = crypto.randomBytes(16).toString('hex');
      const validator = crypto.randomBytes(32).toString('hex');
      const hashedValidator = await bcrypt.hash(validator, 10);
      // Set expiry in Asia/Dhaka timezone
      const nowDhaka = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" }));
      const expires = new Date(nowDhaka.getTime() + 30 * 24 * 60 * 60 * 1000);
      const [existingTokens] = await dbPool.execute("SELECT * FROM auth_tokens WHERE email = ?", [user.Email]);
      if (existingTokens.length > 0) {
        await dbPool.execute("UPDATE auth_tokens SET selector = ?, hashed_validator = ?, expires = ? WHERE email = ?", [selector, hashedValidator, expires, user.Email]);
      } else {
        await dbPool.execute("INSERT INTO auth_tokens (selector, hashed_validator, email, expires) VALUES (?, ?, ?, ?)", [selector, hashedValidator, user.Email, expires]);
      }
      res.cookie('photo_url', user.Photo_url || '', { httpOnly: false, secure: process.env.NODE_ENV === 'production', expires });
      res.cookie('remember_me_token', `${selector}:${validator}`, { httpOnly: true, secure: process.env.NODE_ENV === 'production', expires });
      res.cookie('name', user.Name ? user.Name.split(' ')[0] : '', { httpOnly: false, secure: process.env.NODE_ENV === 'production', expires });
      res.redirect('/');
    } catch (err) {
      res.redirect('/?error=auth_failed');
    }
  }
);
app.get('/manual', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'manual.html')); 
});
app.get('/', async (req, res) => {
  if (req.query && req.query.token) {
    res.cookie('token', req.query.token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 60 * 1000
    });
  }
  const user = await getRememberMeUser(req.cookies);
  if (!user) return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  req.session.email = user.Email;
  req.session.name = user.Name;
  req.session.user = user.id;

  return user.type === 0 ? res.redirect('/student') : res.redirect('/admin/dashboard');
});

app.get('/api/logout', async (req, res) => {
  req.session.destroy(async err => {
    clearAuthCookies(res);
    if (req.cookies && req.cookies.remember_me_token) {
      const [selector] = req.cookies.remember_me_token.split(':');
      if (selector) await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
    }
    res.redirect('/');
  });
});

app.get('/admin/dashboard', async (req, res) => {
  const user = await getRememberMeUser(req.cookies);
  if (!user) {
    clearAuthCookies(res);
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/student', async (req, res) => {
  const user = await getRememberMeUser(req.cookies);
  if (!user) {
    clearAuthCookies(res);
    res.redirect('/');
  }
  if (!user.StudentID) {
    res.sendFile(path.join(__dirname, 'public', 'id_submission.html'));
  }
  res.cookie('student_id', user.StudentID, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
  res.sendFile(path.join(__dirname, 'public', 'student.html'));
});

// --- Attendance API ---
app.post('/api/attend', ipWhitelistMiddleware, async (req, res) => {
  const { studentId, token } = req.body;
  const [rows] = await dbPool.execute(`SELECT * FROM verification ORDER BY ID DESC LIMIT 1`);
  if (req.cookies.attended) return res.status(401).json({ success: false, message: 'Your device already has an entry' });
  if (rows.length === 0 || !crypto.timingSafeEqual(Buffer.from(rows[0].token, 'utf8'), Buffer.from(token || '', 'utf8'))) {
    return res.status(401).json({ success: false, message: 'Invalid or missing token.' });
  }
  if (!studentId) return res.status(400).json({ success: false, message: 'Student ID is required.' });
  try {
    await dbPool.execute(`UPDATE records SET \`${new_column}\` = ? WHERE StudentID = ?`, [1, studentId]);
    res.cookie('attended', 1, {
      maxAge: 36 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production'
    });
    res.status(200).json({ success: true, message: 'Attendance recorded successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to record attendance. A database error occurred.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password, rememberMe } = req.body;
  try {
    const [rows] = await dbPool.execute(`SELECT * FROM users WHERE Email = ?`, [email]);
    if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    if (password == rows[0].Password) {
      req.session.email = email;
      req.session.name = rows[0].Name;
      req.session.user = 1;
      if (rememberMe) {
        const selector = crypto.randomBytes(16).toString('hex');
        const validator = crypto.randomBytes(32).toString('hex');
        const hashedValidator = await bcrypt.hash(validator, 10);
        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await dbPool.execute("INSERT INTO auth_tokens (selector, hashed_validator, email, expires) VALUES (?, ?, ?, ?)", [selector, hashedValidator, email, expires]);
        res.cookie('remember_me_token', `${selector}:${validator}`, { httpOnly: true, secure: true, expires });
      }
      res.status(200).json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'A database error occurred.' });
  }
});

app.post('/api/Qw7pZ9x2Vb1Lk8sJr4Tn6Yc3Mf5Hu0XoPq2Wv8Ez1Rt6Sb9Lm4Jk7Np3Vx5Yc2Tf8', async (req, res) => {
  const sectionValue = req.body.section;
  try {
    const [rows] = await dbPool.execute(`SELECT * FROM records WHERE Section = ?`, [sectionValue]);
    if (rows.length === 0) return res.status(404).json({ success: false, message: 'There is no data present' });
    const fields = Object.keys(rows[0] || {});
    const csvRows = [
      fields.join(','),
      ...rows.map(row => fields.map(f => `"${(row[f] ?? '').toString().replace(/"/g, '""')}"`).join(','))
    ];
    const csvContent = csvRows.join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="section_${sectionValue}.csv"`);
    res.status(200).send(csvContent);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to record attendance. A database error occurred.' });
  }
});

app.post('/api/attendance/stop', async (req, res) => {
  await dbPool.execute("UPDATE verification SET token = NULL WHERE date = ?", [new_column]);
  res.sendStatus(200);
});

app.post('/api/attendance/start', async (req, res) => {
  try {
    const randomString = crypto.randomBytes(32).toString('hex');
    await dbPool.execute("INSERT INTO verification (token, date) VALUES (?, ?)", [randomString, new_column]);
    const [columns] = await dbPool.execute(`
      SELECT * FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'records' AND COLUMN_NAME = ?
    `, [process.env.DB_DATABASE, new_column]);
    if (columns.length === 0) {
      console.log(`Adding new column: ${new_column}`);
      await dbPool.execute(`ALTER TABLE records ADD COLUMN \`${new_column}\` TINYINT DEFAULT 0`);
    }
    const url = `https://attain423.vercel.app/?token=${randomString}`;
    const qrCodeDataURL = await QRCode.toDataURL(url);
    res.send(`<img src="${qrCodeDataURL}">`);
  } catch (err) {
    res.status(500).send('Error generating QR code.');
  }
});

app.post('/api/submit_id', async (req, res) => {
  const {studentId} = req.body;
  console.log('Received Student ID:', studentId);
  if (!req.cookies || !req.cookies.remember_me_token) return res.status(401).json({ success: false, message: 'Not authenticated.' });
  const [selector, validator] = req.cookies.remember_me_token.split(':');
  if (!selector || !validator) return res.status(401).json({ success: false, message: 'Invalid token.' });
  const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);
  if (tokenRows.length === 0) return res.status(401).json({ success: false, message: 'Token not found.' });
  const authToken = tokenRows[0];
  const match = await bcrypt.compare(validator, authToken.hashed_validator);
  if (!match) return res.status(401).json({ success: false, message: 'Token mismatch.' });
  const [userRows] = await dbPool.execute('SELECT * FROM records WHERE StudentID = ?', [studentId]);
  if (userRows.length > 0) {
    return res.status(400).json({ success: false, message: 'This Student ID is already associated with another account. If you believe this is an error, please contact your faculty for assistance.' });
  }
  else if (userRows.length === 0) {
    return res.status(400).json({ success: false, message: 'No record was found for this Student ID in the attendance sheet. For further assistance, please contact your faculty.' });
  }
  await dbPool.execute(`UPDATE users SET StudentID = ? WHERE Email = ?`, [studentId, authToken.email]);
  return res.status(200).json({ success: true, message: 'Successfully submitted Student Id.' });
});

// --- 404 Handler ---
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <head>
        <title>404 Not Found</title>
        <style>
          body { background: #f9f6fd; color: #444; font-family: 'Segoe UI', 'Arial', sans-serif; text-align: center; padding: 60px; }
          .emoji { font-size: 5rem; margin-bottom: 20px; animation: bounce 1.2s infinite; }
          @keyframes bounce { 0%, 100% { transform: translateY(0);} 50% { transform: translateY(-20px);} }
          .title { font-size: 2.5rem; margin-bottom: 10px; color: #7c3aed; }
          .subtitle { font-size: 1.2rem; margin-bottom: 30px; }
          a { color: #7c3aed; text-decoration: none; font-weight: bold; transition: color 0.2s; }
          a:hover { color: #4f46e5; }
        </style>
      </head>
      <body>
        <div class="emoji">🐾</div>
        <div class="title">404 - Page Not Found</div>
        <div class="subtitle">Oops! Looks like you took a wrong turn.<br>
        Let's get you back <a href="/">home</a>!</div>
      </body>
    </html>
  `);
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running for local development on http://localhost:${PORT}`);
  });
}
