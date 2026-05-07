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
const fileUpload = require('express-fileupload');

const app = express();
const PORT = process.env.PORT || 3000;

// Validate required environment variables
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_DATABASE', 'SESSION_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.warn('Missing environment variables:', missingEnvVars.join(', '));
}

// Create database pool with error handling (non-blocking)
const dbPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_DATABASE || 'attendance',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
  enableKeepAlive: true
});

// Handle database pool errors (non-blocking)
dbPool.on('error', (err) => {
  console.error('Database pool error:', err.message);
});

const sessionStore = new MySQLStore({}, dbPool);

app.use(cookieParser());
app.use(express.json());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
const sessionSecret = process.env.SESSION_SECRET || 'development-secret-key-change-in-production';
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set in production. Using default key. Please set SESSION_SECRET environment variable on Vercel!');
}

app.use(session({
  secret: sessionSecret,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Diagnostic health check endpoint
app.get('/api/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  };

  // Check environment variables
  const envCheck = {};
  requiredEnvVars.forEach(envVar => {
    envCheck[envVar] = !!process.env[envVar];
  });
  health.environmentVariables = envCheck;

  // Check database connection
  try {
    const connection = await dbPool.getConnection();
    health.database = { connected: true };
    connection.release();
  } catch (err) {
    health.database = { connected: false, error: err.message };
    health.status = 'warning';
  }

  const statusCode = health.status === 'ok' ? 200 : 503;
  res.status(statusCode).json(health);
});

// 404 and error handlers before other routes
app.use((req, res, next) => {
  res.status(404).json({ success: false, message: 'Route not found', path: req.path });
});

// --- Helper Functions ---
const clearAuthCookies = (res) => {
  res.clearCookie('remember_me_token', { path: '/' });
  res.clearCookie('name', { path: '/' });
  res.clearCookie('photo_url', { path: '/' });
  res.clearCookie('student_id', { path: '/' });
  res.clearCookie('token', { path: '/' });
  res.clearCookie('session', { path: '/' });
};

const getRememberMeUser = async (cookies) => {
  try {
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
  } catch (error) {
    console.error('Error in getRememberMeUser:', error);
    return null;
  }
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
let requestIp;
let isp = null;
const ipWhitelistMiddleware = async (req, res, next) => {
  requestIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (requestIp && requestIp.includes(',')) requestIp = requestIp.split(',')[0].trim();
  if (requestIp && requestIp.startsWith('::ffff:')) requestIp = requestIp.replace('::ffff:', '');

  try {
    const https = require('https');

    // Use ipinfo.io to get ISP info
    https.get(`https://ipinfo.io/${requestIp}/json`, (res2) => {
      let data2 = '';
      res2.on('data', chunk => data2 += chunk);
      res2.on('end', () => {
        try {
          const info = JSON.parse(data2);
          
          if (info.org) {
            // org is usually like "AS15169 Google LLC"
            isp = info.org.split(' ').slice(1).join(' ');
            console.log('IP Address:', requestIp);
            console.log('ISP Provider:', isp);
          } else {
            console.log('IP Address:', requestIp);
            console.log('ISP info not found.');
          } 
          const allowedIsp = process.env.ALLOWED_ISP_NAME;
          if (isp && isp.toLowerCase().includes(allowedIsp.toLowerCase())) {
            return next();
          } 
          else {
            return res.status(403).json({ success: false, message: 'Access denied: This action can only be performed from an authorized network.' });
          }
        } catch (parseErr) {
          return res.status(403).json({ success: false, message: 'Access denied: Unable to verify ISP.' });
        }
      });
    }).on('error', err => {
      console.error('Error fetching ISP info:', err.message);
      return res.status(403).json({ success: false, message: 'Access denied: Unable to verify your network provider. Please contact your administrator if you believe this is an error.' });
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
      res.cookie('photo_url', user.Photo_url || '', { httpOnly: false, 
      secure: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/' });
      res.cookie('remember_me_token', `${selector}:${validator}`, { httpOnly: false, 
      secure: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/' });
      res.cookie('name', user.Name ? user.Name.split(' ')[0] : '', { httpOnly: false, 
      secure: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/' });
      res.cookie('student_id', user.StudentID || '', { 
      httpOnly: false, 
      secure: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/'
      });
      
      // Set session variables
      req.session.email = user.Email;
      req.session.name = user.Name;
      req.session.user = user.id;
            
      return res.redirect(user.type === 0 ? '/student' : '/admin/dashboard');

    } catch (err) {
      console.error('Google auth error:', err);
      return res.redirect('/?error=auth_failed');
    }
  }
);
app.get('/manual', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'manual.html')); 
});


app.get('/', async (req, res) => {
  console.log('Root route accessed');
  try {
    if (req.query && req.query.token) {
      res.cookie('token', req.query.token, {
        httpOnly: false, 
        secure: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
      });
    }
    
    // Check if user has active session

    console.log('Session user ID:', req.session.user);
    if (req.session && req.session.user) {
      
      const [userRows] = await dbPool.execute('SELECT type FROM users WHERE id = ?', [req.session.user]);
      if (userRows.length > 0) {
        return userRows[0].type === 0 ? res.redirect('/student') : res.redirect('/admin/dashboard');
      }
    }
    
    // Check for remember me cookie
    const user = await getRememberMeUser(req.cookies);
    if (!user) return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    
    req.session.email = user.Email;
    req.session.name = user.Name;
    req.session.user = user.id;

    return user.type === 0 ? res.redirect('/student') : res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('Root route error:', error);
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.get('/register', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/profile', async (req, res) => {
  const user = await getRememberMeUser(req.cookies);
  if (!user) {
    clearAuthCookies(res);
    return res.redirect('/');
  }
  return res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/api/profile', async (req, res) => {
  try {
    const user = await getRememberMeUser(req.cookies);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    res.json({
      id: user.id,
      Name: user.Name,
      Email: user.Email,
      StudentID: user.StudentID || null,
      type: user.type,
      Photo_url: user.Photo_url
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ success: false, message: 'Error fetching profile' });
  }
});

app.post('/api/profile/update', async (req, res) => {
  try {
    const user = await getRememberMeUser(req.cookies);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const { fullname, currentPassword, newPassword } = req.body;

    // Validation
    if (!fullname || !fullname.trim()) {
      return res.status(400).json({ success: false, message: 'Full name is required.' });
    }

    // If password change is requested, verify current password
    if (currentPassword && newPassword) {
      const [userRows] = await dbPool.execute('SELECT Password FROM users WHERE id = ?', [user.id]);
      if (userRows.length === 0) {
        return res.status(404).json({ success: false, message: 'User not found.' });
      }

      const passwordMatch = await bcrypt.compare(currentPassword, userRows[0].Password);
      if (!passwordMatch) {
        return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long.' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      await dbPool.execute('UPDATE users SET Name = ?, Password = ? WHERE id = ?', [fullname.trim(), hashedNewPassword, user.id]);
    } else {
      // Just update name
      await dbPool.execute('UPDATE users SET Name = ? WHERE id = ?', [fullname.trim(), user.id]);
    }

    res.json({ success: true, message: 'Profile updated successfully.' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, message: 'Error updating profile.' });
  }
});

app.get('/api/logout', async (req, res) => {
  req.session.destroy(async err => {
    clearAuthCookies(res);
    if (req.cookies && req.cookies.remember_me_token) {
      const [selector] = req.cookies.remember_me_token.split(':');
      if (selector) await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
    }
    return res.redirect('/');
  });
});

app.get('/admin/dashboard', async (req, res) => {
  const user = await getRememberMeUser(req.cookies);
  if (!user) {
    clearAuthCookies(res);
    return res.redirect('/');
  }
  return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.post('/api/students/reset-id', async (req, res) => {
  const { email } = req.body;
  await dbPool.execute('UPDATE users SET StudentID = NULL WHERE Email = ?', [email]);
  res.status(200).json({ success: true, message: 'Student ID reset successfully.' });
});

app.get('/student', async (req, res) => {
   const user = await getRememberMeUser(req.cookies);
   if (!user) {
     clearAuthCookies(res);
      return res.redirect('/');
}
 if (!user.StudentID) {
    return res.sendFile(path.join(__dirname, 'public', 'id_submission.html'));
  }
  
  
  return res.sendFile(path.join(__dirname, 'public', 'student.html'));
});

// --- Attendance API ---
app.post('/api/attend', ipWhitelistMiddleware, async (req, res) => {
  const { studentId, token } = req.body;
  await dbPool.execute('INSERT INTO student_response (StudentID, ip, isp) VALUES (?, ?, ?)', [studentId, requestIp, isp]);
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
    
    // Use bcrypt.compare for password verification
    const passwordMatch = await bcrypt.compare(password, rows[0].Password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }
    
    req.session.email = email;
    req.session.name = rows[0].Name;
    req.session.user = rows[0].id;
    
    if (rememberMe) {
      const selector = crypto.randomBytes(16).toString('hex');
      const validator = crypto.randomBytes(32).toString('hex');
      const hashedValidator = await bcrypt.hash(validator, 10);
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const [existingTokens] = await dbPool.execute("SELECT * FROM auth_tokens WHERE email = ?", [email]);
      if (existingTokens.length > 0) {
        await dbPool.execute("UPDATE auth_tokens SET selector = ?, hashed_validator = ?, expires = ? WHERE email = ?", [selector, hashedValidator, expires, email]);
      } else {
        await dbPool.execute("INSERT INTO auth_tokens (selector, hashed_validator, email, expires) VALUES (?, ?, ?, ?)", [selector, hashedValidator, email, expires]);
      }
      res.cookie('remember_me_token', `${selector}:${validator}`, { httpOnly: true, secure: true, expires });
    }
    res.status(200).json({ success: true, message: 'Login successful', type: rows[0].type });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'A database error occurred.' });
  }
});

app.post('/api/register', async (req, res) => {
  const { fullname, email, student_id, password } = req.body;
  try {
    // Validation
    if (!fullname || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
    }

    // Check if email already exists
    const [existingEmailUsers] = await dbPool.execute(`SELECT * FROM users WHERE Email = ?`, [email]);
    if (existingEmailUsers.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }

    // Check if student ID already exists (only for student domain)
    if (student_id) {
      const [existingStudentIds] = await dbPool.execute(`SELECT * FROM users WHERE StudentID = ?`, [student_id]);
      if (existingStudentIds.length > 0) {
        return res.status(400).json({ success: false, message: 'Student ID already registered.' });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user based on email domain
    const domain = email.split('@')[1];
    if (domain === 'g.bracu.ac.bd') {
      // Student domain - requires StudentID
      if (!student_id) {
        return res.status(400).json({ success: false, message: 'Student ID is required for student accounts.' });
      }
      await dbPool.execute(
        `INSERT INTO users (Email, Password, Name, StudentID, type) VALUES (?, ?, ?, ?, ?)`,
        [email, hashedPassword, fullname, student_id, 0]
      );
    } else if (domain === 'bracu.ac.bd') {
      // Faculty domain - no StudentID required
      await dbPool.execute(
        `INSERT INTO users (Email, Password, Name, type) VALUES (?, ?, ?, ?)`,
        [email, hashedPassword, fullname, 1]
      );
    } else {
      return res.status(400).json({ success: false, message: 'Only @bracu.ac.bd and @g.bracu.ac.bd emails are allowed.' });
    }

    res.status(201).json({ success: true, message: 'Account created successfully.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'A database error occurred during registration.' });
  }
});

app.post('/api/download_report', async (req, res) => {
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
      
      await dbPool.execute(`ALTER TABLE records ADD COLUMN \`${new_column}\` TINYINT DEFAULT 0`);
      await dbPool.execute(`INSERT IGNORE INTO history (history_dates) VALUES (?)`, [new_column]);
      
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
  if (!req.cookies || !req.cookies.remember_me_token) return res.status(401).json({ success: false, message: 'Not authenticated.' });
  const [selector, validator] = req.cookies.remember_me_token.split(':');
  if (!selector || !validator) return res.status(401).json({ success: false, message: 'Invalid token.' });
  const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);
  if (tokenRows.length === 0) return res.status(401).json({ success: false, message: 'Token not found.' });
  const authToken = tokenRows[0];
  const match = await bcrypt.compare(validator, authToken.hashed_validator);
  if (!match) return res.status(401).json({ success: false, message: 'Token mismatch.' });
  const [userRows] = await dbPool.execute('SELECT * FROM records WHERE StudentID = ?', [studentId]);
  const [userRows2] = await dbPool.execute('SELECT * FROM users WHERE StudentID = ?', [studentId]);
  if (userRows.length > 0 && userRows2.length > 0) {
    return res.status(400).json({ success: false, message: 'This Student ID is already associated with another account. If you believe this is an error, please contact your faculty for assistance.' });
  }
  else if (userRows.length === 0) {
    return res.status(400).json({ success: false, message: 'No record was found for this Student ID in the attendance sheet. For further assistance, please contact your faculty.' });
  }
  await dbPool.execute(`UPDATE users SET StudentID = ? WHERE Email = ?`, [studentId, authToken.email]);

  res.cookie('student_id', studentId|| '', { 
      httpOnly: false, 
      secure: true, // This will be true on Vercel
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/' // Makes the cookie work everywhere on your site
    });
  return res.status(200).json({ success: true, message: 'Successfully submitted Student Id.' });
});
app.post('/api/attendance/manual/present', async (req, res) => {
  const { student_id } = req.body;
  if (!student_id) return res.status(400).json({ success: false, message: 'Student ID is required.' });
  try {
    const [rows] = await dbPool.execute(`SELECT * FROM records WHERE StudentID = ?`, [student_id]);
    if (rows.length === 0) return res.status(404).json({ success: false, message: 'No record found for this Student ID.' });
    if (rows[0][new_column] === 1) return res.status(400).json({ success: false, message: 'Attendance for this student has already been recorded for today.' });
    await dbPool.execute(`UPDATE records SET \`${new_column}\` = ? WHERE StudentID = ?`, [1, student_id]);
    return res.status(200).json({ success: true, message: 'Attendance recorded successfully!' });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to record attendance. Either todays attendence haven\'t been initiated or a database error occurred.' });
  }
});
app.post('/api/attendance/manual/absent', async (req, res) => {
  const { student_id } = req.body;
  if (!student_id) return res.status(400).json({ success: false, message: 'Student ID is required.' });
  try {
    const [rows] = await dbPool.execute(`SELECT * FROM records WHERE StudentID = ?`, [student_id]);
    if (rows.length === 0) return res.status(404).json({ success: false, message: 'No record found for this Student ID.' });
    await dbPool.execute(`UPDATE records SET \`${new_column}\` = ? WHERE StudentID = ?`, [0, student_id]);
    return res.status(200).json({ success: true, message: 'Attendance removed successfully!' });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to record attendance. Either todays attendence haven\'t been initiated or a database error occurred.' });
  }
});

app.post('/api/students/add', async(req, res)=>{
  const { student_id, name, email, course_code, section } = req.body;
  try {
    await dbPool.query(
      'INSERT IGNORE INTO records (StudentID, Name, Email, Course, Section) VALUES (?, ?, ?, ?, ?)',
      [student_id, name, email, course_code, section]
    );
    return res.status(200).json({ success: true, message: 'Student added successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Database error while adding student.' });
  }


});


app.post('/api/students/add-csv', async (req, res) => {
  if (!req.files || !req.files.csv_file) {
    return res.status(400).json({ success: false, message: 'CSV file is required.' });
  }
  const csvData = req.files.csv_file.data.toString('utf8');
  if (!csvData) {
    return res.status(400).json({ success: false, message: 'CSV data is required.' });
  }

  // Parse CSV (assume first row is header)
  const rows = csvData
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);

  if (rows.length < 2) {
    return res.status(400).json({ success: false, message: 'CSV must have at least one data row.' });
  }

  // Expecting: student_id, name, email, course_code, section
  const headers = rows[0].split(',').map(h => h.trim().toLowerCase());
  const requiredFields = ['student_id', 'name', 'email', 'course_code', 'section'];
  for (const field of requiredFields) {
    if (!headers.includes(field)) {
      return res.status(400).json({ success: false, message: `Missing required column: ${field}` });
    }
  }

  const idxStudentId = headers.indexOf('student_id');
  const idxName = headers.indexOf('name');
  const idxEmail = headers.indexOf('email');
  const idxCourse = headers.indexOf('course_code');
  const idxSection = headers.indexOf('section');

  const insertRows = [];
  for (let i = 1; i < rows.length; i++) {
    const values = rows[i].split(',').map(v => v.trim().replace(/^"|"$/g, ''));
    const studentId = values[idxStudentId] || '';
    const name = values[idxName] || '';
    const email = values[idxEmail] || '';
    const course = values[idxCourse] || '';
    const section = values[idxSection] || '';
    if (studentId && name && email && course && section) {
      insertRows.push([studentId, name, email, course, section]);
    }
  }

  if (insertRows.length === 0) {
    return res.status(400).json({ success: false, message: 'No valid student records found in CSV.' });
  }

  try {
    // Insert or ignore duplicates based on StudentID
    await dbPool.query(
      'INSERT IGNORE INTO records (StudentID, Name, Email, Course, Section) VALUES ?',
      [insertRows]
    );
    return res.status(200).json({ success: true, message: `${insertRows.length} students added.` });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Database error while adding students.' });
  }
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

// Export app for Vercel
module.exports = app;

if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });

  // Handle server errors
  server.on('error', (err) => {
    console.error('Server error:', err);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    server.close(() => {
      console.log('Server closed');
      process.exit(0);
    });
  });
}

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
