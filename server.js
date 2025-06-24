// server.js

// --- ADD THIS LINE AT THE VERY TOP ---
// This will load the variables from your .env file for local development
require('dotenv').config();
// 1. Import it
const cookieParser = require('cookie-parser');
const session = require('express-session');
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const QRCode = require('qrcode');
// 2. Initialize the App
const app = express();
const MySQLStore = require('express-mysql-session')(session);
app.use(cookieParser());
// At the top of server.js, with your other imports
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    ssl: { ca: process.env.DB_SSL_CA }
});

// 4. NOW, create the session store using the initialized dbPool
const sessionStore = new MySQLStore({}, dbPool);

// 1. Configure Express Session (place this with your other app.use() calls)
app.use(session({
    secret: process.env.SESSION_SECRET,
    // Connect session to our MySQL database store
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// 2. Initialize Passport and connect it to the session
app.use(passport.initialize());
app.use(passport.session());

// 3. Configure the Google Strategy for Passport
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
    // Note: `passReqToCallback` is not needed for this corrected logic.
  },
  async (accessToken, refreshToken, profile, done) => {
    // This function is called after the user successfully logs in with Google.
    // 'profile' contains the user's info (name, email, Google ID, etc.).
    const { id: googleId, displayName: name } = profile;
    const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
    if (!email) {
      return done(new Error("No email found in Google profile"), null);
    }

    try {
      // Check if user already exists
      let [rows] = await dbPool.execute(
        'SELECT * FROM users WHERE google_id = ? OR Email = ?',
        [googleId, email]
      );

      let user = rows[0];

      if (!user) {
        // Insert new user if they don't exist
        const [insertResult] = await dbPool.execute(
          'INSERT INTO users (Name, Email, google_id, Photo_url) VALUES (?, ?, ?, ?)',
          [name, email, googleId, profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null]
        );
        // We need the newly created user object, including the ID.
        [rows] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [insertResult.insertId]);
        user = rows[0];
      }
      
      // Pass the user object to the next step in the authentication flow.
      return done(null, user);

    } catch (err) {
      console.error('Error during Google user verification:', err);
      return done(err, null);
    }
  }
));

// This is a necessary step to manage the user's session.
// It stores the user ID in the session.
passport.serializeUser((user, done) => {
  done(null, user.id); 
});

// It retrieves the full user details from the database based on the ID in the session.
passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await dbPool.execute('SELECT * FROM users WHERE id = ?', [id]);
    done(null, rows[0]);
  } catch (err) {
    done(err, null);
  }
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }) // 'scope' asks for user's profile info and email
);
// 2. SETUP THE AUTHENTICATION ROUTE
// This is the correct place to handle the response, including setting cookies.
app.get('/auth/google/callback', 
  // This middleware triggers the Passport authentication flow.
  passport.authenticate('google', { 
    failureRedirect: '/login', // Redirect if authentication fails
    session: false // We are using a custom token, so we can disable sessions here if we want
  }),
  // This function executes only on successful authentication.
  async (req, res) => {
    // The authenticated user object is available on `req.user`.
    const user = req.user;

    try {
      // 1. Generate secure tokens
      const selector = crypto.randomBytes(16).toString('hex');
      const validator = crypto.randomBytes(32).toString('hex');
      const hashedValidator = await bcrypt.hash(validator, 10);

      // 2. Set expiry date (e.g., 30 days from now)
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

      // 3. Store in the database, linked to the user's email or ID
      // Check if a token already exists for this email
      const [existingTokens] = await dbPool.execute(
        "SELECT * FROM auth_tokens WHERE email = ?",
        [user.Email]
      );
      if (existingTokens.length > 0) {
        // Update the existing token
        const sql = "UPDATE auth_tokens SET selector = ?, hashed_validator = ?, expires = ? WHERE email = ?";
        await dbPool.execute(sql, [selector, hashedValidator, expires, user.Email]);
      } else {
        // Insert a new token
        const sql = "INSERT INTO auth_tokens (selector, hashed_validator, email, expires) VALUES (?, ?, ?, ?)";
        await dbPool.execute(sql, [selector, hashedValidator, user.Email, expires]);
      }

      // 4. Create and set the cookie on the response object
      // Set a cookie for the user's profile picture URL
      res.cookie('photo_url', user.Photo_url || '', {
          httpOnly: false, // Can be accessed by client-side JS if needed
          secure: process.env.NODE_ENV === 'production',
          expires: expires
      });
      res.cookie('remember_me_token', `${selector}:${validator}`, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
          expires: expires
      });
      // Set a separate cookie for the user's first name
      const firstName = user.Name ? user.Name.split(' ')[0] : '';
      res.cookie('name', firstName, {
          httpOnly: false, // Can be accessed by client-side JS if needed
          secure: process.env.NODE_ENV === 'production',
          expires: expires
      });

      // 5. Redirect the user to the desired page
      res.redirect('/student');

    } catch(err) {
      console.error('Error creating remember_me token:', err);
      res.redirect('/login?error=auth_failed');
    }
  }
);

// The IP address you want to allow
const ALLOWED_IP = '103.73.227.130'; // e.g., '203.0.113.42'


const ipWhitelistMiddleware = (req, res, next) => {
    // On platforms like Vercel, the real IP is in the 'x-forwarded-for' header.
    // req.ip should correctly handle this if 'trust proxy' is enabled (Vercel does this).
    // Get the IP address, handle possible IPv6 format, and extract IPv4 if present
    let requestIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (requestIp && requestIp.includes(',')) {
      // x-forwarded-for can be a comma-separated list
      requestIp = requestIp.split(',')[0].trim();
    }
    // If IPv6 format like "::ffff:192.168.0.115", extract IPv4 part
    if (requestIp && requestIp.startsWith('::ffff:')) {
      requestIp = requestIp.replace('::ffff:', '');
    }

    console.log(`Incoming request from IP: ${requestIp}`); // For debugging

    if (requestIp === ALLOWED_IP) {
        // IP matches, so continue to the actual route handler
        next();
    } else {
        // IP does not match, send a 'Forbidden' error
        res.status(403).json({ success: false, message: 'Access denied: This action can only be performed from an authorized network.' });
    }
};







// Vercel provides its own port, but we define one for local testing.
const PORT = process.env.PORT || 3000;

// 3. Set up Middleware

app.use(express.json());

// Set current date in dd-mm-yyyy format

const now = new Date();
const dd = String(now.getDate()).padStart(2, '0');
const mm = String(now.getMonth() + 1).padStart(2, '0');
const yyyy = now.getFullYear();
const new_column = `${dd}_${mm}_${yyyy}`;


app.get('/', async (req, res) => {
  const token = req.params.token;
  // If a token is provided as a query parameter, set it as a cookie (for QR code attendance flow)
  if (req.query && req.query.token) {
    res.cookie('token', req.query.token, {
      httpOnly: false, // Can be accessed by client-side JS if needed
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 60 * 1000 // 30 minutes
    });
  }
  // Check if the 'remember_me_token' cookie exists
  if (!req.cookies || !req.cookies.remember_me_token) {
    // If no cookie, just show the main page.
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }

  try {
    const [selector, validator] = req.cookies.remember_me_token.split(':');

    if (!selector || !validator) {
      // Malformed cookie, clear it and show the main page
      res.clearCookie('remember_me_token');
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    // 1. Find the token selector in the database
    const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);

    if (tokenRows.length === 0) {
      console.log('DEBUG: Remember-me selector not found in DB.');
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    const authToken = tokenRows[0];

    // 2. Check if the token has expired (CRITICAL SECURITY FIX)
    if (new Date(authToken.expires) < new Date()) {
      console.log('DEBUG: Remember-me token has expired.');
      // Clean up expired token from the database
      await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    // 3. Compare the cookie's validator with the hashed validator in the DB
    const dbHashedValidator = authToken.hashed_validator;
    const match = await bcrypt.compare(validator, dbHashedValidator);

    // Add this log to see the result of the comparison
    console.log(`DEBUG: bcrypt.compare result: ${match}`); 

    if (match) {
      // SUCCESS: Token is valid. Log the user in.
      const [userRows] = await dbPool.execute('SELECT * FROM users WHERE Email = ?', [authToken.email]);
      
      if (userRows.length > 0) {
          const user = userRows[0];
          // Assuming you are using express-session
          req.session.email = user.Email;
          req.session.name = user.Name;
          req.session.user = user.id; // Store user ID for consistency
          
          console.log(`DEBUG: User ${user.Email} authenticated via token. Redirecting...`);
          return res.redirect('/student');
      }
    }
    
    // If match is false, or user not found, fall through and show the main page.
    res.sendFile(path.join(__dirname, 'public', 'index.html'));

  } catch (err) {
    console.error("Error during 'remember me' authentication:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.get('/api/logout', async (req, res) => {
    req.session.destroy(async err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        } else {
            // Also clear any "remember me" cookie if you use one
            // Clear all relevant cookies
            res.clearCookie('remember_me_token', { path: '/', httpOnly: true, secure: true });
            res.clearCookie('name', { path: '/' });
            res.clearCookie('attended', { path: '/' });

            // Remove the auth_token from the database if present
            if (req.cookies && req.cookies.remember_me_token) {
              const [selector] = req.cookies.remember_me_token.split(':');
              if (selector) {
                try {
                  await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
                } catch (err) {
                  console.error('Error deleting auth_token during logout:', err);
                }
              }
            }

            res.redirect('/');
        }
    });
});


app.get('/admin/dashboard', async (req, res) => {
  // Check for remember_me_token cookie
  if (!req.cookies || !req.cookies.remember_me_token) {
    // No token, redirect to home
    return res.redirect('/');
  }

  try {
    const [selector, validator] = req.cookies.remember_me_token.split(':');
    if (!selector || !validator) {
      // Malformed cookie, clear all cookies and redirect
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    // Find token in DB
    const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);
    if (tokenRows.length === 0) {
      // Token not found, clear all cookies and redirect
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    const authToken = tokenRows[0];
    // Check expiry
    if (new Date(authToken.expires) < new Date()) {
      await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    // Compare validator
    const match = await bcrypt.compare(validator, authToken.hashed_validator);
    if (!match) {
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    // All good, serve admin.html
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  } catch (err) {
    res.clearCookie('remember_me_token');
    res.clearCookie('name');
    res.clearCookie('attended');
    res.redirect('/');
  }
});
app.get('/student', async(req, res) => {
  // Check for remember_me_token cookie
  if (!req.cookies || !req.cookies.remember_me_token) {
    // No token, redirect to home
    res.redirect('/');
    return;
  }

  try {
    const [selector, validator] = req.cookies.remember_me_token.split(':');
    if (!selector || !validator) {
      // Malformed cookie, clear all cookies and redirect
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    // Find token in DB
    const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);
    if (tokenRows.length === 0) {
      // Token not found, clear all cookies and redirect
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    const authToken = tokenRows[0];
    // Check expiry
    if (new Date(authToken.expires) < new Date()) {
      await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    // Compare validator
    const match = await bcrypt.compare(validator, authToken.hashed_validator);
    if (!match) {
      res.clearCookie('remember_me_token');
      res.clearCookie('name');
      res.clearCookie('attended');
      return res.redirect('/');
    }

    // All good, serve student.html
    const sql=`SELECT * FROM users WHERE Email = ?`;
    const [rows] = await dbPool.execute(sql, [authToken.email]);
    if (!rows[0] || rows[0].StudentID == null) {
      // If the student ID is not set, show the ID submission page
      return res.sendFile(path.join(__dirname, 'public', 'id_submission.html'));
    }
    res.sendFile(path.join(__dirname, 'public', 'student.html'));
  } catch (err) {
    res.clearCookie('remember_me_token');
    res.clearCookie('name');
    res.clearCookie('attended');
    res.redirect('/');
  }
});

// API ROUTE FOR ATTENDANCE
app.post('/api/attend', ipWhitelistMiddleware, async (req, res) => {
    const { studentId, token } = req.body;
    const sql = `SELECT * FROM verification ORDER BY ID DESC LIMIT 1`;
    const [rows] = await dbPool.execute(sql);
    // Check if token exists and matches the latest generated token (crypto-generated)
    if (req.cookies.attended){
      return res.status(401).json({ success: false, message: 'Your device already has an entry' });
    }
    if (rows.length === 0 || !crypto.timingSafeEqual(Buffer.from(rows[0].token, 'utf8'), Buffer.from(token || '', 'utf8'))) {
      return res.status(401).json({ success: false, message: 'Invalid or missing token.' });
    }
    if (!studentId) {
        return res.status(400).json({ success: false, message: 'Student ID is required.' });
    }

    try {
  
        const sql = `UPDATE records SET ${new_column} = ? WHERE ID = ?`;
        const attendanceStatus = 1;
        
        await dbPool.execute(sql, [attendanceStatus, studentId]);
        
        // Set a cookie named "attendance" with value 1, expires in 1.5 days (36 hours)
        res.cookie('attended', 1, {
            maxAge: 36 * 60 * 60 * 1000, // 36 hours in milliseconds
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        });
        res.status(200).json({ success: true, message: 'Attendance recorded successfully!' });

    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ success: false, message: 'Failed to record attendance. A database error occurred.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password, rememberMe } = req.body;
     // Store email in session for later use
    
   try {
      const sql = `SELECT * FROM users WHERE Email = ?`;
      const [rows] = await dbPool.execute(sql, [email]);
      if (rows.length === 0) {
        return res.status(401).json({ success: false, message: 'Invalid email or password.' });
      }
      const dbHashedPassword = rows[0].Password;
      

      //const match = await bcrypt.compare(password, dbHashedPassword);
      if (password==dbHashedPassword) {
        req.session.email = email;
        req.session.name = rows[0].Name;
        req.session.user=1; // Store user ID in session for later use
        if (rememberMe){
          const selector = crypto.randomBytes(16).toString('hex');
          const validator = crypto.randomBytes(32).toString('hex');
          const hashedValidator = await bcrypt.hash(validator, 10);

          // 2. Set expiry date (e.g., 30 days from now)
          const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

          // 3. Store in database
          const sql = "INSERT INTO auth_tokens (selector, hashed_validator, email, expires) VALUES (?, ?, ?, ?)";
          await dbPool.execute(sql, [selector, hashedValidator, email, expires]);

          // 4. Create and set the cookie
          res.cookie('remember_me_token', `${selector}:${validator}`, {
              httpOnly: true,
              secure: true, // In production
              expires: expires // Use the same expiry date
          });
        }
      res.status(200).json({ success: true, message: 'Login successful' });

      } else {
        res.status(401).json({ success: false, message: 'Invalid email or password.' });
      }
     
   }
   catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ success: false, message: ' A database error occurred.' });
    }

  });
  app.post('/api/Qw7pZ9x2Vb1Lk8sJr4Tn6Yc3Mf5Hu0XoPq2Wv8Ez1Rt6Sb9Lm4Jk7Np3Vx5Yc2Tf8', async (req, res) => {
    const section= req.body;
  try {
    // The client sends { section: "A" } (for example), so extract the value
    const sectionValue = section.section;
    const sql = `SELECT * FROM records WHERE Section = ?`;
    const [rows] = await dbPool.execute(sql, [sectionValue]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'There is no data present' });
    }

    // Convert rows to CSV
    const fields = Object.keys(rows[0] || {});
    const csvRows = [
      fields.join(','), // header
      ...rows.map(row => fields.map(f => `"${(row[f] ?? '').toString().replace(/"/g, '""')}"`).join(','))
    ];
    const csvContent = csvRows.join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="section_${sectionValue}.csv"`);
    res.status(200).send(csvContent);
  }
  catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ success: false, message: 'Failed to record attendance. A database error occurred.' });
  }

  });

app.post('/api/attendance/stop', async (req, res) => {

      const randomString = null;
      const trial = `SELECT * FROM verification ORDER BY ID DESC LIMIT 1`;
      const [rows] = await dbPool.execute(trial);
      const sql = "INSERT INTO verification (token, date) VALUES (?, ?)";
      await dbPool.execute(sql, [randomString, new_column]);

});

  app.post('/api/attendance/start', async (req, res) => {
    
    try {
      // Generate a random 64-character string
      const randomString = crypto.randomBytes(32).toString('hex');
      const trial = `SELECT * FROM verification ORDER BY ID DESC LIMIT 1`;
      const [rows] = await dbPool.execute(trial);
      const sql = "INSERT INTO verification (token, date) VALUES (?, ?)";
      await dbPool.execute(sql, [randomString, new_column]);

      // Add a new column to the records table with the name from the variable "new_column"
      // Check if the column already exists
      
      // 1. SQL to check if the column already exists in the 'records' table
        const checkColumnSql = `
          SELECT * FROM INFORMATION_SCHEMA.COLUMNS
          WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'records' AND COLUMN_NAME = ?
        `;

        // 2. Execute the check. 'process.env.DB_DATABASE' gets your database name from your .env file
        const [columns] = await dbPool.execute(checkColumnSql, [process.env.DB_DATABASE, new_column]);

        // 3. If the query returns 0 rows, the column does not exist, so we add it.
        if (columns.length === 0) {
          console.log(`Column ${new_column} does not exist. Adding it...`);
          const alterSql = `ALTER TABLE records ADD COLUMN \`${new_column}\` INT DEFAULT 0`;
          await dbPool.execute(alterSql);
        } else {
          console.log(`Column ${new_column} already exists. Skipping.`);
        }
      // Append it as a query parameter to the URL
      const url = `https://attain423.vercel.app/?token=${randomString}`;

      // Generate QR code as a Data URL string
      const qrCodeDataURL = await QRCode.toDataURL(url);
      
      // Send an HTML response that displays the QR code
      res.send(`<img src="${qrCodeDataURL}">`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating QR code.');
  }
  });
app.post('/api/submit_id', async(req,res)=>{
  const { studentId, token } = req.body;
  // Set a cookie for studentId, expires in 30 days
  res.cookie('student_id', studentId, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
  });

  // Get the selector and validator from the remember_me_token cookie
  if (!req.cookies || !req.cookies.remember_me_token) {
    return res.status(401).json({ success: false, message: 'Not authenticated.' });
  }
  const [selector, validator] = req.cookies.remember_me_token.split(':');
  if (!selector || !validator) {
    return res.status(401).json({ success: false, message: 'Invalid token.' });
  }
  // Find token in DB
  const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);
  if (tokenRows.length === 0) {
    return res.status(401).json({ success: false, message: 'Token not found.' });
  }
  const authToken = tokenRows[0];
  // Compare validator
  const match = await bcrypt.compare(validator, authToken.hashed_validator);
  if (!match) {
    return res.status(401).json({ success: false, message: 'Token mismatch.' });
  }
  // Use the email from the token
  const email = authToken.email;
  // Update the user's StudentID where the email matches
  const updateSql = `UPDATE users SET StudentID = ? WHERE Email = ?`;
  await dbPool.execute(updateSql, [studentId, email]);


  return res.status(200).json({ success: true, message: 'Token not found.' });; // Redirect to the student page with the studentId as a query parameter

});

// Catch-all for undefined routes (404 handler)
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <head>
        <title>404 Not Found</title>
        <style>
          body {
            background: #f9f6fd;
            color: #444;
            font-family: 'Segoe UI', 'Arial', sans-serif;
            text-align: center;
            padding: 60px;
          }
          .emoji {
            font-size: 5rem;
            margin-bottom: 20px;
            animation: bounce 1.2s infinite;
          }
          @keyframes bounce {
            0%, 100% { transform: translateY(0);}
            50% { transform: translateY(-20px);}
          }
          .title {
            font-size: 2.5rem;
            margin-bottom: 10px;
            color: #7c3aed;
          }
          .subtitle {
            font-size: 1.2rem;
            margin-bottom: 30px;
          }
          a {
            color: #7c3aed;
            text-decoration: none;
            font-weight: bold;
            transition: color 0.2s;
          }
          a:hover {
            color: #4f46e5;
          }
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
