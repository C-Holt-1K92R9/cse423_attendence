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



// The IP address you want to allow
const ALLOWED_IP = '103.55.146.25'; // e.g., '203.0.113.42'


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

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    // This function runs after a user successfully authenticates with Google.
    // It finds an existing user or creates a new one in your database.
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;
    try {
        let [rows] = await dbPool.execute('SELECT * FROM users WHERE google_id = ?', [googleId]);
        if (rows.length > 0) {
            // User already exists
            return done(null, rows[0]);
        } else {
            // New user, create them
            if (email.split('@')[1] !== 'g.bracu.ac.bd') {
            await dbPool.execute('INSERT INTO users (google_id, Email, Name) VALUES (?, ?, ?)', [googleId, email, name]);
            let [newUserRows] = await dbPool.execute('SELECT * FROM users WHERE google_id = ?', [googleId]);
            return done(null, newUserRows[0]);
          }
            else {
                return done(null, false, { message: 'You are not allowed to login with this email. You must use your G-Suit email provided by BRAC University.' });
            }
        }
    } catch (error) {
        return done(error);
    }
  }
));
// 4. Tell Passport how to save and retrieve a user from the session
passport.serializeUser((user, done) => {
    // Save a minimal amount of user info (e.g., the user ID) to the session.
    done(null, user.id); // In a real app, you'd use your database user ID
});

passport.deserializeUser((id, done) => {
    // Retrieve the full user details from the session ID.
    // In a real app, you'd fetch this from your database using the id.
    // For this example, we'll just pass a simple object.
    done(null, { id: id }); // Replace with a call to your database
});
// Route to start the Google login process
// When a user clicks a "Login with Google" button, they should be sent to this URL.
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }) // 'scope' asks for user's profile info and email
);

// The callback route that Google redirects to after the user approves the login
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }), // If login fails, redirect to /login
  async(req, res) => {
    // Successful authentication, redirect to the dashboard.
           const selector = crypto.randomBytes(16).toString('hex');
          const validator = crypto.randomBytes(32).toString('hex');
          const hashedValidator = await bcrypt.hash(validator, 10);

          // 2. Set expiry date (e.g., 30 days from now)
          const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

          // 3. Store in database
          const sql = "INSERT INTO auth_tokens (selector, hashed_validator, user_id, expires) VALUES (?, ?, ?, ?)";
          await dbPool.execute(sql, [selector, hashedValidator, email, expires]);

          // 4. Create and set the cookie
          res.cookie('remember_me_token', `${selector}:${validator}`, {
              httpOnly: true,
              secure: true, // In production
              expires: expires // Use the same expiry date
          });
    res.redirect('/student');
  }
);




app.use(cookieParser());
// Vercel provides its own port, but we define one for local testing.
const PORT = process.env.PORT || 3000;
// --- DATABASE CONNECTION SETUP FROM ENVIRONMENT VARIABLES ---
// Securely reads connection details from process.env (from .env locally, or Vercel settings when deployed)



// 3. Set up Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Set current date in dd-mm-yyyy format

    const now = new Date();
    const dd = String(now.getDate()).padStart(2, '0');
    const mm = String(now.getMonth() + 1).padStart(2, '0');
    const yyyy = now.getFullYear();
    const new_column = `${dd}_${mm}_${yyyy}`;

app.get('/', async (req, res) => {
  if (req.cookies && req.cookies.remember_me_token) {
    const sql = `SELECT * FROM auth_tokens WHERE selector = ?`;
    const selector = req.cookies.remember_me_token.split(':')[0];
    const [rows] = await dbPool.execute(sql, [selector]);
    if (rows.length === 0) {
      return res.status(401).send('Invalid remember me token.');
    }
    const dbHashedValidator = rows[0].hashed_validator;
    const validator = req.cookies.remember_me_token.split(':')[1];
    const match = await bcrypt.compare(validator, dbHashedValidator);
    if (match) {
        req.session.email = rows[0].user_id;
        const sql = `SELECT * FROM users WHERE Email = ?`;
        const [rows2] = await dbPool.execute(sql, [rows[0].user_id]);
        req.session.name = rows2[0].Name;
        req.session.user=1;
      return res.redirect('/admin/dashboard');
    }
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
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
          const sql = "INSERT INTO auth_tokens (selector, hashed_validator, user_id, expires) VALUES (?, ?, ?, ?)";
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

app.get('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        } else {
            // Also clear any "remember me" cookie if you use one
            res.clearCookie('remember_me_token', { path: '/', httpOnly: true, secure: true });
            res.redirect('/login');
        }
    });
});


app.get('/admin/dashboard', async(req, res) => {
  if (req.cookies && req.cookies.remember_me_token) {
    const sql = `SELECT * FROM auth_tokens WHERE selector = ?`;
    const selector = req.cookies.remember_me_token.split(':')[0];
    const [rows] = await dbPool.execute(sql, [selector]);
    if (rows.length === 0) {
      return res.status(401).send('Invalid remember me token.');
    }
    const dbHashedValidator = rows[0].hashed_validator;
    const validator = req.cookies.remember_me_token.split(':')[1];
    const match = await bcrypt.compare(validator, dbHashedValidator);
    if (match) {
        req.session.email = rows[0].user_id;
        const sql = `SELECT * FROM users WHERE Email = ?`;
        const [rows2] = await dbPool.execute(sql, [rows[0].user_id]);
        req.session.name = rows2[0].Name;
        req.session.user=1;
         res.sendFile(path.join(__dirname, 'public', 'admin.html'));
      
    }
  }
 return res.redirect('/');
});

app.get('/student', async(req, res) => {
  if (req.cookies && req.cookies.remember_me_token) {
    const sql = `SELECT * FROM auth_tokens WHERE selector = ?`;
    const selector = req.cookies.remember_me_token.split(':')[0];
    const [rows] = await dbPool.execute(sql, [selector]);
    if (rows.length === 0) {
      return res.status(401).send('Invalid remember me token.');
    }
    const dbHashedValidator = rows[0].hashed_validator;
    const validator = req.cookies.remember_me_token.split(':')[1];
    const match = await bcrypt.compare(validator, dbHashedValidator);
    if (match) {
        req.session.email = rows[0].user_id;
        const sql = `SELECT * FROM users WHERE Email = ?`;
        const [rows2] = await dbPool.execute(sql, [rows[0].user_id]);
        req.session.name = rows2[0].Name;
        req.session.user=1;
      res.sendFile(path.join(__dirname, 'public', 'student.html'));
    }
  }
  return res.redirect('/');
  
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
  app.post('/api/attendance/start', async (req, res) => {
    
    try {
      // Generate a random 64-character string
      const randomString = crypto.randomBytes(32).toString('hex');
      const trial = `SELECT * FROM verification ORDER BY ID DESC LIMIT 1`;
      const [rows] = await dbPool.execute(trial);
      const sql = "INSERT INTO verification (token, date) VALUES (?, ?)";
      await dbPool.execute(sql, [randomString, new_column]);

      // Add a new column to the records table with the name from the variable "new_column"
      const alterSql = `ALTER TABLE records ADD COLUMN \`${new_column}\` INT DEFAULT 0`;
      dbPool.execute(alterSql).catch(() => {});
      // Append it as a query parameter to the URL
      const url = `http://192.168.0.112:3000?token=${randomString}`;

      // Generate QR code as a Data URL string
      const qrCodeDataURL = await QRCode.toDataURL(url);
      
      // Send an HTML response that displays the QR code
      res.send(`<img src="${qrCodeDataURL}">`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating QR code.');
  }
  });


module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running for local development on http://localhost:${PORT}`);
  });
}
