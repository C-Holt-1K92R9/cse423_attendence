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
// 2. Initialize the App
const app = express();

app.use(cookieParser());
// Vercel provides its own port, but we define one for local testing.
const PORT = process.env.PORT || 3000;
app.use(session({
    // This 'secret' is used to sign the session ID cookie.
    // It should be a long, random string stored in your .env file for security.
    secret: process.env.SESSION_SECRET || 'a-default-secret-for-development',

    // These two options are recommended for best practices.
    resave: false,
    saveUninitialized: false,

    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        maxAge: 24 * 60 * 60 * 1000 // Cookie expires in 24 hours
    }
}));
// --- DATABASE CONNECTION SETUP FROM ENVIRONMENT VARIABLES ---
// Securely reads connection details from process.env (from .env locally, or Vercel settings when deployed)
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    // SSL is configured from an environment variable instead of a file.
    ssl: {
        ca: process.env.DB_SSL_CA,
    }
});


// 3. Set up Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/login', async (req, res) => {
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


app.get('/admin/dashboard', (req, res) => {
  if (!(req.session && req.session.user)) {
        return res.redirect('/');
    }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
// 4. Define Routes
// This route serves the main page.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API ROUTE FOR ATTENDANCE
app.post('/api/attend', async (req, res) => {
    const { studentId } = req.body;

    if (!studentId) {
        return res.status(400).json({ success: false, message: 'Student ID is required.' });
    }

    try {
        const attendanceColumn = 'attendance';
        const sql = `UPDATE records SET ${attendanceColumn} = ? WHERE ID = ?`;
        const attendanceStatus = 1;
        
        await dbPool.execute(sql, [attendanceStatus, studentId]);
        
        console.log(`Attendance recorded for student ID: ${studentId} with status: ${attendanceStatus}`);
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


module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running for local development on http://localhost:${PORT}`);
  });
}
