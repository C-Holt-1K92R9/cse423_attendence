// server.js

// 1. Import Dependencies
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
// We no longer need the 'fs' module because the certificate will be in an environment variable.

// 2. Initialize the App
const app = express();
// The PORT variable is not needed on Vercel, but we can keep it for local testing.
const PORT = 3000;

// --- DATABASE CONNECTION SETUP FROM ENVIRONMENT VARIABLES ---
// We now securely read connection details from process.env, which Vercel will provide.
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


// 4. Define Routes
// This route serves the main page. It is important for Vercel to know this.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- API ROUTE FOR ATTENDANCE (NO CHANGES HERE) ---
app.post('/api/attend', async (req, res) => {
    const { studentId } = req.body;

    if (!studentId) {
        return res.status(400).json({ success: false, message: 'Student ID is required.' });
    }

    try {
        const sql = "INSERT INTO records (student_id, attendance) VALUES (?, ?)";
        const attendanceStatus = "present";
        
        await dbPool.execute(sql, [studentId, attendanceStatus]);
        
        console.log(`Attendance recorded for student ID: ${studentId} with status: ${attendanceStatus}`);
        res.status(200).json({ success: true, message: 'Attendance recorded successfully!' });

    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ success: false, message: 'Failed to record attendance. A database error occurred.' });
    }
});

// 5. EXPORT THE APP FOR VERCEL
// We no longer call app.listen(). Vercel handles starting the server.
// Instead, we export the app instance for Vercel to use.
module.exports = app;
