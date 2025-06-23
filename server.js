// server.js

// --- ADD THIS LINE AT THE VERY TOP ---
// This will load the variables from your .env file for local development
require('dotenv').config();

// 1. Import Dependencies
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');

// 2. Initialize the App
const app = express();
// Vercel provides its own port, but we define one for local testing.
const PORT = process.env.PORT || 3000;

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

// 5. EXPORT THE APP FOR VERCEL & START SERVER LOCALLY
// This line exports the app for Vercel's serverless environment.
module.exports = app;

// This block checks if the file is being run directly with `node server.js`.
// If it is, it starts the server. This part is ignored by Vercel.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running for local development on http://localhost:${PORT}`);
  });
}
