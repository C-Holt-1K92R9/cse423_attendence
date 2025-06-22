// server.js

// 1. Import Dependencies
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
// Import the Node.js 'fs' (File System) module to read the certificate file.
const fs = require('fs');

// 2. Initialize the App
const app = express();
const PORT = 3000;

// --- AIVEN DATABASE CONNECTION SETUP ---
// We're using the connection details from your Aiven connection string.
// Make sure you have the 'ca.pem' file in the same directory as this server.js file.
const dbPool = mysql.createPool({
    host: 'mysql-attendence-hellboy2942002-9a4d.b.aivencloud.com',
    user: 'avnadmin',
    password: 'AVNS_ijgFwuuMNCWFv3G-6A5',
    database: 'defaultdb',
    port: 21873,
    // SSL configuration is required to connect securely to Aiven.
    ssl: {
        // fs.readFileSync reads the CA certificate file you downloaded from Aiven.
        // path.join ensures the file path works on any operating system.
        ca: fs.readFileSync(path.join(__dirname, 'ca.pem')),
    }
});


// 3. Set up Middleware
app.use(express.static(path.join(__dirname, 'public')));
// This is very important! It allows our server to understand JSON data
// sent from the frontend in the body of a request.
app.use(express.json());


// 4. Define Routes
// This route serves the main page.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- API ROUTE FOR ATTENDANCE ---
// This is the backend endpoint that the form will submit to.
app.post('/api/attend', async (req, res) => {
    // We get the studentId from the request's body.
    const { studentId } = req.body;

    if (!studentId) {
        return res.status(400).json({ success: false, message: 'Student ID is required.' });
    }

    try {
        // The SQL query is updated to insert into both student_id and the new attendance column.
        const sql = "UPDATE records SET attendance = ? WHERE student_id = ?";
        const attendanceStatus = 1; // Assuming 1 means present, you can change this based on your logic.
        
        // Execute the query, passing both the studentId and the status.
        const [result] = await dbPool.execute(sql, [attendanceStatus, studentId]);
        
        if (result.affectedRows === 0) {
            // No rows updated, student ID not found
            console.warn(`No record found for student ID: ${studentId}`);
            return res.status(404).json({ success: false, message: 'Student ID not found.' });
        }

        console.log(`Attendance recorded for student ID: ${studentId} with status: ${attendanceStatus}`);
        res.status(200).json({ success: true, message: 'Attendance recorded successfully!' });

    } catch (error) {
        console.error("Database error:", error);
        // Provide a more generic error to the client for security.
        res.status(500).json({ success: false, message: 'Failed to record attendance. A database error occurred.' });
    }
});


// 5. Start the Server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
