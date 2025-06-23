// server.js

// No need for dotenv or mysql2 for this test
const express = require('express');
const path = require('path');

// 1. Initialize the App
const app = express();
const PORT = 3000;

// 2. Set up Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// 3. Define Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- SUPER SIMPLE API ROUTE FOR TESTING ---
app.post('/api/attend', async (req, res) => {
    // We will log that the function was called. This MUST appear in your Vercel logs.
    console.log("--- TEST /api/attend function invoked ---");
    console.log("Received body:", req.body);
    
    const { studentId } = req.body;

    if (!studentId) {
        console.log("TEST: Student ID was missing.");
        return res.status(400).json({ success: false, message: '[TEST] Student ID is required.' });
    }

    // We send a success message immediately without touching the database.
    console.log(`TEST: Successfully received request for student ID: ${studentId}`);
    res.status(200).json({ success: true, message: `[TEST] Attendance recorded for ${studentId}!` });
});

// 4. EXPORT THE APP FOR VERCEL & START SERVER LOCALLY
module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running for local development on http://localhost:${PORT}`);
  });
}
