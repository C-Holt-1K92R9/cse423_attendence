
  // Check if the 'remember_me_token' cookie exists
  if (!req.cookies || !req.cookies.remember_me_token) {
    // If no cookie, just show the main page.
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }

  try {
    const [selector, validator] = req.cookies.remember_me_token.split(':');

    if (!selector || !validator) {
      // Malformed cookie, clear it and show the main page
      res.clearCookie('remember_me_token');
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    // 1. Find the token selector in the database
    const [tokenRows] = await dbPool.execute('SELECT * FROM auth_tokens WHERE selector = ?', [selector]);

    if (tokenRows.length === 0) {
      console.log('DEBUG: Remember-me selector not found in DB.');
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }

    const authToken = tokenRows[0];

    // 2. Check if the token has expired (CRITICAL SECURITY FIX)
    if (new Date(authToken.expires) < new Date()) {
      console.log('DEBUG: Remember-me token has expired.');
      // Clean up expired token from the database
      await dbPool.execute('DELETE FROM auth_tokens WHERE selector = ?', [selector]);
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
          res.redirect('/student');
      }
    }
    
    // If match is false, or user not found, fall through and show the main page.
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));

  } catch (err) {
    console.error("Error during 'remember me' authentication:", err);
    res.status(500).send("Internal Server Error");
  }