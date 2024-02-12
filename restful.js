// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Create an Express application
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Dummy database for storing users
const users = [];

// Endpoint for user registration
app.post('/register', async (req, res) => {
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    
    // Create a new user object
    const user = {
      id: users.length + 1,
      username: req.body.username,
      password: hashedPassword
    };

    // Add the user to the database
    users.push(user);
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint for user login
app.post('/login', async (req, res) => {
  try {
    // Find the user by username
    const user = users.find(u => u.username === req.body.username);
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare the password
    if (await bcrypt.compare(req.body.password, user.password)) {
      // Generate JWT token
      const token = jwt.sign({ username: user.username }, 'secret_key');
      return res.status(200).json({ token });
    } else {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint for data retrieval (protected)
app.get('/data', authenticateToken, (req, res) => {
  res.json({ data: 'This is some sensitive data!' });
});

// Middleware function to authenticate JWT token
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    req.user = user;
    next();
  });
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
