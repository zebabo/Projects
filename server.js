const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const session = require('express-session'); // Add express-session for managing user sessions

dotenv.config();

const app = express();
const port = 3000;

// Serve static files like HTML, CSS, etc.
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to parse incoming JSON data
app.use(bodyParser.json());

// Middleware for sessions
app.use(
    session({
        secret: 'your_secret_key', // Replace with a strong, unique secret
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false }, // In production, set secure: true when using HTTPS
    })
);

// Create a MySQL database connection
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Connect to MySQL
connection.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL: ', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Route to render the registration form
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Route to handle the registration form submission
app.post('/register', (req, res) => {
    const { nome, email, nif, password, repeatPassword } = req.body;

    // Validate that passwords match
    if (password !== repeatPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match!' });
    }

    // Hash password before saving to the database
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ success: false, message: 'Internal server error' });
        }

        // Check if the email already exists in the database
        connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'An error occurred while checking the email.' });
            }

            if (results.length > 0) {
                return res.status(400).json({ success: false, message: 'Email already in use!' });
            }

            // Insert new user into the database
            const query = 'INSERT INTO users (nome, email, nif, password) VALUES (?, ?, ?, ?)';
            connection.query(query, [nome, email, nif, hashedPassword], (err, results) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).json({ success: false, message: 'An error occurred while registering the user.' });
                }

                res.json({ success: true, message: 'Registration successful!' });
            });
        });
    });
});

// Route to render the login form
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route to handle login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Check if the email exists in the database
    connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while checking the email.' });
        }

        if (results.length === 0) {
            return res.status(400).json({ success: false, message: 'Email not found!' });
        }

        const user = results[0];

        // Compare the hashed password with the entered password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing password:', err);
                return res.status(500).json({ success: false, message: 'Internal server error' });
            }

            if (!isMatch) {
                return res.status(400).json({ success: false, message: 'Incorrect password!' });
            }

            // Store user details in the session
            req.session.user = { id: user.id, nome: user.nome };
            res.json({ success: true, message: 'Login successful!' });
        });
    });
});

// Route for the home page
app.get('/', (req, res) => {
    if (req.session.user) {
        // If the user is logged in, send the home page with user info
        res.send(`
            <html>
                <head>
                    <title>Home</title>
                </head>
                <body>
                    <h1>Welcome, ${req.session.user.nome}!</h1>
                    <button onclick="location.href='/logout'">Logout</button>
                </body>
            </html>
        `);
    } else {
        // If the user is not logged in, send the default home page
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// Route to handle logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('An error occurred while logging out.');
        }
        res.redirect('/'); // Redirect to the home page after logout
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
