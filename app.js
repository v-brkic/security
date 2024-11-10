const express = require('express');
const { Pool } = require('pg');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3000;

app.use(session({
  secret: 'mySecret',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, secure: false } // Set `secure: true` if using HTTPS
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

/*const pool = new Pool({
  host: 'localhost',
  user: 'postgres',
  password: 'bazepodataka',
  database: 'lab2security',
  port: 5432,
});*/
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});


pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Connected to PostgreSQL database');
  release();
});

let sqlVulnerabilityEnabled = false;
let bacVulnerabilityEnabled = false;
let xssVulnerabilityEnabled = false;

app.get('/', (req, res) => {
  const xssMessage = req.query.message || '';
  res.render('index', {
    sqlVulnerabilityEnabled,
    bacVulnerabilityEnabled,
    xssVulnerabilityEnabled,
    xssMessage: xssVulnerabilityEnabled ? xssMessage : escapeHtml(xssMessage),
    userId: req.session.loggedin ? req.session.userId : null,
  });
});

app.post('/login', (req, res) => {
  const { username } = req.body;

  let userId;
  switch (username) {
    case 'admin':
      userId = 1;
      break;
    case 'user1':
      userId = 2;
      break;
    case 'user2':
      userId = 3;
      break;
    default:
      userId = null;
  }

  if (userId) {
    req.session.loggedin = true;
    req.session.username = username;
    req.session.userId = userId;
    res.redirect('/profile');
  } else {
    res.send('Invalid username');
  }
});

app.get('/profile', (req, res) => {
  if (req.session.loggedin) {
    res.render('profile', { username: req.session.username, userId: req.session.userId });
  } else {
    res.redirect('/');
  }
});

app.get('/user/:id', (req, res) => {
  let userId = parseInt(req.params.id);

  if (bacVulnerabilityEnabled || (req.session.loggedin && req.session.userId === userId)) {
    let query = 'SELECT * FROM users WHERE id = $1';
    pool.query(query, [userId], (err, result) => {
      if (err) throw err;
      res.json(result.rows);
    });
  } else {
    res.status(403).send('Access Denied');
  }
});

// Middleware for admin access control
function isAdmin(req, res, next) {
  if (bacVulnerabilityEnabled || req.session.username === 'admin') {
    return next();
  } else {
    res.status(403).send('Access Denied: Admins only');
  }
}

// Improved escapeHtml function to prevent XSS
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;")
    .replace(/\(/g, "&#40;")
    .replace(/\)/g, "&#41;")
    .replace(/;/g, "&#59;")
    .replace(/=/g, "&#61;");
}

// Admin-only endpoint with BAC protection
app.get('/admin', isAdmin, (req, res) => {
  res.send('Welcome Admin! You have exclusive access to this page.');
});

app.post('/search', (req, res) => {
  const userInput = req.body.username;
  let query;
  let params = [];

  if (!sqlVulnerabilityEnabled) {
    if (!userInput.match(/^[a-zA-Z0-9_-]+$/)) {
      return res.status(400).send("Invalid input.");
    }
    query = 'SELECT id, username FROM users WHERE username = $1';
    params = [userInput];
  } else {
    query = `SELECT * FROM users WHERE username = '${userInput}'`;
  }

  pool.query(query, params, (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Database error. Please check your query.");
    }

    const results = sqlVulnerabilityEnabled ? result.rows : result.rows.map(row => ({ id: row.id, username: row.username }));
    res.json(results);
  });
});

app.post('/xss', (req, res) => {
  const userMessage = xssVulnerabilityEnabled ? req.body.message : escapeHtml(req.body.message);
  res.redirect('/?message=' + encodeURIComponent(userMessage));
});


app.post('/toggle-sql-vulnerability', (req, res) => {
  sqlVulnerabilityEnabled = !sqlVulnerabilityEnabled;
  res.redirect('/');
});

app.post('/toggle-bac-vulnerability', (req, res) => {
  bacVulnerabilityEnabled = !bacVulnerabilityEnabled;
  res.redirect('/');
});

app.post('/toggle-xss-vulnerability', (req, res) => {
  xssVulnerabilityEnabled = !xssVulnerabilityEnabled;
  res.redirect('/');
});

app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
