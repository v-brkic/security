const express = require('express');
const { Pool } = require('pg');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3000;

// postavljanje sigurnih postavki za sesije
app.use(session({
  secret: 'mySecret', // sigurna vrijednost za zaštitu integriteta sesija
  resave: false,      // izbjegava ponovne spremanja sesija koje nisu promijenjene
  saveUninitialized: true,
  cookie: { httpOnly: true, secure: false } // httpOnly: sprječava pristup kolačiću preko JavaScript-a
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// spajanje na bazu podataka korištenjem podataka iz varijabli okruženja
const pool = new Pool({
  host: process.env.DB_HOST,        // vanjski URL baze podataka
  user: process.env.DB_USER,        // korisničko ime
  password: process.env.DB_PASSWORD, // lozinka
  database: process.env.DB_NAME,     // ime baze podataka
  port: process.env.DB_PORT,         // port baze podataka
});

// provjera povezanosti s bazom i ispis poruke ako uspije
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Connected to PostgreSQL database');
  release();
});

// ranjivosti na SQL Injection, BAC (Broken Access Control) i XSS kontrolirane su pomoću ovih zastavica
let sqlVulnerabilityEnabled = false;
let bacVulnerabilityEnabled = false;
let xssVulnerabilityEnabled = false;

// početna ruta koja prikazuje glavnu stranicu, s podacima o ranjivostima
app.get('/', (req, res) => {
  const xssMessage = req.query.message || '';
  res.render('index', {
    sqlVulnerabilityEnabled,
    bacVulnerabilityEnabled,
    xssVulnerabilityEnabled,
    xssMessage: xssVulnerabilityEnabled ? xssMessage : escapeHtml(xssMessage), // primjenjuje se obrana od XSS-a
    userId: req.session.loggedin ? req.session.userId : null, // prikazivanje korisnikovog ID-a ako je prijavljen
  });
});

// ruta za prijavu -> provjera korisničkog imena i dodjeljivanje sesije
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

// ruta za profil korisnika, dostupna samo prijavljenim korisnicima
app.get('/profile', (req, res) => {
  if (req.session.loggedin) {
    res.render('profile', { username: req.session.username, userId: req.session.userId });
  } else {
    res.redirect('/');
  }
});

// ruta za pristup podacima o korisnicima, s provjerom prava pristupa i kontrolom BAC
app.get('/user/:id', (req, res) => {
  let userId = parseInt(req.params.id);

  // kontrola pristupa, dopušta pristup samo ovlaštenim korisnicima
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

// middleware funkcija koja provjerava pristup samo za admina
function isAdmin(req, res, next) {
  if (bacVulnerabilityEnabled || req.session.username === 'admin') {
    return next();
  } else {
    res.status(403).send('Access Denied: Admins only');
  }
}

// funkcija za enkodiranje podataka korisnika radi sprječavanja XSS napada
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

// adminska stranica koja je zaštićena od BAC ranjivosti
app.get('/admin', isAdmin, (req, res) => {
  res.send('Welcome Admin! You have exclusive access to this page.');
});

// ruta za pretraživanje korisnika s provjerom i zaštitom od SQL injection napada
app.post('/search', (req, res) => {
  const userInput = req.body.username;  //ovdje namjerno nisam stavio escapeHtml() funkciju za userInput kako bi omogućio SQL injection, inače bi escapeHtml() funkciju primjernio na svim ovakvim mjestima
  let query;
  let params = [];

  if (!sqlVulnerabilityEnabled) {
    // regex validacija za sprečavanje unosa specijalnih znakova koji mogu izazvati SQL Injection
    if (!userInput.match(/^[a-zA-Z0-9_-]+$/)) {
      return res.status(400).send("Invalid input.");
    }
    query = 'SELECT id, username FROM users WHERE username = $1';
    params = [userInput];
  } else {
    // ranjivi upit na SQL Injection kada je `sqlVulnerabilityEnabled` uključen
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

// ruta za testiranje XSS ranjivosti
app.post('/xss', (req, res) => {
  const userMessage = xssVulnerabilityEnabled ? req.body.message : escapeHtml(req.body.message); // xss zaštićenje ako je ranjivost isključena
  res.redirect('/?message=' + encodeURIComponent(userMessage));
});

// toggling ranjivosti za SQL injection, BAC i XSS
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
