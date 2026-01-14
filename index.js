require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const { Pool } = require('pg');

const app = express();

// 1. เชื่อมต่อ Database (Postgres)
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// 2. ตั้งค่า Session
app.use(session({
  secret: 'secret_key_changeme',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// 3. ตั้งค่า Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
  },
  async function(accessToken, refreshToken, profile, cb) {
    try {
      // เช็คว่ามี User นี้ใน DB หรือยัง?
      const res = await pool.query('SELECT * FROM users WHERE google_id = $1', [profile.id]);
      
      if (res.rows.length === 0) {
        // ถ้ายังไม่มี -> สร้าง User ใหม่
        const newUser = await pool.query(
          'INSERT INTO users (google_id, email, full_name, profile_picture) VALUES ($1, $2, $3, $4) RETURNING *',
          [profile.id, profile.emails[0].value, profile.displayName, profile.photos[0].value]
        );
        return cb(null, newUser.rows[0]);
      } else {
        // ถ้ามีแล้ว -> Login ได้เลย
        return cb(null, res.rows[0]);
      }
    } catch (err) {
      return cb(err, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// 4. สร้าง Routes (หน้าเว็บ)
app.get('/', (req, res) => {
  res.send('<h1>หน้าแรก</h1><a href="/auth/google">Login with Google</a>');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    // Login สำเร็จ!
    res.redirect('/profile');
  });

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  res.send(`<h1>สวัสดีคุณ ${req.user.full_name}</h1><img src="${req.user.profile_picture}"><br><a href="/logout">Logout</a>`);
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// เริ่มรัน Server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});