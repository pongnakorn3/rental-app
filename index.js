require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Import Strategies ของทั้ง 3 ค่าย
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const LineStrategy = require('passport-line-auth').Strategy;

const app = express();

// --- ตั้งค่า EJS และการรับค่าจากฟอร์ม ---
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true })); 
app.use(express.static('public')); 
// ---------------------------------------

// 1. เชื่อมต่อ Database
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

// ==========================================
// ฟังก์ชันกลางสำหรับจัดการ Database (Social Login)
// ==========================================
async function authUser(provider, profile, cb) {
    try {
        let queryField = '';
        if (provider === 'google') queryField = 'google_id';
        else if (provider === 'facebook') queryField = 'facebook_id';
        else if (provider === 'line') queryField = 'line_id';

        const res = await pool.query(`SELECT * FROM users WHERE ${queryField} = $1`, [profile.id]);

        if (res.rows.length === 0) {
            const email = (profile.emails && profile.emails[0]) ? profile.emails[0].value : null;
            const photo = (profile.photos && profile.photos[0]) ? profile.photos[0].value : null;

            const newUser = await pool.query(
                `INSERT INTO users (${queryField}, email, full_name, profile_picture) VALUES ($1, $2, $3, $4) RETURNING *`,
                [profile.id, email, profile.displayName, photo]
            );
            return cb(null, newUser.rows[0]);
        } else {
            return cb(null, res.rows[0]);
        }
    } catch (err) {
        return cb(err, null);
    }
}

// 3. ตั้งค่า Strategies (Google / Facebook / LINE)
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
  }, (accessToken, refreshToken, profile, cb) => authUser('google', profile, cb)
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ['id', 'displayName', 'photos', 'email']
  }, (accessToken, refreshToken, profile, cb) => authUser('facebook', profile, cb)
));

passport.use(new LineStrategy({
    channelID: process.env.LINE_CHANNEL_ID,
    channelSecret: process.env.LINE_CHANNEL_SECRET,
    callbackURL: process.env.LINE_CALLBACK_URL,
    scope: ['profile', 'openid', 'email'],
    botPrompt: 'normal'
  }, (accessToken, refreshToken, profile, cb) => authUser('line', profile, cb)
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ==========================================
// 4. Routes (หน้าเว็บ)
// ==========================================

app.get('/', (req, res) => {
  res.render('home'); 
});

app.get('/login', (req, res) => {
  res.render('login');
});

// [แก้ไข] Login ด้วย Email หรือ เบอร์โทร
app.post('/login', async (req, res) => {
    // รับค่าเป็น username (อย่าลืมแก้ name="username" ในไฟล์ login.ejs)
    const { username, password } = req.body; 
    
    try {
        // ค้นหา User โดยเช็คทั้ง 2 ช่อง (email หรือ phone)
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR phone = $1', 
            [username]
        );
        
        if (result.rows.length > 0) {
            const user = result.rows[0];
            
            // ถ้าไม่มีรหัสผ่าน (พวก Social Login)
            if (!user.password) {
                return res.send('บัญชีนี้สมัครผ่าน Social Login กรุณาเข้าสู่ระบบด้วยปุ่ม Google/Facebook/Line');
            }

            // เช็ค Password
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                req.login(user, (err) => {
                    if (err) return next(err);
                    return res.redirect('/profile');
                });
            } else {
                res.send('รหัสผ่านไม่ถูกต้อง <a href="/login">ลองใหม่</a>');
            }
        } else {
            res.send('ไม่พบข้อมูลในระบบ (อีเมลหรือเบอร์โทรไม่ถูกต้อง) <a href="/register">สมัครสมาชิก</a>');
        }
    } catch (err) {
        console.error(err);
        res.send('เกิดข้อผิดพลาดในการเข้าสู่ระบบ');
    }
});

app.get('/register', (req, res) => {
  res.render('register');
});

// [แก้ไข] Register ด้วย Email หรือ เบอร์โทร
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    let email = null;
    let phone = null;

    // --- ส่วนตรวจสอบ Logic ใหม่ ---
    if (username.includes('@')) {
        // CASE 1: เป็นอีเมล (มี @)
        email = username;
    } else {
        // CASE 2: ไม่มี @ (ระบบเข้าใจว่าเป็นเบอร์โทร)
        
        // ใช้ Regex เช็คว่า "เป็นตัวเลขล้วน" หรือไม่?
        const isNumeric = /^[0-9]+$/.test(username);

        if (isNumeric) {
            // เช็คเพิ่มว่าต้องเป็น 10 หลัก (ถ้าต้องการ)
            if (username.length !== 10) {
                return res.send('<h3>เบอร์โทรศัพท์ต้องมี 10 หลัก</h3><a href="/register">กลับไปสมัครใหม่</a>');
            }
            phone = username;
        } else {
            // ถ้าไม่มี @ และไม่ใช่ตัวเลข (เช่นใส่ว่า "somchai") -> แจ้ง Error
            return res.send(`
                <h3>รูปแบบข้อมูลไม่ถูกต้อง!</h3>
                <p>คุณกรอก: "${username}"</p>
                <p>หากเป็นเบอร์โทรศัพท์ ต้องเป็นตัวเลขล้วนเท่านั้น</p>
                <p>หากเป็นอีเมล ต้องมีเครื่องหมาย @</p>
                <a href="/register">กลับไปสมัครใหม่</a>
            `);
        }
    }
    // -----------------------------

    try {
        // 1. เช็คก่อนว่าซ้ำไหม (เช็คทั้ง email และ phone)
        const userCheck = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR phone = $2', 
            [email, phone]
        );
        
        if (userCheck.rows.length > 0) {
            return res.send('<h1>ข้อมูลนี้ (อีเมลหรือเบอร์โทร) มีผู้ใช้งานแล้ว!</h1><a href="/register">กลับไปสมัครใหม่</a>');
        }

        // 2. เข้ารหัสรหัสผ่าน
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 3. บันทึกลง Database
        await pool.query(
            `INSERT INTO users (email, phone, password, full_name, profile_picture) 
             VALUES ($1, $2, $3, $4, $5)`,
            [email, phone, hashedPassword, 'New User', '/logo.png'] 
        );

        // 4. สำเร็จ -> ไปหน้า Login
        res.redirect('/login');


    } catch (err) {
        console.error(err);
        res.send('เกิดข้อผิดพลาดในการสมัครสมาชิก: ' + err.message);
    }
});

// --- Auth Routes (Social) ---

// Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/profile'));

// Facebook
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => res.redirect('/profile'));

// LINE
app.get('/auth/line', passport.authenticate('line'));
app.get('/auth/line/callback', passport.authenticate('line', { failureRedirect: '/' }), (req, res) => res.redirect('/profile'));

// Profile Page
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  
  // โชว์เบอร์โทรด้วย (ถ้ามี)
  const displayContact = req.user.email || req.user.phone || 'ไม่ระบุ';

  res.send(`
    <div style="text-align:center; margin-top:50px; font-family: sans-serif;">
        <h1>ยินดีต้อนรับคุณ ${req.user.full_name}</h1>
        <img src="${req.user.profile_picture}" width="150" style="border-radius:50%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"><br>
        <p>Contact: ${displayContact}</p>
        <br>
        <a href="/logout" style="background: #ff4d4d; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Logout</a>
    </div>
  `);
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// Start Server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});