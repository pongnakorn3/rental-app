require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // 1. เพิ่มตัวจัดการไฟล์

// Import Strategies
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const LineStrategy = require('passport-line-auth').Strategy;

const app = express();

// --- ตั้งค่า EJS และ Public Folder ---
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true })); 
app.use(express.static('public')); 
// ---------------------------------------

// --- ตั้งค่าการอัปโหลดรูป (Multer) : แก้ไขใหม่ให้ชัวร์ที่สุด ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // 2. ระบุที่อยู่แบบเจาะจง (Absolute Path) กันคอมพิวเตอร์งง
        const uploadPath = path.join(__dirname, 'public/uploads');

        // 3. ถ้าไม่มีโฟลเดอร์ ให้สร้างเดี๋ยวนี้เลย!
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }

        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        // ตั้งชื่อไฟล์: id-วันที่-นามสกุลไฟล์เดิม
        cb(null, req.user.id + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

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

            // เพิ่ม default kyc_status = 'unverified'
            const newUser = await pool.query(
                `INSERT INTO users (${queryField}, email, full_name, profile_picture, kyc_status) VALUES ($1, $2, $3, $4, 'unverified') RETURNING *`,
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

// 3. Setup Passport Strategies
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
  }, (accessToken, refreshToken, profile, cb) => authUser('google', profile, cb)));
  
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ['id', 'displayName', 'photos', 'email']
  }, (accessToken, refreshToken, profile, cb) => authUser('facebook', profile, cb)));
  
passport.use(new LineStrategy({
    channelID: process.env.LINE_CHANNEL_ID,
    channelSecret: process.env.LINE_CHANNEL_SECRET,
    callbackURL: process.env.LINE_CALLBACK_URL,
    scope: ['profile', 'openid', 'email'],
    botPrompt: 'normal'
  }, (accessToken, refreshToken, profile, cb) => authUser('line', profile, cb)));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ==========================================
// Middleware: ยามเฝ้าประตู (Check KYC)
// ==========================================
const checkKYC = (req, res, next) => {
    // 1. ถ้ายังไม่ล็อกอิน -> ไปหน้า Login
    if (!req.isAuthenticated()) return res.redirect('/login');

    // 2. ถ้าสถานะเป็น 'verified' แล้ว -> ปล่อยผ่านไปได้เลย
    if (req.user.kyc_status === 'verified') {
        return next();
    }

    // 3. ถ้ายังไม่ผ่าน และกำลังจะไปหน้า /kyc-verify หรือ logout -> ปล่อยให้ไป
    if (req.path === '/kyc-verify' || req.path === '/logout') {
        return next();
    }

    // 4. นอกนั้น ดีดไปหน้ายืนยันตัวตนให้หมด
    res.redirect('/kyc-verify');
};

// ==========================================
// Routes
// ==========================================

app.get('/', (req, res) => res.render('home'));
app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res, next) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1 OR phone = $1', [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (!user.password) return res.send('กรุณาใช้ Social Login');
            
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                req.login(user, (err) => {
                    if (err) return next(err);
                    return res.redirect('/profile');
                });
            } else {
                res.send('รหัสผิด');
            }
        } else {
            res.send('ไม่พบผู้ใช้');
        }
    } catch (err) { res.send('Error Login'); }
});

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
    const { username, password, name, tel } = req.body;
    let email = null;
    let finalPhone = tel ? tel.replace('+66', '0') : null;
    if (username && username.includes('@')) email = username;

    try {
        const userCheck = await pool.query('SELECT * FROM users WHERE phone = $1 OR email = $2', [finalPhone, email]);
        if (userCheck.rows.length > 0) return res.send('มีผู้ใช้นี้แล้ว');

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await pool.query(
            `INSERT INTO users (email, phone, password, full_name, profile_picture, kyc_status) 
             VALUES ($1, $2, $3, $4, $5, 'unverified')`,
            [email, finalPhone, hashedPassword, name, '/logo.png']
        );
        res.redirect('/login');
    } catch (err) { res.send('Error Register: ' + err.message); }
});

// --- Auth Social Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/profile'));

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => res.redirect('/profile'));

app.get('/auth/line', passport.authenticate('line'));
app.get('/auth/line/callback', passport.authenticate('line', { failureRedirect: '/' }), (req, res) => res.redirect('/profile'));

// ==========================================
// หน้า KYC Verify (อัปโหลดรูป)
// ==========================================
app.get('/kyc-verify', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    if (req.user.kyc_status === 'verified') return res.redirect('/profile');

    res.render('kyc_verify', { 
        user: req.user,
        status: req.user.kyc_status 
    });
});

app.post('/kyc-verify', upload.fields([{ name: 'id_card' }, { name: 'face_pair' }]), async (req, res) => {
    try {
        const idCardFile = req.files['id_card'] ? req.files['id_card'][0].filename : null;
        const faceFile = req.files['face_pair'] ? req.files['face_pair'][0].filename : null;

        if (!idCardFile || !faceFile) {
            return res.send('กรุณาอัปโหลดรูปให้ครบทั้ง 2 รูป');
        }

        await pool.query(
            `UPDATE users SET id_card_image = $1, face_image = $2, kyc_status = 'pending' WHERE id = $3`,
            [idCardFile, faceFile, req.user.id]
        );

        res.redirect('/kyc-verify');
    } catch (err) {
        console.error(err);
        res.send('เกิดข้อผิดพลาดในการอัปโหลด: ' + err.message);
    }
});

// ==========================================
// หน้า Profile (ใส่ checkKYC)
// ==========================================
app.get('/profile', checkKYC, (req, res) => {
  const displayContact = req.user.email || req.user.phone || 'ไม่ระบุ';
  res.send(`
    <div style="text-align:center; margin-top:50px; font-family: sans-serif;">
        <span style="color:green; font-weight:bold;">✅ ยืนยันตัวตนแล้ว</span>
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

app.listen(3000, () => console.log('Server running on http://localhost:3000'));