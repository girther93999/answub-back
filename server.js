const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const INVITES_FILE = path.join(__dirname, 'invites.json');

// Rate limiting storage (in-memory)
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// Middleware
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit payload size
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
function initDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = { users: [], keys: [] };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
}

// Initialize invites file
function initInvites() {
    if (!fs.existsSync(INVITES_FILE)) {
        const defaultInvites = { 
            invites: [
                "4NIRIOJEJEOJ",
                "K9X2M8P4Q7R3",
                "L5W9T1V6Y8Z2",
                "A7B3C9D5E1F8",
                "G2H6J4K8M3N7"
            ] 
        };
        fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
    } else {
        // Check if file is empty or has no invites
        try {
            const data = fs.readFileSync(INVITES_FILE, 'utf8');
            const invitesData = JSON.parse(data);
            if (!invitesData.invites || invitesData.invites.length === 0) {
                // File exists but is empty, add default invites
                const defaultInvites = { 
                    invites: [
                        "4NIRIOJEJEOJ",
                        "K9X2M8P4Q7R3",
                        "L5W9T1V6Y8Z2",
                        "A7B3C9D5E1F8",
                        "G2H6J4K8M3N7"
                    ] 
                };
                fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
            }
        } catch (error) {
            // File is corrupted, recreate with defaults
            const defaultInvites = { 
                invites: [
                    "4NIRIOJEJEOJ",
                    "K9X2M8P4Q7R3",
                    "L5W9T1V6Y8Z2",
                    "A7B3C9D5E1F8",
                    "G2H6J4K8M3N7"
                ] 
            };
            fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
        }
    }
}

// Read invites
function readInvites() {
    try {
        const data = fs.readFileSync(INVITES_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return { invites: [] };
    }
}

// Check if invite code is valid (case-insensitive)
function isValidInvite(code) {
    if (!code || typeof code !== 'string') return false;
    const invitesData = readInvites();
    if (!invitesData.invites || !Array.isArray(invitesData.invites)) return false;
    // Case-insensitive comparison
    return invitesData.invites.some(invite => invite.toLowerCase() === code.toLowerCase());
}

function readDB() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return { users: [], keys: [] };
    }
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Hash password
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Generate session token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Generate key with custom format
function generateKey(format) {
    let key = format;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    
    for (let i = 0; i < key.length; i++) {
        if (key[i] === '*') {
            const randomChar = chars[Math.floor(Math.random() * chars.length)];
            key = key.substring(0, i) + randomChar + key.substring(i + 1);
        }
    }
    
    return key;
}

// Calculate expiry date
function calculateExpiry(duration, amount) {
    if (duration === 'lifetime') {
        return null;
    }
    
    const now = new Date();
    const expiry = new Date(now);
    
    switch (duration) {
        case 'second':
            expiry.setSeconds(now.getSeconds() + amount);
            break;
        case 'minute':
            expiry.setMinutes(now.getMinutes() + amount);
            break;
        case 'hour':
            expiry.setHours(now.getHours() + amount);
            break;
        case 'day':
            expiry.setDate(now.getDate() + amount);
            break;
        case 'month':
            expiry.setMonth(now.getMonth() + amount);
            break;
    }
    
    return expiry.toISOString();
}

// Add time to existing key
function addTimeToKey(expiresAt, duration, amount) {
    let baseDate;
    
    if (expiresAt) {
        baseDate = new Date(expiresAt);
        if (baseDate < new Date()) {
            baseDate = new Date();
        }
    } else {
        baseDate = new Date();
    }
    
    const newExpiry = new Date(baseDate);
    
    switch (duration) {
        case 'second':
            newExpiry.setSeconds(baseDate.getSeconds() + amount);
            break;
        case 'minute':
            newExpiry.setMinutes(baseDate.getMinutes() + amount);
            break;
        case 'hour':
            newExpiry.setHours(baseDate.getHours() + amount);
            break;
        case 'day':
            newExpiry.setDate(baseDate.getDate() + amount);
            break;
        case 'month':
            newExpiry.setMonth(baseDate.getMonth() + amount);
            break;
    }
    
    return newExpiry.toISOString();
}

initDB();
initInvites();

// AUTH ROUTES

// Input validation
function validateInput(str, maxLength = 50) {
    if (!str || typeof str !== 'string') return false;
    if (str.length > maxLength) return false;
    // Prevent SQL/NoSQL injection characters
    const dangerousChars = /[<>'"`;\\]/;
    return !dangerousChars.test(str);
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 100;
}

// Register
app.post('/api/auth/register', (req, res) => {
    const { username, email, password, inviteCode } = req.body;
    
    // Input validation
    if (!username || !email || !password || !inviteCode) {
        return res.json({ success: false, message: 'All fields required, including invite code' });
    }
    
    // Validate invite code
    if (!isValidInvite(inviteCode)) {
        return res.json({ success: false, message: 'Invalid invite code. Registration is invite-only.' });
    }
    
    if (!validateInput(username, 30)) {
        return res.json({ success: false, message: 'Invalid username' });
    }
    
    if (!validateEmail(email)) {
        return res.json({ success: false, message: 'Invalid email' });
    }
    
    if (password.length < 6 || password.length > 100) {
        return res.json({ success: false, message: 'Password must be 6-100 characters' });
    }
    
    const db = readDB();
    
    // Check if username already exists (case-insensitive)
    const existingUserByUsername = db.users.find(u => 
        u.username && u.username.toLowerCase() === username.toLowerCase()
    );
    if (existingUserByUsername) {
        return res.json({ success: false, message: 'Username already taken. Please choose a different username.' });
    }
    
    // Check if email already exists (case-insensitive)
    const existingUserByEmail = db.users.find(u => 
        u.email && u.email.toLowerCase() === email.toLowerCase()
    );
    if (existingUserByEmail) {
        return res.json({ success: false, message: 'Email already registered. Please use a different email or login.' });
    }
    
    // Create user
    const user = {
        id: crypto.randomBytes(16).toString('hex'),
        username: username,
        email: email,
        password: hashPassword(password),
        createdAt: new Date().toISOString(),
        token: generateToken(),
        failedLogins: 0,
        lockedUntil: null
    };
    
    db.users.push(user);
    writeDB(db);
    
    res.json({ 
        success: true, 
        message: 'Account created',
        token: user.token,
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    });
});

// Login with rate limiting
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password required' });
    }
    
    if (!validateInput(username, 30)) {
        return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check rate limiting by IP
    const attemptKey = `${clientIp}_${username}`;
    const attempts = loginAttempts.get(attemptKey) || { count: 0, firstAttempt: Date.now() };
    
    // Reset if lockout time passed
    if (attempts.lockedUntil && Date.now() > attempts.lockedUntil) {
        loginAttempts.delete(attemptKey);
    } else if (attempts.lockedUntil) {
        const remainingMinutes = Math.ceil((attempts.lockedUntil - Date.now()) / 60000);
        return res.json({ 
            success: false, 
            message: `Too many failed attempts. Try again in ${remainingMinutes} minutes.` 
        });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    
    if (!user || user.password !== hashPassword(password)) {
        // Increment failed attempts
        attempts.count++;
        attempts.firstAttempt = attempts.firstAttempt || Date.now();
        
        if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
            attempts.lockedUntil = Date.now() + LOCKOUT_TIME;
            loginAttempts.set(attemptKey, attempts);
            return res.json({ 
                success: false, 
                message: 'Too many failed attempts. Account locked for 15 minutes.' 
            });
        }
        
        loginAttempts.set(attemptKey, attempts);
        return res.json({ 
            success: false, 
            message: `Invalid username or password. ${MAX_LOGIN_ATTEMPTS - attempts.count} attempts remaining.` 
        });
    }
    
    // Successful login - clear attempts
    loginAttempts.delete(attemptKey);
    
    // Generate new token
    user.token = generateToken();
    user.lastLogin = new Date().toISOString();
    writeDB(db);
    
    res.json({ 
        success: true,
        token: user.token,
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    });
});

// Verify token
app.post('/api/auth/verify', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Token required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid token' });
    }
    
    res.json({ 
        success: true,
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    });
});

// KEY MANAGEMENT ROUTES

// Generate key
app.post('/api/keys/generate', (req, res) => {
    const { token, format, duration, amount } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid authentication' });
    }
    
    if (!format || !format.includes('*')) {
        return res.json({ success: false, message: 'Invalid format' });
    }
    
    const key = generateKey(format);
    const expiresAt = calculateExpiry(duration, parseInt(amount) || 1);
    
    const keyEntry = {
        key: key,
        userId: user.id,
        username: user.username,
        format: format,
        duration: duration,
        amount: amount,
        expiresAt: expiresAt,
        createdAt: new Date().toISOString(),
        usedBy: null,
        usedAt: null,
        hwid: null,
        ip: null,
        lastCheck: null
    };
    
    db.keys.push(keyEntry);
    writeDB(db);
    
    res.json({ success: true, key: key, data: keyEntry });
});

// Get user's keys
app.post('/api/keys/list', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid authentication' });
    }
    
    // Get only this user's keys
    const userKeys = db.keys.filter(k => k.userId === user.id);
    
    res.json({ success: true, keys: userKeys });
});

// Get stats for user
app.post('/api/keys/stats', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid authentication' });
    }
    
    const userKeys = db.keys.filter(k => k.userId === user.id);
    const now = new Date();
    
    const total = userKeys.length;
    const active = userKeys.filter(k => !k.expiresAt || new Date(k.expiresAt) > now).length;
    const expired = userKeys.filter(k => k.expiresAt && new Date(k.expiresAt) < now).length;
    const used = userKeys.filter(k => k.usedBy).length;
    const unused = total - used;
    
    res.json({
        success: true,
        stats: { total, active, expired, used, unused }
    });
});

// Add time to key
app.post('/api/keys/addtime', (req, res) => {
    const { token, key, duration, amount } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid authentication' });
    }
    
    const keyEntry = db.keys.find(k => k.key === key && k.userId === user.id);
    
    if (!keyEntry) {
        return res.json({ success: false, message: 'Key not found' });
    }
    
    keyEntry.expiresAt = addTimeToKey(keyEntry.expiresAt, duration, parseInt(amount));
    writeDB(db);
    
    res.json({ success: true, message: 'Time added', expiresAt: keyEntry.expiresAt });
});

// Reset HWID
app.post('/api/keys/resethwid', (req, res) => {
    const { token, key } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid authentication' });
    }
    
    const keyEntry = db.keys.find(k => k.key === key && k.userId === user.id);
    
    if (!keyEntry) {
        return res.json({ success: false, message: 'Key not found' });
    }
    
    keyEntry.hwid = null;
    keyEntry.usedBy = null;
    writeDB(db);
    
    res.json({ success: true, message: 'HWID reset' });
});

// Delete key
app.delete('/api/keys/:key', (req, res) => {
    const keyToDelete = req.params.key;
    const token = req.headers.authorization;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const db = readDB();
    const user = db.users.find(u => u.token === token);
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid authentication' });
    }
    
    // Only delete if key belongs to user
    db.keys = db.keys.filter(k => !(k.key === keyToDelete && k.userId === user.id));
    writeDB(db);
    
    res.json({ success: true, message: 'Key deleted' });
});

// CLIENT VALIDATION (No auth required - used by C++ app)
app.post('/api/validate', (req, res) => {
    const { key, hwid, ip, accountId, apiToken } = req.body;
    
    let clientIp = ip || 
                   req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                   req.headers['x-real-ip'] ||
                   req.socket.remoteAddress ||
                   'Unknown';
    
    if (clientIp.startsWith('::ffff:')) {
        clientIp = clientIp.substring(7);
    }
    
    if (clientIp === '::1' || clientIp === '127.0.0.1') {
        clientIp = 'localhost (127.0.0.1)';
    }
    
    if (!key) {
        return res.json({ success: false, message: 'Key required' });
    }
    
    const db = readDB();
    const keyEntry = db.keys.find(k => k.key === key);
    
    if (!keyEntry) {
        return res.json({ success: false, message: 'Invalid key' });
    }
    
    // ACCOUNT VERIFICATION: Check if key belongs to the account
    if (accountId && apiToken) {
        // Verify the account exists and token is valid
        const user = db.users.find(u => u.id === accountId && u.token === apiToken);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid account credentials' });
        }
        
        // Check if key belongs to this account
        if (keyEntry.userId !== accountId) {
            return res.json({ success: false, message: 'Key does not belong to this account' });
        }
    }
    
    if (keyEntry.expiresAt) {
        const expiry = new Date(keyEntry.expiresAt);
        if (expiry < new Date()) {
            return res.json({ success: false, message: 'Key expired' });
        }
    }
    
    const now = new Date().toISOString();
    
    // HWID LOCK: Bind key to first HWID that uses it
    if (!keyEntry.hwid && hwid) {
        // First time use - bind to this HWID permanently
        keyEntry.usedBy = hwid;
        keyEntry.usedAt = now;
        keyEntry.hwid = hwid;
        keyEntry.ip = clientIp;
        keyEntry.hwidLocked = true;
    } else if (keyEntry.hwid && hwid && keyEntry.hwid !== hwid) {
        // HWID MISMATCH - Key is locked to different hardware
        return res.json({ 
            success: false, 
            message: 'HWID Lock: This key is bound to a different computer. Contact support to reset HWID.' 
        });
    } else if (!hwid) {
        // No HWID provided
        return res.json({ 
            success: false, 
            message: 'Hardware ID required for validation' 
        });
    }
    
    // Update last check time
    keyEntry.lastCheck = now;
    if (!keyEntry.ip) keyEntry.ip = clientIp;
    
    writeDB(db);
    
    res.json({ 
        success: true, 
        message: 'Key valid',
        data: {
            duration: keyEntry.duration,
            expiresAt: keyEntry.expiresAt,
            hwid: keyEntry.hwid,
            ip: keyEntry.ip
        }
    });
});

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
    next();
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ success: true, message: 'Server running' });
});

// Self-ping to keep server alive (every 14 minutes)
if (process.env.RENDER) {
    setInterval(() => {
        const https = require('https');
        const url = process.env.RENDER_EXTERNAL_URL || 'https://answub-back.onrender.com';
        
        https.get(`${url}/api/health`, (res) => {
            console.log(`[Self-Ping] Status: ${res.statusCode} at ${new Date().toISOString()}`);
        }).on('error', (err) => {
            console.error(`[Self-Ping] Error: ${err.message}`);
        });
    }, 14 * 60 * 1000); // 14 minutes in milliseconds
    
    console.log('✅ Self-ping enabled - will ping every 14 minutes to keep server alive');
}

// Cleanup old login attempts every hour
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of loginAttempts.entries()) {
        if (value.lockedUntil && now > value.lockedUntil) {
            loginAttempts.delete(key);
        }
    }
}, 60 * 60 * 1000);

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Astreon Auth Server running on port ${PORT}`);
    console.log(`📁 Database: ${DB_FILE}`);
    console.log(`🔒 Security: Rate limiting enabled`);
    console.log(`🔒 Max login attempts: ${MAX_LOGIN_ATTEMPTS}`);
});
