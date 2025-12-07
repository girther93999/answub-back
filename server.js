const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const INVITES_FILE = path.join(__dirname, 'invites.json');
const UPDATES_DIR = path.join(__dirname, 'updates');
const UPDATE_INFO_FILE = path.join(__dirname, 'update_info.json');
const ADMIN_USERNAME = 'K7mP9xQ2vR5wN8bL3jF6hT4'; // Hardcoded admin username
const ADMIN_PASSWORD = 'X9zA4cM7nB2dG8kY5pV1sW6'; // Hardcoded admin password
const BOT_API_KEY = process.env.BOT_API_KEY || crypto.createHash('sha256').update(ADMIN_USERNAME + ADMIN_PASSWORD + 'BOT_SECRET_2024').digest('hex'); // Bot-only API key

// MongoDB connection string (use environment variable or fallback to local JSON)
const MONGODB_URI = process.env.MONGODB_URI || null;

// Rate limiting storage (in-memory)
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// Admin token storage (in-memory, secure)
const adminTokens = new Map(); // token -> { username, createdAt, lastAccess }
const ADMIN_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

// Middleware
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit payload size
// Static file serving removed - frontend is deployed separately

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: String, required: true },
    lastLogin: String,
    failedLogins: { type: Number, default: 0 },
    lockedUntil: String
});

const inviteSchema = new mongoose.Schema({
    hash: { type: String, required: true, unique: true },
    codeEncrypted: { type: String, required: true }, // Encrypted plain code for display
    createdAt: { type: String, required: true },
    usedBy: String, // User ID who used it
    usedAt: String, // When it was used
    isUsed: { type: Boolean, default: false }
});

const Invite = mongoose.model('Invite', inviteSchema);

const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    username: { type: String, required: true },
    format: String,
    duration: String,
    amount: String,
    expiresAt: String,
    createdAt: { type: String, required: true },
    usedBy: String,
    usedAt: String,
    hwid: String,
    ip: String,
    lastCheck: String,
    hwidLocked: Boolean
});

const User = mongoose.model('User', userSchema);
const Key = mongoose.model('Key', keySchema);

// Initialize database
async function initDB() {
    console.log('🔍 Checking MongoDB connection...');
    if (MONGODB_URI) {
        console.log('📡 MongoDB URI found, attempting connection...');
        try {
            await mongoose.connect(MONGODB_URI);
            console.log('✅ Connected to MongoDB - Data will persist!');
            console.log(`📊 Database: ${mongoose.connection.name}`);
            console.log(`🔗 Connection state: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
        } catch (error) {
            console.error('❌ MongoDB connection failed, using JSON fallback');
            console.error('Error details:', error.message);
            // Fallback to JSON
            if (!fs.existsSync(DB_FILE)) {
                const initialData = { users: [], keys: [] };
                fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
            }
        }
    } else {
        // No MongoDB URI, use JSON file
        console.log('⚠️  No MongoDB URI found, using JSON file (data may not persist on server restart)');
        console.log('💡 To enable persistent storage, set MONGODB_URI environment variable in Render.com');
        if (!fs.existsSync(DB_FILE)) {
            const initialData = { users: [], keys: [] };
            fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
        }
    }
}

// Initialize updates directory
function initUpdatesDir() {
    if (!fs.existsSync(UPDATES_DIR)) {
        fs.mkdirSync(UPDATES_DIR, { recursive: true });
    }
}

// Hash invite code (one-way encryption)
function hashInvite(code) {
    return crypto.createHash('sha256').update(code.toUpperCase().trim()).digest('hex');
}

// Encrypt invite code for storage (reversible with key)
function encryptInviteCode(code) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.createHash('sha256').update(ADMIN_PASSWORD + ADMIN_USERNAME).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(code, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

// Decrypt invite code for display
function decryptInviteCode(encryptedCode) {
    try {
        const algorithm = 'aes-256-cbc';
        const key = crypto.createHash('sha256').update(ADMIN_PASSWORD + ADMIN_USERNAME).digest();
        const parts = encryptedCode.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return null;
    }
}

// Initialize invites file
async function initInvites() {
    // Hardcoded random invite codes (8 characters each) - these will be hashed
    const hardcodedInvites = [
        "8SHD7YCS",
        "K9X2M8P4",
        "L5W9T1V6",
        "A7B3C9D5",
        "G2H6J4K8",
        "M3N7P9Q1",
        "R5S2T8U4",
        "V6W3X9Y7",
        "Z1A4B8C2",
        "D5E9F3G7"
    ];
    
    if (mongoose.connection.readyState === 1) {
        // Use MongoDB
        try {
            const existingCount = await Invite.countDocuments();
            if (existingCount === 0) {
                // Initialize with hardcoded invites (hashed + encrypted)
                const invitesToAdd = hardcodedInvites.map(code => ({
                    hash: hashInvite(code),
                    codeEncrypted: encryptInviteCode(code),
                    createdAt: new Date().toISOString(),
                    isUsed: false
                }));
                await Invite.insertMany(invitesToAdd);
                console.log(`✅ Initialized ${hardcodedInvites.length} invite codes in MongoDB`);
            }
        } catch (error) {
            console.error('Error initializing invites in MongoDB:', error);
        }
    } else {
        // Use JSON file (store hashed versions)
        if (!fs.existsSync(INVITES_FILE)) {
            const hashedInvites = hardcodedInvites.map(code => hashInvite(code));
            const defaultInvites = { invites: hashedInvites };
            fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
            console.log(`✅ Initialized ${hardcodedInvites.length} invite codes`);
        } else {
            // Check if file is empty or has no invites
            try {
                const data = fs.readFileSync(INVITES_FILE, 'utf8');
                const invitesData = JSON.parse(data);
                if (!invitesData.invites || invitesData.invites.length === 0) {
                    // File exists but is empty, use hardcoded invites (hashed)
                    const hashedInvites = hardcodedInvites.map(code => hashInvite(code));
                    const defaultInvites = { invites: hashedInvites };
                    fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
                    console.log(`✅ Initialized ${hardcodedInvites.length} invite codes`);
                }
            } catch (error) {
                // File is corrupted, create new one with hardcoded invites (hashed)
                const hashedInvites = hardcodedInvites.map(code => hashInvite(code));
                const defaultInvites = { invites: hashedInvites };
                fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
                console.log(`✅ Initialized ${hardcodedInvites.length} invite codes`);
            }
        }
    }
}

// Read invites (returns all invites with decrypted codes and status)
async function readInvites() {
    if (mongoose.connection.readyState === 1) {
        // Use MongoDB
        try {
            const invites = await Invite.find({}).sort({ createdAt: -1 });
            return { 
                invites: invites.map(inv => ({
                    hash: inv.hash,
                    code: decryptInviteCode(inv.codeEncrypted) || '***',
                    codeEncrypted: inv.codeEncrypted,
                    createdAt: inv.createdAt,
                    isUsed: inv.isUsed || false,
                    usedBy: inv.usedBy || null,
                    usedAt: inv.usedAt || null
                }))
            };
        } catch (error) {
            console.error('Error reading invites from MongoDB:', error);
            return { invites: [] };
        }
    } else {
        // Use JSON file
        try {
            const data = fs.readFileSync(INVITES_FILE, 'utf8');
            const parsed = JSON.parse(data);
            // Migrate old format if needed
            if (parsed.invites && parsed.invites.length > 0 && typeof parsed.invites[0] === 'string') {
                // Old format - convert to new format
                parsed.invites = parsed.invites.map(hash => ({
                    hash: hash,
                    code: '***',
                    codeEncrypted: '',
                    createdAt: new Date().toISOString(),
                    isUsed: false,
                    usedBy: null,
                    usedAt: null
                }));
                fs.writeFileSync(INVITES_FILE, JSON.stringify(parsed, null, 2));
            }
            // Decrypt codes for display
            parsed.invites = parsed.invites.map(inv => ({
                ...inv,
                code: inv.codeEncrypted ? (decryptInviteCode(inv.codeEncrypted) || '***') : (inv.code || '***')
            }));
            return parsed;
        } catch (error) {
            return { invites: [] };
        }
    }
}

// Check if invite code is valid and return invite object (case-insensitive, compares hashes)
async function isValidInvite(code) {
    if (!code || typeof code !== 'string') return null;
    const codeHash = hashInvite(code);
    
    if (mongoose.connection.readyState === 1) {
        // Use MongoDB
        try {
            const invite = await Invite.findOne({ hash: codeHash, isUsed: false });
            return invite;
        } catch (error) {
            console.error('Error checking invite in MongoDB:', error);
            return null;
        }
    } else {
        // Use JSON file
        const invitesData = await readInvites();
        if (!invitesData.invites || !Array.isArray(invitesData.invites)) return null;
        const inviteObj = invitesData.invites.find(inv => inv.hash === codeHash && !inv.isUsed);
        return inviteObj || null;
    }
}

// Mark invite as used
async function markInviteAsUsed(invite, userId) {
    if (mongoose.connection.readyState === 1) {
        // Use MongoDB
        try {
            await Invite.updateOne(
                { hash: invite.hash },
                { 
                    isUsed: true, 
                    usedBy: userId, 
                    usedAt: new Date().toISOString() 
                }
            );
        } catch (error) {
            console.error('Error marking invite as used in MongoDB:', error);
        }
    } else {
        // Use JSON file
        try {
            const invitesData = await readInvites();
            const inviteIndex = invitesData.invites.findIndex(inv => inv.hash === invite.hash);
            if (inviteIndex !== -1) {
                invitesData.invites[inviteIndex].isUsed = true;
                invitesData.invites[inviteIndex].usedBy = userId;
                invitesData.invites[inviteIndex].usedAt = new Date().toISOString();
                fs.writeFileSync(INVITES_FILE, JSON.stringify(invitesData, null, 2));
            }
        } catch (error) {
            console.error('Error marking invite as used in JSON:', error);
        }
    }
}

async function readDB() {
    if (mongoose.connection.readyState === 1) {
        // Using MongoDB
        try {
            const users = await User.find({}).lean();
            const keys = await Key.find({}).lean();
            return { users, keys };
        } catch (error) {
            console.error('MongoDB read error:', error);
            return { users: [], keys: [] };
        }
    } else {
        // Fallback to JSON
        try {
            const data = fs.readFileSync(DB_FILE, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return { users: [], keys: [] };
        }
    }
}

async function writeDB(data) {
    if (mongoose.connection.readyState === 1) {
        // Using MongoDB - data is already saved via model operations
        // This function is kept for compatibility but MongoDB saves automatically
        return;
    } else {
        // Fallback to JSON
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    }
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

// Initialize everything (async)
(async () => {
    await initDB();
    await initInvites();
    initUpdatesDir();
})();

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
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, inviteCode } = req.body;
    
    // Input validation
    if (!username || !email || !password || !inviteCode) {
        return res.json({ success: false, message: 'All fields required, including invite code' });
    }
    
    // Validate invite code
    const invite = await isValidInvite(inviteCode);
    if (!invite) {
        return res.json({ success: false, message: 'Invalid or already used invite code. Registration is invite-only.' });
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
    
    try {
        const db = await readDB();
        
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
        const userData = {
            id: crypto.randomBytes(16).toString('hex'),
            username: username,
            email: email,
            password: hashPassword(password),
            createdAt: new Date().toISOString(),
            token: generateToken(),
            failedLogins: 0,
            lockedUntil: null
        };
        
        if (mongoose.connection.readyState === 1) {
            // Save to MongoDB
            console.log('💾 Saving user to MongoDB...');
            const user = new User(userData);
            await user.save();
            console.log(`✅ User saved to MongoDB: ${userData.username} (ID: ${userData.id})`);
        } else {
            // Save to JSON
            console.log('💾 Saving user to JSON file (MongoDB not connected)...');
            db.users.push(userData);
            await writeDB(db);
            console.log(`✅ User saved to JSON: ${userData.username}`);
        }
        
        // Mark invite as used
        await markInviteAsUsed(invite, userData.id);
        
        res.json({ 
            success: true, 
            message: 'Account created',
            token: userData.token,
            user: {
                id: userData.id,
                username: userData.username,
                email: userData.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.json({ success: false, message: 'Registration failed. Please try again.' });
    }
});

// Login with rate limiting
app.post('/api/auth/login', async (req, res) => {
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
    
    try {
        // Check for hardcoded admin account first (encrypted check)
        const adminUserEncrypted = Buffer.from(ADMIN_USERNAME).toString('base64');
        const adminPassEncrypted = Buffer.from(ADMIN_PASSWORD).toString('base64');
        const inputUserEncrypted = Buffer.from(username).toString('base64');
        const inputPassEncrypted = Buffer.from(password).toString('base64');
        
        if (inputUserEncrypted === adminUserEncrypted && inputPassEncrypted === adminPassEncrypted) {
            // Admin login - store token securely
            const adminToken = generateToken() + '_admin_' + Date.now();
            adminTokens.set(adminToken, {
                username: ADMIN_USERNAME,
                createdAt: Date.now(),
                lastAccess: Date.now()
            });
            
            // Cleanup old admin tokens
            cleanupAdminTokens();
            
            return res.json({
                success: true,
                token: adminToken,
                user: {
                    id: 'admin',
                    username: ADMIN_USERNAME,
                    email: 'admin@astreon.local',
                    isAdmin: true
                },
                isAdmin: true
            });
        }
        
        const db = await readDB();
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
        
        // Keep existing token - don't regenerate it (ensures C++ client credentials stay valid)
        // Only generate token if user doesn't have one (shouldn't happen, but safety check)
        if (!user.token) {
            user.token = generateToken();
        }
        user.lastLogin = new Date().toISOString();
        
        if (mongoose.connection.readyState === 1) {
            await User.updateOne({ id: user.id }, { lastLogin: user.lastLogin });
        } else {
            await writeDB(db);
        }
        
        res.json({ 
            success: true,
            token: user.token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.json({ success: false, message: 'Login failed. Please try again.' });
    }
});

// Verify token
app.post('/api/auth/verify', async (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Token required' });
    }
    
    try {
        // Check if admin token first
        if (isAdminToken(token)) {
            return res.json({
                success: true,
                user: {
                    id: 'admin',
                    username: ADMIN_USERNAME,
                    email: 'admin@astreon.local',
                    isAdmin: true
                },
                isAdmin: true
            });
        }
        
        const db = await readDB();
        
        // Check if database is empty
        if (!db.users || db.users.length === 0) {
            return res.json({ success: false, message: 'Database reset. Please login again.' });
        }
        
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Session expired. Please login again.' });
        }
        
        res.json({ 
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Verify error:', error);
        res.json({ success: false, message: 'Verification failed. Please try again.' });
    }
});

// ACCOUNT SETTINGS ROUTES

// Update password
app.post('/api/account/update-password', async (req, res) => {
    const { token, currentPassword, newPassword } = req.body;
    
    if (!token || !currentPassword || !newPassword) {
        return res.json({ success: false, message: 'All fields required' });
    }
    
    if (newPassword.length < 6 || newPassword.length > 100) {
        return res.json({ success: false, message: 'Password must be 6-100 characters' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        // Verify current password
        if (user.password !== hashPassword(currentPassword)) {
            return res.json({ success: false, message: 'Current password is incorrect' });
        }
        
        // Update password
        user.password = hashPassword(newPassword);
        
        if (mongoose.connection.readyState === 1) {
            await User.updateOne({ id: user.id }, { password: user.password });
        } else {
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Update password error:', error);
        res.json({ success: false, message: 'Failed to update password. Please try again.' });
    }
});

// Update email
app.post('/api/account/update-email', async (req, res) => {
    const { token, newEmail } = req.body;
    
    if (!token || !newEmail) {
        return res.json({ success: false, message: 'Email required' });
    }
    
    if (!validateEmail(newEmail)) {
        return res.json({ success: false, message: 'Invalid email format' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        // Check if email already exists
        const existingUser = db.users.find(u => 
            u.email.toLowerCase() === newEmail.toLowerCase() && u.id !== user.id
        );
        if (existingUser) {
            return res.json({ success: false, message: 'Email already registered' });
        }
        
        // Update email
        user.email = newEmail;
        
        if (mongoose.connection.readyState === 1) {
            await User.updateOne({ id: user.id }, { email: user.email });
        } else {
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'Email updated successfully', email: newEmail });
    } catch (error) {
        console.error('Update email error:', error);
        res.json({ success: false, message: 'Failed to update email. Please try again.' });
    }
});

// Update username
app.post('/api/account/update-username', async (req, res) => {
    const { token, newUsername } = req.body;
    
    if (!token || !newUsername) {
        return res.json({ success: false, message: 'Username required' });
    }
    
    if (!validateInput(newUsername, 30)) {
        return res.json({ success: false, message: 'Invalid username' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        // Check if username already exists
        const existingUser = db.users.find(u => 
            u.username.toLowerCase() === newUsername.toLowerCase() && u.id !== user.id
        );
        if (existingUser) {
            return res.json({ success: false, message: 'Username already taken' });
        }
        
        // Update username in user record
        user.username = newUsername;
        
        // Update username in all keys belonging to this user
        db.keys.forEach(key => {
            if (key.userId === user.id) {
                key.username = newUsername;
            }
        });
        
        if (mongoose.connection.readyState === 1) {
            await User.updateOne({ id: user.id }, { username: user.username });
            await Key.updateMany({ userId: user.id }, { username: user.username });
        } else {
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'Username updated successfully', username: newUsername });
    } catch (error) {
        console.error('Update username error:', error);
        res.json({ success: false, message: 'Failed to update username. Please try again.' });
    }
});

// Delete account
app.post('/api/account/delete', async (req, res) => {
    const { token, password } = req.body;
    
    if (!token || !password) {
        return res.json({ success: false, message: 'Password required to delete account' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        // Verify password
        if (user.password !== hashPassword(password)) {
            return res.json({ success: false, message: 'Incorrect password' });
        }
        
        // Delete all keys belonging to this user
        if (mongoose.connection.readyState === 1) {
            await Key.deleteMany({ userId: user.id });
            await User.deleteOne({ id: user.id });
        } else {
            db.keys = db.keys.filter(k => k.userId !== user.id);
            db.users = db.users.filter(u => u.id !== user.id);
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Delete account error:', error);
        res.json({ success: false, message: 'Failed to delete account. Please try again.' });
    }
});

// KEY MANAGEMENT ROUTES

// Generate key
app.post('/api/keys/generate', async (req, res) => {
    const { token, format, duration, amount } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        if (!format || !format.includes('*')) {
            return res.json({ success: false, message: 'Invalid format' });
        }
        
        const key = generateKey(format);
        // Don't set expiresAt on generation - it will start when first used
        const expiresAt = null;
        
        const keyEntry = {
            key: key,
            userId: user.id,
            username: user.username,
            format: format,
            duration: duration,
            amount: amount,
            expiresAt: expiresAt, // Will be set on first use
            createdAt: new Date().toISOString(),
            usedBy: null,
            usedAt: null,
            hwid: null,
            ip: null,
            lastCheck: null
        };
        
        if (mongoose.connection.readyState === 1) {
            const keyDoc = new Key(keyEntry);
            await keyDoc.save();
        } else {
            db.keys.push(keyEntry);
            await writeDB(db);
        }
        
        res.json({ success: true, key: key, data: keyEntry });
    } catch (error) {
        console.error('Generate key error:', error);
        res.json({ success: false, message: 'Failed to generate key. Please try again.' });
    }
});

// Get user's keys
app.post('/api/keys/list', async (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        // Get only this user's keys
        const userKeys = db.keys.filter(k => k.userId === user.id);
        
        res.json({ success: true, keys: userKeys });
    } catch (error) {
        console.error('List keys error:', error);
        res.json({ success: false, message: 'Failed to load keys. Please try again.' });
    }
});

// Get stats for user
app.post('/api/keys/stats', async (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    try {
        const db = await readDB();
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
    } catch (error) {
        console.error('Stats error:', error);
        res.json({ success: false, message: 'Failed to load stats. Please try again.' });
    }
});

// Add time to key (admin or owner)
app.post('/api/keys/addtime', async (req, res) => {
    const { token, key, duration, amount } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const isAdmin = isAdminToken(token);
    
    try {
        const db = await readDB();
        
        // Find key
        const keyEntry = db.keys.find(k => k.key === key);
        
        if (!keyEntry) {
            return res.json({ success: false, message: 'Key not found' });
        }
        
        // If not admin, check if user owns the key
        if (!isAdmin) {
            const user = db.users.find(u => u.token === token);
            if (!user) {
                return res.json({ success: false, message: 'Invalid authentication' });
            }
            if (keyEntry.userId !== user.id) {
                return res.json({ success: false, message: 'You do not have permission to modify this key' });
            }
        }
        
        keyEntry.expiresAt = addTimeToKey(keyEntry.expiresAt, duration, parseInt(amount));
        
        if (mongoose.connection.readyState === 1) {
            await Key.updateOne({ key: keyEntry.key }, { expiresAt: keyEntry.expiresAt });
        } else {
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'Time added', expiresAt: keyEntry.expiresAt });
    } catch (error) {
        console.error('Add time error:', error);
        res.json({ success: false, message: 'Failed to add time. Please try again.' });
    }
});

// Reset HWID (admin or owner)
app.post('/api/keys/resethwid', async (req, res) => {
    const { token, key } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    const isAdmin = isAdminToken(token);
    
    try {
        const db = await readDB();
        
        // Find key
        const keyEntry = db.keys.find(k => k.key === key);
        
        if (!keyEntry) {
            return res.json({ success: false, message: 'Key not found' });
        }
        
        // If not admin, check if user owns the key
        if (!isAdmin) {
            const user = db.users.find(u => u.token === token);
            if (!user) {
                return res.json({ success: false, message: 'Invalid authentication' });
            }
            if (keyEntry.userId !== user.id) {
                return res.json({ success: false, message: 'You do not have permission to modify this key' });
            }
        }
        
        keyEntry.hwid = null;
        keyEntry.usedBy = null;
        
        if (mongoose.connection.readyState === 1) {
            await Key.updateOne({ key: keyEntry.key }, { hwid: null, usedBy: null });
        } else {
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'HWID reset' });
    } catch (error) {
        console.error('Reset HWID error:', error);
        res.json({ success: false, message: 'Failed to reset HWID. Please try again.' });
    }
});

// Delete key (admin or owner)
app.delete('/api/keys/:key', async (req, res) => {
    const keyToDelete = req.params.key;
    const token = req.headers.authorization;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    // Check if admin token
    const isAdmin = isAdminToken(token);
    
    try {
        const db = await readDB();
        
        // Find key
        const keyEntry = db.keys.find(k => k.key === keyToDelete);
        
        if (!keyEntry) {
            return res.json({ success: false, message: 'Key not found' });
        }
        
        // If not admin, check if user owns the key
        if (!isAdmin) {
            const user = db.users.find(u => u.token === token);
            if (!user) {
                return res.json({ success: false, message: 'Invalid authentication' });
            }
            if (keyEntry.userId !== user.id) {
                return res.json({ success: false, message: 'You do not have permission to delete this key' });
            }
        }
        
        // Delete key
        if (mongoose.connection.readyState === 1) {
            await Key.deleteOne({ key: keyToDelete });
        } else {
            db.keys = db.keys.filter(k => k.key !== keyToDelete);
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'Key deleted' });
    } catch (error) {
        console.error('Delete key error:', error);
        res.json({ success: false, message: 'Failed to delete key. Please try again.' });
    }
});

// CLIENT VALIDATION (No auth required - used by C++ app)
app.post('/api/validate', async (req, res) => {
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
    
    try {
        const db = await readDB();
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
        
        // FIRST USE: Start countdown timer when key is first used
        const isFirstUse = !keyEntry.usedAt;
        if (isFirstUse && hwid) {
            // First time use - start expiration countdown NOW
            if (keyEntry.duration !== 'lifetime') {
                keyEntry.expiresAt = calculateExpiry(keyEntry.duration, parseInt(keyEntry.amount) || 1);
            }
            keyEntry.usedAt = now;
        }
        
        // HWID LOCK: Bind key to first HWID that uses it
        if (!keyEntry.hwid && hwid) {
            // First time use - bind to this HWID permanently
            keyEntry.usedBy = hwid;
            if (!keyEntry.usedAt) keyEntry.usedAt = now;
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
        
        if (mongoose.connection.readyState === 1) {
            await Key.updateOne({ key: keyEntry.key }, keyEntry);
        } else {
            await writeDB(db);
        }
        
        // Calculate time remaining
        let timeRemaining = null;
        let timeRemainingSeconds = null;
        if (keyEntry.expiresAt) {
            const expiry = new Date(keyEntry.expiresAt);
            const nowDate = new Date();
            timeRemainingSeconds = Math.max(0, Math.floor((expiry - nowDate) / 1000));
            
            if (timeRemainingSeconds > 0) {
                const days = Math.floor(timeRemainingSeconds / 86400);
                const hours = Math.floor((timeRemainingSeconds % 86400) / 3600);
                const minutes = Math.floor((timeRemainingSeconds % 3600) / 60);
                const seconds = timeRemainingSeconds % 60;
                
                if (days > 0) {
                    timeRemaining = `${days}d ${hours}h ${minutes}m`;
                } else if (hours > 0) {
                    timeRemaining = `${hours}h ${minutes}m ${seconds}s`;
                } else if (minutes > 0) {
                    timeRemaining = `${minutes}m ${seconds}s`;
                } else {
                    timeRemaining = `${seconds}s`;
                }
            } else {
                timeRemaining = "Expired";
            }
        }
        
        res.json({ 
            success: true, 
            message: 'Key valid',
            data: {
                duration: keyEntry.duration,
                amount: keyEntry.amount,
                expiresAt: keyEntry.expiresAt,
                timeRemaining: timeRemaining,
                timeRemainingSeconds: timeRemainingSeconds,
                hwid: keyEntry.hwid,
                ip: keyEntry.ip,
                usedAt: keyEntry.usedAt,
                createdAt: keyEntry.createdAt
            }
        });
    } catch (error) {
        console.error('Validate error:', error);
        res.json({ success: false, message: 'Validation failed. Please try again.' });
    }
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
    const url = process.env.RENDER_EXTERNAL_URL || 'https://answub-back.onrender.com';
    
    // Ping immediately on startup
    https.get(`${url}/api/health`, (res) => {
        console.log(`[Self-Ping] Initial ping: ${res.statusCode} at ${new Date().toISOString()}`);
    }).on('error', (err) => {
        console.error(`[Self-Ping] Initial ping error: ${err.message}`);
    });
    
    // Then ping every 14 minutes
    setInterval(() => {
        https.get(`${url}/api/health`, (res) => {
            console.log(`[Self-Ping] Status: ${res.statusCode} at ${new Date().toISOString()}`);
        }).on('error', (err) => {
            console.error(`[Self-Ping] Error: ${err.message}`);
        });
    }, 14 * 60 * 1000); // 14 minutes in milliseconds
    
    console.log('✅ Self-ping enabled - will ping every 14 minutes to keep server alive');
}

// Admin verification helper
function isAdminToken(token) {
    if (!token) return false;
    
    // Check if token is in admin tokens map
    if (adminTokens.has(token)) {
        const tokenData = adminTokens.get(token);
        
        // Check if token expired
        if (Date.now() - tokenData.createdAt > ADMIN_TOKEN_EXPIRY) {
            adminTokens.delete(token);
            return false;
        }
        
        // Update last access
        tokenData.lastAccess = Date.now();
        return true;
    }
    
    return false;
}

// Cleanup expired admin tokens
function cleanupAdminTokens() {
    const now = Date.now();
    for (const [token, data] of adminTokens.entries()) {
        if (now - data.createdAt > ADMIN_TOKEN_EXPIRY) {
            adminTokens.delete(token);
        }
    }
}

// Admin middleware
function requireAdmin(req, res, next) {
    const token = req.headers['authorization'] || req.body.token || req.query.token;
    
    if (!isAdminToken(token)) {
        return res.json({ success: false, message: 'Unauthorized: Admin access required' });
    }
    
    next();
}

// Bot-only middleware (stricter than admin - only bot API key works)
function requireBot(req, res, next) {
    // Check X-Bot-Api-Key header first (preferred), then Authorization, then body/query
    const token = req.headers['x-bot-api-key'] || req.headers['authorization'] || req.body.botApiKey || req.query.botApiKey;
    
    if (!token || token !== BOT_API_KEY) {
        console.log(`[SECURITY] Bot API key check failed. Provided: ${token ? token.substring(0, 10) + '...' : 'none'}`);
        return res.json({ success: false, message: 'Unauthorized: Bot API key required' });
    }
    
    next();
}

// Better admin check - verify admin credentials directly (for file upload)
function verifyAdmin(username, password) {
    const adminUserEncrypted = Buffer.from(ADMIN_USERNAME).toString('base64');
    const adminPassEncrypted = Buffer.from(ADMIN_PASSWORD).toString('base64');
    const inputUserEncrypted = Buffer.from(username).toString('base64');
    const inputPassEncrypted = Buffer.from(password).toString('base64');
    return inputUserEncrypted === adminUserEncrypted && inputPassEncrypted === adminPassEncrypted;
}

// FILE UPLOAD ENDPOINTS (Admin Only)

// Upload update file (admin only)
const multer = require('multer');
const upload = multer({ 
    dest: UPDATES_DIR,
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB max
});

app.post('/api/admin/upload', upload.single('file'), async (req, res) => {
    const { username, password, version, changelog } = req.body;
    
    // Verify admin
    if (!verifyAdmin(username, password)) {
        return res.json({ success: false, message: 'Unauthorized' });
    }
    
    if (!req.file) {
        return res.json({ success: false, message: 'No file uploaded' });
    }
    
    if (!version || version.trim() === '') {
        return res.json({ success: false, message: 'Version is required' });
    }
    
    // Rename file to a standard name
    const finalPath = path.join(UPDATES_DIR, 'latest.exe');
    if (fs.existsSync(finalPath)) {
        fs.unlinkSync(finalPath); // Delete old file
    }
    fs.renameSync(req.file.path, finalPath);
    
    // Save version info
    const updateInfo = {
        version: version.trim(),
        filename: 'latest.exe',
        size: req.file.size,
        uploadedAt: new Date().toISOString()
    };
    
    try {
        fs.writeFileSync(UPDATE_INFO_FILE, JSON.stringify(updateInfo, null, 2));
        console.log('Saved update info:', updateInfo);
    } catch (error) {
        console.error('Error saving update info:', error);
    }
    
    // Send Discord webhook notification
    const discordWebhookUrl = 'https://discord.com/api/webhooks/1447110036043071609/FOS8y4mOfXPRyG47NIXXMEFr1mLcmZyvLmwMcjw77sgfb4ym0FNHl3FQwnFPwFjLpR0K';
    const changelogText = changelog && changelog.trim() ? changelog.trim() : 'No changes specified';
    
    const embed = {
        title: 'Fortnite Private - Update Available',
        description: `Version ${updateInfo.version} is now available.`,
        color: 0x5865F2, // Dark blue/purple
        fields: [
            {
                name: 'Changes',
                value: changelogText,
                inline: false
            },
            {
                name: 'File Size',
                value: `${(updateInfo.size / 1024 / 1024).toFixed(2)} MB`,
                inline: true
            },
            {
                name: 'Released',
                value: new Date(updateInfo.uploadedAt).toLocaleString(),
                inline: true
            }
        ],
        footer: {
            text: 'Astreon'
        },
        timestamp: updateInfo.uploadedAt
    };
    
    const webhookPayload = {
        embeds: [embed],
        content: 'Run Fortnite Private loader again to update.'
    };
    
    // Send Discord webhook (non-blocking)
    try {
        const url = new URL(discordWebhookUrl);
        const postData = JSON.stringify(webhookPayload);
        
        const options = {
            hostname: url.hostname,
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const req = https.request(options, (res) => {
            if (res.statusCode !== 200 && res.statusCode !== 204) {
                console.error('Discord webhook returned status:', res.statusCode);
            }
        });
        
        req.on('error', (err) => {
            console.error('Failed to send Discord webhook:', err);
        });
        
        req.write(postData);
        req.end();
    } catch (err) {
        console.error('Error sending Discord webhook:', err);
    }
    
    res.json({ 
        success: true, 
        message: 'File uploaded successfully',
        version: updateInfo.version,
        filename: updateInfo.filename,
        size: updateInfo.size,
        uploadedAt: updateInfo.uploadedAt
    });
});

// Check for updates (public endpoint for C++ client)
app.get('/api/updates/check', (req, res) => {
    try {
        const updateFile = path.join(UPDATES_DIR, 'latest.exe');
        const clientVersion = req.query.version || '';
        
        if (fs.existsSync(updateFile)) {
            // Read version info
            let updateInfo = null;
            if (fs.existsSync(UPDATE_INFO_FILE)) {
                try {
                    updateInfo = JSON.parse(fs.readFileSync(UPDATE_INFO_FILE, 'utf8'));
                } catch (e) {
                    console.error('Error reading update info:', e);
                }
            }
            
            const stats = fs.statSync(updateFile);
            const serverVersion = updateInfo ? updateInfo.version : null;
            
            // Normalize versions for comparison (remove leading zeros, handle different formats)
            const normalizeVersion = (v) => {
                if (!v) return '';
                return v.trim().replace(/^0+/, '').replace(/\.0+$/, '') || '0';
            };
            
            const normalizedClient = normalizeVersion(clientVersion);
            const normalizedServer = normalizeVersion(serverVersion);
            
            // If client provided version and it matches server version, no update needed
            if (clientVersion && serverVersion && 
                (clientVersion.trim() === serverVersion.trim() || normalizedClient === normalizedServer)) {
                res.json({
                    success: true,
                    hasUpdate: false,
                    message: 'Already on latest version',
                    currentVersion: clientVersion,
                    serverVersion: serverVersion,
                    version: serverVersion // Include version even when no update
                });
            } else if (serverVersion) {
                // Update available - return server version
                res.json({
                    success: true,
                    hasUpdate: true,
                    version: serverVersion,
                    serverVersion: serverVersion, // Explicit server version
                    filename: 'latest.exe',
                    size: stats.size,
                    modifiedAt: stats.mtime.toISOString(),
                    downloadUrl: '/api/updates/download',
                    currentVersion: clientVersion || 'unknown'
                });
            } else {
                // Update file exists but no version info - still allow update
                res.json({
                    success: true,
                    hasUpdate: true,
                    filename: 'latest.exe',
                    size: stats.size,
                    modifiedAt: stats.mtime.toISOString(),
                    downloadUrl: '/api/updates/download'
                });
            }
        } else {
            // No update file - check if we have version info from previous upload
            let lastVersion = null;
            if (fs.existsSync(UPDATE_INFO_FILE)) {
                try {
                    const updateInfo = JSON.parse(fs.readFileSync(UPDATE_INFO_FILE, 'utf8'));
                    lastVersion = updateInfo.version;
                } catch (e) {
                    // Ignore error
                }
            }
            
            res.json({
                success: true,
                hasUpdate: false,
                serverVersion: lastVersion || null,
                version: lastVersion || null
            });
        }
    } catch (error) {
        console.error('Update check error:', error);
        res.json({
            success: false,
            hasUpdate: false,
            error: 'Failed to check for updates'
        });
    }
});

// ADMIN ENDPOINTS

// Get all users (admin only)
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const db = await readDB();
        const users = db.users.map(u => ({
            id: u.id,
            username: u.username,
            email: u.email,
            createdAt: u.createdAt,
            lastLogin: u.lastLogin || 'Never',
            keyCount: db.keys.filter(k => k.userId === u.id).length
        }));
        res.json({ success: true, users });
    } catch (error) {
        console.error('Get users error:', error);
        res.json({ success: false, message: 'Failed to fetch users' });
    }
});

// Get user details with all keys (admin only)
app.get('/api/admin/users/:userId', requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const db = await readDB();
        
        const user = db.users.find(u => u.id === userId);
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userKeys = db.keys.filter(k => k.userId === userId).map(k => ({
            key: k.key,
            format: k.format,
            duration: k.duration,
            amount: k.amount,
            expiresAt: k.expiresAt,
            createdAt: k.createdAt,
            usedBy: k.usedBy,
            usedAt: k.usedAt,
            hwid: k.hwid,
            ip: k.ip
        }));
        
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin || 'Never'
            },
            keys: userKeys,
            totalKeys: userKeys.length
        });
    } catch (error) {
        console.error('Get user details error:', error);
        res.json({ success: false, message: 'Failed to fetch user details' });
    }
});

// Delete user (admin only)
app.delete('/api/admin/users/:userId', requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const db = await readDB();
        
        // Remove user
        db.users = db.users.filter(u => u.id !== userId);
        
        // Remove all user's keys
        db.keys = db.keys.filter(k => k.userId !== userId);
        
        if (mongoose.connection.readyState === 1) {
            await User.deleteOne({ id: userId });
            await Key.deleteMany({ userId: userId });
        } else {
            await writeDB(db);
        }
        
        res.json({ success: true, message: 'User and all associated keys deleted' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.json({ success: false, message: 'Failed to delete user' });
    }
});

// Create user (admin only)
app.post('/api/admin/users', requireAdmin, async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.json({ success: false, message: 'Username, email, and password required' });
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
    
    try {
        const db = await readDB();
        
        // Check if username already exists
        const existingUser = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (existingUser) {
            return res.json({ success: false, message: 'Username already taken' });
        }
        
        // Check if email already exists
        const existingEmail = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (existingEmail) {
            return res.json({ success: false, message: 'Email already registered' });
        }
        
        const userData = {
            id: crypto.randomBytes(16).toString('hex'),
            username: username,
            email: email,
            password: hashPassword(password),
            createdAt: new Date().toISOString(),
            token: generateToken(),
            failedLogins: 0,
            lockedUntil: null
        };
        
        if (mongoose.connection.readyState === 1) {
            const user = new User(userData);
            await user.save();
        } else {
            db.users.push(userData);
            await writeDB(db);
        }
        
        res.json({
            success: true,
            message: 'User created successfully',
            user: {
                id: userData.id,
                username: userData.username,
                email: userData.email
            }
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.json({ success: false, message: 'Failed to create user' });
    }
});

// Get all invites (admin only) - returns all invites with codes and status
app.get('/api/admin/invites', requireAdmin, async (req, res) => {
    try {
        const invitesData = await readInvites();
        res.json({ 
            success: true, 
            invites: invitesData.invites || []
        });
    } catch (error) {
        console.error('Get invites error:', error);
        res.json({ success: false, message: 'Failed to fetch invites' });
    }
});

// Add invite codes (admin only)
app.post('/api/admin/invites', requireAdmin, async (req, res) => {
    const { count = 10 } = req.body;
    
    try {
        // Generate new invites
        const newInvites = [];
        const newHashes = [];
        for (let i = 0; i < count; i++) {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let invite = '';
            for (let j = 0; j < 8; j++) {
                invite += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            newInvites.push(invite);
            newHashes.push(hashInvite(invite));
        }
        
        if (mongoose.connection.readyState === 1) {
            // Save to MongoDB
            const invitesToAdd = newInvites.map((code, index) => ({
                hash: newHashes[index],
                codeEncrypted: encryptInviteCode(code),
                createdAt: new Date().toISOString(),
                isUsed: false
            }));
            await Invite.insertMany(invitesToAdd);
        } else {
            // Save to JSON file
            const invitesData = await readInvites();
            const existingInvites = invitesData.invites || [];
            const newInviteObjects = newInvites.map((code, index) => ({
                hash: newHashes[index],
                codeEncrypted: encryptInviteCode(code),
                createdAt: new Date().toISOString(),
                isUsed: false,
                usedBy: null,
                usedAt: null
            }));
            invitesData.invites = [...existingInvites, ...newInviteObjects];
            fs.writeFileSync(INVITES_FILE, JSON.stringify(invitesData, null, 2));
        }
        
        // Return plain text codes only once (for admin to see/save)
        res.json({ success: true, message: `${count} invite codes generated`, invites: newInvites });
    } catch (error) {
        console.error('Add invites error:', error);
        res.json({ success: false, message: 'Failed to generate invites' });
    }
});

// Delete invite code (admin only) - accepts either hash, plain code, or hash in query param
app.delete('/api/admin/invites/:invite', requireAdmin, async (req, res) => {
    const { invite } = req.params;
    const { hash } = req.query; // Allow hash to be passed as query parameter for "***" codes
    
    try {
        // Determine the hash to delete
        let inviteHash;
        if (hash && hash.length === 64) {
            // Hash provided in query parameter (for "***" codes)
            inviteHash = hash;
        } else if (invite.length === 64) {
            // Invite is already a hash
            inviteHash = invite;
        } else if (invite === '***') {
            // Can't delete "***" without hash - return error
            return res.json({ success: false, message: 'Cannot delete code. Please use the hash from the invite object.' });
        } else {
            // Plain code - hash it
            inviteHash = hashInvite(invite);
        }
        
        if (mongoose.connection.readyState === 1) {
            // Delete from MongoDB
            const result = await Invite.deleteOne({ hash: inviteHash });
            if (result.deletedCount === 0) {
                return res.json({ success: false, message: 'Invite code not found' });
            }
        } else {
            // Delete from JSON file
            const invitesData = await readInvites();
            const existingInvites = invitesData.invites || [];
            const filteredInvites = existingInvites.filter(i => {
                // Support both old format (string hash) and new format (object)
                if (typeof i === 'string') {
                    return i !== inviteHash;
                }
                return i.hash !== inviteHash;
            });
            
            if (filteredInvites.length === existingInvites.length) {
                return res.json({ success: false, message: 'Invite code not found' });
            }
            
            invitesData.invites = filteredInvites;
            fs.writeFileSync(INVITES_FILE, JSON.stringify(invitesData, null, 2));
        }
        
        res.json({ success: true, message: 'Invite code deleted' });
    } catch (error) {
        console.error('Delete invite error:', error);
        res.json({ success: false, message: 'Failed to delete invite' });
    }
});

// Bot-only key generation (no user account required, only bot can access)
app.post('/api/admin/keys/generate', requireBot, async (req, res) => {
    const { format, duration, amount } = req.body;
    
    if (!format || !format.includes('*')) {
        return res.json({ success: false, message: 'Invalid format. Must include * for random characters.' });
    }
    
    if (!duration || !['days', 'weeks', 'months', 'years'].includes(duration)) {
        return res.json({ success: false, message: 'Invalid duration. Must be: days, weeks, months, or years.' });
    }
    
    if (!amount || amount < 1) {
        return res.json({ success: false, message: 'Amount must be at least 1.' });
    }
    
    try {
        const key = generateKey(format);
        const expiresAt = null; // Will be set on first use
        
        const keyEntry = {
            key: key,
            userId: 'admin', // Special admin user ID
            username: 'Admin',
            format: format,
            duration: duration,
            amount: amount,
            expiresAt: expiresAt,
            createdAt: new Date().toISOString(),
            usedBy: null,
            usedAt: null,
            hwid: null,
            ip: null,
            lastCheck: null,
            hwidLocked: false
        };
        
        if (mongoose.connection.readyState === 1) {
            const keyDoc = new Key(keyEntry);
            await keyDoc.save();
        } else {
            const db = await readDB();
            db.keys.push(keyEntry);
            await writeDB(db);
        }
        
        res.json({ success: true, key: key, data: keyEntry });
    } catch (error) {
        console.error('Admin generate key error:', error);
        res.json({ success: false, message: 'Failed to generate key. Please try again.' });
    }
});

// Bot-only key list (all keys, only bot can access)
app.get('/api/admin/keys', requireBot, async (req, res) => {
    try {
        const db = await readDB();
        res.json({ success: true, keys: db.keys });
    } catch (error) {
        console.error('Admin list keys error:', error);
        res.json({ success: false, message: 'Failed to list keys.' });
    }
});

// Cleanup old invite codes (admin only) - keeps only specified codes
app.post('/api/admin/invites/cleanup', requireAdmin, async (req, res) => {
    const { keepCodes = [] } = req.body; // Array of codes to keep
    
    try {
        if (mongoose.connection.readyState === 1) {
            // MongoDB cleanup
            if (keepCodes.length > 0) {
                const keepHashes = keepCodes.map(code => hashInvite(code));
                const result = await Invite.deleteMany({ hash: { $nin: keepHashes } });
                res.json({ success: true, message: `Cleaned up ${result.deletedCount} invite codes`, deleted: result.deletedCount });
            } else {
                res.json({ success: false, message: 'No codes specified to keep' });
            }
        } else {
            // JSON file cleanup
            const invitesData = await readInvites();
            const existingInvites = invitesData.invites || [];
            
            if (keepCodes.length > 0) {
                const keepHashes = keepCodes.map(code => hashInvite(code));
                const filteredInvites = existingInvites.filter(i => {
                    const inviteHash = typeof i === 'string' ? i : i.hash;
                    return keepHashes.includes(inviteHash);
                });
                
                invitesData.invites = filteredInvites;
                fs.writeFileSync(INVITES_FILE, JSON.stringify(invitesData, null, 2));
                res.json({ 
                    success: true, 
                    message: `Cleaned up ${existingInvites.length - filteredInvites.length} invite codes`,
                    deleted: existingInvites.length - filteredInvites.length
                });
            } else {
                res.json({ success: false, message: 'No codes specified to keep' });
            }
        }
    } catch (error) {
        console.error('Cleanup invites error:', error);
        res.json({ success: false, message: 'Failed to cleanup invites' });
    }
});

// Download update file (public endpoint for C++ client)
app.get('/api/updates/download', (req, res) => {
    const updateFile = path.join(UPDATES_DIR, 'latest.exe');
    
    if (!fs.existsSync(updateFile)) {
        return res.status(404).json({ success: false, message: 'Update file not found' });
    }
    
    res.download(updateFile, 'update.exe', (err) => {
        if (err) {
            console.error('Download error:', err);
            res.status(500).json({ success: false, message: 'Download failed' });
        }
    });
});

// Cleanup old login attempts and admin tokens every hour
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of loginAttempts.entries()) {
        if (value.lockedUntil && now > value.lockedUntil) {
            loginAttempts.delete(key);
        }
    }
    cleanupAdminTokens();
}, 60 * 60 * 1000);

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Astreon Auth Server running on port ${PORT}`);
    console.log(`📁 Database: ${DB_FILE}`);
    console.log(`🔒 Security: Rate limiting enabled`);
    console.log(`🔒 Max login attempts: ${MAX_LOGIN_ATTEMPTS}`);
});
