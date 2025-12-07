const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const INVITES_FILE = path.join(__dirname, 'invites.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');

// MongoDB connection string (use environment variable or fallback to local JSON)
const MONGODB_URI = process.env.MONGODB_URI || null;

// Rate limiting storage (in-memory)
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// Middleware
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit payload size
app.use(express.static(path.join(__dirname, 'public')));

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

// Initialize messages file
function initMessages() {
    if (!fs.existsSync(MESSAGES_FILE)) {
        const initialMessages = {
            messages: [],
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(MESSAGES_FILE, JSON.stringify(initialMessages, null, 2));
    }
}

// Initialize invites file
function initInvites() {
    // Hardcoded random invite codes (8 characters each)
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
    
    if (!fs.existsSync(INVITES_FILE)) {
        const defaultInvites = { invites: hardcodedInvites };
        fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
        console.log(`✅ Initialized ${hardcodedInvites.length} invite codes`);
    } else {
        // Check if file is empty or has no invites
        try {
            const data = fs.readFileSync(INVITES_FILE, 'utf8');
            const invitesData = JSON.parse(data);
            if (!invitesData.invites || invitesData.invites.length === 0) {
                // File exists but is empty, use hardcoded invites
                const defaultInvites = { invites: hardcodedInvites };
                fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
                console.log(`✅ Initialized ${hardcodedInvites.length} invite codes`);
            }
        } catch (error) {
            // File is corrupted, create new one with hardcoded invites
            const defaultInvites = { invites: hardcodedInvites };
            fs.writeFileSync(INVITES_FILE, JSON.stringify(defaultInvites, null, 2));
            console.log(`✅ Initialized ${hardcodedInvites.length} invite codes`);
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
    initInvites();
    initMessages();
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
        
        // Generate new token
        user.token = generateToken();
        user.lastLogin = new Date().toISOString();
        
        if (mongoose.connection.readyState === 1) {
            await User.updateOne({ id: user.id }, { token: user.token, lastLogin: user.lastLogin });
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

// Add time to key
app.post('/api/keys/addtime', async (req, res) => {
    const { token, key, duration, amount } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        const keyEntry = db.keys.find(k => k.key === key && k.userId === user.id);
        
        if (!keyEntry) {
            return res.json({ success: false, message: 'Key not found' });
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

// Reset HWID
app.post('/api/keys/resethwid', async (req, res) => {
    const { token, key } = req.body;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    try {
        const db = await readDB();
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

// Delete key
app.delete('/api/keys/:key', async (req, res) => {
    const keyToDelete = req.params.key;
    const token = req.headers.authorization;
    
    if (!token) {
        return res.json({ success: false, message: 'Authentication required' });
    }
    
    try {
        const db = await readDB();
        const user = db.users.find(u => u.token === token);
        
        if (!user) {
            return res.json({ success: false, message: 'Invalid authentication' });
        }
        
        // Only delete if key belongs to user
        if (mongoose.connection.readyState === 1) {
            await Key.deleteOne({ key: keyToDelete, userId: user.id });
        } else {
            db.keys = db.keys.filter(k => !(k.key === keyToDelete && k.userId === user.id));
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
    const https = require('https');
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
