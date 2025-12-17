const API = 'https://answub-back.onrender.com/api';

function showRegister() {
    document.getElementById('login-form').classList.remove('active');
    document.getElementById('register-form').classList.add('active');
}

function showLogin() {
    document.getElementById('register-form').classList.remove('active');
    document.getElementById('login-form').classList.add('active');
}

async function register() {
    const inviteCode = document.getElementById('register-invite').value.trim();
    const username = document.getElementById('register-username').value.trim();
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    
    if (!inviteCode || !username || !email || !password) {
        alert('All fields are required, including invite code');
        return;
    }
    
    if (password.length < 6) {
        alert('Password must be at least 6 characters');
        return;
    }
    
    try {
        const response = await fetch(`${API}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, inviteCode })
        });
        
        const data = await response.json();
        
        if (data.success) {
            localStorage.setItem('artic_token', data.token);
            localStorage.setItem('artic_user', JSON.stringify(data.user));
            
            // Backup account data (encrypted/hidden) - only for recovery, not visible on web
            const backupData = {
                username: data.user.username,
                accountId: data.user.id,
                timestamp: Date.now()
            };
            // Store as base64 encoded to hide from casual inspection
            localStorage.setItem('_artic_backup', btoa(JSON.stringify(backupData)));
            
            // Redirect based on account type
            if (data.accountType === 'reseller') {
                window.location.href = 'reseller.html';
            } else {
                window.location.href = 'dashboard.html';
            }
        } else {
            alert(data.message);
        }
    } catch (error) {
        alert('Connection error. Server may be offline.');
    }
}

async function login() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    
    if (!username || !password) {
        alert('Username and password required');
        return;
    }
    
    try {
        const response = await fetch(`${API}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            localStorage.setItem('artic_token', data.token);
            localStorage.setItem('artic_user', JSON.stringify(data.user));
            
            // Backup account data (encrypted/hidden) - only for recovery, not visible on web
            const backupData = {
                username: data.user.username,
                accountId: data.user.id,
                timestamp: Date.now()
            };
            // Store as base64 encoded to hide from casual inspection
            localStorage.setItem('_artic_backup', btoa(JSON.stringify(backupData)));
            
            // Redirect based on account type
            if (data.accountType === 'reseller') {
                window.location.href = 'reseller.html';
            } else {
                window.location.href = 'dashboard.html';
            }
        } else {
            alert('Login failed: ' + (data.message || 'Invalid username or password. Please check your credentials.'));
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Connection error. Server may be offline. Please check your internet connection and try again.');
    }
}

// Clear any keys from localStorage (security)
function clearLocalKeys() {
    // Remove any keys that might be stored locally
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.includes('key') && key !== 'artic_token' && key !== 'artic_user') {
            keysToRemove.push(key);
        }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
}

// Enter key support
document.addEventListener('DOMContentLoaded', () => {
    // Clear any local keys (security measure)
    clearLocalKeys();
    
    document.getElementById('login-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') login();
    });
    
    document.getElementById('register-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') register();
    });
});

