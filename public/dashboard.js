const API = 'https://answub-back.onrender.com/api';

let currentModalKey = '';
let currentToken = '';
let currentUser = null;

// Security: Clear any keys from localStorage
function clearLocalKeys() {
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.includes('key') && key !== 'astreon_token' && key !== 'astreon_user') {
            keysToRemove.push(key);
        }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
}

// Check authentication
async function checkAuth() {
    // Clear any local keys on page load (security)
    clearLocalKeys();
    
    currentToken = localStorage.getItem('astreon_token');
    const userStr = localStorage.getItem('astreon_user');
    
    if (!currentToken || !userStr) {
        // No auth, redirect to login
        window.location.href = 'index.html';
        return false;
    }
    
    try {
        currentUser = JSON.parse(userStr);
    } catch (e) {
        // Invalid user data
        localStorage.removeItem('astreon_token');
        localStorage.removeItem('astreon_user');
        window.location.href = 'index.html';
        return false;
    }
    
    // Verify token is still valid
    try {
        const response = await fetch(`${API}/auth/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken })
        });
        
        const data = await response.json();
        
        // Check if user is a reseller and redirect
        if (data.success && data.accountType === 'reseller') {
            window.location.href = 'reseller.html';
            return false;
        }
        
        if (!data.success) {
            // Token invalid - show helpful message
            if (data.message) {
                if (data.message.includes('Database reset') || data.message.includes('Session expired')) {
                    // Check if we have backup data - try to restore session
                    const backupStr = localStorage.getItem('_astreon_backup');
                    if (backupStr) {
                        try {
                            const backupData = JSON.parse(atob(backupStr));
                            // Try to restore using backup token
                            if (backupData.token) {
                                // Verify backup token
                                fetch(`${API}/auth/verify`, {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ token: backupData.token })
                                })
                                .then(res => res.json())
                                .then(verifyData => {
                                    if (verifyData.success) {
                                        // Backup token still valid - restore session
                                        localStorage.setItem('astreon_token', backupData.token);
                                        localStorage.setItem('astreon_user', JSON.stringify(verifyData.user));
                                        window.location.reload();
                                    } else {
                                        alert(`Your session expired. Your account "${backupData.username}" may still exist. Please try logging in again.`);
                                    }
                                })
                                .catch(() => {
                                    alert(`Your session expired. Your account "${backupData.username}" may still exist. Please try logging in again.`);
                                });
                                return false; // Don't logout yet, wait for restore attempt
                            } else {
                                alert(`Your session expired. Your account "${backupData.username}" may still exist. Please try logging in again.`);
                            }
                        } catch (e) {
                            alert('Your session expired. Please login again.');
                        }
                    } else {
                        alert('Your session expired. Please login again.');
                    }
                } else {
                    console.error('Auth error:', data.message);
                }
            }
            logout();
            return false;
        }
        
        const usernameDisplay = document.getElementById('username-display');
        const overviewUsername = document.getElementById('overview-username');
        if (usernameDisplay) usernameDisplay.textContent = currentUser.username;
        if (overviewUsername) overviewUsername.textContent = currentUser.username;
        
        // Display account credentials (check if elements exist)
        const accountIdEl = document.getElementById('account-id');
        const apiTokenEl = document.getElementById('api-token');
        const accountUsernameEl = document.getElementById('account-username');
        const codeAccountId = document.getElementById('code-account-id');
        const codeApiToken = document.getElementById('code-api-token');
        
        if (accountIdEl) accountIdEl.textContent = currentUser.id;
        if (apiTokenEl) apiTokenEl.textContent = currentToken;
        if (accountUsernameEl) accountUsernameEl.textContent = currentUser.username;
        if (codeAccountId) codeAccountId.textContent = currentUser.id;
        if (codeApiToken) codeApiToken.textContent = currentToken;
        
        return true;
    } catch (error) {
        console.error('Auth check failed:', error);
        return false;
    }
}

function logout() {
    // Clear all auth data and any cached keys
    // Keep backup data for recovery (hidden, not visible on web)
    const backupData = localStorage.getItem('_astreon_backup');
    localStorage.clear();
    sessionStorage.clear();
    if (backupData) {
        localStorage.setItem('_astreon_backup', backupData);
    }
    window.location.href = 'index.html';
}

// Toggle amount input based on duration
document.getElementById('duration')?.addEventListener('change', function() {
    const amountGroup = document.getElementById('amount-group');
    if (this.value === 'lifetime') {
        amountGroup.style.display = 'none';
    } else {
        amountGroup.style.display = 'block';
    }
});

// Load stats
async function loadStats() {
    try {
        const response = await fetch(`${API}/keys/stats`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('stat-total').textContent = data.stats.total;
            document.getElementById('stat-active').textContent = data.stats.active;
            document.getElementById('stat-used').textContent = data.stats.used;
            document.getElementById('stat-expired').textContent = data.stats.expired;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load saved key generation preferences
function loadKeyPreferences() {
    const savedFormat = localStorage.getItem('astreon_key_format');
    const savedDuration = localStorage.getItem('astreon_key_duration');
    const savedAmount = localStorage.getItem('astreon_key_amount');
    
    if (savedFormat) {
        document.getElementById('format').value = savedFormat;
    }
    if (savedDuration) {
        document.getElementById('duration').value = savedDuration;
    }
    if (savedAmount) {
        document.getElementById('amount').value = savedAmount;
    }
}

// Save key generation preferences
function saveKeyPreferences(format, duration, amount) {
    localStorage.setItem('astreon_key_format', format);
    localStorage.setItem('astreon_key_duration', duration);
    localStorage.setItem('astreon_key_amount', amount);
}

// Generate key
async function generateKey() {
    const format = document.getElementById('format').value;
    const duration = document.getElementById('duration').value;
    const amount = document.getElementById('amount').value;
    
    if (!format || !format.includes('*')) {
        alert('Format must include at least one * for random characters');
        return;
    }
    
    // Save preferences for next time
    saveKeyPreferences(format, duration, amount);
    
    try {
        const response = await fetch(`${API}/keys/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken, format, duration, amount })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('generated-key').textContent = data.key;
            document.getElementById('generated-result').style.display = 'block';
            
            let info = `Duration: ${duration === 'lifetime' ? 'Lifetime' : `${amount} ${duration}(s)`}`;
            if (data.data.expiresAt) {
                info += ` | Expires: ${new Date(data.data.expiresAt).toLocaleString()}`;
            }
            document.getElementById('key-info').textContent = info;
            
            loadKeys();
            loadStats();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Connection error. Make sure server is running.');
    }
}

// Copy key to clipboard
function copyKey() {
    const key = document.getElementById('generated-key').textContent;
    navigator.clipboard.writeText(key).then(() => {
        alert('Key copied!');
    });
}

// Copy credential to clipboard
function copyCredential(elementId) {
    const value = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(value).then(() => {
        alert('Copied to clipboard!');
    });
}

// Load all keys
async function loadKeys() {
    try {
        const response = await fetch(`${API}/keys/list`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const tbody = document.getElementById('keys-table');
            tbody.innerHTML = '';
            
            if (data.keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="loading">No keys generated yet</td></tr>';
                return;
            }
            
            const sortedKeys = data.keys.sort((a, b) => 
                new Date(b.createdAt) - new Date(a.createdAt)
            );
            
            sortedKeys.forEach(key => {
                const tr = document.createElement('tr');
                
                let status = 'Active';
                let statusClass = 'status-active';
                
                if (key.expiresAt) {
                    const expiry = new Date(key.expiresAt);
                    if (expiry < new Date()) {
                        status = 'Expired';
                        statusClass = 'status-expired';
                    }
                }
                
                if (key.usedBy) {
                    status = 'Used';
                    statusClass = 'status-used';
                }
                
                const expiryText = key.expiresAt 
                    ? new Date(key.expiresAt).toLocaleString() 
                    : 'Never';
                
                const ip = key.ip || '-';
                const lastCheck = key.lastCheck 
                    ? new Date(key.lastCheck).toLocaleString() 
                    : '-';
                
                // HWID Lock display with hover tooltip
                let hwidDisplay = '';
                if (key.hwid) {
                    hwidDisplay = `
                        <div class="hwid-container">
                            <span class="hwid-indicator"><i class="fas fa-lock"></i> Locked</span>
                            <div class="hwid-tooltip">
                                <code>${key.hwid}</code>
                            </div>
                        </div>
                    `;
                } else {
                    hwidDisplay = '<span class="hwid-indicator"><i class="fas fa-unlock"></i> Not Locked</span>';
                }
                
                tr.innerHTML = `
                    <td><code>${key.key}</code></td>
                    <td><span class="status ${statusClass}">${status}</span></td>
                    <td>${expiryText}</td>
                    <td>${hwidDisplay}</td>
                    <td>${ip}</td>
                    <td>${new Date(key.createdAt).toLocaleString()}</td>
                    <td>${lastCheck}</td>
                    <td>
                        <div class="table-actions">
                            <button class="table-action-btn" onclick="openAddTimeModal('${key.key}')" title="Add Time"><i class="fas fa-clock"></i></button>
                            <button class="table-action-btn" onclick="resetHWID('${key.key}')" ${!key.hwid ? 'disabled' : ''} title="Reset HWID"><i class="fas fa-unlock-alt"></i></button>
                            <button class="table-action-btn table-action-btn-danger" onclick="deleteKey('${key.key}')" title="Delete"><i class="fas fa-trash"></i></button>
                        </div>
                    </td>
                `;
                
                tbody.appendChild(tr);
            });
        }
    } catch (error) {
        console.error('Error loading keys:', error);
    }
}

// Open add time modal
function openAddTimeModal(key) {
    if (!key) return;
    currentModalKey = key;
    const modal = document.getElementById('addTimeModal');
    const modalKey = document.getElementById('modal-key');
    if (modal && modalKey) {
        modalKey.textContent = key;
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
}

// Close add time modal
function closeAddTimeModal() {
    const modal = document.getElementById('addTimeModal');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
    currentModalKey = '';
}

// Add time to key
async function addTime() {
    const duration = document.getElementById('modal-duration').value;
    const amount = document.getElementById('modal-amount').value;
    
    if (!amount || amount < 1) {
        alert('Please enter a valid amount');
        return;
    }
    
    try {
        const response = await fetch(`${API}/keys/addtime`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken, key: currentModalKey, duration, amount })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`Added ${amount} ${duration}(s) to key`);
            closeAddTimeModal();
            loadKeys();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Error adding time');
    }
}

// Reset HWID
async function resetHWID(key) {
    if (!confirm(`Reset HWID for key: ${key}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/keys/resethwid`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken, key })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('HWID reset successfully');
            loadKeys();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Error resetting HWID');
    }
}

// Delete key
async function deleteKey(key) {
    if (!confirm(`Delete key: ${key}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/keys/${encodeURIComponent(key)}`, {
            method: 'DELETE',
            headers: {
                'Authorization': currentToken
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            loadKeys();
            loadStats();
        } else {
            alert('Error deleting key');
        }
    } catch (error) {
        alert('Error deleting key');
    }
}

// Close modal when clicking outside
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('addTimeModal');
    if (modal) {
        // Ensure modal is hidden on page load
        modal.style.display = 'none';
        modal.classList.remove('active');
        
        // Close when clicking outside
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeAddTimeModal();
            }
        });
        
        // Close on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && modal.classList.contains('active')) {
                closeAddTimeModal();
            }
        });
    }
});

// User menu toggle
function toggleUserMenu() {
    const dropdown = document.getElementById('userMenuDropdown');
    const trigger = document.querySelector('.user-menu-trigger');
    if (dropdown) {
        dropdown.classList.toggle('show');
        trigger.classList.toggle('active');
    }
}

// Close user menu when clicking outside
document.addEventListener('click', (e) => {
    const userMenu = document.querySelector('.user-menu');
    if (userMenu && !userMenu.contains(e.target)) {
        const dropdown = document.getElementById('userMenuDropdown');
        const trigger = document.querySelector('.user-menu-trigger');
        if (dropdown) {
            dropdown.classList.remove('show');
            trigger.classList.remove('active');
        }
    }
});

// Tab navigation
function showTab(tabName) {
    // Load saved preferences when showing generate tab
    if (tabName === 'generate') {
        loadKeyPreferences();
    }
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab
    const tabElement = document.getElementById(tabName + '-tab');
    if (tabElement) {
        tabElement.classList.add('active');
    }
    
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab') === tabName) {
            item.classList.add('active');
        }
    });
    
    // Load data if needed
    if (tabName === 'keys') {
        loadKeys();
    } else if (tabName === 'overview') {
        loadStats();
    } else if (tabName === 'admin' && currentUser && currentUser.isAdmin) {
        loadAdminUsers();
        loadAdminResellers();
        loadAdminInvites();
        checkUpdateInfo();
    }
    
    // Close user menu if open
    const dropdown = document.getElementById('userMenuDropdown');
    const trigger = document.querySelector('.user-menu-trigger');
    if (dropdown && dropdown.classList.contains('show')) {
        dropdown.classList.remove('show');
        trigger.classList.remove('active');
    }
}

// Copy to clipboard (for credentials)
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success notification
        const notification = document.createElement('div');
        notification.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #0d1117; border: 1px solid #3fb950; color: #3fb950; padding: 16px 24px; border-radius: 8px; z-index: 10001; box-shadow: 0 4px 12px rgba(0,0,0,0.3);';
        notification.innerHTML = '<i class="fas fa-check-circle"></i> Copied to clipboard!';
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }).catch(() => {
        alert('Failed to copy. Please select and copy manually.');
    });
}

// Copy code to clipboard
function copyCode(elementId) {
    const codeElement = document.getElementById(elementId);
    // Get text content (strips HTML tags)
    const text = codeElement.textContent || codeElement.innerText;
    
    // Replace placeholders with actual values
    let finalText = text;
    if (currentUser && currentUser.id) {
        finalText = finalText.replace(/YOUR_ACCOUNT_ID/g, currentUser.id);
    }
    if (currentToken) {
        finalText = finalText.replace(/YOUR_API_TOKEN/g, currentToken);
    }
    
    navigator.clipboard.writeText(finalText).then(() => {
        // Show success notification
        const notification = document.createElement('div');
        notification.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #0d1117; border: 1px solid #3fb950; color: #3fb950; padding: 16px 24px; border-radius: 8px; z-index: 10001; box-shadow: 0 4px 12px rgba(0,0,0,0.3);';
        notification.innerHTML = '<i class="fas fa-check-circle"></i> Code copied to clipboard!';
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }).catch(() => {
        alert('Failed to copy. Please select and copy manually.');
    });
}

// Show file content in modal
async function showFile(filename) {
    try {
        // Try to fetch from current domain first (frontend deployment)
        let response = await fetch(`/${filename}`);
        
        // If not found, try backend
        if (!response.ok) {
            response = await fetch(`${API.replace('/api', '')}/${filename}`);
        }
        
        if (!response.ok) {
            // If still not found, show instructions
            alert(`To view ${filename}:\n\n1. Go to your local project folder\n2. Open ${filename} in your editor\n\nThese files are in the frontend folder.`);
            return;
        }
        
        const content = await response.text();
        
        // Create modal to display file
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'flex';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 90%; max-height: 90vh; overflow: auto;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid #30363d;">
                    <h2 style="margin: 0; color: #c9d1d9;"><i class="fas fa-file-code"></i> ${filename}</h2>
                    <button onclick="this.closest('.modal').remove()" style="background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 16px; border-radius: 6px; cursor: pointer;">
                        <i class="fas fa-times"></i> Close
                    </button>
                </div>
                <pre style="background: #0d1117; padding: 20px; border-radius: 8px; overflow-x: auto; border: 1px solid #30363d;"><code style="color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.6;">${escapeHtml(content)}</code></pre>
            </div>
        `;
        document.body.appendChild(modal);
        
        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
    } catch (error) {
        alert(`To view ${filename}:\n\n1. Go to your local project folder\n2. Open ${filename} in your editor\n\nThese files are in the root of your Astreon auth folder.`);
    }
}

// Escape HTML for safe display
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Download file
async function downloadFile(filename) {
    try {
        // Try to fetch from current domain first (frontend deployment)
        let response = await fetch(`/${filename}`);
        
        // If not found, try backend
        if (!response.ok) {
            response = await fetch(`${API.replace('/api', '')}/${filename}`);
        }
        
        if (!response.ok) {
            alert(`To download ${filename}:\n\n1. Go to your local project folder\n2. Copy ${filename} from the frontend folder\n3. Add it to your C++ project`);
            return;
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        
        // Cleanup
        setTimeout(() => {
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        }, 100);
    } catch (error) {
        alert(`To download ${filename}:\n\n1. Go to your local project folder\n2. Copy ${filename} from the frontend folder\n3. Add it to your C++ project`);
    }
}

// Update username
async function updateUsername() {
    const newUsername = document.getElementById('new-username').value.trim();
    
    if (!newUsername) {
        alert('Please enter a new username');
        return;
    }
    
    if (newUsername.length < 3 || newUsername.length > 30) {
        alert('Username must be 3-30 characters');
        return;
    }
    
    if (!confirm(`Change username to "${newUsername}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/account/update-username`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken, newUsername: newUsername })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Username updated successfully!');
            document.getElementById('new-username').value = '';
            document.getElementById('username-display').textContent = newUsername;
            document.getElementById('account-username').textContent = newUsername;
            currentUser.username = newUsername;
            localStorage.setItem('astreon_user', JSON.stringify(currentUser));
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Connection error. Make sure server is running.');
    }
}

// Update email
async function updateEmail() {
    const newEmail = document.getElementById('new-email').value.trim();
    
    if (!newEmail) {
        alert('Please enter a new email');
        return;
    }
    
    if (!confirm(`Change email to "${newEmail}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/account/update-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken, newEmail: newEmail })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Email updated successfully!');
            document.getElementById('new-email').value = '';
            currentUser.email = newEmail;
            localStorage.setItem('astreon_user', JSON.stringify(currentUser));
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Connection error. Make sure server is running.');
    }
}

// Update password
async function updatePassword() {
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    
    if (!currentPassword || !newPassword) {
        alert('Please fill in all fields');
        return;
    }
    
    if (newPassword.length < 6) {
        alert('New password must be at least 6 characters');
        return;
    }
    
    if (!confirm('Change your password?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/account/update-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                token: currentToken, 
                currentPassword: currentPassword,
                newPassword: newPassword 
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Password updated successfully!');
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Connection error. Make sure server is running.');
    }
}

// Delete account
async function deleteAccount() {
    const password = document.getElementById('delete-password').value;
    
    if (!password) {
        alert('Please enter your password to confirm');
        return;
    }
    
    if (!confirm('⚠️ WARNING: This will permanently delete your account and ALL your license keys!\n\nThis action CANNOT be undone!\n\nAre you absolutely sure?')) {
        return;
    }
    
    if (!confirm('Last chance! Are you 100% sure you want to delete your account?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/account/delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken, password: password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Account deleted successfully. You will be logged out.');
            logout();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Connection error. Make sure server is running.');
    }
}

// Admin functions
async function loadAdminUsers() {
    const listDiv = document.getElementById('admin-users-list');
    if (!listDiv) return;
    
    try {
        const response = await fetch(`${API}/admin/users`, {
            method: 'GET',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.users) {
            if (data.users.length === 0) {
                listDiv.innerHTML = '<div style="color: #888888; text-align: center; padding: 2rem;">No users found</div>';
                return;
            }
            
            let html = '<div class="admin-table-container"><table class="admin-table"><thead><tr>';
            html += '<th>Username</th><th>Email</th><th>Keys</th><th>Created</th><th>Last Login</th><th>Actions</th>';
            html += '</tr></thead><tbody>';
            
            data.users.forEach(user => {
                html += `<tr>
                    <td><strong>${escapeHtml(user.username)}</strong></td>
                    <td>${escapeHtml(user.email)}</td>
                    <td>${user.keyCount}</td>
                    <td>${new Date(user.createdAt).toLocaleDateString()}</td>
                    <td>${user.lastLogin === 'Never' ? 'Never' : new Date(user.lastLogin).toLocaleDateString()}</td>
                    <td>
                        <button class="btn btn-secondary" onclick="viewUserDetails('${user.id}')" title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-danger" onclick="deleteUser('${user.id}', '${escapeHtml(user.username)}')" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            });
            
            html += '</tbody></table></div>';
            listDiv.innerHTML = html;
        } else {
            listDiv.innerHTML = '<div style="color: #ef4444;">Failed to load users</div>';
        }
    } catch (error) {
        listDiv.innerHTML = '<div style="color: #ef4444;">Error loading users</div>';
    }
}

async function viewUserDetails(userId) {
    const modal = document.getElementById('userDetailsModal');
    const content = document.getElementById('userDetailsContent');
    const title = document.getElementById('userDetailsTitle');
    
    modal.style.display = 'flex';
    content.innerHTML = '<div class="loading">Loading...</div>';
    
    try {
        const response = await fetch(`${API}/admin/users/${userId}`, {
            method: 'GET',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            title.textContent = `User: ${data.user.username}`;
            
            let html = `<div class="user-details-section">
                <h4>User Information</h4>
                <p><strong>ID:</strong> ${data.user.id}</p>
                <p><strong>Username:</strong> ${escapeHtml(data.user.username)}</p>
                <p><strong>Email:</strong> ${escapeHtml(data.user.email)}</p>
                <p><strong>Created:</strong> ${new Date(data.user.createdAt).toLocaleString()}</p>
                <p><strong>Last Login:</strong> ${data.user.lastLogin === 'Never' ? 'Never' : new Date(data.user.lastLogin).toLocaleString()}</p>
                ${data.user.accountType ? `<p><strong>Account Type:</strong> ${escapeHtml(data.user.accountType)}</p>` : ''}
                ${data.user.balance !== undefined ? `<p><strong>Balance:</strong> $${parseFloat(data.user.balance || 0).toFixed(2)}</p>` : ''}
            </div>`;
            
            // Admin-only credentials section
            if (data.user.token) {
                html += `<div class="user-details-section" style="background: #1a1a1a; border: 1px solid #3fb950; border-radius: 8px; padding: 1.5rem; margin-top: 1.5rem;">
                    <h4 style="color: #3fb950; margin-bottom: 1rem;">
                        <i class="fas fa-key"></i> Account Credentials (Admin Only)
                    </h4>
                    <div style="margin-bottom: 1rem;">
                        <label style="display: block; color: #888888; font-size: 0.875rem; margin-bottom: 0.5rem;">Account ID</label>
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <code style="flex: 1; background: #0d1117; padding: 0.75rem; border-radius: 6px; border: 1px solid #30363d; font-size: 0.875rem; word-break: break-all;">${escapeHtml(data.user.id)}</code>
                            <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${escapeHtml(data.user.id)}')" title="Copy Account ID">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    </div>
                    <div>
                        <label style="display: block; color: #888888; font-size: 0.875rem; margin-bottom: 0.5rem;">API Token</label>
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <code style="flex: 1; background: #0d1117; padding: 0.75rem; border-radius: 6px; border: 1px solid #30363d; font-size: 0.875rem; word-break: break-all;">${escapeHtml(data.user.token)}</code>
                            <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${escapeHtml(data.user.token)}')" title="Copy API Token">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    </div>
                    <div style="margin-top: 1rem; padding: 0.75rem; background: #161b22; border-radius: 6px; border-left: 3px solid #3fb950;">
                        <p style="color: #888888; font-size: 0.875rem; margin: 0;">
                            <i class="fas fa-info-circle"></i> Use these credentials to integrate with the authentication system. These are only visible to admins.
                        </p>
                    </div>
                </div>`;
            }
            
            if (data.keys && data.keys.length > 0) {
                html += `<div class="user-details-section">
                    <h4>Keys (${data.keys.length})</h4>
                    <div class="admin-table-container">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>Key</th>
                                    <th>Duration</th>
                                    <th>Expires</th>
                                    <th>HWID</th>
                                    <th>IP</th>
                                    <th>Used At</th>
                                </tr>
                            </thead>
                            <tbody>`;
                
                data.keys.forEach(key => {
                    html += `<tr>
                        <td><code style="font-size: 0.75rem;">${escapeHtml(key.key)}</code></td>
                        <td>${key.amount || ''} ${key.duration || ''}</td>
                        <td>${key.expiresAt ? new Date(key.expiresAt).toLocaleDateString() : 'Never'}</td>
                        <td><code style="font-size: 0.7rem;">${key.hwid || 'Not locked'}</code></td>
                        <td>${key.ip || 'N/A'}</td>
                        <td>${key.usedAt ? new Date(key.usedAt).toLocaleString() : 'Never'}</td>
                    </tr>`;
                });
                
                html += `</tbody></table></div></div>`;
            } else {
                html += '<div class="user-details-section"><p style="color: #888888;">No keys found</p></div>';
            }
            
            content.innerHTML = html;
        } else {
            content.innerHTML = '<div style="color: #ef4444;">Failed to load user details</div>';
        }
    } catch (error) {
        content.innerHTML = '<div style="color: #ef4444;">Error loading user details</div>';
    }
}

function closeUserDetailsModal() {
    document.getElementById('userDetailsModal').style.display = 'none';
}

async function deleteUser(userId, username) {
    if (!confirm(`⚠️ Delete user "${username}"?\n\nThis will permanently delete the user and ALL their license keys!\n\nThis action CANNOT be undone!`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('User deleted successfully');
            loadAdminUsers();
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Error deleting user');
    }
}

function showCreateUserModal() {
    document.getElementById('createUserModal').style.display = 'flex';
    document.getElementById('new-user-account-type').value = 'user';
    document.getElementById('new-user-username').value = '';
    document.getElementById('new-user-email').value = '';
    document.getElementById('new-user-password').value = '';
    document.getElementById('new-user-balance').value = '0';
    document.getElementById('user-product-private').checked = true;
    document.getElementById('user-product-public').checked = false;
    toggleUserTypeFields();
    document.getElementById('create-user-status').innerHTML = '';
}

function toggleUserTypeFields() {
    const accountType = document.getElementById('new-user-account-type').value;
    const resellerFields = document.getElementById('reseller-fields');
    if (accountType === 'reseller') {
        resellerFields.style.display = 'block';
    } else {
        resellerFields.style.display = 'none';
    }
}

function closeCreateUserModal() {
    document.getElementById('createUserModal').style.display = 'none';
}

async function createUser() {
    const accountType = document.getElementById('new-user-account-type').value;
    const username = document.getElementById('new-user-username').value.trim();
    const email = document.getElementById('new-user-email').value.trim();
    const password = document.getElementById('new-user-password').value;
    const statusDiv = document.getElementById('create-user-status');
    
    if (!username || !email || !password) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">All fields required</div>';
        return;
    }
    
    if (password.length < 6) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Password must be at least 6 characters</div>';
        return;
    }
    
    // Validate reseller fields if account type is reseller
    if (accountType === 'reseller') {
        const allowedProducts = [];
        if (document.getElementById('user-product-private').checked) {
            allowedProducts.push('private');
        }
        if (document.getElementById('user-product-public').checked) {
            allowedProducts.push('public');
        }
        
        if (allowedProducts.length === 0) {
            statusDiv.innerHTML = '<div style="color: #ef4444;">At least one product must be selected for resellers</div>';
            return;
        }
    }
    
    statusDiv.innerHTML = '<div style="color: #888888;">Creating user...</div>';
    
    try {
        const requestBody = {
            username,
            email,
            password,
            accountType
        };
        
        // Add reseller-specific fields
        if (accountType === 'reseller') {
            requestBody.initialBalance = parseFloat(document.getElementById('new-user-balance').value) || 0;
            const allowedProducts = [];
            if (document.getElementById('user-product-private').checked) {
                allowedProducts.push('private');
            }
            if (document.getElementById('user-product-public').checked) {
                allowedProducts.push('public');
            }
            requestBody.allowedProducts = allowedProducts;
        }
        
        const response = await fetch(`${API}/admin/users`, {
            method: 'POST',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusDiv.innerHTML = '<div style="color: #22c55e;">✅ User created successfully!</div>';
            setTimeout(() => {
                closeCreateUserModal();
                loadAdminUsers();
                if (accountType === 'reseller') {
                    loadAdminResellers();
                }
            }, 1000);
        } else {
            statusDiv.innerHTML = `<div style="color: #ef4444;">❌ Error: ${data.message}</div>`;
        }
    } catch (error) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">❌ Error creating user</div>';
    }
}

async function loadAdminInvites() {
    const listDiv = document.getElementById('admin-invites-list');
    if (!listDiv) return;
    
    try {
        const response = await fetch(`${API}/admin/invites`, {
            method: 'GET',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.invites) {
            const invites = data.invites || [];
            
            if (invites.length === 0) {
                listDiv.innerHTML = '<div style="color: #888888; text-align: center; padding: 2rem;">No invite codes</div>';
                return;
            }
            
            const usedCount = invites.filter(inv => inv.isUsed).length;
            const unusedCount = invites.length - usedCount;
            
            let html = `<div style="margin-bottom: 1rem; display: flex; gap: 1rem; color: #888888; font-size: 0.875rem;">
                <span>Total: <strong>${invites.length}</strong></span>
                <span>Used: <strong style="color: #ef4444;">${usedCount}</strong></span>
                <span>Available: <strong style="color: #22c55e;">${unusedCount}</strong></span>
            </div>`;
            
            html += '<div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse;">';
            html += '<thead><tr style="border-bottom: 1px solid #1a1a1a;">';
            html += '<th style="padding: 0.75rem; text-align: left; color: #888888; font-size: 0.75rem; font-weight: 600;">Code</th>';
            html += '<th style="padding: 0.75rem; text-align: left; color: #888888; font-size: 0.75rem; font-weight: 600;">Status</th>';
            html += '<th style="padding: 0.75rem; text-align: left; color: #888888; font-size: 0.75rem; font-weight: 600;">Created</th>';
            html += '<th style="padding: 0.75rem; text-align: left; color: #888888; font-size: 0.75rem; font-weight: 600;">Used By</th>';
            html += '<th style="padding: 0.75rem; text-align: left; color: #888888; font-size: 0.75rem; font-weight: 600;">Actions</th>';
            html += '</tr></thead><tbody>';
            
            invites.forEach(invite => {
                const statusClass = invite.isUsed ? 'status-expired' : 'status-active';
                const statusText = invite.isUsed ? 'Used' : 'Available';
                const createdDate = invite.createdAt ? new Date(invite.createdAt).toLocaleDateString() : '-';
                const usedDate = invite.usedAt ? new Date(invite.usedAt).toLocaleDateString() : '-';
                
                html += `<tr style="border-bottom: 1px solid #1a1a1a;">`;
                html += `<td style="padding: 0.75rem;"><code style="user-select: all; background: #0a0a0a; padding: 0.25rem 0.5rem; border-radius: 4px; border: 1px solid #1a1a1a;">${escapeHtml(invite.code || '***')}</code></td>`;
                html += `<td style="padding: 0.75rem;"><span class="status ${statusClass}">${statusText}</span></td>`;
                html += `<td style="padding: 0.75rem; color: #888888; font-size: 0.875rem;">${createdDate}</td>`;
                html += `<td style="padding: 0.75rem; color: #888888; font-size: 0.875rem;">${invite.usedBy ? escapeHtml(invite.usedBy) : '-'}</td>`;
                html += `<td style="padding: 0.75rem;"><button class="table-action-btn table-action-btn-danger" onclick="deleteInvite('${escapeHtml(invite.code || '***')}', '${escapeHtml(invite.hash)}')" title="Delete"><i class="fas fa-trash"></i></button></td>`;
                html += `</tr>`;
            });
            
            html += '</tbody></table></div>';
            listDiv.innerHTML = html;
        } else {
            listDiv.innerHTML = '<div style="color: #ef4444;">Failed to load invites</div>';
        }
    } catch (error) {
        listDiv.innerHTML = '<div style="color: #ef4444;">Error loading invites</div>';
    }
}

async function generateInvites() {
    const count = prompt('How many invite codes to generate?', '10');
    if (!count || isNaN(count) || parseInt(count) < 1) return;
    
    try {
        const response = await fetch(`${API}/admin/invites`, {
            method: 'POST',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ count: parseInt(count) })
        });
        
        const data = await response.json();
        
        if (data.success && data.invites) {
            // Show codes in alert for easy copying
            const codesText = data.invites.join('\n');
            alert(`✅ Generated ${data.invites.length} invite codes!\n\nCodes:\n${codesText}\n\n(These are saved and will be shown in the list)`);
            loadAdminInvites();
        } else {
            alert('Error: ' + (data.message || 'Failed to generate invites'));
        }
    } catch (error) {
        alert('Error generating invites');
    }
}

async function deleteInvite(invite, hash) {
    if (!confirm(`Delete invite code "${invite === '***' ? '(encrypted code)' : invite}"?`)) return;
    
    try {
        // If invite is "***" or we have a hash, use hash for deletion
        let url = `${API}/admin/invites/${encodeURIComponent(invite)}`;
        if ((invite === '***' || !invite) && hash) {
            url += `?hash=${encodeURIComponent(hash)}`;
        }
        
        const response = await fetch(url, {
            method: 'DELETE',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            loadAdminInvites();
        } else {
            alert('Error: ' + (data.message || 'Failed to delete invite'));
        }
    } catch (error) {
        alert('Error deleting invite');
    }
}

async function uploadUpdate() {
    const fileInput = document.getElementById('update-file');
    const versionInput = document.getElementById('update-version');
    const changelogInput = document.getElementById('update-changelog');
    const statusDiv = document.getElementById('upload-status');
    
    if (!versionInput.value || versionInput.value.trim() === '') {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Please enter a version number</div>';
        return;
    }
    
    if (!fileInput.files || !fileInput.files[0]) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Please select a file</div>';
        return;
    }
    
    const file = fileInput.files[0];
    if (!file.name.endsWith('.exe')) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Only .exe files are allowed</div>';
        return;
    }
    
    // Use encrypted admin credentials
    const username = ADMIN_CREDS.u;
    const password = ADMIN_CREDS.p;
    
    statusDiv.innerHTML = '<div style="color: #888888;">Uploading...</div>';
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('version', versionInput.value.trim());
    formData.append('changelog', changelogInput.value.trim() || 'No changes specified');
    formData.append('username', username);
    formData.append('password', password);
    
    try {
        const response = await fetch(`${API.replace('/api', '')}/api/admin/upload`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusDiv.innerHTML = `<div style="color: #22c55e;">✅ Upload successful! Version: ${data.version}, File: ${data.filename}, Size: ${(data.size / 1024 / 1024).toFixed(2)} MB</div>`;
            fileInput.value = '';
            versionInput.value = '';
            checkUpdateInfo();
        } else {
            statusDiv.innerHTML = `<div style="color: #ef4444;">❌ Error: ${data.message}</div>`;
        }
    } catch (error) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">❌ Upload failed. Please try again.</div>';
    }
}

async function checkUpdateInfo() {
    const infoDiv = document.getElementById('update-info');
    
    try {
        const response = await fetch(`${API.replace('/api', '')}/api/updates/check`);
        const data = await response.json();
        
        if (data.success) {
            if (data.hasUpdate) {
                const sizeMB = (data.size / 1024 / 1024).toFixed(2);
                const date = new Date(data.modifiedAt).toLocaleString();
                infoDiv.innerHTML = `
                    <div style="color: #22c55e;">
                        <strong>✅ Update Available</strong><br>
                        <strong>Current Version: ${data.serverVersion || data.version || 'N/A'}</strong><br>
                        File: ${data.filename}<br>
                        Size: ${sizeMB} MB<br>
                        Uploaded: ${date}
                    </div>
                `;
            } else {
                // No update available, but show current version if available
                const versionInfo = data.serverVersion || data.version || 'N/A';
                infoDiv.innerHTML = `
                    <div style="color: #888888;">
                        <strong>Current Version: ${versionInfo}</strong><br>
                        No update file available
                    </div>
                `;
            }
        } else {
            infoDiv.innerHTML = '<div style="color: #888888;">No update file available</div>';
        }
    } catch (error) {
        infoDiv.innerHTML = '<div style="color: #ef4444;">Error checking update info</div>';
    }
}

// Encrypted admin credentials (base64 encoded to hide from source)
const ADMIN_CREDS = {
    u: atob('SzdtUDl4UTJ2UjV3TjhiTDNqRjZoVDQ='), // Random admin username
    p: atob('WDl6QTRjTTduQjJkRzhrWTVwVjFzVzY=') // Random admin password
};

// Check if user is admin and show admin panel
function checkAdminAccess() {
    // Decrypt and check admin username
    const adminUser = ADMIN_CREDS.u;
    if (currentUser && currentUser.username === adminUser) {
        // Add admin tab to sidebar
        const sidebar = document.querySelector('.sidebar-nav');
        if (sidebar && !document.getElementById('admin-nav-item')) {
            const adminNav = document.createElement('button');
            adminNav.id = 'admin-nav-item';
            adminNav.className = 'nav-item';
            adminNav.setAttribute('data-tab', 'admin');
            adminNav.onclick = () => showTab('admin');
            adminNav.innerHTML = '<i class="fas fa-shield-alt"></i><span>Admin</span>';
            sidebar.appendChild(adminNav);
        }
        
        // Show admin tab
        const adminTab = document.getElementById('admin-tab');
        if (adminTab) {
            adminTab.style.display = 'block';
        }
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    // Load saved key generation preferences on page load
    loadKeyPreferences();
    
    if (await checkAuth()) {
        // Load overview stats by default
        loadStats();
        // Check admin access
        checkAdminAccess();
        if (currentUser && currentUser.isAdmin) {
            loadAdminUsers();
            loadAdminResellers();
            loadAdminInvites();
            checkUpdateInfo();
        }
    }
});

// Reseller Management Functions
async function loadAdminResellers() {
    const listDiv = document.getElementById('admin-resellers-list');
    if (!listDiv) return;
    
    try {
        const response = await fetch(`${API}/admin/resellers`, {
            method: 'GET',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.resellers) {
            if (data.resellers.length === 0) {
                listDiv.innerHTML = '<div style="color: #888888; text-align: center; padding: 2rem;">No resellers found</div>';
                return;
            }
            
            let html = '<div class="admin-table-container"><table class="admin-table"><thead><tr>';
            html += '<th>Username</th><th>Email</th><th>Balance</th><th>Products</th><th>Keys</th><th>Created</th><th>Actions</th>';
            html += '</tr></thead><tbody>';
            
            data.resellers.forEach(reseller => {
                const products = (reseller.allowedProducts || []).join(', ') || 'None';
                html += `<tr>
                    <td><strong>${escapeHtml(reseller.username)}</strong></td>
                    <td>${escapeHtml(reseller.email)}</td>
                    <td>$${parseFloat(reseller.balance || 0).toFixed(2)}</td>
                    <td>${escapeHtml(products)}</td>
                    <td>${reseller.keyCount}</td>
                    <td>${new Date(reseller.createdAt).toLocaleDateString()}</td>
                    <td>
                        <button class="btn btn-secondary btn-small" onclick="manageReseller('${reseller.id}')" title="Manage">
                            <i class="fas fa-cog"></i>
                        </button>
                    </td>
                </tr>`;
            });
            
            html += '</tbody></table></div>';
            listDiv.innerHTML = html;
        } else {
            listDiv.innerHTML = '<div style="color: #ef4444;">Error loading resellers</div>';
        }
    } catch (error) {
        console.error('Error loading resellers:', error);
        listDiv.innerHTML = '<div style="color: #ef4444;">Error loading resellers</div>';
    }
}

function showCreateResellerModal() {
    document.getElementById('createResellerModal').style.display = 'flex';
    document.getElementById('new-reseller-username').value = '';
    document.getElementById('new-reseller-email').value = '';
    document.getElementById('new-reseller-password').value = '';
    document.getElementById('new-reseller-balance').value = '0';
    document.getElementById('reseller-product-private').checked = true;
    document.getElementById('reseller-product-public').checked = false;
    document.getElementById('create-reseller-status').innerHTML = '';
}

function closeCreateResellerModal() {
    document.getElementById('createResellerModal').style.display = 'none';
}

async function createReseller() {
    const username = document.getElementById('new-reseller-username').value.trim();
    const email = document.getElementById('new-reseller-email').value.trim();
    const password = document.getElementById('new-reseller-password').value;
    const balance = parseFloat(document.getElementById('new-reseller-balance').value) || 0;
    const statusDiv = document.getElementById('create-reseller-status');
    
    if (!username || !email || !password) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Username, email, and password required</div>';
        return;
    }
    
    const allowedProducts = [];
    if (document.getElementById('reseller-product-private').checked) {
        allowedProducts.push('private');
    }
    if (document.getElementById('reseller-product-public').checked) {
        allowedProducts.push('public');
    }
    
    if (allowedProducts.length === 0) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">At least one product must be selected</div>';
        return;
    }
    
    statusDiv.innerHTML = '<div style="color: #888888;">Creating reseller...</div>';
    
    try {
        const response = await fetch(`${API}/auth/register-reseller`, {
            method: 'POST',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email,
                password,
                initialBalance: balance,
                allowedProducts
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusDiv.innerHTML = '<div style="color: #22c55e;">✅ Reseller created successfully!</div>';
            setTimeout(() => {
                closeCreateResellerModal();
                loadAdminResellers();
            }, 1000);
        } else {
            statusDiv.innerHTML = `<div style="color: #ef4444;">❌ Error: ${data.message}</div>`;
        }
    } catch (error) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">❌ Error creating reseller</div>';
    }
}

async function manageReseller(userId) {
    const modal = document.getElementById('manageResellerModal');
    const contentDiv = document.getElementById('manage-reseller-content');
    
    try {
        const response = await fetch(`${API}/admin/users/${userId}`, {
            method: 'GET',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.user) {
            const user = data.user;
            if (user.accountType !== 'reseller') {
                alert('This user is not a reseller');
                return;
            }
            
            document.getElementById('manage-reseller-title').textContent = `Manage Reseller: ${escapeHtml(user.username)}`;
            
            contentDiv.innerHTML = `
                <div class="form-section">
                    <label class="form-label">Current Balance: $${parseFloat(user.balance || 0).toFixed(2)}</label>
                </div>
                <div class="form-section">
                    <label class="form-label">Add Balance ($)</label>
                    <input type="number" id="add-balance-amount" placeholder="0.00" step="0.01" min="0" value="0" class="form-input">
                    <button class="btn btn-primary" onclick="addResellerBalance('${userId}')" style="margin-top: 0.5rem;">
                        <i class="fas fa-plus"></i>
                        <span>Add Balance</span>
                    </button>
                </div>
                <div class="form-section">
                    <label class="form-label">Set Balance ($)</label>
                    <input type="number" id="set-balance-amount" placeholder="${parseFloat(user.balance || 0).toFixed(2)}" step="0.01" min="0" value="${parseFloat(user.balance || 0).toFixed(2)}" class="form-input">
                    <button class="btn btn-primary" onclick="setResellerBalance('${userId}')" style="margin-top: 0.5rem;">
                        <i class="fas fa-save"></i>
                        <span>Set Balance</span>
                    </button>
                </div>
                <div class="form-section">
                    <label class="form-label">Allowed Products</label>
                    <div style="margin-top: 0.5rem;">
                        <label style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                            <input type="checkbox" id="manage-product-private" ${(user.allowedProducts || []).includes('private') ? 'checked' : ''} style="margin-right: 0.5rem;">
                            <span>Private</span>
                        </label>
                        <label style="display: flex; align-items: center;">
                            <input type="checkbox" id="manage-product-public" ${(user.allowedProducts || []).includes('public') ? 'checked' : ''} style="margin-right: 0.5rem;">
                            <span>Public (Coming Soon)</span>
                        </label>
                    </div>
                    <button class="btn btn-primary" onclick="updateResellerProducts('${userId}')" style="margin-top: 0.5rem;">
                        <i class="fas fa-save"></i>
                        <span>Update Products</span>
                    </button>
                </div>
                <div id="manage-reseller-status" style="margin-top: 1rem;"></div>
            `;
            
            modal.style.display = 'flex';
        } else {
            alert('Error loading reseller details');
        }
    } catch (error) {
        console.error('Error loading reseller:', error);
        alert('Error loading reseller details');
    }
}

function closeManageResellerModal() {
    document.getElementById('manageResellerModal').style.display = 'none';
}

async function addResellerBalance(userId) {
    const amount = parseFloat(document.getElementById('add-balance-amount').value);
    const statusDiv = document.getElementById('manage-reseller-status');
    
    if (isNaN(amount) || amount <= 0) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Invalid amount</div>';
        return;
    }
    
    try {
        const response = await fetch(`${API}/admin/resellers/${userId}/add-balance`, {
            method: 'POST',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ amount })
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusDiv.innerHTML = `<div style="color: #22c55e;">✅ Added $${amount.toFixed(2)}. New balance: $${data.balance.toFixed(2)}</div>`;
            setTimeout(() => {
                manageReseller(userId);
            }, 1000);
        } else {
            statusDiv.innerHTML = `<div style="color: #ef4444;">❌ Error: ${data.message}</div>`;
        }
    } catch (error) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">❌ Error adding balance</div>';
    }
}

async function setResellerBalance(userId) {
    const amount = parseFloat(document.getElementById('set-balance-amount').value);
    const statusDiv = document.getElementById('manage-reseller-status');
    
    if (isNaN(amount) || amount < 0) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">Invalid amount</div>';
        return;
    }
    
    try {
        const response = await fetch(`${API}/admin/resellers/${userId}/balance`, {
            method: 'POST',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ balance: amount })
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusDiv.innerHTML = `<div style="color: #22c55e;">✅ Balance set to $${data.balance.toFixed(2)}</div>`;
            setTimeout(() => {
                manageReseller(userId);
            }, 1000);
        } else {
            statusDiv.innerHTML = `<div style="color: #ef4444;">❌ Error: ${data.message}</div>`;
        }
    } catch (error) {
        statusDiv.innerHTML = '<div style="color: #ef4444;">❌ Error setting balance</div>';
    }
}

async function updateResellerProducts(userId) {
    const allowedProducts = [];
    if (document.getElementById('manage-product-private').checked) {
        allowedProducts.push('private');
    }
    if (document.getElementById('manage-product-public').checked) {
        allowedProducts.push('public');
    }
    
    if (allowedProducts.length === 0) {
        document.getElementById('manage-reseller-status').innerHTML = '<div style="color: #ef4444;">At least one product must be selected</div>';
        return;
    }
    
    try {
        const response = await fetch(`${API}/admin/resellers/${userId}/products`, {
            method: 'POST',
            headers: {
                'Authorization': currentToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ allowedProducts })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('manage-reseller-status').innerHTML = '<div style="color: #22c55e;">✅ Products updated successfully</div>';
            setTimeout(() => {
                loadAdminResellers();
            }, 1000);
        } else {
            document.getElementById('manage-reseller-status').innerHTML = `<div style="color: #ef4444;">❌ Error: ${data.message}</div>`;
        }
    } catch (error) {
        document.getElementById('manage-reseller-status').innerHTML = '<div style="color: #ef4444;">❌ Error updating products</div>';
    }
}

