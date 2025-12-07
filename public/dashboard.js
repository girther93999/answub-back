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
        
        if (!data.success) {
            logout();
            return false;
        }
        
        document.getElementById('username-display').textContent = currentUser.username;
        
        // Display account credentials
        document.getElementById('account-id').textContent = currentUser.id;
        document.getElementById('api-token').textContent = currentToken;
        document.getElementById('account-username').textContent = currentUser.username;
        
        // Update code examples
        document.getElementById('code-account-id').textContent = currentUser.id;
        document.getElementById('code-api-token').textContent = currentToken;
        
        // Load messages
        loadMessages();
        
        return true;
    } catch (error) {
        console.error('Auth check failed:', error);
        return false;
    }
}

function logout() {
    // Clear all auth data and any cached keys
    localStorage.clear();
    sessionStorage.clear();
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

// Generate key
async function generateKey() {
    const format = document.getElementById('format').value;
    const duration = document.getElementById('duration').value;
    const amount = document.getElementById('amount').value;
    
    if (!format || !format.includes('*')) {
        alert('Format must include at least one * for random characters');
        return;
    }
    
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
            info += ` | Status: Unused (countdown starts on first use)`;
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
                
                // Check if key has been used
                const isUnused = !key.usedAt;
                
                if (isUnused) {
                    status = 'Unused';
                    statusClass = 'status-active';
                } else if (key.usedBy) {
                    status = 'Used';
                    statusClass = 'status-used';
                }
                
                if (key.expiresAt) {
                    const expiry = new Date(key.expiresAt);
                    if (expiry < new Date()) {
                        status = 'Expired';
                        statusClass = 'status-expired';
                    }
                }
                
                const expiryText = isUnused 
                    ? 'Starts on first use' 
                    : (key.expiresAt 
                        ? new Date(key.expiresAt).toLocaleString() 
                        : 'Lifetime');
                
                const ip = key.ip || '-';
                const lastCheck = key.lastCheck 
                    ? new Date(key.lastCheck).toLocaleString() 
                    : '-';
                
                // HWID Lock display
                let hwidDisplay = '';
                if (key.hwid) {
                    hwidDisplay = `
                        <div style="display: flex; flex-direction: column; gap: 0.25rem;">
                            <code style="font-size: 0.75rem;">${key.hwid}</code>
                            <span class="status status-used" style="font-size: 0.65rem;">🔒 Locked</span>
                        </div>
                    `;
                } else {
                    hwidDisplay = '<span class="status status-active" style="font-size: 0.75rem;">🔓 Not Locked</span>';
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
                        <div class="actions">
                            <button class="btn btn-action" onclick="openAddTimeModal('${key.key}')">+ Time</button>
                            <button class="btn btn-action" onclick="resetHWID('${key.key}')" ${!key.hwid ? 'disabled' : ''}>Reset HWID</button>
                            <button class="btn btn-danger" onclick="deleteKey('${key.key}')">Delete</button>
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
    currentModalKey = key;
    document.getElementById('modal-key').textContent = key;
    document.getElementById('addTimeModal').classList.add('active');
}

// Close add time modal
function closeAddTimeModal() {
    document.getElementById('addTimeModal').classList.remove('active');
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
document.getElementById('addTimeModal')?.addEventListener('click', function(e) {
    if (e.target === this) {
        closeAddTimeModal();
    }
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    if (await checkAuth()) {
        loadKeys();
        loadStats();
    }
});

