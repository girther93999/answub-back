const API = 'https://answub-back.onrender.com/api';

let currentModalKey = '';
let currentToken = '';
let currentUser = null;
let currentBalance = 0;
let allowedProducts = [];

// Check authentication
async function checkAuth() {
    currentToken = localStorage.getItem('astreon_token');
    const userStr = localStorage.getItem('astreon_user');
    
    if (!currentToken || !userStr) {
        window.location.href = 'index.html';
        return false;
    }
    
    try {
        currentUser = JSON.parse(userStr);
        
        // Check if user is a reseller
        if (currentUser.accountType !== 'reseller') {
            // Redirect to normal dashboard
            window.location.href = 'dashboard.html';
            return false;
        }
    } catch (e) {
        localStorage.removeItem('astreon_token');
        localStorage.removeItem('astreon_user');
        window.location.href = 'index.html';
        return false;
    }
    
    // Verify token
    try {
        const response = await fetch(`${API}/auth/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken })
        });
        
        const data = await response.json();
        
        if (!data.success || data.accountType !== 'reseller') {
            logout();
            return false;
        }
        
        // Load balance and products
        await loadBalance();
        
        return true;
    } catch (error) {
        console.error('Auth error:', error);
        logout();
        return false;
    }
}

// Load balance and allowed products
async function loadBalance() {
    try {
        const response = await fetch(`${API}/reseller/balance?token=${encodeURIComponent(currentToken)}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentBalance = data.balance || 0;
            allowedProducts = data.allowedProducts || [];
            updateBalanceDisplay();
            updateProductSelect();
        }
    } catch (error) {
        console.error('Error loading balance:', error);
    }
}

function updateBalanceDisplay() {
    const balanceElements = document.querySelectorAll('#stat-balance, #generate-balance');
    balanceElements.forEach(el => {
        if (el) el.textContent = `$${currentBalance.toFixed(2)}`;
    });
}

function updateProductSelect() {
    const select = document.getElementById('product-select');
    if (!select) return;
    
    // Clear existing options
    select.innerHTML = '';
    
    // Add allowed products
    allowedProducts.forEach(product => {
        const option = document.createElement('option');
        option.value = product;
        option.textContent = product.charAt(0).toUpperCase() + product.slice(1);
        select.appendChild(option);
    });
    
    // Update allowed products display
    const productsDiv = document.getElementById('allowed-products');
    if (productsDiv) {
        if (allowedProducts.length === 0) {
            productsDiv.innerHTML = '<div style="color: #888888;">No products assigned</div>';
        } else {
            productsDiv.innerHTML = allowedProducts.map(p => 
                `<span style="display: inline-block; background: #1a1a1a; padding: 0.5rem 1rem; border-radius: 6px; margin-right: 0.5rem; border: 1px solid #3fb950;">${p.charAt(0).toUpperCase() + p.slice(1)}</span>`
            ).join('');
        }
    }
}

// Load stats
async function loadStats() {
    try {
        const response = await fetch(`${API}/reseller/keys?token=${encodeURIComponent(currentToken)}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success && data.keys) {
            const keys = data.keys;
            const total = keys.length;
            const active = keys.filter(k => k.expiresAt && new Date(k.expiresAt) > new Date() && !k.usedBy).length;
            const used = keys.filter(k => k.usedBy).length;
            
            document.getElementById('stat-total').textContent = total;
            document.getElementById('stat-active').textContent = active;
            document.getElementById('stat-used').textContent = used;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load reseller keys
async function loadResellerKeys() {
    const tbody = document.getElementById('keys-table');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="5" class="loading">Loading keys...</td></tr>';
    
    try {
        const response = await fetch(`${API}/reseller/keys?token=${encodeURIComponent(currentToken)}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success && data.keys) {
            if (data.keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888888; padding: 2rem;">No keys generated yet</td></tr>';
                return;
            }
            
            let html = '';
            data.keys.forEach(key => {
                const status = key.usedBy ? 'Used' : (key.expiresAt && new Date(key.expiresAt) < new Date() ? 'Expired' : 'Active');
                const statusClass = status === 'Active' ? 'success' : status === 'Used' ? 'warning' : 'danger';
                const duration = key.duration && key.amount ? `${key.amount} ${key.duration}` : 'N/A';
                const product = key.product || 'N/A';
                
                html += `<tr>
                    <td><code style="background: #1a1a1a; padding: 0.25rem 0.5rem; border-radius: 4px;">${escapeHtml(key.key)}</code></td>
                    <td>${escapeHtml(product)}</td>
                    <td><span class="badge badge-${statusClass}">${status}</span></td>
                    <td>${duration}</td>
                    <td>${new Date(key.createdAt).toLocaleString()}</td>
                </tr>`;
            });
            
            tbody.innerHTML = html;
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #ef4444;">Error loading keys</td></tr>';
        }
    } catch (error) {
        console.error('Error loading keys:', error);
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #ef4444;">Error loading keys</td></tr>';
    }
}

// Generate reseller key
async function generateResellerKey() {
    const format = document.getElementById('format').value;
    const duration = document.getElementById('duration').value;
    const amount = document.getElementById('amount').value;
    const product = document.getElementById('product-select').value;
    
    if (!format || !format.includes('*')) {
        alert('Format must include at least one * for random characters');
        return;
    }
    
    if (currentBalance < 1.0) {
        alert(`Insufficient balance. You need $1.00 to generate a key. Current balance: $${currentBalance.toFixed(2)}`);
        return;
    }
    
    if (!allowedProducts.includes(product)) {
        alert(`You don't have permission to generate keys for product: ${product}`);
        return;
    }
    
    try {
        const response = await fetch(`${API}/reseller/keys/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                token: currentToken, 
                format, 
                duration, 
                amount,
                product
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('generated-key').textContent = data.key;
            document.getElementById('generated-result').style.display = 'block';
            
            let info = `Product: ${product} | Duration: ${duration === 'lifetime' ? 'Lifetime' : `${amount} ${duration}(s)`}`;
            info += ` | New Balance: $${data.balance.toFixed(2)}`;
            document.getElementById('key-info').textContent = info;
            
            // Update balance
            currentBalance = data.balance;
            updateBalanceDisplay();
            
            // Reload keys and stats
            loadResellerKeys();
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
        alert('Key copied to clipboard!');
    }).catch(() => {
        alert('Failed to copy. Please select and copy manually.');
    });
}

// Tab navigation
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const tabElement = document.getElementById(tabName + '-tab');
    if (tabElement) {
        tabElement.classList.add('active');
    }
    
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab') === tabName) {
            item.classList.add('active');
        }
    });
    
    if (tabName === 'keys') {
        loadResellerKeys();
    } else if (tabName === 'overview') {
        loadStats();
    } else if (tabName === 'generate') {
        updateBalanceDisplay();
    }
}

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

// Logout
function logout() {
    localStorage.removeItem('astreon_token');
    localStorage.removeItem('astreon_user');
    window.location.href = 'index.html';
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    if (await checkAuth()) {
        document.getElementById('username-display').textContent = currentUser.username;
        document.getElementById('overview-username').textContent = currentUser.username;
        loadStats();
    }
});

