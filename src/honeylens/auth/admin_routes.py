"""
admin_routes.py — Admin Panel API Routes
=========================================
Provides admin panel endpoints for user management and system monitoring.

Endpoints:
    GET  /sensor_admin              Admin panel dashboard HTML
    GET  /sensor_admin/status       System status (honeypots, services)
    GET  /sensor_admin/users        List all users
    POST /sensor_admin/users        Create new user
    GET  /sensor_admin/users/{id}   Get user details
    PUT  /sensor_admin/users/{id}   Update user
    DELETE /sensor_admin/users/{id} Delete user (soft delete)
    POST /sensor_admin/users/{id}/reset_password  Reset user password
    GET  /sensor_admin/audit        Get admin audit log
    GET  /sensor_admin/export/attackers  Export attacker IPs

Requires: FastAPI, user_manager.py, auth.py
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 — constant systemctl commands, arguments as a list

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from honeylens.auth.user_manager import (
    User,
    authenticate_user,
    create_user,
    delete_user,
    get_audit_log,
    get_user_by_id,
    list_users,
    reset_password,
    update_user,
)
from honeylens.database import db_cursor
from honeylens.honeypots import units
from honeylens.honeypots.manifest import HONEYPOTS

logger = logging.getLogger("admin")

# =============================================================================
# Router Setup
# =============================================================================

router = APIRouter(prefix="/sensor_admin", tags=["admin"])


# =============================================================================
# Authentication Dependencies
# =============================================================================


async def get_current_user(request: Request) -> User:
    """
    Get authenticated user from request state (set by AuthMiddleware).
    Falls back to re-authenticating if state not available.
    """
    # Try to get user from middleware state first
    if hasattr(request.state, "user") and request.state.user:
        user = request.state.user
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account disabled")
        if user.is_locked:
            raise HTTPException(status_code=403, detail="Account temporarily locked")
        return user

    # Fallback: re-authenticate from Authorization header
    import base64

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )

    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials") from None

    user = authenticate_user(username, password)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    if user.is_locked:
        raise HTTPException(status_code=403, detail="Account temporarily locked")

    return user


async def require_admin(request: Request) -> User | None:
    """Require admin role for endpoint."""
    # Check for legacy auth (config.py credentials)
    if hasattr(request.state, "is_admin") and request.state.is_admin:
        if hasattr(request.state, "user") and request.state.user:
            user = request.state.user
            if not user.is_admin:
                raise HTTPException(status_code=403, detail="Admin access required")
            return user
        else:
            # Legacy config.py auth - has admin access, return None
            return None

    # Get user from database auth
    user = await get_current_user(request)

    if user is None:
        raise HTTPException(status_code=403, detail="Admin access required")

    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    return user


# =============================================================================
# Request/Response Models
# =============================================================================


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    name: str = ""
    lastname: str = ""
    role: str = "user"


class UpdateUserRequest(BaseModel):
    name: str | None = None
    lastname: str | None = None
    email: str | None = None
    role: str | None = None
    is_active: bool | None = None


# =============================================================================
# Admin Panel HTML
# =============================================================================

ADMIN_PANEL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sensor Admin Panel</title>
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --success: #3fb950;
            --danger: #f85149;
            --warning: #d29922;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.5;
        }

        .header {
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 { font-size: 20px; font-weight: 600; }
        .header .user-info { color: var(--text-muted); }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
        }

        .card h2 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th, td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: rgba(0,0,0,0.2);
            font-weight: 600;
            color: var(--text-muted);
        }

        tr:hover { background: rgba(255,255,255,0.02); }

        .btn {
            display: inline-block;
            padding: 6px 12px;
            font-size: 13px;
            font-weight: 500;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--bg-card);
            color: var(--text);
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn:hover { background: var(--border); }
        .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
        .btn-primary:hover { opacity: 0.9; }
        .btn-danger { background: var(--danger); border-color: var(--danger); color: #fff; }
        .btn-danger:hover { opacity: 0.9; }
        .btn-sm { padding: 4px 8px; font-size: 12px; }

        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }

        .status-running { background: rgba(63, 185, 80, 0.2); color: var(--success); }
        .status-stopped { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
        .status-active { background: rgba(63, 185, 80, 0.2); color: var(--success); }
        .status-disabled { background: rgba(139, 148, 158, 0.2); color: var(--text-muted); }
        .status-locked { background: rgba(210, 153, 34, 0.2); color: var(--warning); }

        .role-admin { color: var(--accent); font-weight: 600; }
        .role-user { color: var(--text-muted); }

        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.7);
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }

        .modal.active { display: flex; }

        .modal-content {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 24px;
            width: 100%;
            max-width: 500px;
        }

        .modal-content h2 { margin-bottom: 20px; }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            font-weight: 500;
        }

        .form-group input, .form-group select {
            width: 100%;
            padding: 8px 12px;
            font-size: 14px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
        }

        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--accent);
        }

        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            margin-top: 20px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }

        .stat-item {
            text-align: center;
            padding: 12px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: 600;
            color: var(--accent);
        }

        .stat-label {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .back-link {
            color: var(--accent);
            text-decoration: none;
        }

        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1><img src="/logo-mark.png" alt="" style="height:22px;width:22px;vertical-align:-4px;margin-right:8px">Sensor Admin Panel</h1>
        <div>
            <span id="version-badge" style="background:rgba(34,211,238,0.15);color:var(--accent);padding:4px 10px;border-radius:4px;font-size:12px;font-weight:600;margin-right:12px;">v-</span>
            <a href="/" class="back-link">← Back to Dashboard</a>
            <span class="user-info" style="margin-left: 20px;">Logged in as: <strong id="current-user">-</strong></span>
        </div>
    </div>

    <div class="container">
        <!-- Stats -->
        <div class="card" style="margin-bottom: 24px;">
            <div class="stats-grid" id="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" id="stat-users">-</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="stat-events">-</div>
                    <div class="stat-label">Events Today</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="stat-attacks">-</div>
                    <div class="stat-label">Attacks Today</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="stat-ips">-</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
            </div>
        </div>

        <!-- AI & Version Status -->
        <div class="card" style="margin-bottom: 24px;">
            <h2>System Information</h2>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:12px;">
                <div style="padding:12px;background:rgba(0,0,0,0.2);border-radius:6px;">
                    <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px;">Sensor Version</div>
                    <div id="sys-version" style="font-size:16px;font-weight:600;color:var(--accent);">-</div>
                </div>
                <div style="padding:12px;background:rgba(0,0,0,0.2);border-radius:6px;">
                    <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px;">Ollama (Local AI)</div>
                    <div id="sys-ollama" style="font-size:14px;font-weight:500;">-</div>
                </div>
                <div style="padding:12px;background:rgba(0,0,0,0.2);border-radius:6px;">
                    <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px;">External AI</div>
                    <div id="sys-claude" style="font-size:14px;font-weight:500;">-</div>
                </div>
            </div>
        </div>

        <!-- Core Services + Quick Actions -->
        <div class="grid">
            <div class="card">
                <h2>Core Services</h2>
                <div id="core-status">Loading...</div>
            </div>
            <div class="card">
                <h2>Quick Actions</h2>
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <button class="btn btn-primary" onclick="showAddUser()">+ Add New User</button>
                    <button class="btn" onclick="exportAttackers(24)">Export Attackers (24h)</button>
                    <button class="btn" onclick="exportAttackers(168)">Export Attackers (7d)</button>
                    <button class="btn" onclick="loadAuditLog()">View Audit Log</button>
                </div>
            </div>
        </div>

        <!-- Honeypots -->
        <div class="card" style="margin-bottom: 24px;">
            <h2>Honeypot Services <span id="hp-count" style="font-size:12px;color:var(--accent);font-weight:400;"></span></h2>
            <div id="honeypot-status">Loading...</div>
        </div>

        <!-- Detectors -->
        <div class="card" style="margin-bottom: 24px;">
            <h2>Detectors</h2>
            <div id="detector-status">Loading...</div>
        </div>

        <!-- Users Table -->
        <div class="card">
            <h2>User Management</h2>
            <table id="users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Last Login</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="users-tbody"></tbody>
            </table>
        </div>

        <!-- Audit Log (hidden by default) -->
        <div class="card" id="audit-card" style="display: none; margin-top: 24px;">
            <h2>Recent Admin Actions</h2>
            <table id="audit-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Admin</th>
                        <th>Action</th>
                        <th>Target</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody id="audit-tbody"></tbody>
            </table>
        </div>
    </div>

    <!-- Add User Modal -->
    <div class="modal" id="add-user-modal">
        <div class="modal-content">
            <h2>Add New User</h2>
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="new-username" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label>First Name</label>
                <input type="text" id="new-name" placeholder="Enter first name">
            </div>
            <div class="form-group">
                <label>Last Name</label>
                <input type="text" id="new-lastname" placeholder="Enter last name">
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="new-email" placeholder="Enter email">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="new-password" placeholder="Min 12 chars, upper, lower, digit, special">
            </div>
            <div class="form-group">
                <label>Role</label>
                <select id="new-role">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <div class="modal-actions">
                <button class="btn" onclick="hideModal('add-user-modal')">Cancel</button>
                <button class="btn btn-primary" onclick="createUser()">Create User</button>
            </div>
        </div>
    </div>

    <script>
        // Load current user
        document.getElementById('current-user').textContent = '${CURRENT_USER}';

        // HTML escape function for XSS prevention
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        async function apiCall(url, options = {}) {
            const resp = await fetch(url, options);
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({detail: 'Request failed'}));
                throw new Error(err.detail || 'Request failed');
            }
            return resp.json();
        }

        async function loadStats() {
            try {
                const data = await apiCall('/sensor_admin/stats');
                document.getElementById('stat-users').textContent = data.total_users;
                document.getElementById('stat-events').textContent = data.events_today.toLocaleString();
                document.getElementById('stat-attacks').textContent = data.attacks_today.toLocaleString();
                document.getElementById('stat-ips').textContent = data.unique_ips_today.toLocaleString();
                // Version & AI status
                if (data.version) {
                    document.getElementById('version-badge').textContent = 'v' + data.version;
                    document.getElementById('sys-version').textContent = data.version + ' (build ' + data.build_number + ')';
                }
                const olEl = document.getElementById('sys-ollama');
                if (data.ollama_status) {
                    olEl.textContent = data.ollama_status;
                    olEl.style.color = data.ollama_status.startsWith('online') ? '#22c55e' : '#f43f5e';
                }
                const clEl = document.getElementById('sys-claude');
                if (data.claude_status) {
                    clEl.textContent = data.claude_status;
                    clEl.style.color = data.claude_status.includes('configured') && !data.claude_status.startsWith('not') ? '#22c55e' : '#eab308';
                }
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }

        function renderStatusTable(items, showToggle) {
            if (!items || Object.keys(items).length === 0) return '<span style="color:#64748b;">No services found</span>';
            let html = '<table><thead><tr><th>Service</th><th>Unit</th><th>Status</th>';
            if (showToggle) html += '<th>Action</th>';
            html += '</tr></thead><tbody>';
            let active = 0, total = 0;
            for (const [name, info] of Object.entries(items)) {
                total++;
                const status = info.status || (info.running ? 'active' : 'stopped');
                let badge;
                if (status === 'active') {
                    badge = '<span class="status-badge status-running">Active</span>';
                    active++;
                } else if (status === 'activating')
                    badge = '<span class="status-badge" style="background:rgba(234,179,8,0.15);color:#eab308;">Starting</span>';
                else if (status === 'inactive' || status === 'unknown')
                    badge = '<span class="status-badge" style="color:#64748b;">—</span>';
                else
                    badge = '<span class="status-badge status-stopped">' + escapeHtml(status) + '</span>';
                const unit = info.unit || '';
                html += '<tr><td>' + escapeHtml(name) + '</td><td style="color:#8899aa;font-size:11px;font-family:monospace;">' + escapeHtml(unit) + '</td><td>' + badge + '</td>';
                if (showToggle) {
                    const proto = unit.replace('sensor-hp-','').replace('sensor-honeypot-','').replace('sensor-','');
                    const btnColor = status === 'active' ? '#ef4444' : '#22c55e';
                    const btnText = status === 'active' ? 'Stop' : 'Start';
                    html += '<td><button data-proto="' + escapeHtml(proto) + '" onclick="toggleHP(this.dataset.proto,this)" style="padding:2px 10px;border-radius:4px;border:1px solid ' + btnColor + ';background:transparent;color:' + btnColor + ';cursor:pointer;font-size:11px;">' + btnText + '</button></td>';
                }
                html += '</tr>';
            }
            html += '</tbody></table>';
            return {html: html, active: active, total: total};
        }

        async function toggleHP(proto, btn) {
            btn.disabled = true; btn.textContent = '...';
            try {
                await apiCall('/honeypots/' + proto + '/toggle', {method:'POST'});
                setTimeout(loadStatus, 2000);
            } catch(e) {
                btn.textContent = 'Error';
                setTimeout(loadStatus, 3000);
            }
        }

        async function loadStatus() {
            try {
                const data = await apiCall('/sensor_admin/status');

                const core = renderStatusTable(data.core || {}, false);
                document.getElementById('core-status').innerHTML = core.html || core;

                const hp = renderStatusTable(data.honeypots || {}, true);
                document.getElementById('honeypot-status').innerHTML = hp.html || hp;
                if (hp.active !== undefined) document.getElementById('hp-count').textContent = '(' + hp.active + '/' + hp.total + ' active)';

                const det = renderStatusTable(data.detectors || {}, false);
                document.getElementById('detector-status').innerHTML = det.html || det;
            } catch (e) {
                document.getElementById('core-status').innerHTML = '<p>Failed to load status</p>';
                document.getElementById('honeypot-status').innerHTML = '<p>Failed to load</p>';
                document.getElementById('detector-status').innerHTML = '<p>Failed to load</p>';
            }
        }

        async function loadUsers() {
            try {
                const data = await apiCall('/sensor_admin/users');
                const tbody = document.getElementById('users-tbody');

                tbody.innerHTML = data.users.map(u => {
                    let status = '';
                    if (!u.is_active) {
                        status = '<span class="status-badge status-disabled">Disabled</span>';
                    } else if (u.is_locked) {
                        status = '<span class="status-badge status-locked">Locked</span>';
                    } else {
                        status = '<span class="status-badge status-active">Active</span>';
                    }

                    const roleClass = u.role === 'admin' ? 'role-admin' : 'role-user';
                    const lastLogin = u.last_login ? new Date(u.last_login).toLocaleString() : 'Never';

                    return `
                        <tr>
                            <td><strong>${u.username}</strong></td>
                            <td>${u.name} ${u.lastname}</td>
                            <td>${u.email}</td>
                            <td><span class="${roleClass}">${u.role}</span></td>
                            <td>${lastLogin}</td>
                            <td>${status}</td>
                            <td>
                                <button class="btn btn-sm" onclick="resetPassword(${u.id})">Reset PW</button>
                                <button class="btn btn-sm ${u.is_active ? 'btn-danger' : 'btn-primary'}"
                                        onclick="toggleUser(${u.id}, ${u.is_active})">
                                    ${u.is_active ? 'Disable' : 'Enable'}
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (e) {
                console.error('Failed to load users:', e);
            }
        }

        async function loadAuditLog() {
            try {
                const data = await apiCall('/sensor_admin/audit');
                const tbody = document.getElementById('audit-tbody');
                const card = document.getElementById('audit-card');

                tbody.innerHTML = data.entries.map(e => `
                    <tr>
                        <td>${new Date(e.timestamp).toLocaleString()}</td>
                        <td>${e.admin_username || '-'}</td>
                        <td>${e.action}</td>
                        <td>${e.target_username || '-'}</td>
                        <td>${e.ip_address || '-'}</td>
                    </tr>
                `).join('');

                card.style.display = 'block';
                card.scrollIntoView({behavior: 'smooth'});
            } catch (e) {
                alert('Failed to load audit log: ' + e.message);
            }
        }

        function showAddUser() {
            document.getElementById('add-user-modal').classList.add('active');
        }

        function hideModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        // Input sanitization and validation
        function sanitizeInput(str) {
            if (!str) return '';
            return str.replace(/[<>&"']/g, function(c) {
                return {'<':'&lt;', '>':'&gt;', '&':'&amp;', '"':'&quot;', "'":'&#39;'}[c];
            });
        }

        function validateName(name, fieldName) {
            if (!name) return null; // Empty is OK
            if (name.length > 128) return fieldName + ' must be 128 characters or less';
            // Check for HTML/script injection
            if (/[<>&"']|javascript:|on\\w+=/i.test(name)) {
                return fieldName + ' contains invalid characters';
            }
            // Only allow letters, spaces, hyphens, apostrophes
            if (!/^[a-zA-Z\\s\\-'\\.]+$/.test(name)) {
                return fieldName + ' can only contain letters, spaces, hyphens, and apostrophes';
            }
            return null;
        }

        function validateUsername(username) {
            if (!username) return 'Username is required';
            if (username.length < 3) return 'Username must be at least 3 characters';
            if (username.length > 64) return 'Username must be 64 characters or less';
            if (!/^[a-zA-Z0-9_]+$/.test(username)) {
                return 'Username can only contain letters, numbers, and underscores';
            }
            return null;
        }

        function validateEmail(email) {
            if (!email) return 'Email is required';
            if (email.length > 256) return 'Email must be 256 characters or less';
            if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/.test(email)) {
                return 'Invalid email address format';
            }
            return null;
        }

        function validatePassword(password) {
            if (!password) return 'Password is required';
            if (password.length < 12) return 'Password must be at least 12 characters';
            if (!/[A-Z]/.test(password)) return 'Password must contain an uppercase letter';
            if (!/[a-z]/.test(password)) return 'Password must contain a lowercase letter';
            if (!/[0-9]/.test(password)) return 'Password must contain a digit';
            if (!/[!@#$%^&*(),.?":{}|<>\\-_=+\\[\\]\\;\'`~]/.test(password)) {
                return 'Password must contain a special character';
            }
            return null;
        }

        async function createUser() {
            // Get values
            const username = document.getElementById('new-username').value.trim();
            const name = document.getElementById('new-name').value.trim();
            const lastname = document.getElementById('new-lastname').value.trim();
            const email = document.getElementById('new-email').value.trim();
            const password = document.getElementById('new-password').value;
            const role = document.getElementById('new-role').value;

            // Client-side validation
            let error = validateUsername(username);
            if (error) { alert(error); return; }

            error = validateEmail(email);
            if (error) { alert(error); return; }

            error = validatePassword(password);
            if (error) { alert(error); return; }

            error = validateName(name, 'First name');
            if (error) { alert(error); return; }

            error = validateName(lastname, 'Last name');
            if (error) { alert(error); return; }

            const data = {
                username: username,
                name: name,
                lastname: lastname,
                email: email.toLowerCase(),
                password: password,
                role: role
            };

            try {
                await apiCall('/sensor_admin/users', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });

                hideModal('add-user-modal');
                loadUsers();
                loadStats();

                // Clear form
                ['username', 'name', 'lastname', 'email', 'password'].forEach(f => {
                    document.getElementById('new-' + f).value = '';
                });
            } catch (e) {
                alert('Failed to create user: ' + e.message);
            }
        }

        async function resetPassword(id) {
            if (!confirm('Reset password for this user?')) return;

            try {
                const data = await apiCall(`/sensor_admin/users/${id}/reset_password`, {
                    method: 'POST'
                });
                alert(`New password: ${data.new_password}\\n\\nPlease save this password - it will not be shown again.`);
            } catch (e) {
                alert('Failed to reset password: ' + e.message);
            }
        }

        async function toggleUser(id, isActive) {
            const action = isActive ? 'disable' : 'enable';
            if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} this user?`)) return;

            try {
                await apiCall(`/sensor_admin/users/${id}`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({is_active: !isActive})
                });
                loadUsers();
            } catch (e) {
                alert('Failed to update user: ' + e.message);
            }
        }

        function exportAttackers(hours) {
            window.location.href = `/sensor_admin/export/attackers?hours=${hours}`;
        }

        // Initial load
        loadStats();
        loadStatus();
        loadUsers();

        // Refresh periodically
        setInterval(loadStats, 60000);
        setInterval(loadStatus, 30000);
    </script>
</body>
</html>
"""


# =============================================================================
# Admin Panel Endpoints
# =============================================================================


@router.get("", response_class=HTMLResponse)
async def admin_panel(request: Request, user: User = Depends(require_admin)):
    """Admin panel dashboard HTML."""
    import html as _html_mod

    username = _html_mod.escape(user.username) if user else "admin (legacy)"
    html = ADMIN_PANEL_HTML.replace("${CURRENT_USER}", username)
    return HTMLResponse(content=html)


@router.get("/stats")
async def admin_stats(user: User = Depends(require_admin)):
    """Get admin panel statistics."""
    with db_cursor() as cur:
        # Total users
        cur.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        total_users = cur.fetchone()[0]

        # Events today
        cur.execute("""
            SELECT COUNT(*) FROM sensor_events
            WHERE timestamp >= CURRENT_DATE
        """)
        events_today = cur.fetchone()[0]

        # Attacks today
        cur.execute("""
            SELECT COUNT(*) FROM sensor_events
            WHERE timestamp >= CURRENT_DATE AND attack_types IS NOT NULL
        """)
        attacks_today = cur.fetchone()[0]

        # Unique IPs today
        cur.execute("""
            SELECT COUNT(DISTINCT src_ip) FROM sensor_events
            WHERE timestamp >= CURRENT_DATE
        """)
        unique_ips = cur.fetchone()[0]

    # Version info — display the minor-version + build separately:
    #   VERSION (full)        e.g. "0.9_005_001"   — used for unique IDs
    #   VERSION_NUMBER (minor) e.g. "0.9_005"      — what humans see in the UI
    #   BUILD_NUMBER          e.g. 1               — increments within a minor
    from honeylens.version import BUILD_NUMBER, PRODUCT_NAME, VERSION_NUMBER

    # Ollama status
    ollama_status = "unknown"
    try:
        import requests as _req

        from honeylens.config import OLLAMA_URL as _ollama_url

        _r = _req.get(f"{_ollama_url}/api/tags", timeout=3)  # noqa: ASYNC210 — 3 s timeout, admin panel; as in 0.9
        if _r.status_code == 200:
            models = [m.get("name", "?") for m in _r.json().get("models", [])]
            ollama_status = (
                f"online ({len(models)} models: {', '.join(models[:3])})"
                if models
                else "online (no models)"
            )
        else:
            ollama_status = f"error (HTTP {_r.status_code})"
    except Exception as e:
        ollama_status = f"offline ({type(e).__name__})"

    # External AI status
    claude_status = "unknown"
    try:
        from honeylens.env import env

        provider = env("AI_PROVIDER", "openai").strip().lower()
        key_name = (
            "NOUS_API_KEY"
            if provider == "nous"
            else ("ANTHROPIC_API_KEY" if provider == "claude" else "OPENAI_API_KEY")
        )
        if env(key_name, "").strip():
            claude_status = f"{provider} configured"
        else:
            claude_status = f"{provider} not configured"
    except Exception:
        claude_status = "not configured"

    return {
        "total_users": total_users,
        "events_today": events_today,
        "attacks_today": attacks_today,
        "unique_ips_today": unique_ips,
        "version": VERSION_NUMBER,
        "build_number": BUILD_NUMBER,
        "product_name": PRODUCT_NAME,
        "ollama_status": ollama_status,
        "claude_status": claude_status,
    }


@router.get("/status")
async def system_status(user: User = Depends(require_admin)):
    """Get system service status — core, honeypots, detectors."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    core_units = [
        ("API Server", "honeylens-api", True),
        ("eBPF Capture", "sensor-capture", False),
        ("AI Analyzer", "honeylens-ai-analyzer", True),
        ("Attacker Profiler", "honeylens-profiler", True),
        ("PostgreSQL", "postgresql", False),
        ("Ollama", "ollama", False),
    ]

    # Honeypots: units from the manifest (rootless quadlets), not a hand-written list as in 0.9.
    honeypot_units = [(units.label(hp.name), hp.unit, True) for hp in HONEYPOTS]

    detector_units = [
        ("MiTM Detector", "sensor-mitm", False),
        ("TTL Deception", "sensor-ttl-deception", False),
        ("Suricata IDS", "suricata", False),
    ]

    all_units = core_units + honeypot_units + detector_units

    def _check_unit(label_unit):
        label, unit, user_unit = label_unit
        try:
            cmd = ["systemctl", "is-active", unit]
            if user_unit:
                cmd.insert(1, "--user")
            result = subprocess.run(  # noqa: S603 # nosec B603 B607 — constant command, units from lists in code
                cmd, capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            return label, {"running": status == "active", "status": status, "unit": unit}
        except Exception:
            return label, {"running": False, "status": "unknown", "unit": unit}

    results = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_check_unit, lu): lu for lu in all_units}
        for f in as_completed(futures):
            label, info = f.result()
            results[label] = info

    def _ordered(units):
        return {label: results[label] for label, _, _ in units if label in results}

    return {
        "core": _ordered(core_units),
        "honeypots": _ordered(honeypot_units),
        "detectors": _ordered(detector_units),
    }


@router.get("/users")
async def list_all_users(user: User = Depends(require_admin)):
    """List all users."""
    users = list_users(include_inactive=True)
    return {"users": [u.to_dict(include_sensitive=True) for u in users]}


@router.post("/users")
async def create_new_user(
    request: Request, data: CreateUserRequest, admin: User = Depends(require_admin)
):
    """Create a new user."""
    # Get client IP
    client_ip = request.client.host if request.client else None

    user, error = create_user(
        username=data.username,
        email=data.email,
        password=data.password,
        name=data.name,
        lastname=data.lastname,
        role=data.role,
        created_by=admin.id if admin else None,
        ip_address=client_ip,
    )

    if error or user is None:
        raise HTTPException(status_code=400, detail=error or "user not created")

    return {"user": user.to_dict(), "message": "User created successfully"}


@router.get("/users/{user_id}")
async def get_user(user_id: int, admin: User = Depends(require_admin)):
    """Get user details."""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user.to_dict(include_sensitive=True)}


@router.put("/users/{user_id}")
async def update_user_endpoint(
    user_id: int, request: Request, data: UpdateUserRequest, admin: User = Depends(require_admin)
):
    """Update user details."""
    client_ip = request.client.host if request.client else None

    user, error = update_user(
        user_id=user_id,
        name=data.name,
        lastname=data.lastname,
        email=data.email,
        role=data.role,
        is_active=data.is_active,
        updated_by=admin.id if admin else None,
        ip_address=client_ip,
    )

    if error or user is None:
        raise HTTPException(status_code=400, detail=error or "user not updated")

    return {"user": user.to_dict(), "message": "User updated successfully"}


@router.delete("/users/{user_id}")
async def delete_user_endpoint(
    user_id: int, request: Request, admin: User = Depends(require_admin)
):
    """Delete user (soft delete)."""
    client_ip = request.client.host if request.client else None

    success, error = delete_user(
        user_id=user_id, deleted_by=admin.id if admin else None, ip_address=client_ip
    )

    if not success:
        raise HTTPException(status_code=400, detail=error)

    return {"message": "User deleted successfully"}


@router.post("/users/{user_id}/reset_password")
async def reset_user_password(user_id: int, request: Request, admin: User = Depends(require_admin)):
    """Reset user password."""
    client_ip = request.client.host if request.client else None

    new_password, error = reset_password(
        user_id=user_id, reset_by=admin.id if admin else None, ip_address=client_ip
    )

    if error:
        raise HTTPException(status_code=400, detail=error)

    return {"new_password": new_password, "message": "Password reset successfully"}


@router.get("/audit")
async def get_audit_log_endpoint(limit: int = 100, admin: User = Depends(require_admin)):
    """Get admin audit log."""
    entries = get_audit_log(limit=limit)
    return {"entries": entries}


@router.get("/export/attackers")
async def export_attackers(hours: int = 24, admin: User = Depends(require_admin)):
    """Export list of attacker IPs."""
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT src_ip::text
            FROM sensor_events
            WHERE timestamp >= NOW() - INTERVAL '%s hours'
              AND attack_types IS NOT NULL
            ORDER BY src_ip::text
        """,
            (hours,),
        )

        ips = [row[0] for row in cur.fetchall()]

    # Return as plain text file
    content = "\n".join(ips)

    return StreamingResponse(
        iter([content]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=attackers_{hours}h.txt"},
    )
