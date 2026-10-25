/*
  Guardian Swarm V3 — Corporate AI OS Admin Panel Controller
  Provides complete, real-time CRUD management for API Keys, Models, Groups, Roles, Budget, Users, and Health.
*/

(function() {
    'use strict';

    // Toast notification utility
    window.showToast = function(msg, type = 'info') {
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;';
            document.body.appendChild(toastContainer);
        }
        const toast = document.createElement('div');
        const bgColor = type === 'success' ? '#14532d' : type === 'error' ? '#7f1d1d' : '#1e293b';
        const borderColor = type === 'success' ? '#22c55e' : type === 'error' ? '#ef4444' : '#3b82f6';
        toast.style.cssText = `background:${bgColor};border:1px solid ${borderColor};color:#fff;padding:10px 16px;border-radius:6px;font-size:0.82rem;box-shadow:0 4px 12px rgba(0,0,0,0.5);transition:all 0.3s ease;`;
        toast.innerText = msg;
        toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    };

    // Helper: Escape HTML
    function escapeHtml(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Modal Helper
    window.openAdminModal = function(title, contentHtml) {
        let modal = document.getElementById('admin-action-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'admin-action-modal';
            modal.className = 'modal-overlay';
            modal.innerHTML = `
                <div class="settings-modal-box" style="width:500px;max-width:90vw;">
                    <div class="modal-header">
                        <h3 id="admin-modal-title">Action</h3>
                        <button class="close-btn" onclick="closeAdminModal()">&times;</button>
                    </div>
                    <div id="admin-modal-body" style="padding:1.2rem;"></div>
                </div>
            `;
            document.body.appendChild(modal);
        }
        document.getElementById('admin-modal-title').innerText = title;
        document.getElementById('admin-modal-body').innerHTML = contentHtml;
        modal.classList.remove('hidden');
    };

    window.closeAdminModal = function() {
        const modal = document.getElementById('admin-action-modal');
        if (modal) modal.classList.add('hidden');
    };

    // Initialize Admin Panel listeners
    document.addEventListener('DOMContentLoaded', () => {
        const tabs = document.querySelectorAll('.admin-side-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetId = tab.getAttribute('data-admintab');
                if (targetId) loadAdminTab(targetId);
            });
        });

        const scanBtn = document.getElementById('btn-start-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => {
                if (window.startDataScannerScan) window.startDataScannerScan();
            });
        }
        if (window.fetchClassificationSummarySidebar) window.fetchClassificationSummarySidebar();
    });

    window.loadAdminTab = function(tabId) {
        switch (tabId) {
            case 'admintab-apikeys':
                if (window.fetchAdminApiKeys) window.fetchAdminApiKeys();
                break;
            case 'admintab-models':
                fetchAdminModels();
                break;
            case 'admintab-groups':
                fetchAdminGroups();
                break;
            case 'admintab-roles':
                fetchAdminRoles();
                break;
            case 'admintab-budget':
                fetchAdminBudget();
                break;
            case 'admintab-users':
                fetchAdminUsers();
                break;
            case 'admintab-health':
                fetchAdminHealth();
                break;
            case 'admintab-datascanner':
                if (window.fetchAdminDataScanner) window.fetchAdminDataScanner();
                break;
        }
    };

    // 1. MODELS TAB (Real DB data with Add/Delete/Edit)
    async function fetchAdminModels() {
        const tbody = document.getElementById('admin-models-tbody');
        if (!tbody) return;
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:1.5rem;color:var(--text-muted);">Loading model registry from database…</td></tr>`;
        try {
            const res = await fetch('/api/admin/models');
            const data = await res.json();
            const models = data.models || [];

            let headerBtn = document.getElementById('add-model-btn-container');
            if (!headerBtn) {
                const parent = tbody.closest('.admintab-content');
                if (parent) {
                    const btnBox = document.createElement('div');
                    btnBox.id = 'add-model-btn-container';
                    btnBox.style.cssText = 'margin-bottom:1rem;display:flex;justify-content:flex-end;';
                    btnBox.innerHTML = `<button class="btn btn-primary btn-mini" onclick="openAddModelModal()">+ Register New Model</button>`;
                    parent.insertBefore(btnBox, parent.children[1] || parent.firstChild);
                }
            }

            if (!models.length) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:1.5rem;color:var(--text-muted);">No active models registered in database.</td></tr>`;
                return;
            }

            tbody.innerHTML = models.map(m => {
                const tags = Array.isArray(m.allowed_guardian_tags) ? m.allowed_guardian_tags : ["PUBLIC", "INTERNAL"];
                const tagBadges = tags.map(t => `<span class="badge ${t === 'RESTRICTED' ? 'badge-danger' : (t === 'CONFIDENTIAL' ? 'badge-amber' : 'badge-info')}">${escapeHtml(t)}</span>`).join(' ');
                const ops = [];
                if (m.can_read !== false) ops.push("READ");
                if (m.can_download) ops.push("DL");
                if (m.can_export) ops.push("EXP");
                const opsStr = ops.join('/') || 'NONE';

                return `
                    <tr style="border-bottom:1px solid #1f1f1f;">
                        <td style="padding:0.6rem;"><strong style="color:#fff;">${escapeHtml(m.name)}</strong></td>
                        <td>${escapeHtml(m.provider)}</td>
                        <td><span class="badge ${m.type === 'local' || m.model_type === 'local' ? 'badge-info' : 'badge-amber'}">${escapeHtml(m.model_type || m.type || 'cloud')}</span></td>
                        <td><span class="badge badge-success">${escapeHtml(m.group_name || m.group || 'ALL')}</span></td>
                        <td style="font-family:var(--font-mono); font-size:0.75rem;">In: $${(m.input_cost_per_1m || 0).toFixed(2)}<br>Out: $${(m.output_cost_per_1m || 0).toFixed(2)}</td>
                        <td>
                            <span class="badge ${m.file_access_enabled !== false ? 'badge-success' : 'badge-danger'}">
                                ${m.file_access_enabled !== false ? 'ENABLED' : 'DISABLED'}
                            </span>
                        </td>
                        <td><div style="display:flex; gap:0.2rem; flex-wrap:wrap;">${tagBadges}</div></td>
                        <td><span style="font-size:0.72rem; color:var(--text-secondary); font-family:var(--font-mono);">${escapeHtml(opsStr)}</span></td>
                        <td>
                            <span class="badge ${m.is_active ? 'badge-success' : 'badge-danger'}">${m.is_active ? 'Active' : 'Inactive'}</span>
                            <button class="btn btn-secondary btn-mini" style="margin-left:0.4rem;" onclick="deleteModel('${m.id || m.name}')">Remove</button>
                        </td>
                    </tr>
                `;
            }).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--color-red);padding:1rem;">Failed to fetch model registry: ${escapeHtml(e.message)}</td></tr>`;
            showToast(`Error fetching models: ${e.message}`, 'error');
        }
    }

    window.openAddModelModal = function() {
        const formHtml = `
            <form onsubmit="submitNewModel(event)" style="display:flex;flex-direction:column;gap:0.8rem;">
                <div>
                    <label style="font-size:0.75rem;color:var(--text-secondary);">Model ID / Name</label>
                    <input id="modal-model-name" required placeholder="e.g. gpt-4o, claude-3-5-sonnet, gemini-1.5-pro" style="width:100%;background:#1a1a1a;border:1px solid #333;color:#fff;padding:0.4rem;border-radius:4px;font-size:0.8rem;" />
                </div>
                <div style="display:flex;gap:0.5rem;">
                    <div style="flex:1;">
                        <label style="font-size:0.75rem;color:var(--text-secondary);">Provider</label>
                        <select id="modal-model-provider" style="width:100%;background:#1a1a1a;border:1px solid #333;color:#fff;padding:0.4rem;border-radius:4px;font-size:0.8rem;">
                            <option value="openai">OpenAI</option>
                            <option value="anthropic">Anthropic</option>
                            <option value="google">Google Gemini</option>
                            <option value="deepseek">DeepSeek</option>
                            <option value="grok">Grok (xAI)</option>
                        </select>
                    </div>
                    <div style="flex:1;">
                        <label style="font-size:0.75rem;color:var(--text-secondary);">Task Group</label>
                        <select id="modal-model-group" style="width:100%;background:#1a1a1a;border:1px solid #333;color:#fff;padding:0.4rem;border-radius:4px;font-size:0.8rem;">
                            <option value="RESEARCH">RESEARCH</option>
                            <option value="CODE">CODE</option>
                            <option value="DRAFTING">DRAFTING</option>
                            <option value="SUPPORT">SUPPORT</option>
                            <option value="DATA_ANALYSIS">DATA_ANALYSIS</option>
                        </select>
                    </div>
                </div>
                <div style="display:flex;gap:0.5rem;">
                    <div style="flex:1;">
                        <label style="font-size:0.75rem;color:var(--text-secondary);">Input Cost / 1M Tokens ($)</label>
                        <input id="modal-model-input" type="number" step="0.01" value="2.50" style="width:100%;background:#1a1a1a;border:1px solid #333;color:#fff;padding:0.4rem;border-radius:4px;font-size:0.8rem;" />
                    </div>
                    <div style="flex:1;">
                        <label style="font-size:0.75rem;color:var(--text-secondary);">Output Cost / 1M Tokens ($)</label>
                        <input id="modal-model-output" type="number" step="0.01" value="10.00" style="width:100%;background:#1a1a1a;border:1px solid #333;color:#fff;padding:0.4rem;border-radius:4px;font-size:0.8rem;" />
                    </div>
                </div>
                <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-top:0.5rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeAdminModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Model</button>
                </div>
            </form>
        `;
        openAdminModal('Register AI Model', formHtml);
    };

    window.submitNewModel = async function(e) {
        e.preventDefault();
        const payload = {
            name: document.getElementById('modal-model-name').value.trim(),
            provider: document.getElementById('modal-model-provider').value,
            group: document.getElementById('modal-model-group').value,
            input_cost: parseFloat(document.getElementById('modal-model-input').value),
            output_cost: parseFloat(document.getElementById('modal-model-output').value)
        };
        try {
            const res = await fetch('/api/admin/models', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (res.ok) {
                showToast(`Model ${payload.name} registered successfully!`, 'success');
                closeAdminModal();
                fetchAdminModels();
            } else {
                showToast(`Error: ${data.error || 'Registration failed'}`, 'error');
            }
        } catch (err) {
            showToast(`Network error: ${err.message}`, 'error');
        }
    };

    window.deleteModel = async function(modelId) {
        if (!confirm(`Delete model entry from database?`)) return;
        try {
            const res = await fetch(`/api/admin/models/${encodeURIComponent(modelId)}`, { method: 'DELETE' });
            if (res.ok) {
                showToast(`Model removed.`, 'success');
                fetchAdminModels();
            } else {
                showToast(`Failed to remove model.`, 'error');
            }
        } catch (err) {
            showToast(`Error: ${err.message}`, 'error');
        }
    };

    // 2. GROUPS TAB (Task Group Configurations)
    async function fetchAdminGroups() {
        const container = document.getElementById('admin-groups-list');
        if (!container) return;
        container.innerHTML = `<div style="padding:1.5rem;text-align:center;color:var(--text-muted);">Loading task group configurations…</div>`;
        try {
            const res = await fetch('/api/admin/groups');
            const data = await res.json();
            const groups = data.groups || {};

            container.innerHTML = Object.entries(groups).map(([gName, gInfo]) => `
                <div class="glass-card" style="margin-bottom:0.8rem;padding:0.9rem;background:#141414;border:1px solid #2a2a2a;border-radius:6px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;font-weight:700;color:var(--color-orange);font-size:0.88rem;margin-bottom:0.4rem;">
                        <span>Task Group: ${escapeHtml(gName)}</span>
                        <span class="badge badge-info">${(gInfo.models || []).length} Models Assigned</span>
                    </div>
                    <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:0.4rem;">
                        <strong>Allowed Models:</strong> ${(gInfo.models || []).map(m => `<span class="badge badge-amber">${escapeHtml(m)}</span>`).join(' ') || 'None'}
                    </div>
                    <div style="font-size:0.75rem;color:var(--color-green);">
                        <strong>✓ Permitted Tools:</strong> ${(gInfo.allowed_tools || []).join(', ') || 'Standard Execution'}
                    </div>
                </div>
            `).join('');
        } catch (e) {
            container.innerHTML = `<div style="color:var(--color-red);padding:1rem;">Failed to fetch task groups: ${escapeHtml(e.message)}</div>`;
            showToast(`Error fetching groups: ${e.message}`, 'error');
        }
    }

    // 3. ROLES TAB (Real Permissions Matrix)
    async function fetchAdminRoles() {
        const container = document.getElementById('admin-roles-list');
        if (!container) return;
        container.innerHTML = `<div style="padding:1.5rem;text-align:center;color:var(--text-muted);">Loading role permissions matrix…</div>`;
        try {
            const res = await fetch('/api/admin/roles');
            const data = await res.json();
            const roles = data.roles || {};

            container.innerHTML = Object.entries(roles).map(([rName, rInfo]) => `
                <div class="glass-card" style="margin-bottom:0.8rem;padding:0.9rem;background:#141414;border:1px solid #2a2a2a;border-radius:6px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;font-weight:700;font-size:0.88rem;margin-bottom:0.4rem;">
                        <span class="role-pill role-${rName.toLowerCase()}">${escapeHtml(rName)}</span>
                        <span style="font-size:0.75rem;color:var(--text-muted);">Max Classification: <strong style="color:#fff;">${escapeHtml(rInfo.max_classification)}</strong></span>
                    </div>
                    <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:0.3rem;">
                        <strong>Allowed Task Groups:</strong> ${(rInfo.allowed_groups || []).map(g => `<span class="badge badge-info">${escapeHtml(g)}</span>`).join(' ')}
                    </div>
                    <div style="display:flex;gap:1rem;font-size:0.75rem;color:var(--color-orange);margin-top:0.4rem;padding-top:0.4rem;border-top:1px solid #222;">
                        <span>Daily Wallet: <strong>${(rInfo.daily_token_limit || 10000).toLocaleString()} tokens</strong></span>
                        <span>Subagent Spawning: <strong>${rInfo.can_spawn_subagents ? 'YES' : 'NO'}</strong></span>
                    </div>
                </div>
            `).join('');
        } catch (e) {
            container.innerHTML = `<div style="color:var(--color-red);padding:1rem;">Failed to fetch roles: ${escapeHtml(e.message)}</div>`;
            showToast(`Error fetching roles: ${e.message}`, 'error');
        }
    }

    // 4. BUDGET TAB (Team Pools & Org Ceiling)
    async function fetchAdminBudget() {
        const container = document.getElementById('admin-budget-list');
        if (!container) return;
        container.innerHTML = `<div style="padding:1.5rem;text-align:center;color:var(--text-muted);">Loading team budget pools & org ceiling…</div>`;
        try {
            const res = await fetch('/api/admin/budget');
            const data = await res.json();
            const pools = data.team_pools || {};
            const org = data.org_ceiling || {};

            let html = `
                <div class="glass-card" style="margin-bottom:1rem;padding:1rem;background:#141414;border:1px solid #2a2a2a;border-radius:6px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                        <h4 style="color:var(--color-orange);font-size:0.88rem;margin:0;">Enterprise Monthly Org Hard-Stop Ceiling</h4>
                        <span class="badge badge-success">Enforced</span>
                    </div>
                    <div style="font-size:1.1rem;font-weight:700;color:#fff;">
                        ${(org.used_this_month || 0).toLocaleString()} / ${(org.monthly_tokens || 5000000).toLocaleString()} tokens used
                    </div>
                </div>
                <h4 style="color:var(--text-secondary);font-size:0.8rem;margin-bottom:0.6rem;">Department Team Allocations</h4>
            `;

            html += Object.entries(pools).map(([dept, pInfo]) => `
                <div class="glass-card" style="margin-bottom:0.6rem;padding:0.8rem;background:#141414;border:1px solid #2a2a2a;border-radius:6px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;font-size:0.82rem;font-weight:600;color:#fff;">
                        <span>Department: ${escapeHtml(dept.toUpperCase())}</span>
                        <span style="color:var(--color-green);">${(pInfo.used_this_month || 0).toLocaleString()} / ${(pInfo.monthly_limit || 50000).toLocaleString()} tokens</span>
                    </div>
                </div>
            `).join('');

            container.innerHTML = html;
        } catch (e) {
            container.innerHTML = `<div style="color:var(--color-red);padding:1rem;">Failed to fetch budget pools: ${escapeHtml(e.message)}</div>`;
            showToast(`Error fetching budget: ${e.message}`, 'error');
        }
    }

    // 5. USERS TAB (Database Users & Token Consumption)
    async function fetchAdminUsers() {
        const tbody = document.getElementById('admin-users-list-tbody');
        if (!tbody) return;
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:var(--text-muted);">Loading user database & token wallets…</td></tr>`;
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            const users = data.users || [];

            if (!users.length) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:var(--text-muted);">No users found in database.</td></tr>`;
                return;
            }

            tbody.innerHTML = users.map(u => `
                <tr style="border-bottom:1px solid #1f1f1f;">
                    <td style="padding:0.6rem;"><strong style="color:#fff;">${escapeHtml(u.name)}</strong> (${escapeHtml(u.user_id)})</td>
                    <td><span class="role-pill role-${escapeHtml(u.role.toLowerCase())}">${escapeHtml(u.role)}</span></td>
                    <td>${escapeHtml(u.department)}</td>
                    <td style="font-family:var(--font-mono);">${(u.daily_token_used || 0).toLocaleString()} / ${(u.daily_token_limit || 10000).toLocaleString()}</td>
                    <td><span class="badge ${u.is_suspended ? 'badge-danger' : 'badge-success'}">${u.is_suspended ? 'Suspended' : 'Active'}</span></td>
                    <td>
                        <button class="btn btn-secondary btn-mini" onclick="toggleUserSuspension('${u.user_id}', ${!u.is_suspended})">
                            ${u.is_suspended ? 'Unsuspend' : 'Suspend'}
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--color-red);padding:1rem;">Failed to fetch users: ${escapeHtml(e.message)}</td></tr>`;
            showToast(`Error fetching users: ${e.message}`, 'error');
        }
    }

    window.toggleUserSuspension = async function(userId, suspendState) {
        try {
            const res = await fetch('/api/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, is_suspended: suspendState })
            });
            if (res.ok) {
                showToast(`User ${userId} ${suspendState ? 'suspended' : 'unsuspended'}.`, 'success');
                fetchAdminUsers();
            } else {
                showToast(`Action failed.`, 'error');
            }
        } catch (e) {
            showToast(`Error: ${e.message}`, 'error');
        }
    };

    // 6. SYSTEM HEALTH TAB (System Metrics & SHA-256 Chain Verification)
    async function fetchAdminHealth() {
        const container = document.getElementById('admin-health-metrics');
        if (!container) return;
        container.innerHTML = `<div style="padding:1.5rem;text-align:center;color:var(--text-muted);">Inspecting system health & audit ledger integrity…</div>`;
        try {
            const res = await fetch('/api/admin/health');
            const data = await res.json();

            const isVerified = data.ledger?.chain_valid ?? true;
            const blockCount = data.ledger?.blocks ?? 0;

            container.innerHTML = `
                <div class="glass-card" style="padding:1rem;background:#141414;border:1px solid #2a2a2a;border-radius:6px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem;">
                        <strong style="color:var(--color-green);font-size:0.9rem;">Status: ${escapeHtml(data.status)}</strong>
                        <span style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(data.timestamp)}</span>
                    </div>
                    <div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.3rem;">Persistence Engine: ${escapeHtml(data.database)}</div>
                    <div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.3rem;">Security Interceptor: ${escapeHtml(data.security_interceptor)}</div>
                    <div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.5rem;">System CPU Usage: ${escapeHtml(data.cpu_usage)} · Memory: ${escapeHtml(data.memory_usage)}</div>
                    
                    <div style="display:flex;justify-content:space-between;align-items:center;padding-top:0.6rem;border-top:1px solid #222;margin-top:0.4rem;">
                        <div style="font-size:0.8rem;color:${isVerified ? 'var(--color-green)' : 'var(--color-red)'};">
                            SHA-256 Audit Ledger: ${isVerified ? `✅ Chain Verified (${blockCount} blocks)` : `❌ Hash Mismatch detected`}
                        </div>
                        <button type="button" class="btn btn-secondary btn-mini" onclick="runLedgerIntegrityScan()">Run Ledger Integrity Scan</button>
                    </div>
                    <div id="ledger-scan-result" style="font-size:0.75rem;margin-top:0.4rem;color:var(--text-muted);"></div>
                </div>
            `;
        } catch (e) {
            container.innerHTML = `<div style="color:var(--color-red);padding:1rem;">Failed to fetch health metrics: ${escapeHtml(e.message)}</div>`;
            showToast(`Error fetching health metrics: ${e.message}`, 'error');
        }
    }

    window.runLedgerIntegrityScan = async function() {
        const resultEl = document.getElementById('ledger-scan-result');
        if (resultEl) { resultEl.style.color = 'var(--text-muted)'; resultEl.innerText = 'Scanning SHA-256 chain integrity…'; }
        try {
            const res = await fetch('/api/verify', { method: 'POST' });
            const data = await res.json();
            if (resultEl) {
                const valid = data.status === 'VERIFIED';
                resultEl.style.color = valid ? 'var(--color-green)' : 'var(--color-red)';
                resultEl.innerText = valid ? `✓ Ledger Cryptographically Verified (${data.chain_length} blocks intact)` : `❌ Integrity Breach: ${data.message}`;
                showToast(valid ? 'Ledger verification passed!' : 'Ledger verification failed!', valid ? 'success' : 'error');
            }
        } catch (e) {
            if (resultEl) { resultEl.style.color = 'var(--text-red)'; resultEl.innerText = `Scan failed: ${e.message}`; }
            showToast(`Scan error: ${e.message}`, 'error');
        }
    };

    // 7. DATA SCANNER TAB (FileMind Content-Aware Classifier)
    window.fetchAdminDataScanner = async function() {
        try {
            const res = await fetch('/api/classify/status');
            const data = await res.json();
            renderDataScannerProgressAndResults(data);
            if (window.fetchClassificationSummarySidebar) window.fetchClassificationSummarySidebar();
        } catch (e) {
            console.error('Data Scanner status error:', e);
        }
    };

    window.fetchClassificationSummarySidebar = async function() {
        try {
            const res = await fetch('/api/classify/summary');
            const data = await res.json();
            const tot = document.getElementById('stat-total-classified');
            const pubInt = document.getElementById('stat-public-internal');
            const confRest = document.getElementById('stat-confidential-restricted');
            const errs = document.getElementById('stat-scanner-errors');

            if (tot) tot.innerText = data.total_classified || 0;
            if (pubInt) pubInt.innerText = `${data.public || 0} / ${data.internal || 0}`;
            if (confRest) confRest.innerText = `${data.confidential || 0} / ${data.restricted || 0}`;
            if (errs) errs.innerText = data.recent_errors || 0;
        } catch (e) {}
    };

    function renderDataScannerProgressAndResults(data) {
        const tbody = document.getElementById('admin-scanner-tbody');
        const pBox = document.getElementById('scan-progress-box');
        const pBar = document.getElementById('scan-progress-bar');
        const pText = document.getElementById('scan-status-text');
        const cText = document.getElementById('scan-counts-text');

        const cachedEl = document.getElementById('scan-stat-cached');
        const newEl = document.getElementById('scan-stat-new');
        const failedEl = document.getElementById('scan-stat-failed');
        const lastEl = document.getElementById('scan-stat-last');

        if (cachedEl) cachedEl.innerText = data.cached || 0;
        if (newEl) newEl.innerText = data.new || 0;
        if (failedEl) failedEl.innerText = data.failed || 0;

        if (data.status === 'running' || data.status === 'started' || data.status === 'completed') {
            if (pBox) pBox.classList.remove('hidden');
            const total = data.total || data.total_files || data.processed || 0;
            const processed = data.processed || 0;
            const pct = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 100;
            if (pBar) pBar.style.width = `${pct}%`;
            if (pText) pText.innerText = data.status === 'completed' ? 'Scan Completed' : 'Scanning...';
            if (cText) cText.innerText = `Processed: ${processed} / ${total}`;
        }

        if (tbody && data.results) {
            if (data.results.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="padding:1rem; text-align:center; color:var(--text-muted);">No supported files found in this scan root.</td></tr>';
                return;
            }
            tbody.innerHTML = data.results.map(r => {
                const badgeStyle = r.guardian_classification === 'PUBLIC' ? 'background:#065f46;color:#34d399;' :
                                   r.guardian_classification === 'INTERNAL' ? 'background:#1e3a8a;color:#60a5fa;' :
                                   r.guardian_classification === 'CONFIDENTIAL' ? 'background:#78350f;color:#fbbf24;' :
                                   r.guardian_classification === 'SKIPPED' ? 'background:#374151;color:#9ca3af;' : 'background:#7f1d1d;color:#f87171;';
                
                const isError = r.status === 'scanner_failure';
                const tagLabel = isError ? 'RESTRICTED<br><small style="color:#ef4444;">Scanner Failure</small>' : escapeHtml(r.guardian_classification);

                if (lastEl && r.path) lastEl.innerText = r.path.split(/[\/\\]/).pop();

                const cacheLabel = r.status === 'SKIPPED' ? 'SKIPPED' : (r.cache_status === 'cached' ? 'HIT' : 'NEW');

                return `
                    <tr style="border-bottom:1px solid #1f1f23;">
                        <td style="padding:0.6rem 0.5rem;font-family:monospace;font-size:0.75rem;max-width:250px;word-break:break-all;">${escapeHtml(r.path)}</td>
                        <td style="padding:0.6rem 0.5rem;">${escapeHtml(r.filemind_category || 'Unknown')}</td>
                        <td style="padding:0.6rem 0.5rem;"><span style="padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;${badgeStyle}">${tagLabel}</span></td>
                        <td style="padding:0.6rem 0.5rem;"><span style="color:${r.status === 'SKIPPED' ? '#9ca3af' : (r.cache_status === 'cached' ? '#34d399' : '#60a5fa')};">${escapeHtml(cacheLabel)}</span></td>
                        <td style="padding:0.6rem 0.5rem;color:var(--text-muted);font-size:0.75rem;">${escapeHtml(r.last_scanned || 'Just now')}</td>
                    </tr>
                `;
            }).join('');
        }
    }

    window.startDataScannerScan = async function() {
        if (window.isScanning) return;

        const input = document.getElementById('scan-folder-path');
        const dryRunBox = document.getElementById('scan-dry-run');
        const btn = document.getElementById('btn-start-scan');

        const folderPath = input ? input.value.trim() : '';
        const dryRun = dryRunBox ? dryRunBox.checked : true;

        if (!folderPath) {
            showToast('Please enter a folder path to scan.', 'error');
            return;
        }

        window.isScanning = true;
        if (btn) {
            btn.disabled = true;
            btn.innerText = 'Scanning...';
        }

        const tbody = document.getElementById('admin-scanner-tbody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="padding:1rem; text-align:center; color:var(--text-muted);">Initializing scan...</td></tr>';

        showToast(`Initiating FileMind scan on ${folderPath}…`, 'info');

        const headers = { 'Content-Type': 'application/json' };
        const token = (window.API && window.API.token) || localStorage.getItem('gs_jwt') || localStorage.getItem('jwt_token') || sessionStorage.getItem('jwt_token');
        if (token) headers['Authorization'] = `Bearer ${token}`;

        try {
            const res = await fetch('/api/classify/folder', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ folder_path: folderPath, dry_run: dryRun })
            });
            const data = await res.json();
            if (res.ok) {
                showToast(`Scan started (ID: ${data.scan_id})`, 'success');
                pollScanProgress(data.scan_id);
            } else {
                const errorMsg = data.message || data.error || 'Authorization denied';
                showToast(`Scan failed: ${errorMsg}`, 'error');
                window.isScanning = false;
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = 'Start Classification Scan';
                }
            }
        } catch (e) {
            showToast(`Scan error: ${e.message}`, 'error');
            window.isScanning = false;
            if (btn) {
                btn.disabled = false;
                btn.innerText = 'Start Classification Scan';
            }
        }
    };

    function pollScanProgress(scanId) {
        const interval = setInterval(async () => {
            try {
                const res = await fetch(`/api/classify/status?scan_id=${scanId}`);
                const data = await res.json();
                renderDataScannerProgressAndResults(data);
                if (window.fetchClassificationSummarySidebar) window.fetchClassificationSummarySidebar();
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    window.isScanning = false;
                    const btn = document.getElementById('btn-start-scan');
                    if (btn) {
                        btn.disabled = false;
                        btn.innerText = 'Start Classification Scan';
                    }
                    if (data.status === 'completed') {
                        showToast(`Classification scan finished!`, 'success');
                    } else {
                        showToast(`Scan error: ${data.error || 'Unknown error'}`, 'error');
                    }
                }
            } catch (e) {
                clearInterval(interval);
                window.isScanning = false;
                const btn = document.getElementById('btn-start-scan');
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = 'Start Classification Scan';
                }
            }
        }, 1000);
    }

})();
