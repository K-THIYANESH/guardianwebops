/**
 * Guardian WebOps API Client
 * Clean HTTP adapter for Research Workflows, Audit Verification, and Governance.
 */
class APIClient {
    static get token() {
        return localStorage.getItem('gw_jwt') || '';
    }

    static getHeaders(extra = {}, includeContentType = true) {
        const h = includeContentType ? { 'Content-Type': 'application/json', ...extra } : { ...extra };
        const tok = this.token;
        if (tok) h['Authorization'] = `Bearer ${tok}`;
        return h;
    }

    static async get(path) {
        const res = await fetch(path, { headers: this.getHeaders({}, false) });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || err.message || `${res.status} ${res.statusText}`);
        }
        return res.json();
    }

    static async post(path, body = {}) {
        const res = await fetch(path, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify(body)
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || err.message || `POST ${path} failed (${res.status})`);
        }
        return res.json();
    }

    // Auth & User
    static login(user_id, password) { return this.post('/api/auth/login', { user_id, password }); }
    static me() { return this.get('/api/auth/me'); }
    static budgetStatus() { return this.get('/api/budget/status'); }

    // Research Workflow
    static getResearchStatus() { return this.get('/api/research/status'); }
    static getResearchTasks() { return this.get('/api/research/tasks'); }
    static submitResearchTask(payload) { return this.post('/api/research/tasks', payload); }
    static getResearchTask(taskId) { return this.get(`/api/research/tasks/${taskId}`); }

    // Audit Ledger & Governance
    static getLedger() { return this.get('/api/ledger'); }
    static verifyLedger() { return this.post('/api/verify', {}); }
    static getTraces() { return this.get('/api/traces'); }
    static getSystemGates() { return this.get('/api/system/gates'); }
}

window.API = APIClient;
