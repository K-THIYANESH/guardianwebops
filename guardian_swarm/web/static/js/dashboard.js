/**
 * Guardian WebOps Dashboard Controller
 * Handles tab navigation, research task execution, evidence table rendering,
 * gate decision presentation, and cryptographic audit log verification.
 */

let currentTasks = [];
let activeTask = null;

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initProviderStatus();
    initTaskSubmission();
    initVendorRows();
    initAuditVerification();
    loadRecentTasks();
    loadAuditLedger();
});

// Navigation Handling
function initNavigation() {
    const navButtons = document.querySelectorAll(".side-nav-item");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const viewTarget = btn.getAttribute("data-view");
            switchTab(viewTarget);
        });
    });

    document.getElementById("btn-open-settings")?.addEventListener("click", () => {
        switchTab("settings-policies");
    });
}

window.switchTab = function(viewId) {
    document.querySelectorAll(".side-nav-item").forEach(b => {
        b.classList.toggle("active", b.getAttribute("data-view") === viewId);
    });

    document.querySelectorAll(".main-view").forEach(v => {
        v.classList.toggle("active", v.id === `view-${viewId}`);
    });
};

// Check TinyFish and System Provider status
async function initProviderStatus() {
    try {
        const status = await API.getResearchStatus();
        const badge = document.getElementById("provider-badge-pill");
        const statusText = document.getElementById("provider-status-text");
        const dot = document.getElementById("provider-indicator-dot");
        const formPill = document.getElementById("form-provider-pill");

        if (status.is_mock) {
            badge.className = "provider-badge-pill mock";
            statusText.textContent = "TinyFish: Simulated Mode";
            formPill.textContent = "Simulated / Mock TinyFish Mode";
            formPill.className = "badge badge-unverified";
        } else {
            badge.className = "provider-badge-pill live";
            statusText.textContent = "TinyFish: Live Integration";
            formPill.textContent = "Live TinyFish Connected";
            formPill.className = "badge badge-found";
        }
    } catch (e) {
        console.warn("Status check notice:", e);
    }
}

// Vendor row dynamic addition/removal
function initVendorRows() {
    const container = document.getElementById("vendor-rows-container");
    const addBtn = document.getElementById("btn-add-vendor");

    addBtn?.addEventListener("click", () => {
        const row = document.createElement("div");
        row.className = "vendor-input-row";
        row.innerHTML = `
            <input type="text" class="form-input vendor-name" placeholder="Vendor">
            <input type="text" class="form-input vendor-domain" placeholder="Domain (e.g. vendor.com)">
            <button type="button" class="btn btn-secondary remove-vendor-btn" title="Remove">&times;</button>
        `;
        container.appendChild(row);
        bindRemoveButtons();
    });

    bindRemoveButtons();
}

function bindRemoveButtons() {
    document.querySelectorAll(".remove-vendor-btn").forEach(btn => {
        btn.onclick = (e) => {
            const rows = document.querySelectorAll(".vendor-input-row");
            if (rows.length > 1) {
                e.target.closest(".vendor-input-row").remove();
            } else {
                alert("At least one vendor is required for research comparison.");
            }
        };
    });
}

// Task Submission
function initTaskSubmission() {
    const form = document.getElementById("research-task-form");
    const submitBtn = document.getElementById("btn-submit-research");
    const preflight = document.getElementById("preflight-status");

    form?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const objective = document.getElementById("task-objective").value.trim();
        if (!objective) {
            alert("Please specify a research objective.");
            return;
        }

        // Collect vendors
        const vendors = [];
        document.querySelectorAll(".vendor-input-row").forEach(row => {
            const name = row.querySelector(".vendor-name")?.value.trim();
            const domain = row.querySelector(".vendor-domain")?.value.trim();
            if (name && domain) {
                vendors.push({ name, domain });
            }
        });

        if (vendors.length === 0) {
            alert("Please enter at least one vendor with a valid domain.");
            return;
        }

        // Collect scope categories
        const scope = [];
        document.querySelectorAll("input[name='scope-cat']:checked").forEach(cb => {
            scope.push(cb.value);
        });

        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span>⏳ Evaluating Gates & Fetching Evidence...</span>`;
        preflight.textContent = "Guardian Interceptor: Evaluating RBAC, Confinement, Privacy, Budget, and Safety...";

        try {
            const payload = {
                objective,
                vendors,
                scope,
                allowed_domains: vendors.map(v => v.domain.toLowerCase())
            };

            const response = await API.submitResearchTask(payload);
            const task = response.task;
            activeTask = task;

            // Render Results
            renderResearchResults(task);
            renderGovernanceDecisions(task);
            loadAuditLedger();

            // Switch to results tab
            window.switchTab("research-results");
        } catch (err) {
            alert(`Research task failed: ${err.message}`);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `
                <svg class="svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polygon points="5 3 19 12 5 21 5 3"/>
                </svg>
                Run Governed Research
            `;
            preflight.textContent = "Ready to evaluate 5-gate policy controls.";
        }
    });
}

// Load recent tasks from backend
async function loadRecentTasks() {
    try {
        const res = await API.getResearchTasks();
        currentTasks = res.tasks || [];
        const badge = document.getElementById("results-count-badge");
        if (badge) badge.textContent = currentTasks.length;

        if (currentTasks.length > 0) {
            activeTask = currentTasks[0];
            renderResearchResults(activeTask);
            renderGovernanceDecisions(activeTask);
        }
    } catch (e) {
        console.warn("Could not load tasks:", e);
    }
}

// Render Research Results
function renderResearchResults(task) {
    const emptyState = document.getElementById("results-empty-state");
    const activeContainer = document.getElementById("results-active-container");
    const tableBody = document.getElementById("evidence-table-body");

    if (!task) {
        emptyState.classList.remove("hidden");
        activeContainer.classList.add("hidden");
        return;
    }

    emptyState.classList.add("hidden");
    activeContainer.classList.remove("hidden");

    document.getElementById("report-task-title").textContent = task.objective;
    document.getElementById("report-task-meta").textContent = 
        `Task ID: ${task.task_id} · Completed: ${new Date(task.completed_at || task.created_at).toLocaleTimeString()}`;

    const statusBadge = document.getElementById("report-status-badge");
    statusBadge.textContent = task.status;
    if (task.status === "COMPLETED") statusBadge.className = "badge badge-found";
    else if (task.status === "PARTIAL") statusBadge.className = "badge badge-conflicting";
    else statusBadge.className = "badge badge-missing";

    const provBadge = document.getElementById("report-provider-badge");
    provBadge.textContent = task.is_mock ? "Simulated TinyFish Mode" : "Live TinyFish Run";

    tableBody.innerHTML = "";

    // Flat listing of claims across vendors
    const results = task.results || [];
    results.forEach(vResult => {
        const claims = vResult.claims || [];
        claims.forEach(c => {
            const tr = document.createElement("tr");

            // Status badge class
            let badgeClass = "badge-unverified";
            if (c.status === "FOUND") badgeClass = "badge-found";
            else if (c.status === "MISSING") badgeClass = "badge-missing";
            else if (c.status === "CONFLICTING") badgeClass = "badge-conflicting";
            else if (c.status === "FAILED_TO_RETRIEVE") badgeClass = "badge-failed";

            let excerptHtml = "";
            if (c.source_excerpt) {
                excerptHtml += `<div class="source-excerpt">"${c.source_excerpt}"</div>`;
            }
            if (c.missing_explanation) {
                excerptHtml += `<div class="missing-note">⚠️ ${c.missing_explanation}</div>`;
            }
            if (c.source_url) {
                excerptHtml += `<a href="${c.source_url}" target="_blank" rel="noopener noreferrer" class="source-link">🔗 View Public Source</a>`;
            }

            tr.innerHTML = `
                <td style="font-weight:600; color:var(--text-secondary);">${c.category}</td>
                <td>
                    <div style="font-weight:600; color:var(--text-primary);">${vResult.vendor_name}</div>
                    <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${vResult.target_domain}</div>
                </td>
                <td style="line-height:1.4;">${c.claim}</td>
                <td><span class="badge ${badgeClass}">${c.status}</span></td>
                <td>${excerptHtml}</td>
            `;
            tableBody.appendChild(tr);
        });
    });
}

// Render Governance Decisions
function renderGovernanceDecisions(task) {
    const container = document.getElementById("governance-gates-list");
    if (!container) return;

    const decisions = task?.gate_decisions || [];
    if (decisions.length === 0) {
        return;
    }

    container.innerHTML = "";
    decisions.forEach(d => {
        const card = document.createElement("div");
        card.className = `gate-card ${d.passed ? 'passed' : 'blocked'}`;
        card.innerHTML = `
            <div class="gate-header">
                <span>${d.gate_name}</span>
                <span class="badge ${d.passed ? 'badge-found' : 'badge-missing'}">${d.passed ? 'Passed' : 'Blocked'}</span>
            </div>
            <div class="gate-details">${d.details}</div>
        `;
        container.appendChild(card);
    });
}

// Audit Ledger & Verification
async function loadAuditLedger() {
    try {
        const data = await API.getLedger();
        const chain = data.chain || [];
        const countBadge = document.getElementById("audit-block-count");
        if (countBadge) countBadge.textContent = `${chain.length} Blocks`;

        const container = document.getElementById("audit-blocks-container");
        if (!container) return;
        container.innerHTML = "";

        // Display recent blocks in reverse order
        chain.slice().reverse().forEach(block => {
            const blockEl = document.createElement("div");
            blockEl.className = "audit-block";

            const verdict = block.verdict || "UNKNOWN";
            let vClass = "badge-unverified";
            if (verdict === "SAFE" || verdict === "APPROVED") vClass = "badge-found";
            else if (verdict === "BLOCKED") vClass = "badge-missing";

            blockEl.innerHTML = `
                <div class="audit-header">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <strong style="font-size:0.85rem; color:var(--text-primary);">${block.action_id || 'Block'}</strong>
                        <span class="badge ${vClass}">${verdict}</span>
                    </div>
                    <span class="audit-meta">${new Date(block.timestamp).toLocaleString()}</span>
                </div>
                <div style="font-size:0.82rem; color:var(--text-secondary); margin-bottom:4px;">
                    <strong>Tool:</strong> ${block.proposed_action?.tool || 'action'} · 
                    <strong>Target:</strong> ${block.proposed_action?.target || 'general'}
                </div>
                <div style="font-size:0.8rem; color:var(--text-muted); line-height:1.4;">
                    ${block.reasoning || ''}
                </div>
                <div class="audit-hash-row">
                    <div><strong>SHA-256 Hash:</strong> ${block.entry_hash || 'none'}</div>
                    <div style="color:var(--text-muted); font-size:10px;">Prev: ${block.prev_hash || '0'.repeat(64)}</div>
                </div>
            `;
            container.appendChild(blockEl);
        });
    } catch (e) {
        console.warn("Ledger load notice:", e);
    }
}

function initAuditVerification() {
    const btn = document.getElementById("btn-verify-audit-chain");
    const banner = document.getElementById("chain-verify-result-banner");

    btn?.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "Verifying cryptographic hashes...";
        try {
            const res = await API.verifyLedger();
            banner.classList.remove("hidden");
            if (res.verified) {
                banner.style.background = "#f0fdf4";
                banner.style.borderColor = "#bbf7d0";
                banner.style.color = "#15803d";
                banner.innerHTML = `<strong>✓ Verification Successful:</strong> ${res.message}`;
            } else {
                banner.style.background = "#fef2f2";
                banner.style.borderColor = "#fecaca";
                banner.style.color = "#b91c1c";
                banner.innerHTML = `<strong>⚠️ Verification Failed:</strong> ${res.message}`;
            }
        } catch (e) {
            alert(`Verification request failed: ${e.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = "🔍 Verify Audit Hash Chain";
        }
    });
}
