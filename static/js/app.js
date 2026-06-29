/* ============================================================
   Ai-SOC.MSP Dashboard V2 — Frontend JavaScript
   FortiSIEM-style interface
   ============================================================ */

// ---- State ----
let currentPage = 'dashboard';
let currentSubTab = '';
let incidentTimerange = '24h';
let icmpTimerange = '24h';
let snmpTimerange = '24h';
let chartInstances = {};
let autoRefreshTimer = null;

// ---- Explorer cross-filter state ----
let explorerAllIncidents = [];   // raw incidents from API
let explorerFilters = { incident: null, host: null, ip: null, user: null };

// ---- Utilities ----
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---- API Helper ----
async function api(url, opts) {
    const resp = await fetch(url, opts || {});
    if (resp.status === 401) {
        window.location.href = '/login';
        throw new Error('Unauthorized');
    }
    return resp.json();
}

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
    // Clock
    updateClock();
    setInterval(updateClock, 1000);

    // Nav clicks
    document.querySelectorAll('.top-nav-item').forEach(el => {
        el.addEventListener('click', e => {
            e.preventDefault();
            navigateTo(el.dataset.page);
        });
    });

    // Auto refresh every 60s
    autoRefreshTimer = setInterval(() => loadCurrentPage(), 60000);

    // Load initial page
    navigateTo('dashboard');
});

function updateClock() {
    const now = new Date();
    const el = document.getElementById('nav-clock');
    if (el) el.textContent = now.toLocaleString('en-US', {
        hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
        month: 'short', day: 'numeric', year: 'numeric'
    });
}

// ---- Navigation ----
function navigateTo(page, subTab) {
    currentPage = page;
    currentSubTab = subTab || '';

    // Update nav active state
    document.querySelectorAll('.top-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.page === page);
    });

    // Build sub-nav
    buildSubNav(page);

    // Load page content
    loadCurrentPage();
}

function buildSubNav(page) {
    const subNav = document.getElementById('sub-navbar');
    let html = '';

    if (page === 'dashboard') {
        html = `<span class="sub-nav-btn active" data-sub="overview"><i class="bi bi-grid"></i> Overview</span>
                <div class="sub-nav-spacer"></div>
                <select class="sub-nav-select" id="dash-timerange" onchange="loadCurrentPage()">
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="12h">Last 12 Hours</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="1h">Last 1 Hour</option>
                    <option value="7d">Last 7 Days</option>
                </select>`;
    } else if (page === 'incidents') {
        const sub = currentSubTab || 'overview';
        currentSubTab = sub;
        html = `<span class="sub-nav-btn ${sub==='overview'?'active':''}" onclick="navigateTo('incidents','overview')"><i class="bi bi-grid"></i> Overview</span>
                <span class="sub-nav-btn ${sub==='list'?'active':''}" onclick="navigateTo('incidents','list')"><i class="bi bi-list-ul"></i> List</span>
                <span class="sub-nav-btn ${sub==='explorer'?'active':''}" onclick="navigateTo('incidents','explorer')"><i class="bi bi-search"></i> Explorer</span>
                <div class="sub-nav-spacer"></div>
                <select class="sub-nav-select" id="inc-category-filter" onchange="loadCurrentPage()">
                    <option value="">All Categories</option>
                    <option value="Security">Security</option>
                    <option value="Performance">Performance</option>
                    <option value="Availability">Availability</option>
                    <option value="Change">Change</option>
                </select>
                <select class="sub-nav-select" id="inc-severity-filter" onchange="loadCurrentPage()">
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <select class="sub-nav-select" id="inc-timerange" onchange="incidentTimerange=this.value;loadCurrentPage()">
                    <option value="2h">Last 2 Hours</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="12h">Last 12 Hours</option>
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>`;
    } else if (page === 'cmdb') {
        html = `<span class="sub-nav-btn active"><i class="bi bi-hdd-stack"></i> Devices</span>
                <div class="sub-nav-spacer"></div>
                <input type="text" class="filter-input" id="cmdb-search" placeholder="Search agents..." oninput="filterCMDBTable()">`;
    } else if (page === 'icmp') {
        const sub = currentSubTab || 'monitoring';
        currentSubTab = sub;
        html = `<span class="sub-nav-btn ${sub==='monitoring'?'active':''}" onclick="navigateTo('icmp','monitoring')"><i class="bi bi-broadcast-pin"></i> ICMP Monitoring</span>
                <span class="sub-nav-btn ${sub==='inventory'?'active':''}" onclick="navigateTo('icmp','inventory')"><i class="bi bi-hdd-network"></i> Device Inventory</span>
                <div class="sub-nav-spacer"></div>`;
        if (sub === 'monitoring') {
            html += `<select class="sub-nav-select" id="icmp-timerange" onchange="icmpTimerange=this.value;loadCurrentPage()">
                    <option value="1h">Last 1 Hour</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                </select>`;
        } else if (sub === 'inventory') {
            html += `<select class="sub-nav-select" id="inv-group-filter" onchange="filterDeviceInventory()">
                    <option value="">All Groups</option>
                </select>
                <input type="text" class="filter-input" id="inv-search" placeholder="Search devices..." oninput="filterDeviceInventory()">`;
        }
    } else if (page === 'snmp') {
        const sub = currentSubTab || 'performance';
        currentSubTab = sub;
        html = `<span class="sub-nav-btn ${sub==='performance'?'active':''}" onclick="navigateTo('snmp','performance')"><i class="bi bi-diagram-3"></i> SNMP Performance</span>
                <span class="sub-nav-btn ${sub==='discovery'?'active':''}" onclick="navigateTo('snmp','discovery')"><i class="bi bi-search"></i> Discovery Scanner</span>
                <div class="sub-nav-spacer"></div>`;
        if (sub === 'performance') {
            html += `<select class="sub-nav-select" id="snmp-timerange" onchange="snmpTimerange=this.value;loadCurrentPage()">
                    <option value="1h">Last 1 Hour</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                </select>`;
        }
    } else if (page === 'cases') {
        const sub = currentSubTab || 'overview';
        currentSubTab = sub;
        html = `<span class="sub-nav-btn ${sub==='overview'?'active':''}" onclick="navigateTo('cases','overview')"><i class="bi bi-grid"></i> Overview</span>
                <span class="sub-nav-btn ${sub==='list'?'active':''}" onclick="navigateTo('cases','list')"><i class="bi bi-list-ul"></i> List</span>
                <div class="sub-nav-spacer"></div>
                <select class="sub-nav-select" id="cases-severity-filter" onchange="loadCurrentPage()">
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <select class="sub-nav-select" id="cases-timerange" onchange="loadCurrentPage()">
                    <option value="1h">Last 1 Hour</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="12h">Last 12 Hours</option>
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d" selected>Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>`;
    } else if (page === 'ueba') {
        uebaAnomalyFilter = null;
        html = `<span class="sub-nav-btn active"><i class="bi bi-person-bounding-box"></i> User & Entity Behavior Analytics</span>
                <div class="sub-nav-spacer"></div>
                <div class="osd-time-bar">
                    <select class="osd-time-select" id="ueba-timerange" onchange="loadCurrentPage()">
                        <option value="1h">Last 1 hour</option>
                        <option value="6h">Last 6 hours</option>
                        <option value="12h">Last 12 hours</option>
                        <option value="24h">Last 24 hours</option>
                        <option value="7d" selected>Last 7 days</option>
                        <option value="30d">Last 30 days</option>
                    </select>
                    <button class="osd-refresh-btn" onclick="loadCurrentPage()" title="Refresh now">
                        <i class="bi bi-arrow-clockwise"></i>
                    </button>
                    <select class="osd-refresh-select" onchange="setAutoRefresh(+this.value)" title="Auto-refresh interval">
                        <option value="0" ${autoRefreshInterval===0?'selected':''}>Refresh every: Off</option>
                        <option value="10" ${autoRefreshInterval===10?'selected':''}>10 seconds</option>
                        <option value="30" ${autoRefreshInterval===30?'selected':''}>30 seconds</option>
                        <option value="60" ${autoRefreshInterval===60?'selected':''}>1 minute</option>
                        <option value="120" ${autoRefreshInterval===120?'selected':''}>2 minutes</option>
                        <option value="300" ${autoRefreshInterval===300?'selected':''}>5 minutes</option>
                        <option value="600" ${autoRefreshInterval===600?'selected':''}>10 minutes</option>
                    </select>
                    <span id="auto-refresh-countdown" class="osd-countdown">${autoRefreshCountdown>0?autoRefreshCountdown+'s':''}</span>
                </div>`;
    }

    subNav.innerHTML = html;
}

function loadCurrentPage() {
    switch (currentPage) {
        case 'dashboard': loadDashboard(); break;
        case 'incidents':
            if (currentSubTab === 'list') loadIncidentsList();
            else if (currentSubTab === 'explorer') loadIncidentsExplorer();
            else loadIncidentsOverview();
            break;
        case 'cmdb': loadCMDB(); break;
        case 'icmp':
            if (currentSubTab === 'inventory') loadDeviceInventory();
            else loadICMP();
            break;
        case 'snmp':
            if (currentSubTab === 'discovery') loadDiscoveryScan();
            else loadSNMP();
            break;
        case 'ueba': loadUEBA(); break;
        case 'cases':
            if (currentSubTab === 'list') loadCasesList();
            else loadCasesOverview();
            break;
    }
}

// ============================================================
// DASHBOARD (Component A) — Improved
// ============================================================
let _dashHostsExpanded = false;
let _dashAllAgents = [];

async function loadDashboard() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const trSel = document.getElementById('dash-timerange');
    const timerange = trSel ? trSel.value : '24h';
    const trLabel = trSel ? trSel.options[trSel.selectedIndex].text : 'Last 24 Hours';

    try {
        const data = await api('/api/dashboard/summary?timerange=' + timerange);
        const alerts = data.alerts || data.alerts_24h || {};
        _dashAllAgents = data.top_agents || [];

        let html = '';

        // --- Stat Cards ---
        html += `<div class="stat-grid">
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3">
                    <i class="bi bi-people-fill"></i>
                </div>
                <div><div class="stat-value">${data.agents.total}</div><div class="stat-label">Total Agents</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(76,175,80,0.15);color:#4caf50">
                    <i class="bi bi-check-circle-fill"></i>
                </div>
                <div><div class="stat-value">${data.agents.active}</div><div class="stat-label">Active Agents</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,23,68,0.15);color:#ff1744">
                    <i class="bi bi-exclamation-triangle-fill"></i>
                </div>
                <div><div class="stat-value">${alerts.total || 0}</div><div class="stat-label">Alerts (${trLabel})</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,109,0,0.15);color:#ff6d00">
                    <i class="bi bi-shield-exclamation"></i>
                </div>
                <div><div class="stat-value">${(alerts.critical||0) + (alerts.high||0)}</div><div class="stat-label">Critical + High</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,193,7,0.15);color:#ffc107">
                    <i class="bi bi-bell-fill"></i>
                </div>
                <div><div class="stat-value">${alerts.medium || 0}</div><div class="stat-label">Medium</div></div>
            </div>
        </div>`;

        // --- Incidents by Category (FortiSIEM-style) ---
        html += `<div class="section-header"><div class="section-title">Incidents by Category</div></div>`;
        html += `<div class="row g-3 mb-4">`;
        const cats = ['Security', 'Performance', 'Availability', 'Change'];
        const catIcons = { Security: 'bi-shield-lock', Performance: 'bi-speedometer2', Availability: 'bi-wifi', Change: 'bi-pencil-square' };
        const catColors = {
            Security: '#e74c3c', Performance: '#3498db',
            Availability: '#2ecc71', Change: '#f39c12'
        };
        for (const cat of cats) {
            const cd = data.by_category[cat] || {};
            const pct = alerts.total ? Math.round((cd.total / alerts.total) * 100) : 0;
            html += `<div class="col-md-3">
                <div class="category-card" onclick="navigateTo('incidents','explorer');setTimeout(()=>{const s=document.getElementById('inc-category-filter');if(s){s.value='${cat}';loadCurrentPage();}},100)" style="border-left:3px solid ${catColors[cat]}">
                    <div class="d-flex align-items-center gap-2 mb-2">
                        <i class="bi ${catIcons[cat]}" style="color:${catColors[cat]};font-size:1.1rem"></i>
                        <h6 class="mb-0" style="color:${catColors[cat]}">${cat}</h6>
                    </div>
                    <div class="cat-counts">
                        <div class="cat-count-item">
                            <div class="label" style="color:#ff1744">Critical</div>
                            <div class="value" style="color:#ff1744">${cd.critical || 0}</div>
                        </div>
                        <div class="cat-count-item">
                            <div class="label" style="color:var(--severity-high)">High</div>
                            <div class="value" style="color:var(--severity-high)">${cd.high || 0}</div>
                        </div>
                        <div class="cat-count-item">
                            <div class="label" style="color:var(--severity-medium)">Medium</div>
                            <div class="value" style="color:var(--severity-medium)">${cd.medium || 0}</div>
                        </div>
                    </div>
                    <div class="cat-total">
                        <div class="cat-progress"><div class="cat-progress-fill" style="width:${pct}%;background:${catColors[cat]}"></div></div>
                        <span>${cd.total || 0} alerts (${pct}%)</span>
                    </div>
                </div>
            </div>`;
        }
        html += `</div>`;

        // --- Top Impacted Hosts (clickable + expandable) ---
        const hostCount = _dashAllAgents.length;
        const showCount = _dashHostsExpanded ? hostCount : Math.min(5, hostCount);
        html += `<div class="section-header">
            <div class="section-title">Top Impacted Hosts - By Severity / Risk Score</div>
            <div class="d-flex align-items-center gap-2">
                <span class="text-muted" style="font-size:0.8rem">${hostCount} host(s)</span>
                ${hostCount > 5 ? `<button class="btn btn-sm btn-outline-secondary" onclick="_dashHostsExpanded=!_dashHostsExpanded;loadDashboard()">
                    ${_dashHostsExpanded ? '<i class="bi bi-chevron-up"></i> Show Top 5' : '<i class="bi bi-chevron-down"></i> Show All '+hostCount}
                </button>` : ''}
            </div>
        </div>`;
        html += `<div class="dash-hosts-grid mb-4">`;
        const displayAgents = _dashAllAgents.slice(0, showCount);
        for (const agent of displayAgents) {
            const sev = agent.severity || {};
            const maxSev = (sev.critical||0) > 0 ? 'critical' : (sev.high||0) > 0 ? 'high' : (sev.medium||0) > 0 ? 'medium' : 'low';
            html += `<div class="host-card host-card-clickable" onclick="showHostDrillDown(${JSON.stringify(agent).replace(/"/g,'&quot;')})">
                <div class="host-card-header">
                    <span class="d-flex align-items-center gap-2">
                        <i class="bi bi-hdd-rack" style="color:var(--severity-${maxSev})"></i>
                        ${escHtml(agent.name)}
                    </span>
                    <span class="risk-badge risk-${maxSev}"><i class="bi bi-graph-up"></i> ${agent.count}</span>
                </div>
                <div class="host-card-body">
                    <div class="host-sev-pills">
                        ${(sev.critical||0)>0?`<span class="micro-pill crit">${sev.critical} Crit</span>`:''}
                        ${(sev.high||0)>0?`<span class="micro-pill high">${sev.high} High</span>`:''}
                        ${(sev.medium||0)>0?`<span class="micro-pill med">${sev.medium} Med</span>`:''}
                        ${(sev.low||0)>0?`<span class="micro-pill low">${sev.low} Low</span>`:''}
                    </div>
                    <div class="host-card-incidents">`;
            for (const inc of (agent.top_incidents || []).slice(0, 3)) {
                html += `<div class="incident-line"><span class="incident-dot high"></span> ${escHtml(inc.desc)} <span class="text-muted">(${inc.count})</span></div>`;
            }
            if (!(agent.top_incidents||[]).length) {
                html += `<div class="incident-line text-muted">No specific incidents</div>`;
            }
            html += `</div></div></div>`;
        }
        if (!displayAgents.length) {
            html += '<div class="text-muted p-3">No impacted hosts in the selected time range</div>';
        }
        html += `</div>`;

        // --- Alert Trend Chart ---
        html += `<div class="row g-3 mb-4">
            <div class="col-lg-7">
                <div class="soc-card" style="height:320px">
                    <div class="soc-card-title"><i class="bi bi-bar-chart"></i> Alert Trend (${trLabel})</div>
                    <div style="position:relative;height:260px"><canvas id="dashboard-trend-chart"></canvas></div>
                </div>
            </div>
            <div class="col-lg-5">
                <div class="soc-card" style="height:320px;overflow-y:auto">
                    <div class="soc-card-title"><i class="bi bi-lightning-charge"></i> Recent Critical Alerts</div>
                    <table class="recent-alerts-table">`;

        for (const alert of (data.recent_critical || []).slice(0, 8)) {
            const mitre = alert.mitre_id ? `<span class="mitre-tag">${escHtml(alert.mitre_id)}</span>` : '';
            html += `<tr>
                <td><span class="sev-badge sev-${(alert.severity||'').toLowerCase()}">${alert.severity}</span></td>
                <td class="ts-cell">${formatTimestamp(alert.timestamp)}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(alert.description)}">${escHtml(alert.description)} ${mitre}</td>
                <td class="text-muted">${escHtml(alert.agent_name)}</td>
            </tr>`;
        }
        if (!data.recent_critical?.length) {
            html += `<tr><td colspan="4" class="text-center text-muted py-3">No critical alerts in the selected range</td></tr>`;
        }

        html += `</table></div></div></div>`;

        // --- Top Source IPs + Top Rules (enriched) ---
        html += `<div class="row g-3 mb-4">
            <div class="col-lg-6">
                <div class="soc-card">
                    <div class="soc-card-title"><i class="bi bi-geo-alt"></i> Top Source IPs</div>
                    <table class="data-table"><thead><tr><th>IP Address</th><th>Critical</th><th>High</th><th>Med</th><th>Total</th></tr></thead><tbody>`;
        for (const ip of (data.top_src_ips || []).slice(0, 8)) {
            const s = ip.severity || {};
            html += `<tr>
                <td><code>${escHtml(ip.ip)}</code></td>
                <td style="color:#ff1744">${s.critical||0}</td>
                <td style="color:#ff6d00">${s.high||0}</td>
                <td style="color:#ffc107">${s.medium||0}</td>
                <td><strong>${ip.count}</strong></td>
            </tr>`;
        }
        if (!(data.top_src_ips||[]).length) html += '<tr><td colspan="5" class="text-center text-muted">No source IPs</td></tr>';
        html += `</tbody></table></div></div>
            <div class="col-lg-6">
                <div class="soc-card">
                    <div class="soc-card-title"><i class="bi bi-diagram-2"></i> Top Triggered Rules</div>
                    <table class="data-table"><thead><tr><th>Rule</th><th>Description</th><th>Agents</th><th>Count</th></tr></thead><tbody>`;
        for (const rule of (data.top_rules || []).slice(0, 8)) {
            const agentList = (rule.agents||[]).slice(0,2).join(', ');
            html += `<tr>
                <td><code>${escHtml(rule.rule_id)}</code></td>
                <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(rule.description)}">${escHtml(rule.description || '-')}</td>
                <td class="text-muted" style="font-size:0.8rem">${escHtml(agentList)}</td>
                <td><strong>${rule.count}</strong></td>
            </tr>`;
        }
        if (!(data.top_rules||[]).length) html += '<tr><td colspan="4" class="text-center text-muted">No rules triggered</td></tr>';
        html += `</tbody></table></div></div></div>`;

        content.innerHTML = html;

        // Render trend chart
        renderDashboardTrend(data.trend || data.trend_hourly || [], trLabel);

    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Failed to load dashboard: ${err.message}</p></div>`;
    }
}

// --- Host Drill-Down Modal ---
function showHostDrillDown(agent) {
    let modal = document.getElementById('hostDrillDownModal');
    if (!modal) {
        const div = document.createElement('div');
        div.innerHTML = `<div class="modal fade" id="hostDrillDownModal" tabindex="-1">
            <div class="modal-dialog modal-lg modal-dialog-centered">
                <div class="modal-content bg-dark text-light border-secondary">
                    <div class="modal-header border-secondary">
                        <h5 class="modal-title" id="hostDrillTitle"></h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body" id="hostDrillBody"></div>
                </div>
            </div>
        </div>`;
        document.body.appendChild(div.firstElementChild);
        modal = document.getElementById('hostDrillDownModal');
    }
    document.getElementById('hostDrillTitle').innerHTML = `<i class="bi bi-hdd-rack me-2"></i>${escHtml(agent.name)} - Alert Breakdown`;
    const sev = agent.severity || {};
    let body = '';

    // Severity summary
    body += `<div class="d-flex gap-3 mb-3 flex-wrap">
        <div class="drill-stat" style="border-color:#ff1744"><div class="drill-val" style="color:#ff1744">${sev.critical||0}</div><div class="drill-lbl">Critical</div></div>
        <div class="drill-stat" style="border-color:#ff6d00"><div class="drill-val" style="color:#ff6d00">${sev.high||0}</div><div class="drill-lbl">High</div></div>
        <div class="drill-stat" style="border-color:#ffc107"><div class="drill-val" style="color:#ffc107">${sev.medium||0}</div><div class="drill-lbl">Medium</div></div>
        <div class="drill-stat" style="border-color:#4caf50"><div class="drill-val" style="color:#4caf50">${sev.low||0}</div><div class="drill-lbl">Low</div></div>
        <div class="drill-stat" style="border-color:#8b949e"><div class="drill-val">${agent.count}</div><div class="drill-lbl">Total</div></div>
    </div>`;

    // Top incidents table
    body += `<h6 class="mb-2">Top Incident Types</h6>`;
    if ((agent.top_incidents||[]).length) {
        body += `<table class="data-table"><thead><tr><th>Incident Description</th><th>Count</th><th>%</th></tr></thead><tbody>`;
        for (const inc of agent.top_incidents) {
            const pct = agent.count ? Math.round((inc.count / agent.count) * 100) : 0;
            body += `<tr>
                <td>${escHtml(inc.desc)}</td>
                <td><strong>${inc.count}</strong></td>
                <td>${buildHealthBar(pct)} ${pct}%</td>
            </tr>`;
        }
        body += `</tbody></table>`;
    } else {
        body += `<div class="text-muted">No detailed incident data available</div>`;
    }

    // Action buttons
    body += `<div class="mt-3 d-flex gap-2">
        <button class="btn btn-sm btn-outline-warning" onclick="navigateTo('incidents','explorer');setTimeout(()=>{bootstrap.Modal.getInstance(document.getElementById('hostDrillDownModal')).hide();},50)">
            <i class="bi bi-search"></i> View in Incidents Explorer
        </button>
        <button class="btn btn-sm btn-outline-info" onclick="navigateTo('cmdb');setTimeout(()=>{bootstrap.Modal.getInstance(document.getElementById('hostDrillDownModal')).hide();},50)">
            <i class="bi bi-hdd-stack"></i> View in CMDB
        </button>
    </div>`;

    document.getElementById('hostDrillBody').innerHTML = body;
    new bootstrap.Modal(modal).show();
}

function renderDashboardTrend(trendData, trLabel) {
    const ctx = document.getElementById('dashboard-trend-chart');
    if (!ctx) return;
    destroyChart('dashboard-trend');

    const labels = trendData.map(t => {
        const d = new Date(t.time);
        if (isNaN(d.getTime())) return t.time;
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
    });

    chartInstances['dashboard-trend'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'Critical', data: trendData.map(t => t.critical || 0), backgroundColor: '#ff1744', stack: 's' },
                { label: 'High', data: trendData.map(t => t.high || 0), backgroundColor: '#ff6d00', stack: 's' },
                { label: 'Medium', data: trendData.map(t => t.medium || 0), backgroundColor: '#ffc107', stack: 's' },
                { label: 'Low', data: trendData.map(t => t.low || 0), backgroundColor: '#4caf50', stack: 's' },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, position: 'bottom', labels: { color: '#8b949e', boxWidth: 12, font: { size: 10 } } },
                tooltip: {
                    callbacks: { title: (items) => items[0]?.label || '' }
                },
            },
            scales: {
                x: { stacked: true, ticks: { color: '#8b949e', maxTicksLimit: 12, font: { size: 9 }, maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { stacked: true, beginAtZero: true, ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            },
        },
    });
}

// ============================================================
// INCIDENTS OVERVIEW (Component B - Overview sub-tab)
// ============================================================
async function loadIncidentsOverview() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const cat = getFilterVal('inc-category-filter');
    const sev = getFilterVal('inc-severity-filter');
    const params = new URLSearchParams({
        timerange: incidentTimerange, limit: 500, min_level: 3,
        ...(cat ? { category: cat } : {}),
        ...(sev ? { severity: sev } : {}),
    });

    try {
        const data = await api(`/api/incidents?${params}`);
        const ss = data.severity_summary || {};
        const cs = data.category_summary || {};
        const totalInc = data.returned || 0;

        let html = '';

        // --- Severity Summary Bar (unique to Incidents Overview) ---
        html += `<div class="inc-overview-summary-bar">
            <div class="inc-summary-total">
                <span class="inc-summary-count">${totalInc}</span>
                <span class="inc-summary-label">Total Incidents</span>
            </div>
            <div class="inc-summary-severity-pills">
                <span class="inc-sev-pill" style="border-color:#ff1744">
                    <span class="inc-sev-dot" style="background:#ff1744"></span>
                    Critical <strong>${ss.Critical||0}</strong>
                </span>
                <span class="inc-sev-pill" style="border-color:#ff6d00">
                    <span class="inc-sev-dot" style="background:#ff6d00"></span>
                    High <strong>${ss.High||0}</strong>
                </span>
                <span class="inc-sev-pill" style="border-color:#ffc107">
                    <span class="inc-sev-dot" style="background:#ffc107"></span>
                    Medium <strong>${ss.Medium||0}</strong>
                </span>
                <span class="inc-sev-pill" style="border-color:#4caf50">
                    <span class="inc-sev-dot" style="background:#4caf50"></span>
                    Low <strong>${ss.Low||0}</strong>
                </span>
            </div>
        </div>`;

        // --- Incident Trend by Category chart + Top Incidents side-by-side ---
        html += `<div class="row g-3 mb-4">`;

        // Left: Trend chart by category (different from Dashboard's severity trend)
        html += `<div class="col-lg-7">
            <div class="soc-card" style="height:300px">
                <div class="soc-card-title"><i class="bi bi-bar-chart"></i> Incident Trend by Category</div>
                <div style="position:relative;height:240px"><canvas id="inc-overview-trend-chart"></canvas></div>
            </div>
        </div>`;

        // Right: Category breakdown donut
        html += `<div class="col-lg-5">
            <div class="soc-card" style="height:300px">
                <div class="soc-card-title"><i class="bi bi-pie-chart"></i> Distribution by Category</div>
                <div style="position:relative;height:200px"><canvas id="inc-overview-cat-donut"></canvas></div>
                <div class="d-flex justify-content-center gap-3 mt-2" style="font-size:0.75rem">
                    <span><span class="inc-sev-dot" style="background:#e74c3c"></span> Security: ${cs.Security||0}</span>
                    <span><span class="inc-sev-dot" style="background:#3498db"></span> Performance: ${cs.Performance||0}</span>
                    <span><span class="inc-sev-dot" style="background:#2ecc71"></span> Availability: ${cs.Availability||0}</span>
                    <span><span class="inc-sev-dot" style="background:#f39c12"></span> Change: ${cs.Change||0}</span>
                </div>
            </div>
        </div>`;
        html += `</div>`;

        // --- Top Incidents (unique to this page) ---
        html += `<div class="section-header"><div class="section-title">Top Incidents</div></div>`;
        html += `<div class="d-flex gap-3 mb-4" style="overflow-x:auto;padding-bottom:4px">`;

        const topRules = (data.rule_breakdown || []).slice(0, 5);
        const ruleHosts = {};
        for (const inc of data.incidents) {
            const rid = inc.rule_id;
            if (!ruleHosts[rid]) ruleHosts[rid] = {};
            const t = inc.target || '';
            ruleHosts[rid][t] = (ruleHosts[rid][t] || 0) + 1;
        }

        for (const rule of topRules) {
            const hosts = ruleHosts[rule.rule_id] || {};
            const topH = Object.entries(hosts).sort((a,b) => b[1]-a[1]).slice(0, 4);
            html += `<div class="top-incident-card">
                <div class="top-incident-header" title="${escHtml(rule.incident)}">${escHtml(rule.incident)}</div>
                <div class="top-incident-body">
                    <div class="top-incident-count">${rule.count}</div>
                    <div class="top-incident-hosts">`;
            for (const [h] of topH) {
                html += `${escHtml(h)}<br>`;
            }
            html += `</div></div></div>`;
        }
        if (!topRules.length) {
            html += '<div class="text-muted p-3">No incidents in the selected time range</div>';
        }
        html += `</div>`;

        // --- Recent Incident Timeline (last 20 — unique to this page) ---
        html += `<div class="section-header"><div class="section-title">Recent Incident Timeline</div></div>`;
        html += `<div class="inc-timeline">`;
        const recentIncs = data.incidents.slice(0, 20);
        for (const inc of recentIncs) {
            const sevClass = (inc.severity || 'low').toLowerCase();
            const catIcon = {Security:'bi-shield-lock',Performance:'bi-speedometer2',Availability:'bi-wifi',Change:'bi-pencil-square'}[inc.category] || 'bi-bell';
            html += `<div class="inc-timeline-item">
                <div class="inc-timeline-marker">
                    <span class="inc-timeline-dot sev-bg-${sevClass}"></span>
                    <span class="inc-timeline-line"></span>
                </div>
                <div class="inc-timeline-content">
                    <div class="inc-timeline-header">
                        <span class="sev-badge sev-${sevClass}">${inc.severity}</span>
                        <span class="inc-timeline-ts">${formatTimestamp(inc.timestamp)}</span>
                        <span class="cat-badge cat-${(inc.category||'').toLowerCase()}"><i class="bi ${catIcon}"></i> ${inc.category}</span>
                    </div>
                    <div class="inc-timeline-desc">${escHtml(inc.incident)}</div>
                    <div class="inc-timeline-meta">
                        ${inc.target ? `<span><i class="bi bi-hdd-rack"></i> ${escHtml(inc.target)}</span>` : ''}
                        ${inc.source ? `<span><i class="bi bi-geo-alt"></i> ${escHtml(inc.source)}</span>` : ''}
                        ${(inc.mitre_ids||[]).length ? `<span class="mitre-tag">${inc.mitre_ids.join(', ')}</span>` : ''}
                    </div>
                </div>
            </div>`;
        }
        if (!recentIncs.length) {
            html += '<div class="text-muted p-3 text-center">No recent incidents</div>';
        }
        html += `</div>`;

        content.innerHTML = html;

        // Render charts
        renderIncOverviewTrendByCategory(data.trend || [], data.incidents);
        renderIncOverviewCatDonut(cs);
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}

function renderIncOverviewTrendByCategory(trendData, incidents) {
    const ctx = document.getElementById('inc-overview-trend-chart');
    if (!ctx) return;
    destroyChart('inc-overview-trend');

    // Build trend data by category from incidents
    const catTrend = {};
    for (const inc of incidents) {
        const ts = inc.timestamp || '';
        if (!ts) continue;
        const dateKey = ts.substring(0, 13); // YYYY-MM-DDTHH
        if (!catTrend[dateKey]) catTrend[dateKey] = {Security:0, Performance:0, Availability:0, Change:0};
        catTrend[dateKey][inc.category] = (catTrend[dateKey][inc.category] || 0) + 1;
    }
    const sortedKeys = Object.keys(catTrend).sort();
    const labels = sortedKeys.map(k => {
        const d = new Date(k + ':00:00');
        return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', hour12:false });
    });

    chartInstances['inc-overview-trend'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'Security', data: sortedKeys.map(k => catTrend[k].Security||0), backgroundColor: '#e74c3c', stack: 's' },
                { label: 'Performance', data: sortedKeys.map(k => catTrend[k].Performance||0), backgroundColor: '#3498db', stack: 's' },
                { label: 'Availability', data: sortedKeys.map(k => catTrend[k].Availability||0), backgroundColor: '#2ecc71', stack: 's' },
                { label: 'Change', data: sortedKeys.map(k => catTrend[k].Change||0), backgroundColor: '#f39c12', stack: 's' },
            ],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: true, position: 'bottom', labels: { color: '#8b949e', boxWidth: 12, font: { size: 10 } } } },
            scales: {
                x: { stacked: true, ticks: { color: '#8b949e', maxTicksLimit: 10, font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { stacked: true, ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            },
        },
    });
}

function renderIncOverviewCatDonut(catSummary) {
    const ctx = document.getElementById('inc-overview-cat-donut');
    if (!ctx) return;
    destroyChart('inc-overview-cat-donut');

    chartInstances['inc-overview-cat-donut'] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Security', 'Performance', 'Availability', 'Change'],
            datasets: [{
                data: [catSummary.Security||0, catSummary.Performance||0, catSummary.Availability||0, catSummary.Change||0],
                backgroundColor: ['#e74c3c', '#3498db', '#2ecc71', '#f39c12'],
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: { display: false },
            },
        },
    });
}


// ============================================================
// INCIDENTS EXPLORER (Component B - Explorer sub-tab)
// ============================================================
async function loadIncidentsExplorer() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const cat = getFilterVal('inc-category-filter');
    const sev = getFilterVal('inc-severity-filter');
    const params = new URLSearchParams({
        timerange: incidentTimerange, limit: 500, min_level: 3,
        ...(cat ? { category: cat } : {}),
        ...(sev ? { severity: sev } : {}),
    });

    try {
        const data = await api(`/api/incidents?${params}`);
        // Store raw data for cross-filtering
        explorerAllIncidents = data.incidents || [];
        explorerFilters = { incident: null, host: null, ip: null, user: null };

        renderExplorerView(data.trend || []);
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}

/* Render the entire Explorer UI from explorerAllIncidents + explorerFilters */
function renderExplorerView(trendData) {
    explorerLastTrend = trendData; // save for re-renders on filter change
    const content = document.getElementById('main-content');
    // Apply cross-filters to get the visible incidents
    const filtered = getFilteredExplorerIncidents();

    let html = '';

    // --- Active filter banner ---
    const activeFilters = Object.entries(explorerFilters).filter(([,v]) => v !== null);
    if (activeFilters.length) {
        html += `<div class="explorer-filter-banner">`;
        for (const [key, val] of activeFilters) {
            html += `<span class="explorer-filter-chip">
                <strong>${key}:</strong> ${escHtml(val)}
                <i class="bi bi-x-circle" onclick="clearExplorerFilter('${key}')"></i>
            </span>`;
        }
        html += `<a href="#" class="explorer-clear-all" onclick="clearAllExplorerFilters();return false">Clear all filters</a>`;
        html += `</div>`;
    }

    // --- Trend Chart ---
    html += `<div class="explorer-chart-container">
        <div class="explorer-chart-title">Incident Trend by Severity</div>
        <div style="position:relative;height:180px"><canvas id="explorer-trend-chart"></canvas></div>
    </div>`;

    // --- Build breakdowns from filtered data ---
    const incidentBD = buildExplorerBreakdown(filtered, 'incident');
    const hostBD     = buildExplorerBreakdown(filtered, 'host');
    const ipBD       = buildExplorerBreakdown(filtered, 'ip');
    const userBD     = buildExplorerBreakdown(filtered, 'user');

    // --- 4-Panel Breakdown (Incident, Host, IP, User) ---
    html += `<div class="breakdown-panels">`;
    html += buildInteractivePanel('Incident', 'incident', incidentBD);
    html += buildInteractivePanel('Host',     'host',     hostBD);
    html += buildInteractivePanel('IP',       'ip',       ipBD);
    html += buildInteractivePanel('User',     'user',     userBD);
    html += `</div>`;

    // --- Severity Summary Bar ---
    const ss = {};
    for (const inc of filtered) { ss[inc.severity] = (ss[inc.severity]||0) + 1; }
    html += `<div class="sev-summary-bar">
        <span class="fw-bold">All: ${filtered.length}</span>
        <span class="sev-summary-item"><span class="dot" style="background:var(--severity-critical)"></span> Critical: ${ss.Critical||0}</span>
        <span class="sev-summary-item"><span class="dot" style="background:var(--severity-high)"></span> High: ${ss.High||0}</span>
        <span class="sev-summary-item"><span class="dot" style="background:var(--severity-medium)"></span> Medium: ${ss.Medium||0}</span>
        <span class="sev-summary-item"><span class="dot" style="background:var(--severity-low)"></span> Low: ${ss.Low||0}</span>
    </div>`;

    // --- Incidents Table ---
    html += `<div class="table-scroll">
        <table class="incidents-table" id="explorer-table">
            <thead><tr>
                <th>Severity</th><th>Category</th><th>Last Occurred</th>
                <th>Incident</th><th>Subcategory</th><th>Source</th>
                <th>Target</th><th>Detail</th><th>Status</th><th>Resolution</th>
            </tr></thead><tbody>`;

    for (const inc of filtered) {
        html += `<tr class="explorer-row" onclick="showExplorerDrillDown(this)" 
            data-incident="${escHtml(inc.incident)}" data-host="${escHtml(inc.target||'')}" 
            data-ip="${escHtml(inc.source||'')}" data-user="${escHtml(inc.user||'')}">
            <td><span class="sev-badge sev-${(inc.severity||'low').toLowerCase()}">${inc.severity}</span></td>
            <td><span class="cat-badge cat-${(inc.category||'').toLowerCase()}">${inc.category}</span></td>
            <td style="white-space:nowrap">${formatTimestamp(inc.timestamp)}</td>
            <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(inc.incident)}">${escHtml(inc.incident)}</td>
            <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(inc.subcategory||'')}</td>
            <td><code>${escHtml(inc.source || '-')}</code></td>
            <td>${escHtml(inc.target || '-')}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(inc.detail||'')}">${escHtml((inc.detail||'').substring(0,60))}</td>
            <td><span style="color:var(--severity-info)">Active</span></td>
            <td>Open</td>
        </tr>`;
    }
    if (!filtered.length) {
        html += '<tr><td colspan="10" class="text-center text-muted py-3">No incidents match the selected filters</td></tr>';
    }

    html += `</tbody></table></div>`;

    content.innerHTML = html;
    renderExplorerTrend(trendData);
}

/* Build breakdown data from filtered incidents for a given dimension */
function buildExplorerBreakdown(incidents, dimension) {
    const counts = {};
    for (const inc of incidents) {
        let key = '';
        if (dimension === 'incident') key = inc.incident || '';
        else if (dimension === 'host') key = inc.target || '';
        else if (dimension === 'ip')   key = inc.source || '';
        else if (dimension === 'user') key = inc.user || '';
        if (!key) key = '[Empty]';
        counts[key] = (counts[key] || 0) + 1;
    }
    return Object.entries(counts)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);
}

/* Get filtered incidents based on active explorerFilters */
function getFilteredExplorerIncidents() {
    return explorerAllIncidents.filter(inc => {
        if (explorerFilters.incident && inc.incident !== explorerFilters.incident) return false;
        if (explorerFilters.host && (inc.target || '') !== explorerFilters.host) return false;
        if (explorerFilters.ip && (inc.source || '') !== explorerFilters.ip) return false;
        if (explorerFilters.user && (inc.user || '') !== explorerFilters.user) return false;
        return true;
    });
}

/* Build interactive breakdown panel with click-to-filter and search */
function buildInteractivePanel(title, dimension, items) {
    const selected = explorerFilters[dimension];
    const total = items.length;
    const panelId = `bp-${dimension}`;
    let html = `<div class="breakdown-panel ${selected ? 'bp-active' : ''}" id="${panelId}">
        <div class="bp-header">
            <span class="bp-title">${title}</span>
            <span class="bp-count">(${total})</span>
        </div>
        <input type="text" class="bp-search" placeholder="Search ${title.toLowerCase()}..." 
               oninput="filterPanelList('${panelId}', this.value)">
        <div class="bp-list">`;
    for (const item of items.slice(0, 20)) {
        const isSelected = selected === item.name;
        html += `<div class="bp-item ${isSelected ? 'selected' : ''}" 
                      onclick="toggleExplorerFilter('${dimension}', '${escHtml(item.name).replace(/'/g, "\\'")}')"
                      data-name="${escHtml(item.name).toLowerCase()}">
            <span class="bp-name" title="${escHtml(item.name)}">${escHtml(item.name)}</span>
            <span class="bp-val">${item.count}</span>
        </div>`;
    }
    if (!items.length) {
        html += '<div class="text-center text-muted py-2" style="font-size:0.75rem">No data</div>';
    }
    html += `</div></div>`;
    return html;
}

/* Toggle a filter on a dimension — click same item to deselect */
function toggleExplorerFilter(dimension, value) {
    if (explorerFilters[dimension] === value) {
        explorerFilters[dimension] = null; // deselect
    } else {
        explorerFilters[dimension] = value;
    }
    // Re-render with cross-filtered data (keep trend data from original load)
    renderExplorerView(explorerLastTrend || []);
}
let explorerLastTrend = [];

function clearExplorerFilter(dimension) {
    explorerFilters[dimension] = null;
    renderExplorerView(explorerLastTrend || []);
}

function clearAllExplorerFilters() {
    explorerFilters = { incident: null, host: null, ip: null, user: null };
    renderExplorerView(explorerLastTrend || []);
}

/* Search/filter items within a single panel list */
function filterPanelList(panelId, query) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    const q = query.toLowerCase();
    panel.querySelectorAll('.bp-item').forEach(el => {
        const name = el.getAttribute('data-name') || '';
        el.style.display = name.includes(q) ? '' : 'none';
    });
}

/* Drill-down modal when clicking a table row */
function showExplorerDrillDown(rowEl) {
    const incident = rowEl.getAttribute('data-incident');
    const host = rowEl.getAttribute('data-host');
    const ip = rowEl.getAttribute('data-ip');
    const user = rowEl.getAttribute('data-user');

    // Find all related incidents
    const related = explorerAllIncidents.filter(inc => inc.incident === incident);
    const relatedHosts = [...new Set(related.map(i => i.target).filter(Boolean))];
    const relatedIPs = [...new Set(related.map(i => i.source).filter(Boolean))];
    const relatedUsers = [...new Set(related.map(i => i.user).filter(Boolean))];
    const sevCounts = {};
    for (const r of related) sevCounts[r.severity] = (sevCounts[r.severity]||0) + 1;

    const modal = document.getElementById('agentDetailModal');
    const title = document.getElementById('agentDetailTitle');
    const body = document.getElementById('agentDetailBody');
    title.textContent = 'Incident Drill-Down';

    body.innerHTML = `
        <div class="detail-section">
            <h6><i class="bi bi-exclamation-triangle"></i> Incident</h6>
            <div style="font-size:0.9rem;margin-bottom:0.75rem">${escHtml(incident)}</div>
            <div class="d-flex gap-3 flex-wrap mb-3">
                <div class="drill-stat" style="border-left-color:var(--accent)"><div class="drill-val">${related.length}</div><div class="drill-lbl">Occurrences</div></div>
                <div class="drill-stat" style="border-left-color:var(--severity-critical)"><div class="drill-val" style="color:var(--severity-critical)">${sevCounts.Critical||0}</div><div class="drill-lbl">Critical</div></div>
                <div class="drill-stat" style="border-left-color:var(--severity-high)"><div class="drill-val" style="color:var(--severity-high)">${sevCounts.High||0}</div><div class="drill-lbl">High</div></div>
                <div class="drill-stat" style="border-left-color:var(--severity-medium)"><div class="drill-val" style="color:var(--severity-medium)">${sevCounts.Medium||0}</div><div class="drill-lbl">Medium</div></div>
                <div class="drill-stat" style="border-left-color:var(--severity-low)"><div class="drill-val" style="color:var(--severity-low)">${sevCounts.Low||0}</div><div class="drill-lbl">Low</div></div>
            </div>
        </div>
        <div class="detail-section">
            <h6><i class="bi bi-diagram-3"></i> Correlated Data</h6>
            <div class="detail-grid">
                <div class="detail-item"><span class="detail-label">Affected Hosts</span>
                    <span class="detail-value">${relatedHosts.length ? relatedHosts.map(h => `<span class="micro-pill high" style="margin:1px">${escHtml(h)}</span>`).join(' ') : '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Source IPs</span>
                    <span class="detail-value">${relatedIPs.length ? relatedIPs.map(ip => `<code style="margin:1px">${escHtml(ip)}</code>`).join(' ') : '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Users</span>
                    <span class="detail-value">${relatedUsers.length ? relatedUsers.join(', ') : '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Category</span>
                    <span class="detail-value">${related[0]?.category || '-'}</span></div>
            </div>
        </div>
        <div class="detail-section">
            <h6><i class="bi bi-clock-history"></i> Recent Occurrences (last 10)</h6>
            <table class="data-table" style="font-size:0.75rem">
                <thead><tr><th>Time</th><th>Severity</th><th>Target</th><th>Source</th></tr></thead>
                <tbody>
                ${related.slice(0, 10).map(r => `<tr>
                    <td style="white-space:nowrap">${formatTimestamp(r.timestamp)}</td>
                    <td><span class="sev-badge sev-${(r.severity||'low').toLowerCase()}">${r.severity}</span></td>
                    <td>${escHtml(r.target||'-')}</td>
                    <td><code>${escHtml(r.source||'-')}</code></td>
                </tr>`).join('')}
                </tbody>
            </table>
        </div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-sm btn-outline-warning" onclick="toggleExplorerFilter('incident','${escHtml(incident).replace(/'/g, "\\'")}');bootstrap.Modal.getInstance(document.getElementById('agentDetailModal')).hide()">
                <i class="bi bi-funnel"></i> Filter by this incident
            </button>
            ${host ? `<button class="btn btn-sm btn-outline-info" onclick="toggleExplorerFilter('host','${escHtml(host).replace(/'/g, "\\'")}');bootstrap.Modal.getInstance(document.getElementById('agentDetailModal')).hide()">
                <i class="bi bi-hdd-rack"></i> Filter by host: ${escHtml(host)}
            </button>` : ''}
        </div>
    `;

    new bootstrap.Modal(modal).show();
}

function renderExplorerTrend(trendData) {
    const ctx = document.getElementById('explorer-trend-chart');
    if (!ctx) return;
    destroyChart('explorer-trend');

    const labels = trendData.map(t => {
        const d = new Date(t.time);
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
    });

    chartInstances['explorer-trend'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'Critical', data: trendData.map(t => t.Critical || 0), backgroundColor: '#ff1744', stack: 's' },
                { label: 'High', data: trendData.map(t => t.High || 0), backgroundColor: '#ff6d00', stack: 's' },
                { label: 'Medium', data: trendData.map(t => t.Medium || 0), backgroundColor: '#ffc107', stack: 's' },
                { label: 'Low', data: trendData.map(t => t.Low || 0), backgroundColor: '#4caf50', stack: 's' },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, position: 'bottom', labels: { color: '#8b949e', boxWidth: 12, font: { size: 10 } } },
            },
            scales: {
                x: { stacked: true, ticks: { color: '#8b949e', maxTicksLimit: 10, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { stacked: true, ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            },
        },
    });
}


// ============================================================
// INCIDENTS LIST (Component C)
// ============================================================
async function loadIncidentsList() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const cat = getFilterVal('inc-category-filter');
    const sev = getFilterVal('inc-severity-filter');
    const params = new URLSearchParams({
        timerange: incidentTimerange, limit: 1000, min_level: 3,
        ...(cat ? { category: cat } : {}),
        ...(sev ? { severity: sev } : {}),
    });

    try {
        const data = await api(`/api/incidents?${params}`);

        let html = '';

        // Severity summary bar
        const ss = data.severity_summary || {};
        html += `<div class="sev-summary-bar mb-3">
            <span class="fw-bold" style="font-size:0.9rem">All: ${data.returned}</span>
            <span class="sev-summary-item"><span class="dot" style="background:var(--severity-critical)"></span> Critical: ${ss.Critical||0}</span>
            <span class="sev-summary-item"><span class="dot" style="background:var(--severity-high)"></span> High: ${ss.High||0}</span>
            <span class="sev-summary-item"><span class="dot" style="background:var(--severity-medium)"></span> Medium: ${ss.Medium||0}</span>
            <span class="sev-summary-item"><span class="dot" style="background:var(--severity-low)"></span> Low: ${ss.Low||0}</span>
            <span class="sev-summary-item"><span class="dot" style="background:var(--severity-info)"></span> Info: ${ss.Info||0}</span>
        </div>`;

        // Search
        html += `<div class="filter-row">
            <input type="text" class="filter-input" id="inc-list-search" placeholder="Search incidents..." style="width:300px" oninput="filterIncidentTable()">
        </div>`;

        // Table
        html += `<div class="table-scroll" style="max-height:calc(100vh - 220px)">
            <table class="incidents-table" id="incidents-list-table">
                <thead><tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Last Occurred</th>
                    <th>Incident</th>
                    <th>Subcategory</th>
                    <th>Source</th>
                    <th>Target</th>
                    <th>MITRE ATT&CK</th>
                    <th>Status</th>
                    <th>Resolution</th>
                </tr></thead><tbody>`;

        for (const inc of data.incidents) {
            const mitreStr = (inc.mitre_ids || []).join(', ');
            html += `<tr>
                <td><span class="sev-badge sev-${inc.severity.toLowerCase()}">${inc.severity}</span></td>
                <td><span class="cat-badge cat-${inc.category.toLowerCase()}">${inc.category}</span></td>
                <td style="white-space:nowrap">${formatTimestamp(inc.timestamp)}</td>
                <td style="max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(inc.incident)}">${escHtml(inc.incident)}</td>
                <td style="max-width:150px">${escHtml(inc.subcategory)}</td>
                <td><code>${escHtml(inc.source || '-')}</code></td>
                <td>${escHtml(inc.target || '-')}</td>
                <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><code>${escHtml(mitreStr || '-')}</code></td>
                <td><span style="color:var(--severity-info)">Active</span></td>
                <td>Open</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;

        content.innerHTML = html;
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}

function filterIncidentTable() {
    const search = (document.getElementById('inc-list-search')?.value || '').toLowerCase();
    const rows = document.querySelectorAll('#incidents-list-table tbody tr');
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(search) ? '' : 'none';
    });
}


// ============================================================
// CMDB / DEVICES (Component D)
// ============================================================
async function loadCMDB() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    try {
        const data = await api('/api/cmdb/agents');
        const agents = data.agents || [];

        // Health overview summary
        const active = agents.filter(a => a.status === 'active').length;
        const disconnected = agents.filter(a => a.status === 'disconnected').length;

        let html = '';

        // Stat cards
        html += `<div class="stat-grid mb-3">
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3"><i class="bi bi-hdd-stack"></i></div>
                <div><div class="stat-value">${agents.length}</div><div class="stat-label">Total Devices</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(76,175,80,0.15);color:#4caf50"><i class="bi bi-check-circle"></i></div>
                <div><div class="stat-value">${active}</div><div class="stat-label">Active</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,23,68,0.15);color:#ff1744"><i class="bi bi-x-circle"></i></div>
                <div><div class="stat-value">${disconnected}</div><div class="stat-label">Disconnected</div></div>
            </div>
        </div>`;

        // Table
        html += `<div class="table-scroll" style="max-height:calc(100vh - 220px)">
            <table class="cmdb-table" id="cmdb-table">
                <thead><tr>
                    <th>ID</th><th>Name</th><th>IP</th><th>Status</th>
                    <th>OS</th><th>CPU</th><th>RAM</th><th>Disk</th>
                    <th>Uptime</th><th>Last Seen</th>
                </tr></thead><tbody>`;

        for (const agent of agents) {
            const ramPct = agent.ram_pct || '';
            const diskPct = agent.disk || '';
            html += `<tr onclick="showAgentDetail('${agent.id}')">
                <td><code>${agent.id}</code></td>
                <td class="fw-bold">${escHtml(agent.name)}</td>
                <td><code>${escHtml(agent.ip)}</code></td>
                <td>
                    <span class="agent-status">
                        <span class="status-dot status-${agent.status === 'active' ? 'active' : agent.status === 'disconnected' ? 'disconnected' : 'never'}"></span>
                        ${agent.status}
                    </span>
                </td>
                <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(agent.os_name || '-')} ${escHtml(agent.os_version || '')}</td>
                <td>${agent.cpu_cores ? agent.cpu_cores + ' cores' : '-'}${agent.cpu_load ? ' / ' + agent.cpu_load : ''}</td>
                <td>${ramPct ? ramPct + '%' : '-'} ${ramPct ? buildHealthBar(ramPct) : ''}</td>
                <td>${diskPct ? diskPct + '%' : '-'} ${diskPct ? buildHealthBar(diskPct) : ''}</td>
                <td>${agent.uptime || '-'}</td>
                <td style="white-space:nowrap">${agent.last_keep_alive ? formatTimestamp(agent.last_keep_alive) : '-'}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;

        content.innerHTML = html;
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}

function filterCMDBTable() {
    const search = (document.getElementById('cmdb-search')?.value || '').toLowerCase();
    const rows = document.querySelectorAll('#cmdb-table tbody tr');
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(search) ? '' : 'none';
    });
}

async function showAgentDetail(agentId) {
    const modal = new bootstrap.Modal(document.getElementById('agentDetailModal'));
    document.getElementById('agent-detail-title').textContent = 'Loading...';
    document.getElementById('agent-detail-body').innerHTML = '<div class="text-center py-4"><div class="spinner-border text-warning"></div></div>';
    modal.show();

    try {
        const data = await api(`/api/cmdb/agents/${agentId}`);
        const a = data.agent || {};
        document.getElementById('agent-detail-title').textContent = `${a.name || 'Unknown'} (${a.id || agentId})`;

        let html = '';

        // General Info
        html += `<div class="detail-section">
            <h6><i class="bi bi-info-circle me-2"></i>General Information</h6>
            <div class="detail-grid">
                <div class="detail-item"><span class="detail-label">Status:</span>
                    <span class="detail-value"><span class="status-dot status-${a.status === 'active' ? 'active' : 'disconnected'}"></span> ${a.status}</span></div>
                <div class="detail-item"><span class="detail-label">IP Address:</span><span class="detail-value">${a.ip || '-'}</span></div>
                <div class="detail-item"><span class="detail-label">OS:</span><span class="detail-value">${a.os_name || '-'} ${a.os_version || ''}</span></div>
                <div class="detail-item"><span class="detail-label">Architecture:</span><span class="detail-value">${a.os_arch || '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Agent Version:</span><span class="detail-value">${a.version || '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Manager:</span><span class="detail-value">${a.manager || '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Groups:</span><span class="detail-value">${(a.group || []).join(', ') || '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Registered:</span><span class="detail-value">${a.date_add || '-'}</span></div>
                <div class="detail-item"><span class="detail-label">Last Keep Alive:</span><span class="detail-value">${a.last_keep_alive || '-'}</span></div>
            </div>
        </div>`;

        // Hardware
        if (a.cpu_name || a.ram_total) {
            html += `<div class="detail-section">
                <h6><i class="bi bi-cpu me-2"></i>Hardware</h6>
                <div class="detail-grid">
                    <div class="detail-item"><span class="detail-label">CPU:</span><span class="detail-value">${a.cpu_name || '-'}</span></div>
                    <div class="detail-item"><span class="detail-label">CPU Cores:</span><span class="detail-value">${a.cpu_cores || '-'}</span></div>
                    <div class="detail-item"><span class="detail-label">RAM Total:</span><span class="detail-value">${a.ram_total ? Math.round(a.ram_total/1024) + ' MB' : '-'}</span></div>
                    <div class="detail-item"><span class="detail-label">RAM Usage:</span><span class="detail-value">${a.ram_usage ? a.ram_usage + '%' : '-'} ${a.ram_usage ? buildHealthBar(a.ram_usage) : ''}</span></div>
                </div>
            </div>`;
        }

        // Network Interfaces
        const ifaces = data.interfaces || [];
        if (ifaces.length) {
            html += `<div class="detail-section">
                <h6><i class="bi bi-ethernet me-2"></i>Network Interfaces (${ifaces.length})</h6>
                <table class="data-table"><thead><tr><th>Interface</th><th>Type</th><th>State</th><th>MAC</th><th>MTU</th><th>RX Bytes</th><th>TX Bytes</th></tr></thead><tbody>`;
            for (const ifc of ifaces.slice(0, 10)) {
                html += `<tr>
                    <td class="fw-bold">${escHtml(ifc.name || '')}</td>
                    <td>${escHtml(ifc.type || '')}</td>
                    <td><span class="agent-status"><span class="status-dot ${ifc.state==='up'?'status-active':'status-disconnected'}"></span> ${ifc.state || '-'}</span></td>
                    <td><code>${escHtml(ifc.mac || '-')}</code></td>
                    <td>${ifc.mtu || '-'}</td>
                    <td>${ifc.rx ? formatBytes(ifc.rx.bytes) : '-'}</td>
                    <td>${ifc.tx ? formatBytes(ifc.tx.bytes) : '-'}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // Recent Alerts
        const alerts = data.alerts || [];
        if (alerts.length) {
            html += `<div class="detail-section">
                <h6><i class="bi bi-bell me-2"></i>Recent Alerts (${alerts.length})</h6>
                <table class="data-table"><thead><tr><th>Severity</th><th>Time</th><th>Rule</th><th>Description</th></tr></thead><tbody>`;
            for (const al of alerts.slice(0, 15)) {
                html += `<tr>
                    <td><span class="sev-badge sev-${al.severity.toLowerCase()}">${al.severity}</span></td>
                    <td style="white-space:nowrap">${formatTimestamp(al.timestamp)}</td>
                    <td><code>${al.rule_id}</code></td>
                    <td>${escHtml(al.description)}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        document.getElementById('agent-detail-body').innerHTML = html;
    } catch (err) {
        document.getElementById('agent-detail-body').innerHTML = `<div class="text-center text-danger py-3">Error: ${err.message}</div>`;
    }
}


// ============================================================
// ICMP DATA
// ============================================================
async function loadICMP() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    try {
        const data = await api(`/api/icmp?timerange=${icmpTimerange}&limit=500`);
        const results = data.data || [];

        // Summary counts
        const up = results.filter(r => r.status === 'UP').length;
        const down = results.filter(r => r.status === 'DOWN').length;
        const stateChanges = results.filter(r => r.state_change).length;

        let html = `<div class="stat-grid mb-3">
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(76,175,80,0.15);color:#4caf50"><i class="bi bi-arrow-up-circle"></i></div>
                <div><div class="stat-value">${up}</div><div class="stat-label">UP Events</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,23,68,0.15);color:#ff1744"><i class="bi bi-arrow-down-circle"></i></div>
                <div><div class="stat-value">${down}</div><div class="stat-label">DOWN Events</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,193,7,0.15);color:#ffc107"><i class="bi bi-arrow-left-right"></i></div>
                <div><div class="stat-value">${stateChanges}</div><div class="stat-label">State Changes</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3"><i class="bi bi-broadcast"></i></div>
                <div><div class="stat-value">${results.length}</div><div class="stat-label">Total Events</div></div>
            </div>
        </div>`;

        // ICMP Trend chart
        html += `<div class="soc-card mb-3" style="height:250px">
            <div class="soc-card-title"><i class="bi bi-broadcast-pin"></i> ICMP Events Over Time</div>
            <div style="position:relative;height:190px"><canvas id="icmp-trend-chart"></canvas></div>
        </div>`;

        // Table
        html += `<div class="table-scroll" style="max-height:calc(100vh - 380px)">
            <table class="data-table" id="icmp-table">
                <thead><tr>
                    <th>Time</th><th>Severity</th><th>Host Name</th><th>Address</th>
                    <th>Status</th><th>RTT (ms)</th><th>Packet Loss %</th><th>Description</th>
                </tr></thead><tbody>`;

        for (const r of results) {
            const statusColor = r.status === 'UP' ? 'var(--severity-low)' :
                               r.status === 'DOWN' ? 'var(--severity-critical)' : 'var(--text-secondary)';
            html += `<tr>
                <td style="white-space:nowrap">${formatTimestamp(r.timestamp)}</td>
                <td><span class="sev-badge sev-${r.severity.toLowerCase()}">${r.severity}</span></td>
                <td class="fw-bold">${escHtml(r.host_name || '-')}</td>
                <td><code>${escHtml(r.host_address || '-')}</code></td>
                <td style="color:${statusColor};font-weight:600">${r.status}</td>
                <td>${r.rtt_ms != null ? parseFloat(r.rtt_ms).toFixed(2) : '-'}</td>
                <td>${r.packet_loss != null ? r.packet_loss + '%' : '-'}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(r.description || '-')}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;

        content.innerHTML = html;

        // Build ICMP trend from results
        const icmpTrend = {};
        for (const r of results) {
            const key = (r.timestamp || '').substring(0, 13);
            if (!icmpTrend[key]) icmpTrend[key] = { up: 0, down: 0 };
            if (r.status === 'UP') icmpTrend[key].up++;
            else if (r.status === 'DOWN') icmpTrend[key].down++;
        }
        renderICMPTrend(Object.entries(icmpTrend).sort((a,b) => a[0].localeCompare(b[0])));

    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}

function renderICMPTrend(trendEntries) {
    const ctx = document.getElementById('icmp-trend-chart');
    if (!ctx) return;
    destroyChart('icmp-trend');

    const labels = trendEntries.map(([k]) => {
        const d = new Date(k);
        return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    });

    chartInstances['icmp-trend'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'UP', data: trendEntries.map(([,v]) => v.up), backgroundColor: '#4caf50', stack: 's' },
                { label: 'DOWN', data: trendEntries.map(([,v]) => v.down), backgroundColor: '#ff1744', stack: 's' },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: true, position: 'bottom', labels: { color: '#8b949e', boxWidth: 12, font: { size: 10 } } } },
            scales: {
                x: { stacked: true, ticks: { color: '#8b949e', maxTicksLimit: 12, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { stacked: true, ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            },
        },
    });
}


// ============================================================
// DEVICE INVENTORY (sub-tab under ICMP DATA) — Full V1 feature parity
// ============================================================
let invDevices = [];
let invSortCol = 'name';
let invSortAsc = true;

async function loadDeviceInventory() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    try {
        const data = await api('/api/v1/devices');
        invDevices = data.devices || [];

        // Populate group filter dropdown
        const groups = [...new Set(invDevices.map(d => d.group))].sort();
        const groupSelect = document.getElementById('inv-group-filter');
        if (groupSelect) {
            const cv = groupSelect.value;
            groupSelect.innerHTML = '<option value="">All Groups</option>' +
                groups.map(g => `<option value="${g}" ${g===cv?'selected':''}>${g}</option>`).join('');
        }

        renderDeviceInventory();
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}

function renderDeviceInventory() {
    const content = document.getElementById('main-content');
    const devices = invDevices;
    const total = devices.length;
    const upCount = devices.filter(d => d.status === 'up').length;
    const downCount = devices.filter(d => d.status === 'down').length;
    const unknownCount = devices.filter(d => d.status !== 'up' && d.status !== 'down').length;
    const snmpCount = devices.filter(d => d.snmp_enabled).length;
    const agentCount = devices.filter(d => d.agent_id).length;

    let html = `<div class="stat-grid mb-3">
        <div class="stat-card-v2">
            <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3"><i class="bi bi-display"></i></div>
            <div><div class="stat-value">${total}</div><div class="stat-label">Total Devices</div></div>
        </div>
        <div class="stat-card-v2">
            <div class="stat-icon-circle" style="background:rgba(76,175,80,0.15);color:#4caf50"><i class="bi bi-check-circle"></i></div>
            <div><div class="stat-value">${upCount}</div><div class="stat-label">Up</div></div>
        </div>
        <div class="stat-card-v2">
            <div class="stat-icon-circle" style="background:rgba(244,67,54,0.15);color:#f44336"><i class="bi bi-x-circle"></i></div>
            <div><div class="stat-value">${downCount}</div><div class="stat-label">Down</div></div>
        </div>
        <div class="stat-card-v2">
            <div class="stat-icon-circle" style="background:rgba(158,158,158,0.15);color:#9e9e9e"><i class="bi bi-question-circle"></i></div>
            <div><div class="stat-value">${unknownCount}</div><div class="stat-label">Unknown</div></div>
        </div>
        <div class="stat-card-v2">
            <div class="stat-icon-circle" style="background:rgba(0,188,212,0.15);color:#00bcd4"><i class="bi bi-broadcast"></i></div>
            <div><div class="stat-value">${snmpCount}</div><div class="stat-label">SNMP Enabled</div></div>
        </div>
        <div class="stat-card-v2">
            <div class="stat-icon-circle" style="background:rgba(156,39,176,0.15);color:#ce93d8"><i class="bi bi-people"></i></div>
            <div><div class="stat-value">${agentCount}</div><div class="stat-label">Wazuh Agents</div></div>
        </div>
    </div>`;

    // Action buttons row
    html += `<div class="d-flex justify-content-between align-items-center mb-2">
        <div style="color:#8b949e;font-size:0.85rem">Monitored Devices</div>
        <div class="d-flex gap-2">
            <a href="/api/v1/devices/export" class="btn btn-sm btn-outline-success"><i class="bi bi-download"></i> Export</a>
            <button class="btn btn-sm btn-outline-info" onclick="showImportModal()"><i class="bi bi-upload"></i> Import</button>
            <button class="btn btn-sm btn-warning" onclick="showAddDeviceModal()"><i class="bi bi-plus-circle"></i> Add Device</button>
        </div>
    </div>`;

    // Sortable table
    const arrow = col => invSortCol === col ? (invSortAsc ? ' ↑' : ' ↓') : ' ↕';
    html += `<div class="table-scroll" style="max-height:calc(100vh - 320px)">
        <table class="data-table" id="inv-table">
            <thead><tr>
                <th class="sortable-th" onclick="sortInventory('name')">NAME${arrow('name')}</th>
                <th class="sortable-th" onclick="sortInventory('address')">ADDRESS${arrow('address')}</th>
                <th class="sortable-th" onclick="sortInventory('group')">GROUP${arrow('group')}</th>
                <th>PROTOCOL</th>
                <th class="sortable-th" onclick="sortInventory('status')">STATUS${arrow('status')}</th>
                <th>CPU</th><th>RAM</th><th>DISK</th><th>UPTIME</th>
                <th>ACTIONS</th>
            </tr></thead>
            <tbody>`;

    // Sort devices
    const sorted = [...devices].sort((a, b) => {
        let va = (a[invSortCol] || '').toString().toLowerCase();
        let vb = (b[invSortCol] || '').toString().toLowerCase();
        if (va < vb) return invSortAsc ? -1 : 1;
        if (va > vb) return invSortAsc ? 1 : -1;
        return 0;
    });

    for (const d of sorted) {
        const statusClass = d.status === 'up' ? 'status-up' : (d.status === 'down' ? 'status-down' : 'status-unknown');
        let statusLabel = d.status === 'up' ? 'Up' : (d.status === 'down' ? 'Down' : 'Unknown');
        if (d.status_source === 'agent') statusLabel += ' (Agent)';
        const statusIcon = d.status === 'up' ? 'bi-check-circle' : (d.status === 'down' ? 'bi-x-circle' : 'bi-question-circle');
        const protocol = d.snmp_enabled ? 'SNMP' : 'ICMP';
        const protocolClass = d.snmp_enabled ? 'protocol-snmp' : 'protocol-icmp';
        const cpu = d.cpu_load ? d.cpu_load + '' : (d.cpu || '-');
        const ram = d.ram ? d.ram + '%' : '-';
        const disk = d.disk ? d.disk + '%' : '-';
        const uptime = d.uptime || '-';

        html += `<tr data-group="${d.group}" data-name="${(d.name||'').toLowerCase()}" data-addr="${(d.address||'').toLowerCase()}"
                     onclick="showDeviceDetails('${escapeHtml(d.address)}')" style="cursor:pointer">
            <td><span class="status-dot ${statusClass}"></span>${escapeHtml(d.name || d.address)}</td>
            <td>${escapeHtml(d.address)}</td>
            <td><span class="group-badge">${escapeHtml(d.group)}</span></td>
            <td><span class="protocol-badge ${protocolClass}">${protocol}</span></td>
            <td><span class="inv-status-badge ${statusClass}"><i class="bi ${statusIcon}"></i> ${statusLabel}</span></td>
            <td>${escapeHtml(cpu)}</td>
            <td>${escapeHtml(ram)}</td>
            <td>${escapeHtml(disk)}</td>
            <td>${escapeHtml(uptime)}</td>
            <td class="inv-actions" onclick="event.stopPropagation()">
                <button class="btn btn-sm btn-outline-info" onclick="showEditDeviceModal('${escapeHtml(d.address)}')" title="Edit"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteDevice('${escapeHtml(d.address)}','${escapeHtml(d.name)}')" title="Delete"><i class="bi bi-trash"></i></button>
            </td>
        </tr>`;
    }

    html += '</tbody></table></div>';
    content.innerHTML = html;
}

function sortInventory(col) {
    if (invSortCol === col) invSortAsc = !invSortAsc;
    else { invSortCol = col; invSortAsc = true; }
    renderDeviceInventory();
}

function filterDeviceInventory() {
    const search = (document.getElementById('inv-search')?.value || '').toLowerCase();
    const group = document.getElementById('inv-group-filter')?.value || '';
    const rows = document.querySelectorAll('#inv-table tbody tr');
    rows.forEach(row => {
        const matchSearch = !search || row.dataset.name.includes(search) || row.dataset.addr.includes(search) || row.textContent.toLowerCase().includes(search);
        const matchGroup = !group || row.dataset.group === group;
        row.style.display = (matchSearch && matchGroup) ? '' : 'none';
    });
}

// ---- Device Details Modal ----
async function showDeviceDetails(address) {
    let modal = document.getElementById('device-detail-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'device-detail-modal';
        modal.className = 'inv-modal-overlay';
        document.body.appendChild(modal);
    }
    modal.innerHTML = `<div class="inv-modal inv-modal-lg">
        <div class="inv-modal-header"><span><i class="bi bi-info-circle"></i> Loading...</span>
            <button class="btn-close btn-close-white" onclick="closeModal('device-detail-modal')"></button></div>
        <div class="inv-modal-body"><div class="text-center py-4"><div class="spinner-border text-warning"></div></div></div>
    </div>`;
    modal.style.display = 'flex';

    try {
        const [device, alertsData] = await Promise.all([
            api('/api/v1/devices/' + encodeURIComponent(address)),
            api('/api/v1/devices/' + encodeURIComponent(address) + '/alerts'),
        ]);

        const statusClass = device.status === 'up' ? 'status-up' : (device.status === 'down' ? 'status-down' : 'status-unknown');
        let statusLabel = device.status === 'up' ? 'Up' : (device.status === 'down' ? 'Down' : 'Unknown');
        if (device.status_source === 'agent') statusLabel += ' (Agent)';
        const statusIcon = device.status === 'up' ? 'bi-check-circle' : 'bi-x-circle';

        const tagsBadges = (device.tags || []).map(t =>
            `<span class="group-badge" style="margin-right:4px">${escapeHtml(t)}</span>`).join('');

        const agentSection = device.agent_id ? `
            <tr><td>Agent ID</td><td style="color:#f7931a">${escapeHtml(device.agent_id)}</td></tr>
            <tr><td>Agent Status</td><td><span class="inv-status-badge ${device.agent_status==='active'?'status-up':'status-down'}">${escapeHtml(device.agent_status||'')}</span></td></tr>
            <tr><td>Last Keep Alive</td><td>${escapeHtml(device.last_keep_alive||'-')}</td></tr>` : '';

        let alertsHtml = '';
        const alerts = alertsData.alerts || [];
        if (alerts.length > 0) {
            alertsHtml = alerts.map(a => {
                const ago = timeAgo(a.timestamp);
                const levelColor = a.level >= 10 ? '#f44336' : (a.level >= 7 ? '#ff9800' : '#ffc107');
                return `<div class="detail-alert-item">
                    <div class="d-flex justify-content-between">
                        <span style="color:${levelColor};font-weight:600">Level ${a.level} - Rule ${escapeHtml(a.rule_id)}</span>
                        <span style="color:#8b949e;font-size:0.8rem">${ago}</span>
                    </div>
                    <div style="color:#8b949e;font-size:0.82rem">${escapeHtml(a.description)}</div>
                </div>`;
            }).join('');
        } else {
            alertsHtml = '<div style="color:#8b949e;text-align:center;padding:20px">No recent alerts</div>';
        }

        modal.innerHTML = `<div class="inv-modal inv-modal-lg">
            <div class="inv-modal-header">
                <span><i class="bi bi-info-circle"></i> ${escapeHtml(device.name||device.address)} — Details</span>
                <button class="btn-close btn-close-white" onclick="closeModal('device-detail-modal')"></button>
            </div>
            <div class="inv-modal-body">
                <div class="detail-grid">
                    <div class="detail-section">
                        <div class="detail-section-title"><i class="bi bi-info-circle" style="color:#2196f3"></i> General Information</div>
                        <table class="detail-table">
                            <tr><td>Address</td><td>${escapeHtml(device.address)}</td></tr>
                            <tr><td>Name</td><td>${escapeHtml(device.name||device.address)}</td></tr>
                            <tr><td>Group</td><td><span class="group-badge">${escapeHtml(device.group)}</span></td></tr>
                            <tr><td>Status</td><td><span class="inv-status-badge ${statusClass}"><i class="bi ${statusIcon}"></i> ${statusLabel}</span>${device.status_source?' via '+device.status_source.toUpperCase():''}</td></tr>
                            <tr><td>Last Seen</td><td>${escapeHtml(device.last_seen||'-')}</td></tr>
                            <tr><td>Tags</td><td>${tagsBadges||'-'}</td></tr>
                            ${agentSection}
                        </table>
                    </div>
                    <div class="detail-section">
                        <div class="detail-section-title"><i class="bi bi-exclamation-triangle" style="color:#ff9800"></i> Recent Wazuh Alerts (${alerts.length})</div>
                        <div class="detail-alerts-scroll">${alertsHtml}</div>
                    </div>
                </div>
                <div class="detail-section" style="margin-top:16px">
                    <div class="detail-section-title"><i class="bi bi-speedometer2" style="color:#4caf50"></i> Performance Metrics</div>
                    <table class="detail-table">
                        <tr><td>CPU</td><td>${escapeHtml(device.cpu_load||device.cpu||'-')}</td></tr>
                        <tr><td>RAM Usage</td><td>${device.ram?device.ram+'%':'-'}</td></tr>
                        <tr><td>Disk Usage</td><td>${device.disk?device.disk+'%':'-'}</td></tr>
                        <tr><td>Uptime</td><td>${escapeHtml(device.uptime||'-')}</td></tr>
                        <tr><td>RTT (avg)</td><td>${device.last_rtt!=null?parseFloat(device.last_rtt).toFixed(2)+' ms':'-'}</td></tr>
                        <tr><td>Packet Loss</td><td>${device.last_loss!=null?device.last_loss+'%':'-'}</td></tr>
                    </table>
                </div>
            </div>
        </div>`;
    } catch (err) {
        modal.innerHTML = `<div class="inv-modal"><div class="inv-modal-header"><span>Error</span>
            <button class="btn-close btn-close-white" onclick="closeModal('device-detail-modal')"></button></div>
            <div class="inv-modal-body"><p style="color:#f44336">${err.message}</p></div></div>`;
    }
}

function timeAgo(ts) {
    if (!ts) return '';
    const diff = (Date.now() - new Date(ts).getTime()) / 1000;
    if (diff < 60) return Math.round(diff) + 's ago';
    if (diff < 3600) return Math.round(diff/60) + 'm ago';
    if (diff < 86400) return Math.round(diff/3600) + 'h ago';
    return Math.round(diff/86400) + 'd ago';
}

// ---- Add / Edit Device Modal ----
function showAddDeviceModal() { showDeviceFormModal(null); }

async function showEditDeviceModal(address) {
    try {
        const device = await api('/api/v1/devices/' + encodeURIComponent(address));
        showDeviceFormModal(device);
    } catch (err) { alert('Error loading device: ' + err.message); }
}

function showDeviceFormModal(device) {
    const isEdit = !!device;
    const title = isEdit ? 'Edit Device' : 'Add Device';
    let modal = document.getElementById('device-form-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'device-form-modal';
        modal.className = 'inv-modal-overlay';
        document.body.appendChild(modal);
    }

    const d = device || {};
    const icmp = d.icmp || {};
    const snmp = d.snmp || {};
    const perf = snmp.performance || {};
    const snmpEnabled = d.snmp_enabled || false;

    modal.innerHTML = `<div class="inv-modal inv-modal-md">
        <div class="inv-modal-header"><span>${title}</span>
            <button class="btn-close btn-close-white" onclick="closeModal('device-form-modal')"></button></div>
        <div class="inv-modal-body">
            <div class="row g-3 mb-3">
                <div class="col-6">
                    <label class="inv-label">IP Address *</label>
                    <input type="text" class="inv-input" id="df-address" value="${escapeHtml(d.address||'')}" ${isEdit?'readonly':''} placeholder="e.g. 192.168.1.100">
                </div>
                <div class="col-6">
                    <label class="inv-label">Name</label>
                    <input type="text" class="inv-input" id="df-name" value="${escapeHtml(d.name||'')}" placeholder="e.g. Core Switch 1">
                </div>
            </div>
            <div class="row g-3 mb-3">
                <div class="col-6">
                    <label class="inv-label">Group</label>
                    <input type="text" class="inv-input" id="df-group" value="${escapeHtml(d.group||'')}" placeholder="e.g. network_devices">
                </div>
                <div class="col-6">
                    <label class="inv-label">Tags (comma-separated)</label>
                    <input type="text" class="inv-input" id="df-tags" value="${escapeHtml((d.tags||[]).join(', '))}" placeholder="e.g. switch, cisco, critical">
                </div>
            </div>
            <div class="inv-form-section">ICMP Settings</div>
            <div class="row g-3 mb-3">
                <div class="col-4">
                    <label class="inv-label">Ping Count</label>
                    <input type="number" class="inv-input" id="df-ping-count" value="${icmp.count||3}">
                </div>
                <div class="col-4">
                    <label class="inv-label">Latency Warning (ms)</label>
                    <input type="number" class="inv-input" id="df-lat-warn" value="${icmp.latency_warn||100}">
                </div>
                <div class="col-4">
                    <label class="inv-label">Latency Critical (ms)</label>
                    <input type="number" class="inv-input" id="df-lat-crit" value="${icmp.latency_crit||500}">
                </div>
            </div>
            <div class="d-flex align-items-center gap-2 mb-3">
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="df-snmp-enabled" ${snmpEnabled?'checked':''} onchange="toggleSnmpFields()">
                    <label class="form-check-label inv-label" for="df-snmp-enabled">Enable SNMP Monitoring</label>
                </div>
            </div>
            <div id="df-snmp-section" style="display:${snmpEnabled?'block':'none'}">
                <div class="row g-3 mb-3">
                    <div class="col-4">
                        <label class="inv-label">SNMP Version</label>
                        <select class="inv-input" id="df-snmp-version">
                            <option value="2c" ${(snmp.version||'2c')==='2c'?'selected':''}>v2c</option>
                            <option value="3" ${snmp.version==='3'?'selected':''}>v3</option>
                        </select>
                    </div>
                    <div class="col-4">
                        <label class="inv-label">Community String</label>
                        <input type="text" class="inv-input" id="df-snmp-community" value="${escapeHtml(snmp.community||'public')}">
                    </div>
                    <div class="col-4">
                        <label class="inv-label">SNMP Port</label>
                        <input type="number" class="inv-input" id="df-snmp-port" value="${snmp.port||161}">
                    </div>
                </div>
                <div class="form-check mb-2">
                    <input class="form-check-input" type="checkbox" id="df-walk-if" ${snmp.walk_interfaces?'checked':''}>
                    <label class="form-check-label inv-label" for="df-walk-if">Walk interface table (traffic counters)</label>
                </div>
                <div class="d-flex align-items-center gap-2 mb-3">
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="df-perf-enabled" ${perf.enabled!==false?'checked':''}>
                        <label class="form-check-label inv-label" for="df-perf-enabled">Enable Performance Monitoring (CPU, RAM, Disk)</label>
                    </div>
                </div>
                <div class="row g-3 mb-3">
                    <div class="col-3"><label class="inv-label">CPU Warn</label><input type="number" step="0.1" class="inv-input" id="df-cpu-warn" value="${perf.cpu_load_warn||2.0}"></div>
                    <div class="col-3"><label class="inv-label">CPU Critical</label><input type="number" step="0.1" class="inv-input" id="df-cpu-crit" value="${perf.cpu_load_crit||5.0}"></div>
                    <div class="col-3"><label class="inv-label">RAM Warn %</label><input type="number" class="inv-input" id="df-ram-warn" value="${perf.ram_warn||80}"></div>
                    <div class="col-3"><label class="inv-label">RAM Critical %</label><input type="number" class="inv-input" id="df-ram-crit" value="${perf.ram_crit||90}"></div>
                </div>
                <div class="row g-3 mb-3">
                    <div class="col-3"><label class="inv-label">Disk Warn %</label><input type="number" class="inv-input" id="df-disk-warn" value="${perf.disk_warn||80}"></div>
                    <div class="col-3"><label class="inv-label">Disk Critical %</label><input type="number" class="inv-input" id="df-disk-crit" value="${perf.disk_crit||90}"></div>
                </div>
            </div>
            <div class="d-flex justify-content-end gap-2 mt-3">
                <button class="btn btn-sm btn-secondary" onclick="closeModal('device-form-modal')">Cancel</button>
                <button class="btn btn-sm btn-success" onclick="saveDevice(${isEdit?'true':'false'}, '${escapeHtml(d.address||'')}')"><i class="bi bi-check-lg"></i> Save Device</button>
            </div>
        </div>
    </div>`;
    modal.style.display = 'flex';
}

function toggleSnmpFields() {
    const sec = document.getElementById('df-snmp-section');
    const chk = document.getElementById('df-snmp-enabled');
    if (sec) sec.style.display = chk && chk.checked ? 'block' : 'none';
}

async function saveDevice(isEdit, origAddress) {
    const payload = {
        address: document.getElementById('df-address')?.value?.trim(),
        name: document.getElementById('df-name')?.value?.trim(),
        group: document.getElementById('df-group')?.value?.trim() || 'default',
        tags: document.getElementById('df-tags')?.value?.trim() || '',
        ping_count: document.getElementById('df-ping-count')?.value,
        latency_warn: document.getElementById('df-lat-warn')?.value,
        latency_crit: document.getElementById('df-lat-crit')?.value,
        snmp_enabled: document.getElementById('df-snmp-enabled')?.checked || false,
    };
    if (!payload.address) { alert('IP Address is required'); return; }

    if (payload.snmp_enabled) {
        payload.snmp_version = document.getElementById('df-snmp-version')?.value || '2c';
        payload.snmp_community = document.getElementById('df-snmp-community')?.value || 'public';
        payload.snmp_port = document.getElementById('df-snmp-port')?.value || 161;
        payload.walk_interfaces = document.getElementById('df-walk-if')?.checked || false;
        payload.perf_enabled = document.getElementById('df-perf-enabled')?.checked || false;
        payload.cpu_warn = document.getElementById('df-cpu-warn')?.value || 2.0;
        payload.cpu_crit = document.getElementById('df-cpu-crit')?.value || 5.0;
        payload.ram_warn = document.getElementById('df-ram-warn')?.value || 80;
        payload.ram_crit = document.getElementById('df-ram-crit')?.value || 90;
        payload.disk_warn = document.getElementById('df-disk-warn')?.value || 80;
        payload.disk_crit = document.getElementById('df-disk-crit')?.value || 90;
    }

    const url = isEdit ? '/api/v1/devices/' + encodeURIComponent(origAddress) : '/api/v1/devices';
    const method = isEdit ? 'PUT' : 'POST';

    try {
        const resp = await fetch(url, {
            method, headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (!resp.ok) { alert(data.error || 'Failed'); return; }
        closeModal('device-form-modal');
        loadDeviceInventory();
    } catch (err) { alert('Error: ' + err.message); }
}

async function deleteDevice(address, name) {
    if (!confirm(`Delete device "${name}" (${address})? This removes it from config.yaml.`)) return;
    try {
        const resp = await fetch('/api/v1/devices/' + encodeURIComponent(address), { method: 'DELETE' });
        const data = await resp.json();
        if (!resp.ok) { alert(data.error || 'Failed'); return; }
        loadDeviceInventory();
    } catch (err) { alert('Error: ' + err.message); }
}

// ---- Import Modal ----
function showImportModal() {
    let modal = document.getElementById('import-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'import-modal';
        modal.className = 'inv-modal-overlay';
        document.body.appendChild(modal);
    }
    modal.innerHTML = `<div class="inv-modal inv-modal-sm">
        <div class="inv-modal-header"><span>Import Devices (CSV)</span>
            <button class="btn-close btn-close-white" onclick="closeModal('import-modal')"></button></div>
        <div class="inv-modal-body">
            <p style="color:#8b949e;font-size:0.85rem">Upload a CSV file with columns: address, name, group, tags, snmp_enabled</p>
            <input type="file" class="form-control form-control-sm" id="import-file" accept=".csv" style="background:#0d1117;border-color:#30363d;color:#e6edf3">
            <div class="d-flex justify-content-end gap-2 mt-3">
                <button class="btn btn-sm btn-secondary" onclick="closeModal('import-modal')">Cancel</button>
                <button class="btn btn-sm btn-success" onclick="doImport()"><i class="bi bi-upload"></i> Import</button>
            </div>
        </div>
    </div>`;
    modal.style.display = 'flex';
}

async function doImport() {
    const fileInput = document.getElementById('import-file');
    if (!fileInput?.files?.length) { alert('Select a CSV file'); return; }
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    try {
        const resp = await fetch('/api/v1/devices/import', { method: 'POST', body: formData });
        const data = await resp.json();
        if (!resp.ok) { alert(data.error || 'Import failed'); return; }
        alert(data.message);
        closeModal('import-modal');
        loadDeviceInventory();
    } catch (err) { alert('Error: ' + err.message); }
}

function closeModal(id) {
    const m = document.getElementById(id);
    if (m) m.style.display = 'none';
}


// ============================================================
// SNMP PERFORMANCE
// ============================================================
async function loadSNMP() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    try {
        const data = await api(`/api/snmp?timerange=${snmpTimerange}&limit=500`);
        const results = data.data || [];

        // Counts by type
        const perfOK = results.filter(r => r.status === 'OK' || r.status === 'PERF_OK').length;
        const perfWarn = results.filter(r => r.status === 'PERF_WARNING').length;
        const perfCrit = results.filter(r => r.status === 'PERF_CRITICAL').length;
        const snmpErr = results.filter(r => r.status === 'SNMP_ERROR').length;
        const ifDown = results.filter(r => r.status === 'INTERFACE_DOWN').length;

        let html = `<div class="stat-grid mb-3">
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(76,175,80,0.15);color:#4caf50"><i class="bi bi-check-circle"></i></div>
                <div><div class="stat-value">${perfOK}</div><div class="stat-label">OK</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,193,7,0.15);color:#ffc107"><i class="bi bi-exclamation-triangle"></i></div>
                <div><div class="stat-value">${perfWarn}</div><div class="stat-label">Warnings</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,23,68,0.15);color:#ff1744"><i class="bi bi-x-octagon"></i></div>
                <div><div class="stat-value">${perfCrit}</div><div class="stat-label">Critical</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(255,109,0,0.15);color:#ff6d00"><i class="bi bi-hdd-network"></i></div>
                <div><div class="stat-value">${ifDown}</div><div class="stat-label">IF Down</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3"><i class="bi bi-diagram-3"></i></div>
                <div><div class="stat-value">${results.length}</div><div class="stat-label">Total Events</div></div>
            </div>
        </div>`;

        // Table
        html += `<div class="table-scroll" style="max-height:calc(100vh - 220px)">
            <table class="data-table">
                <thead><tr>
                    <th>Time</th><th>Severity</th><th>Host</th><th>Address</th>
                    <th>Type</th><th>Status</th><th>CPU Load</th><th>RAM %</th>
                    <th>Disk %</th><th>Description</th>
                </tr></thead><tbody>`;

        for (const r of results) {
            const statusColor = r.status === 'OK' ? 'var(--severity-low)' :
                               r.status === 'PERF_WARNING' ? 'var(--severity-medium)' :
                               r.status === 'PERF_CRITICAL' ? 'var(--severity-critical)' :
                               r.status === 'INTERFACE_DOWN' ? 'var(--severity-high)' :
                               'var(--text-secondary)';
            html += `<tr>
                <td style="white-space:nowrap">${formatTimestamp(r.timestamp)}</td>
                <td><span class="sev-badge sev-${r.severity.toLowerCase()}">${r.severity}</span></td>
                <td class="fw-bold">${escHtml(r.host_name || '-')}</td>
                <td><code>${escHtml(r.host_address || '-')}</code></td>
                <td>${escHtml(r.check_type || '-')}</td>
                <td style="color:${statusColor};font-weight:600">${r.status || '-'}</td>
                <td>${r.cpu_load || '-'}</td>
                <td>${r.ram_percent || '-'}</td>
                <td>${r.disk_percent || '-'}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(r.description || '-')}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;

        if (!results.length) {
            html = `<div class="empty-state">
                <i class="bi bi-diagram-3"></i>
                <p>No SNMP performance data found in the selected time range.</p>
                <p class="text-muted">SNMP data appears when devices with <code>snmp_enabled: true</code> are polled by the monitor wodle.</p>
            </div>`;
        }

        content.innerHTML = html;
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><i class="bi bi-exclamation-circle"></i><p>Error: ${err.message}</p></div>`;
    }
}


// ============================================================
// DISCOVERY SCANNER (sub-tab under SNMP PERF)
// ============================================================
let discoveryPolling = null;

async function loadDiscoveryScan() {
    const content = document.getElementById('main-content');

    let html = `<div class="soc-card mb-3">
        <div class="soc-card-title"><i class="bi bi-search"></i> SNMP Discovery Scanner</div>
        <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem">
            Scan a subnet for SNMP-enabled devices. Devices found can be added to the monitoring config.
        </p>
        <div class="d-flex gap-2 align-items-end flex-wrap">
            <div>
                <label class="form-label" style="color:#8b949e;font-size:0.8rem">Subnet (CIDR)</label>
                <input type="text" class="form-control form-control-sm" id="disc-subnet"
                    placeholder="e.g. 192.168.10.0/24" style="width:220px;background:#0d1117;border-color:#30363d;color:#e6edf3">
            </div>
            <div>
                <label class="form-label" style="color:#8b949e;font-size:0.8rem">SNMP Community</label>
                <input type="text" class="form-control form-control-sm" id="disc-community"
                    value="public" style="width:160px;background:#0d1117;border-color:#30363d;color:#e6edf3">
            </div>
            <div class="form-check" style="margin-bottom:0.4rem">
                <input class="form-check-input" type="checkbox" id="disc-ping-first" checked>
                <label class="form-check-label" style="color:#8b949e;font-size:0.85rem" for="disc-ping-first">Ping first</label>
            </div>
            <button class="btn btn-sm btn-warning" id="disc-scan-btn" onclick="startDiscoveryScan()">
                <i class="bi bi-play-fill"></i> Start Scan
            </button>
        </div>
    </div>

    <div id="disc-status" class="mb-3" style="display:none"></div>

    <div id="disc-results-container" style="display:none">
        <div class="soc-card">
            <div class="soc-card-title"><i class="bi bi-list-check"></i> Discovered Devices — <span id="disc-result-count">0</span> found</div>
            <div class="table-scroll" style="max-height:calc(100vh - 420px)">
                <table class="data-table" id="disc-table">
                    <thead><tr>
                        <th>Address</th><th>sysName</th><th>Vendor</th><th>OS</th>
                        <th>SNMP</th><th>Template</th><th>Actions</th>
                    </tr></thead>
                    <tbody id="disc-tbody"></tbody>
                </table>
            </div>
        </div>
    </div>`;

    content.innerHTML = html;

    // Check if there's an existing scan running or completed
    try {
        const status = await api('/api/discovery/status');
        if (status.running) {
            showDiscoveryRunning(status.subnet);
            pollDiscoveryStatus();
        } else if (status.status === 'completed' && status.results.length > 0) {
            renderDiscoveryResults(status.results);
        }
    } catch (err) {
        // No previous scan
    }
}

async function startDiscoveryScan() {
    const subnet = document.getElementById('disc-subnet')?.value?.trim();
    const community = document.getElementById('disc-community')?.value?.trim() || 'public';
    const pingFirst = document.getElementById('disc-ping-first')?.checked ?? true;

    if (!subnet) {
        alert('Please enter a subnet (e.g. 192.168.10.0/24)');
        return;
    }

    const btn = document.getElementById('disc-scan-btn');
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Starting...';

    try {
        const resp = await fetch('/api/discovery/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ subnet, community, ping_first: pingFirst })
        });
        const data = await resp.json();
        if (!resp.ok) {
            alert(data.error || 'Failed to start scan');
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-play-fill"></i> Start Scan';
            return;
        }
        showDiscoveryRunning(subnet);
        pollDiscoveryStatus();
    } catch (err) {
        alert('Error: ' + err.message);
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-play-fill"></i> Start Scan';
    }
}

function showDiscoveryRunning(subnet) {
    const statusDiv = document.getElementById('disc-status');
    if (statusDiv) {
        statusDiv.style.display = 'block';
        statusDiv.innerHTML = `<div class="soc-card" style="border-left:3px solid #f7931a">
            <div class="d-flex align-items-center gap-2">
                <div class="spinner-border spinner-border-sm text-warning"></div>
                <span style="color:#e6edf3">Scanning <strong>${escapeHtml(subnet)}</strong> for SNMP-enabled devices...</span>
            </div>
        </div>`;
    }
    const btn = document.getElementById('disc-scan-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Scanning...';
    }
}

function pollDiscoveryStatus() {
    if (discoveryPolling) clearInterval(discoveryPolling);
    discoveryPolling = setInterval(async () => {
        try {
            const status = await api('/api/discovery/status');
            if (!status.running) {
                clearInterval(discoveryPolling);
                discoveryPolling = null;
                const btn = document.getElementById('disc-scan-btn');
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="bi bi-play-fill"></i> Start Scan';
                }
                const statusDiv = document.getElementById('disc-status');
                if (status.status === 'completed') {
                    if (statusDiv) {
                        statusDiv.innerHTML = `<div class="soc-card" style="border-left:3px solid #4caf50">
                            <span style="color:#4caf50"><i class="bi bi-check-circle"></i> Scan completed — ${status.result_count} device(s) found</span>
                        </div>`;
                    }
                    renderDiscoveryResults(status.results);
                } else if (status.status === 'timeout') {
                    if (statusDiv) {
                        statusDiv.innerHTML = `<div class="soc-card" style="border-left:3px solid #f44336">
                            <span style="color:#f44336"><i class="bi bi-clock"></i> Scan timed out</span>
                        </div>`;
                    }
                } else {
                    if (statusDiv) {
                        statusDiv.innerHTML = `<div class="soc-card" style="border-left:3px solid #f44336">
                            <span style="color:#f44336"><i class="bi bi-exclamation-triangle"></i> Scan error: ${escapeHtml(status.status)}</span>
                        </div>`;
                    }
                }
            }
        } catch (err) {
            clearInterval(discoveryPolling);
            discoveryPolling = null;
        }
    }, 3000);
}

function renderDiscoveryResults(results) {
    const container = document.getElementById('disc-results-container');
    const tbody = document.getElementById('disc-tbody');
    const countEl = document.getElementById('disc-result-count');
    if (!container || !tbody) return;

    container.style.display = 'block';
    countEl.textContent = results.length;

    tbody.innerHTML = results.map(d => {
        const snmpBadge = d.snmp_reachable
            ? '<span class="protocol-badge protocol-snmp">SNMP</span>'
            : '<span class="protocol-badge protocol-icmp">ICMP only</span>';
        return `<tr>
            <td>${escapeHtml(d.address || d.ip || '')}</td>
            <td>${escapeHtml(d.sysName || d.name || '-')}</td>
            <td>${escapeHtml(d.vendor || '-')}</td>
            <td>${escapeHtml(d.os || '-')}</td>
            <td>${snmpBadge}</td>
            <td>${escapeHtml(d.template || d.suggested_template || '-')}</td>
            <td><button class="btn btn-sm btn-outline-success" onclick='addDiscoveredDevice(${JSON.stringify(d).replace(/'/g,"&#39;")})'>
                <i class="bi bi-plus-circle"></i> Add
            </button></td>
        </tr>`;
    }).join('');
}

async function addDiscoveredDevice(device) {
    try {
        const resp = await fetch('/api/discovery/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(device)
        });
        const data = await resp.json();
        if (resp.ok) {
            alert(data.message || 'Device added successfully');
        } else {
            alert(data.error || 'Failed to add device');
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}


// ============================================================
// UTILITIES
// ============================================================
// ============================================================
// UEBA — User & Entity Behavior Analytics (Enhanced)
// ============================================================
let uebaData = null;
let uebaActiveTab = 'hosts';
let uebaActiveRankingTab = 'risk';
let uebaAnomalyFilter = null; // for chart click-through filtering
let uebaRiskLevelFilter = null; // for card click-through (high/medium/low/critical)

// Auto-refresh state
let autoRefreshInterval = 0; // 0 = off, value in seconds
let autoRefreshCountdown = 0;
let autoRefreshCountdownTimer = null;

function setAutoRefresh(seconds) {
    autoRefreshInterval = seconds;
    if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
    if (autoRefreshCountdownTimer) { clearInterval(autoRefreshCountdownTimer); autoRefreshCountdownTimer = null; }
    const badge = document.getElementById('auto-refresh-countdown');
    if (!seconds) {
        if (badge) badge.textContent = '';
        return;
    }
    autoRefreshCountdown = seconds;
    autoRefreshCountdownTimer = setInterval(() => {
        autoRefreshCountdown--;
        if (badge) badge.textContent = autoRefreshCountdown > 0 ? autoRefreshCountdown + 's' : '';
        if (autoRefreshCountdown <= 0) autoRefreshCountdown = autoRefreshInterval;
    }, 1000);
    autoRefreshTimer = setInterval(() => {
        if (currentPage === 'ueba') loadUEBA(true);
        else loadCurrentPage();
    }, seconds * 1000);
}

function uebaCardClick(tab, rankingTab, riskLevel) {
    uebaActiveTab = tab;
    if (rankingTab) uebaActiveRankingTab = rankingTab;
    uebaRiskLevelFilter = riskLevel || null;
    renderUEBAMainSection();
    const section = document.getElementById('ueba-main-section-content');
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function loadUEBA(silent) {
    const content = document.getElementById('main-content');
    if (!silent) {
        content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div><p class="mt-3 text-muted">Analyzing entity behavior...</p></div>';
    }

    const trSel = document.getElementById('ueba-timerange');
    const timerange = trSel ? trSel.value : '7d';

    try {
        uebaData = await api('/api/ueba/summary?timerange=' + timerange);
        renderUEBA(uebaData);
    } catch (e) {
        if (!silent) {
            content.innerHTML = `<div class="text-center py-5 text-danger"><i class="bi bi-exclamation-triangle" style="font-size:2rem"></i><p class="mt-2">Error loading UEBA data: ${e.message}</p></div>`;
        }
    }
}

function _uebaRiskColor(score) {
    return score >= 75 ? '#ff1744' : score >= 50 ? '#ff6d00' : score >= 25 ? '#ffc107' : '#4caf50';
}
function _uebaRiskBg(score) {
    return score >= 75 ? 'rgba(255,23,68,0.15)' : score >= 50 ? 'rgba(255,109,0,0.15)' : score >= 25 ? 'rgba(255,193,7,0.15)' : 'rgba(76,175,80,0.15)';
}

function renderUEBA(data) {
    const content = document.getElementById('main-content');
    const summary = data.summary || {};
    const entities = data.entities || [];
    const userEntities = data.user_entities || [];
    const correlations = data.correlations || [];
    const anomalyTypes = data.anomaly_types || {};
    const topAnomalies = data.top_anomalies || [];
    const riskTrend = data.risk_trend || [];
    const mlSummary = data.ml_summary || {};
    const mlAnomalies = data.ml_anomalies || [];

    let html = '';

    // --- Risk Summary Cards (clickable) ---
    const mlCount = mlSummary.total_ml_anomalies || 0;
    const mlActive = mlSummary.detectors_active || 0;
    const mlTotal = mlSummary.detectors_total || 4;
    html += `<div class="stat-grid">
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('hosts')">
            <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3"><i class="bi bi-hdd-stack-fill"></i></div>
            <div><div class="stat-value">${summary.total_entities || 0}</div><div class="stat-label">Host Entities</div></div>
        </div>
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('users')">
            <div class="stat-icon-circle" style="background:rgba(0,188,212,0.15);color:#00bcd4"><i class="bi bi-people-fill"></i></div>
            <div><div class="stat-value">${summary.total_users || 0}</div><div class="stat-label">User Entities</div></div>
        </div>
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('hosts','risk_level','high')">
            <div class="stat-icon-circle" style="background:rgba(255,23,68,0.15);color:#ff1744"><i class="bi bi-exclamation-octagon-fill"></i></div>
            <div><div class="stat-value">${summary.high_risk || 0}</div><div class="stat-label">High Risk</div></div>
        </div>
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('hosts','risk_level','medium')">
            <div class="stat-icon-circle" style="background:rgba(255,193,7,0.15);color:#ffc107"><i class="bi bi-shield-exclamation"></i></div>
            <div><div class="stat-value">${summary.medium_risk || 0}</div><div class="stat-label">Medium Risk</div></div>
        </div>
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('anomalies')">
            <div class="stat-icon-circle" style="background:rgba(156,39,176,0.15);color:#9c27b0"><i class="bi bi-bug-fill"></i></div>
            <div><div class="stat-value">${summary.total_anomalies || 0}</div><div class="stat-label">Anomalies</div></div>
        </div>
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('correlations')">
            <div class="stat-icon-circle" style="background:rgba(255,109,0,0.15);color:#ff6d00"><i class="bi bi-diagram-3-fill"></i></div>
            <div><div class="stat-value">${correlations.length}</div><div class="stat-label">Cross-Entity</div></div>
        </div>
        <div class="stat-card-v2 ueba-clickable-card" onclick="uebaCardClick('ml_anomalies')">
            <div class="stat-icon-circle" style="background:rgba(0,230,118,0.15);color:#00e676"><i class="bi bi-cpu-fill"></i></div>
            <div><div class="stat-value">${mlCount}</div><div class="stat-label">ML Anomalies</div></div>
            <div style="font-size:.65rem;color:#aaa;margin-top:2px">${mlActive}/${mlTotal} detectors</div>
        </div>
    </div>`;

    // --- Row: Risk Trend + Anomaly Type Breakdown ---
    html += `<div class="row g-3 mb-4">
        <div class="col-lg-7">
            <div class="soc-card" style="height:300px">
                <div class="soc-card-title"><i class="bi bi-graph-up-arrow"></i> Risk Trend Over Time</div>
                <div style="position:relative;height:240px"><canvas id="ueba-risk-trend-chart"></canvas></div>
            </div>
        </div>
        <div class="col-lg-5">
            <div class="soc-card" style="height:300px">
                <div class="soc-card-title d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-pie-chart"></i> Anomaly Types</span>
                    <span id="ueba-donut-filter-badge"></span>
                </div>
                <div style="position:relative;height:240px"><canvas id="ueba-anomaly-donut"></canvas></div>
            </div>
        </div>
    </div>`;

    // --- Main Tabbed Section: Hosts | Users | Correlations ---
    html += `<div class="soc-card mb-4">
        <div class="ueba-main-tabs">
            <span class="ueba-main-tab ${uebaActiveTab==='hosts'?'active':''}" onclick="uebaActiveTab='hosts';renderUEBAMainSection()">
                <i class="bi bi-hdd-stack"></i> Host Entities <span class="ueba-tab-count">${entities.length}</span>
            </span>
            <span class="ueba-main-tab ${uebaActiveTab==='users'?'active':''}" onclick="uebaActiveTab='users';renderUEBAMainSection()">
                <i class="bi bi-people"></i> User Entities <span class="ueba-tab-count">${userEntities.length}</span>
            </span>
            <span class="ueba-main-tab ${uebaActiveTab==='correlations'?'active':''}" onclick="uebaActiveTab='correlations';renderUEBAMainSection()">
                <i class="bi bi-diagram-3"></i> Cross-Entity Correlations <span class="ueba-tab-count">${correlations.length}</span>
            </span>
            <span class="ueba-main-tab ${uebaActiveTab==='anomalies'?'active':''}" onclick="uebaActiveTab='anomalies';renderUEBAMainSection()">
                <i class="bi bi-bug"></i> Top Anomalies <span class="ueba-tab-count">${topAnomalies.length}</span>
            </span>
            <span class="ueba-main-tab ${uebaActiveTab==='ml_anomalies'?'active':''}" onclick="uebaActiveTab='ml_anomalies';renderUEBAMainSection()">
                <i class="bi bi-cpu"></i> ML Detections <span class="ueba-tab-count">${mlAnomalies.length}</span>
            </span>
        </div>
        <div id="ueba-main-section-content"></div>
    </div>`;

    content.innerHTML = html;

    // Render charts + main section after DOM ready
    setTimeout(() => {
        renderUEBARiskTrend(riskTrend);
        renderUEBAAnomalyDonut(anomalyTypes);
        renderUEBAMainSection();
    }, 50);
}

// --- Main Section Renderer (tab-driven) ---
function renderUEBAMainSection() {
    const container = document.getElementById('ueba-main-section-content');
    if (!container || !uebaData) return;

    // Update tab active states
    document.querySelectorAll('.ueba-main-tab').forEach(t => {
        const tabName = t.textContent.trim().toLowerCase();
        t.classList.toggle('active',
            (uebaActiveTab === 'hosts' && tabName.startsWith('host')) ||
            (uebaActiveTab === 'users' && tabName.startsWith('user')) ||
            (uebaActiveTab === 'correlations' && tabName.startsWith('cross')) ||
            (uebaActiveTab === 'anomalies' && tabName.startsWith('top')) ||
            (uebaActiveTab === 'ml_anomalies' && tabName.startsWith('ml'))
        );
    });

    if (uebaActiveTab === 'ml_anomalies') {
        renderUEBAMLAnomaliesTab(container);
        return;
    }
    if (uebaActiveTab === 'hosts') {
        renderUEBAHostsTab(container);
    } else if (uebaActiveTab === 'users') {
        renderUEBAUsersTab(container);
    } else if (uebaActiveTab === 'correlations') {
        renderUEBACorrelationsTab(container);
    } else if (uebaActiveTab === 'anomalies') {
        renderUEBAAnomaliesTab(container);
    }
}

// --- Hosts Tab with sub-tabs (Risk, Entity Type, Risk Level, Alerts, Anomalies, MITRE) ---
function renderUEBAHostsTab(container) {
    const entities = uebaData.entities || [];
    let html = '';

    // Sub-tab bar for ranking views
    html += `<div class="ueba-ranking-tabs">
        <span class="ueba-rank-tab ${uebaActiveRankingTab==='risk'?'active':''}" onclick="uebaActiveRankingTab='risk';uebaRiskLevelFilter=null;renderUEBAMainSection()">Risk</span>
        <span class="ueba-rank-tab ${uebaActiveRankingTab==='entity_type'?'active':''}" onclick="uebaActiveRankingTab='entity_type';uebaRiskLevelFilter=null;renderUEBAMainSection()">Entity Type</span>
        <span class="ueba-rank-tab ${uebaActiveRankingTab==='risk_level'?'active':''}" onclick="uebaActiveRankingTab='risk_level';renderUEBAMainSection()">Risk Level</span>
        <span class="ueba-rank-tab ${uebaActiveRankingTab==='alerts'?'active':''}" onclick="uebaActiveRankingTab='alerts';uebaRiskLevelFilter=null;renderUEBAMainSection()">Alerts</span>
        <span class="ueba-rank-tab ${uebaActiveRankingTab==='anomalies_tab'?'active':''}" onclick="uebaActiveRankingTab='anomalies_tab';uebaRiskLevelFilter=null;renderUEBAMainSection()">Anomalies</span>
        <span class="ueba-rank-tab ${uebaActiveRankingTab==='mitre'?'active':''}" onclick="uebaActiveRankingTab='mitre';uebaRiskLevelFilter=null;renderUEBAMainSection()">MITRE ATT&CK</span>
        <div style="flex:1"></div>`;

    // Show active filter badges
    if (uebaRiskLevelFilter) {
        const rlColor = uebaRiskLevelFilter === 'high' ? '#ff1744' : uebaRiskLevelFilter === 'medium' ? '#ffc107' : uebaRiskLevelFilter === 'critical' ? '#ff1744' : '#4caf50';
        html += `<span class="ueba-filter-active" onclick="uebaRiskLevelFilter=null;renderUEBAMainSection()">
            <i class="bi bi-funnel-fill"></i> ${uebaRiskLevelFilter.charAt(0).toUpperCase() + uebaRiskLevelFilter.slice(1)} Risk <i class="bi bi-x-lg ms-1"></i></span> `;
    }
    if (uebaAnomalyFilter) {
        html += `<span class="ueba-filter-active" onclick="uebaAnomalyFilter=null;updateDonutFilterBadge();renderUEBAMainSection()">
            <i class="bi bi-funnel-fill"></i> ${escHtml(uebaAnomalyFilter)} <i class="bi bi-x-lg ms-1"></i></span> `;
    }

    html += `<input type="text" class="filter-input" id="ueba-entity-search" placeholder="Search entities..." oninput="filterUEBATable()" style="width:220px">
    </div>`;

    // Apply risk level filter to entities
    let filtered = entities;
    if (uebaRiskLevelFilter) {
        const rlMap = { 'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low' };
        const targetLevel = rlMap[uebaRiskLevelFilter] || uebaRiskLevelFilter;
        // High Risk card means risk_score >= 50 (High + Critical)
        if (uebaRiskLevelFilter === 'high') {
            filtered = entities.filter(e => e.risk_score >= 50);
        } else if (uebaRiskLevelFilter === 'medium') {
            filtered = entities.filter(e => e.risk_score >= 25 && e.risk_score < 50);
        } else {
            filtered = entities.filter(e => e.risk_level === targetLevel);
        }
    }

    if (uebaActiveRankingTab === 'mitre') {
        html += renderUEBAMitreHeatmap(filtered);
    } else if (uebaActiveRankingTab === 'entity_type') {
        html += renderUEBAGroupedByType(filtered);
    } else if (uebaActiveRankingTab === 'risk_level') {
        html += renderUEBAGroupedByRiskLevel(filtered);
    } else {
        // Standard table with different sort
        let sorted = [...filtered];
        if (uebaActiveRankingTab === 'alerts') sorted.sort((a, b) => b.total_alerts - a.total_alerts);
        else if (uebaActiveRankingTab === 'anomalies_tab') sorted.sort((a, b) => b.anomaly_count - a.anomaly_count);
        else sorted.sort((a, b) => b.risk_score - a.risk_score);

        // Apply anomaly filter from donut click
        if (uebaAnomalyFilter) {
            sorted = sorted.filter(e => (e.anomalies || []).some(a => a.type === uebaAnomalyFilter));
        }

        html += _renderEntityTable(sorted, 'host');
    }

    // When a risk-level filter is active, also show matching user entities
    if (uebaRiskLevelFilter) {
        const allUsers = uebaData.user_entities || [];
        let filteredUsers;
        if (uebaRiskLevelFilter === 'high') {
            filteredUsers = allUsers.filter(u => u.risk_score >= 50);
        } else if (uebaRiskLevelFilter === 'medium') {
            filteredUsers = allUsers.filter(u => u.risk_score >= 25 && u.risk_score < 50);
        } else if (uebaRiskLevelFilter === 'critical') {
            filteredUsers = allUsers.filter(u => u.risk_score >= 75);
        } else {
            filteredUsers = allUsers.filter(u => u.risk_level && u.risk_level.toLowerCase() === uebaRiskLevelFilter);
        }
        if (filteredUsers.length) {
            html += `<div class="ueba-ranking-tabs mt-3">
                <span class="ueba-rank-tab active"><i class="bi bi-people-fill"></i> User Entities — ${uebaRiskLevelFilter.charAt(0).toUpperCase()+uebaRiskLevelFilter.slice(1)} Risk</span>
                <span class="text-muted ms-2">${filteredUsers.length} user${filteredUsers.length!==1?'s':''}</span>
            </div>`;
            html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
                <th style="width:50px">Risk</th><th>User</th><th>Hosts</th><th>Risk Level</th><th>Alerts</th><th>Anomalies</th><th>MITRE</th>
            </tr></thead><tbody>`;
            for (const user of filteredUsers) {
                const riskColor = _uebaRiskColor(user.risk_score);
                const riskBg = _uebaRiskBg(user.risk_score);
                let hostBadges = (user.hosts || []).slice(0, 3).map(h => `<code class="ueba-indicator">${escHtml(h)}</code>`).join(' ');
                if ((user.hosts || []).length > 3) hostBadges += ` <span class="text-muted">+${user.hosts.length - 3}</span>`;
                let anomBadges = (user.anomalies || []).slice(0, 2).map(a => {
                    const aColor = a.severity === 'Critical' ? '#ff1744' : a.severity === 'High' ? '#ff6d00' : '#ffc107';
                    return `<span class="ueba-anom-badge" style="color:${aColor};border-color:${aColor}">${escHtml(a.type)}</span>`;
                }).join(' ');
                if ((user.anomalies || []).length > 2) anomBadges += ` <span class="text-muted">+${user.anomalies.length - 2}</span>`;
                if (!user.anomalies?.length) anomBadges = '<span class="text-muted">-</span>';
                let mitreTags = (user.mitre || []).slice(0, 3).map(m => `<span class="mitre-tag">${escHtml(m)}</span>`).join(' ');
                if ((user.mitre || []).length > 3) mitreTags += ` <span class="text-muted">+${user.mitre.length - 3}</span>`;
                html += `<tr class="ueba-entity-row" onclick="showUEBAUserDetail('${escHtml(user.name)}')" style="cursor:pointer">
                    <td><div class="ueba-risk-gauge" style="background:${riskBg};color:${riskColor}">${user.risk_score}</div></td>
                    <td><i class="bi bi-person-fill" style="color:${riskColor}"></i> <strong>${escHtml(user.name)}</strong></td>
                    <td>${hostBadges || '-'}</td>
                    <td><span class="sev-badge sev-${user.risk_level.toLowerCase()}">${user.risk_level}</span></td>
                    <td>${user.total_alerts}</td>
                    <td>${anomBadges}</td>
                    <td>${mitreTags || '-'}</td>
                </tr>`;
            }
            html += '</tbody></table></div>';
        }
    }

    container.innerHTML = html;

    // Render sparklines after DOM update
    setTimeout(() => {
        for (const entity of entities) {
            const sparkId = 'spark-' + entity.name.replace(/[^a-zA-Z0-9]/g, '_');
            renderUEBASparkline(sparkId, entity.activity || []);
        }
    }, 30);
}

// --- Users Tab ---
function renderUEBAUsersTab(container) {
    const users = uebaData.user_entities || [];
    let html = '';

    if (!users.length) {
        html = '<div class="text-center text-muted py-5"><i class="bi bi-person-x" style="font-size:2rem"></i><p class="mt-2">No user-level entity data found. User entities are tracked via <code>data.srcuser</code> fields in Wazuh alerts.</p></div>';
        container.innerHTML = html;
        return;
    }

    html += `<div class="ueba-ranking-tabs">
        <span class="ueba-rank-tab active">User Risk Rankings</span>
        <div style="flex:1"></div>
        <input type="text" class="filter-input" id="ueba-user-search" placeholder="Search users..." oninput="filterUEBAUserTable()" style="width:220px">
    </div>`;

    html += `<div class="table-responsive"><table class="soc-table" id="ueba-user-table"><thead><tr>
        <th style="width:50px">Risk</th><th>User</th><th>Hosts</th><th>Risk Level</th><th>Alerts</th><th>Anomalies</th><th>MITRE</th><th>Activity</th>
    </tr></thead><tbody>`;

    for (const user of users) {
        const riskColor = _uebaRiskColor(user.risk_score);
        const riskBg = _uebaRiskBg(user.risk_score);
        const sparkId = 'uspark-' + user.name.replace(/[^a-zA-Z0-9]/g, '_');

        let hostBadges = (user.hosts || []).slice(0, 3).map(h => `<code class="ueba-indicator">${escHtml(h)}</code>`).join(' ');
        if ((user.hosts || []).length > 3) hostBadges += ` <span class="text-muted">+${user.hosts.length - 3}</span>`;

        let anomBadges = '';
        for (const a of (user.anomalies || []).slice(0, 2)) {
            const aColor = a.severity === 'Critical' ? '#ff1744' : a.severity === 'High' ? '#ff6d00' : '#ffc107';
            anomBadges += `<span class="ueba-anom-badge" style="color:${aColor};border-color:${aColor}" title="${escHtml(a.description)}">${escHtml(a.type)}</span> `;
        }
        if ((user.anomalies || []).length > 2) anomBadges += `<span class="text-muted">+${user.anomalies.length - 2}</span>`;
        if (!user.anomalies?.length) anomBadges = '<span class="text-muted">None</span>';

        let mitreTags = (user.mitre || []).slice(0, 3).map(m => `<span class="mitre-tag">${escHtml(m)}</span>`).join(' ');
        if ((user.mitre || []).length > 3) mitreTags += ` <span class="text-muted">+${user.mitre.length - 3}</span>`;

        html += `<tr class="ueba-entity-row" data-entity="${escHtml(user.name)}" onclick="showUEBAUserDetail('${escHtml(user.name)}')" style="cursor:pointer">
            <td><div class="ueba-risk-gauge" style="background:${riskBg};color:${riskColor}">${user.risk_score}</div></td>
            <td><div class="d-flex align-items-center gap-2"><i class="bi bi-person-fill" style="color:${riskColor};font-size:1.1rem"></i><strong>${escHtml(user.name)}</strong></div></td>
            <td>${hostBadges || '<span class="text-muted">-</span>'}</td>
            <td><span class="sev-badge sev-${user.risk_level.toLowerCase()}">${user.risk_level}</span></td>
            <td>${user.total_alerts}</td>
            <td>${anomBadges}</td>
            <td>${mitreTags || '<span class="text-muted">-</span>'}</td>
            <td><canvas id="${sparkId}" width="120" height="30"></canvas></td>
        </tr>`;
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;

    setTimeout(() => {
        for (const user of users) {
            const sparkId = 'uspark-' + user.name.replace(/[^a-zA-Z0-9]/g, '_');
            renderUEBASparkline(sparkId, user.activity || []);
        }
    }, 30);
}

// --- Correlations Tab ---
function renderUEBACorrelationsTab(container) {
    const correlations = uebaData.correlations || [];
    let html = '';

    if (!correlations.length) {
        html = '<div class="text-center text-muted py-5"><i class="bi bi-diagram-3" style="font-size:2rem"></i><p class="mt-2">No cross-entity correlations detected. Correlations are identified when a single source IP triggers alerts on 2+ different hosts.</p></div>';
        container.innerHTML = html;
        return;
    }

    html += `<div class="ueba-ranking-tabs"><span class="ueba-rank-tab active">Source IPs Targeting Multiple Hosts</span></div>`;

    html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
        <th>Severity</th><th>Source IP</th><th>Targets</th><th>Target Hosts</th><th>Users</th><th>Alerts</th><th>Top Activity</th><th>MITRE</th>
    </tr></thead><tbody>`;

    for (const c of correlations) {
        const sevColor = c.severity === 'Critical' ? '#ff1744' : c.severity === 'High' ? '#ff6d00' : '#ffc107';
        const targetBadges = c.targets.slice(0, 4).map(t => `<code class="ueba-indicator" style="cursor:pointer" onclick="event.stopPropagation();showUEBAEntityDetail('${escHtml(t)}')">${escHtml(t)}</code>`).join(' ');
        const extraTargets = c.targets.length > 4 ? ` <span class="text-muted">+${c.targets.length - 4}</span>` : '';
        const userBadges = (c.users || []).slice(0, 3).map(u => `<code class="ueba-indicator">${escHtml(u)}</code>`).join(' ');
        const ruleBadges = (c.top_rules || []).slice(0, 2).map(r => `<span class="text-muted" style="font-size:0.75rem">${escHtml(r)}</span>`).join('<br>');
        const mitreTags = (c.mitre || []).slice(0, 3).map(m => `<span class="mitre-tag">${escHtml(m)}</span>`).join(' ');

        html += `<tr class="ueba-entity-row" style="cursor:pointer" onclick="showUEBACorrelationDetail('${escHtml(c.source_ip)}')">
            <td><span class="sev-badge sev-${c.severity.toLowerCase()}">${c.severity}</span></td>
            <td><strong style="color:${sevColor}"><i class="bi bi-globe me-1"></i>${escHtml(c.source_ip)}</strong></td>
            <td><span class="ueba-risk-gauge-sm" style="color:${sevColor}">${c.target_count}</span></td>
            <td>${targetBadges}${extraTargets}</td>
            <td>${userBadges || '<span class="text-muted">-</span>'}</td>
            <td>${c.total_alerts}</td>
            <td>${ruleBadges || '-'}</td>
            <td>${mitreTags || '<span class="text-muted">-</span>'}</td>
        </tr>`;
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// --- Top Anomalies Tab ---
function renderUEBAAnomaliesTab(container) {
    let anomalies = uebaData.top_anomalies || [];
    if (uebaAnomalyFilter) {
        anomalies = anomalies.filter(a => a.type === uebaAnomalyFilter);
    }

    let html = `<div class="ueba-ranking-tabs">
        <span class="ueba-rank-tab active">Top Detected Anomalies</span>
        <div style="flex:1"></div>`;
    if (uebaAnomalyFilter) {
        html += `<span class="ueba-filter-active" onclick="uebaAnomalyFilter=null;renderUEBAMainSection();updateDonutFilterBadge()">
            <i class="bi bi-funnel-fill"></i> ${escHtml(uebaAnomalyFilter)} <i class="bi bi-x-lg ms-1"></i>
        </span>`;
    }
    html += `</div>`;

    if (!anomalies.length) {
        html += '<div class="text-center text-muted py-4">No anomalies match the current filter</div>';
        container.innerHTML = html;
        return;
    }

    html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
        <th>Severity</th><th>Anomaly Type</th><th>Entity</th><th>Entity Type</th><th>Risk Score</th><th>Description</th><th>Indicators</th>
    </tr></thead><tbody>`;

    for (const a of anomalies) {
        const isUser = a.entity_type === 'User';
        const isMl = a.source === 'ml';
        const clickFn = isMl ? '' : (isUser ? `showUEBAUserDetail('${escHtml(a.entity)}')` : `showUEBAEntityDetail('${escHtml(a.entity)}')`);
        const mlBadge = isMl ? `<span class="ueba-ml-badge" title="Detected by RCF ML Engine"><i class="bi bi-cpu"></i> ML</span>` : '';
        const gradeCol = isMl ? `<td><span class="ueba-ml-grade" style="color:${a.anomaly_grade>=0.8?'#ff1744':a.anomaly_grade>=0.5?'#ff6d00':'#ffc107'}">${(a.anomaly_grade*100).toFixed(0)}%</span></td>` : `<td><div class="ueba-risk-gauge-sm" style="color:${_uebaRiskColor(a.risk_score)}">${a.risk_score}</div></td>`;

        html += `<tr class="ueba-entity-row" style="cursor:pointer" onclick="${clickFn}">
            <td><span class="sev-badge sev-${(a.severity||'').toLowerCase()}">${a.severity}</span></td>
            <td><strong>${escHtml(a.type)}</strong> ${mlBadge}</td>
            <td><span class="d-flex align-items-center gap-1"><i class="bi bi-box-arrow-up-right" style="font-size:0.7rem"></i>${escHtml(a.entity)}</span></td>
            <td><span class="ueba-type-badge">${a.entity_type}</span></td>
            ${gradeCol}
            <td>${escHtml(a.description)}</td>
            <td>${(a.indicators||[]).slice(0,3).map(i => `<code class="ueba-indicator">${escHtml(i)}</code>`).join(' ')}</td>
        </tr>`;
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// --- ML Anomalies Tab (RCF Detector Results) ---
function renderUEBAMLAnomaliesTab(container) {
    const mlAnomalies = uebaData.ml_anomalies || [];
    const mlSummary = uebaData.ml_summary || {};

    let html = '';

    // Detector status panel
    html += `<div class="ueba-ranking-tabs">
        <span class="ueba-rank-tab active"><i class="bi bi-cpu"></i> RCF ML Anomaly Detection Engine</span>
        <div style="flex:1"></div>
        <button class="btn btn-sm btn-outline-success" onclick="loadRCFDetectorPanel()"><i class="bi bi-gear"></i> Manage Detectors</button>
    </div>`;

    // Summary row — dynamically built from detector data returned by backend
    const byDet = mlSummary.by_detector || {};
    const detNames = Object.keys(byDet);
    // Also include any detectors from mlAnomalies not in byDet
    for (const a of mlAnomalies) {
        if (a.detector_name && !detNames.includes(a.detector_name)) detNames.push(a.detector_name);
    }
    const _detColorPalette = ['#ff1744','#ff6d00','#2196f3','#9c27b0','#00bcd4','#4caf50','#ff5722','#3f51b5'];
    // Build detector info from ML anomalies metadata (labels, icons come from backend)
    const _detMeta = {};
    for (const a of mlAnomalies) {
        if (a.detector_name && !_detMeta[a.detector_name]) {
            _detMeta[a.detector_name] = { label: a.detector_label || a.detector_name, icon: a.detector_icon || 'cpu' };
        }
    }
    const colClass = detNames.length <= 4 ? 'col-md-3' : detNames.length <= 6 ? 'col-md-2' : 'col-lg-2 col-md-3';
    html += `<div class="row g-2 mb-3">`;
    detNames.forEach((dname, idx) => {
        const cnt = byDet[dname] || 0;
        const meta = _detMeta[dname] || {};
        const label = meta.label || dname.replace(/-/g,' ').replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
        const icon = meta.icon || 'cpu';
        const color = _detColorPalette[idx % _detColorPalette.length];
        html += `<div class="${colClass}"><div class="soc-card p-3 text-center">
            <div style="color:${color};font-size:1.5rem"><i class="bi bi-${icon}"></i></div>
            <div style="font-size:1.3rem;font-weight:700">${cnt}</div>
            <div style="font-size:.75rem;color:#aaa">${escHtml(label)}</div>
        </div></div>`;
    });
    if (!detNames.length) {
        html += `<div class="col-12"><div class="soc-card p-3 text-center text-muted">
            <i class="bi bi-cpu"></i> No detectors discovered. Create detectors in OpenSearch and they will auto-appear here.
        </div></div>`;
    }
    html += `</div>`;

    if (!mlAnomalies.length) {
        html += `<div class="soc-card p-4 text-center">
            <div style="font-size:2rem;color:#ffc107"><i class="bi bi-cpu"></i></div>
            <p class="mt-2 text-muted">No ML anomalies detected in the selected timerange.</p>
            <p class="text-muted" style="font-size:.85rem">The RCF detectors may need to be started. Click "Manage Detectors" above to check their status and start them.</p>
            <p class="text-muted" style="font-size:.85rem">Once started, detectors need ~30 minutes to build their baseline models before detecting anomalies.</p>
        </div>`;
        html += `<div id="rcf-detector-panel"></div>`;
        container.innerHTML = html;
        return;
    }

    // ML Anomalies table
    html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
        <th>Grade</th><th>Confidence</th><th>Detector</th><th>Entity</th><th>Severity</th>
        <th>Time Window</th><th>Feature Value</th><th>Correlated Alerts</th>
    </tr></thead><tbody>`;

    for (const a of mlAnomalies) {
        const gradeColor = a.anomaly_grade >= 0.8 ? '#ff1744' : a.anomaly_grade >= 0.5 ? '#ff6d00' : '#ffc107';
        const confPct = (a.confidence * 100).toFixed(0);
        const startStr = a.start_time ? new Date(a.start_time).toLocaleString() : '';
        const endStr = a.end_time ? new Date(a.end_time).toLocaleString() : '';
        const fvals = Object.entries(a.feature_values || {}).map(([k,v]) => `${k}: ${typeof v==='number'?v.toFixed(1):v}`).join(', ') || '-';
        const expected = a.expected_values?.expected;
        const fvDisplay = expected !== undefined ? `${fvals} (expected: ${typeof expected==='number'?expected.toFixed(1):expected})` : fvals;
        const corrAlerts = (a.correlated_alerts || []);
        const corrHtml = corrAlerts.length ? corrAlerts.slice(0,3).map(ca =>
            `<div style="font-size:.75rem;margin-bottom:2px"><span class="sev-badge sev-${_levelToSev(ca.level)}" style="font-size:.6rem">${ca.level}</span> ${escHtml(ca.description||'')}</div>`
        ).join('') : '<span class="text-muted" style="font-size:.75rem">No alerts in window</span>';

        html += `<tr class="ueba-entity-row" style="cursor:pointer" onclick="showUEBAEntityDetail('${escHtml(a.entity)}')">
            <td><span class="ueba-ml-grade" style="color:${gradeColor};font-size:1.1rem;font-weight:700">${(a.anomaly_grade*100).toFixed(0)}%</span></td>
            <td><span style="color:#aaa">${confPct}%</span></td>
            <td><i class="bi bi-${a.detector_icon||'cpu'}"></i> ${escHtml(a.detector_label||'')}</td>
            <td><strong>${escHtml(a.entity)}</strong></td>
            <td><span class="sev-badge sev-${(a.severity||'').toLowerCase()}">${a.severity}</span></td>
            <td style="font-size:.75rem">${startStr}<br>→ ${endStr}</td>
            <td style="font-size:.75rem">${escHtml(fvDisplay)}</td>
            <td>${corrHtml}</td>
        </tr>`;
    }

    html += '</tbody></table></div>';
    html += `<div id="rcf-detector-panel"></div>`;
    container.innerHTML = html;
}

function _levelToSev(level) {
    if (level >= 12) return 'critical';
    if (level >= 10) return 'high';
    if (level >= 7) return 'medium';
    return 'low';
}

async function loadRCFDetectorPanel() {
    const panel = document.getElementById('rcf-detector-panel');
    if (!panel) return;
    panel.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-warning"></div> Loading detector status...</div>';
    try {
        const data = await api('/api/ueba/rcf/detectors');
        const dets = data.detectors || [];
        let html = `<div class="soc-card mt-3"><div class="soc-card-title d-flex align-items-center"><i class="bi bi-gear"></i> RCF Anomaly Detector Status <span class="ms-2 badge bg-secondary">${dets.length} detector${dets.length!==1?'s':''} discovered</span>
            <div class="ms-auto"><button class="btn btn-sm btn-outline-info" onclick="rcfRefreshDetectors()" title="Re-scan for new/removed detectors"><i class="bi bi-arrow-repeat"></i> Re-scan Detectors</button></div>
        </div>`;
        html += `<p style="font-size:.78rem;color:#8b949e;margin:8px 0 12px">Detectors are auto-discovered from OpenSearch. Any new detector you create in Wazuh will appear here automatically within 5 minutes (or click Re-scan).</p>`;
        html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
            <th>Detector</th><th>Category</th><th>Type</th><th>Interval</th><th>State</th><th>Entities</th><th>Actions</th>
        </tr></thead><tbody>`;
        for (const d of dets) {
            const stateColor = d.state === 'RUNNING' ? '#00e676' : d.state === 'DISABLED' ? '#ff9800' : d.state === 'INIT' ? '#2196f3' : '#f44336';
            const stateBadge = `<span style="color:${stateColor};font-weight:600">${d.state}</span>`;
            const canStart = d.state === 'DISABLED' || d.state === 'ERROR' || d.state === 'UNKNOWN';
            const canStop = d.state === 'RUNNING' || d.state === 'INIT';
            const startBtn = canStart ? `<button class="btn btn-sm btn-outline-success me-1" onclick="rcfDetectorAction('${d.id}','start')"><i class="bi bi-play-fill"></i> Start</button>` : '';
            const stopBtn = canStop ? `<button class="btn btn-sm btn-outline-danger" onclick="rcfDetectorAction('${d.id}','stop')"><i class="bi bi-stop-fill"></i> Stop</button>` : '';
            const detType = d.detector_type === 'MULTI_ENTITY' ? '<span class="badge bg-info" style="font-size:.65rem">Multi-Entity</span>' : '<span class="badge bg-secondary" style="font-size:.65rem">Single</span>';
            html += `<tr>
                <td><i class="bi bi-${d.icon}"></i> <strong>${escHtml(d.label)}</strong>${d.description ? '<div style="font-size:.7rem;color:#8b949e">'+escHtml(d.description)+'</div>':''}</td>
                <td>${escHtml(d.category)}</td>
                <td>${detType}</td>
                <td style="font-size:.8rem">${escHtml(d.interval||'')}</td>
                <td>${stateBadge}</td>
                <td>${d.total_entities || 0}</td>
                <td>${startBtn}${stopBtn}</td>
            </tr>`;
        }
        if (!dets.length) {
            html += `<tr><td colspan="7" class="text-center text-muted py-3">No detectors found targeting wazuh-alerts-*. Create anomaly detectors in OpenSearch and they will auto-appear here.</td></tr>`;
        }
        html += '</tbody></table></div></div>';
        panel.innerHTML = html;
    } catch (e) {
        panel.innerHTML = `<div class="text-danger py-2">Error loading detectors: ${e.message}</div>`;
    }
}

async function rcfRefreshDetectors() {
    try {
        await api('/api/ueba/rcf/detectors/refresh', { method: 'POST' });
        loadRCFDetectorPanel();
    } catch (e) {
        alert('Error refreshing: ' + e.message);
    }
}

async function rcfDetectorAction(detectorId, action) {
    try {
        await api(`/api/ueba/rcf/detectors/${detectorId}/${action}`, { method: 'POST' });
        loadRCFDetectorPanel();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// --- Grouped view: by Entity Type ---
function renderUEBAGroupedByType(entities) {
    const groups = {};
    for (const e of entities) {
        const t = e.entity_type || 'Unknown';
        if (!groups[t]) groups[t] = [];
        groups[t].push(e);
    }

    let html = '';
    for (const [type, members] of Object.entries(groups)) {
        const avgRisk = Math.round(members.reduce((s, e) => s + e.risk_score, 0) / members.length);
        html += `<div class="ueba-group-header">
            <span class="ueba-type-badge" style="font-size:0.8rem">${escHtml(type)}</span>
            <span class="text-muted ms-2">${members.length} entities</span>
            <span class="ms-2" style="color:${_uebaRiskColor(avgRisk)}">Avg Risk: ${avgRisk}</span>
        </div>`;
        html += _renderEntityTable(members, 'host');
    }
    return html;
}

// --- Grouped view: by Risk Level ---
function renderUEBAGroupedByRiskLevel(entities) {
    const levels = ['Critical', 'High', 'Medium', 'Low'];
    const levelColors = { Critical: '#ff1744', High: '#ff6d00', Medium: '#ffc107', Low: '#4caf50' };
    let html = '';

    for (const level of levels) {
        const members = entities.filter(e => e.risk_level === level);
        if (!members.length) continue;
        html += `<div class="ueba-group-header">
            <span class="sev-badge sev-${level.toLowerCase()}" style="font-size:0.8rem">${level} Risk</span>
            <span class="text-muted ms-2">${members.length} entities</span>
        </div>`;
        html += _renderEntityTable(members, 'host');
    }
    if (!html) html = '<div class="text-center text-muted py-4">No entities found</div>';
    return html;
}

// --- MITRE ATT&CK Heatmap ---
function renderUEBAMitreHeatmap(entities) {
    const mitreCounts = {};
    const mitreEntities = {};
    for (const e of entities) {
        for (const m of (e.mitre || [])) {
            mitreCounts[m] = (mitreCounts[m] || 0) + 1;
            if (!mitreEntities[m]) mitreEntities[m] = [];
            mitreEntities[m].push(e.name);
        }
    }

    const sorted = Object.entries(mitreCounts).sort((a, b) => b[1] - a[1]);
    if (!sorted.length) {
        return '<div class="text-center text-muted py-4"><i class="bi bi-shield-x" style="font-size:2rem"></i><p class="mt-2">No MITRE ATT&CK techniques detected in the selected time range</p></div>';
    }

    const maxCount = sorted[0][1];
    let html = '<div class="ueba-mitre-grid">';
    for (const [technique, count] of sorted) {
        const intensity = Math.max(0.2, count / maxCount);
        const entList = (mitreEntities[technique] || []).slice(0, 5);
        html += `<div class="ueba-mitre-cell" style="background:rgba(156,39,176,${intensity})" title="${entList.join(', ')}" onclick="showUEBAMitreDetail('${escHtml(technique)}')">
            <div class="ueba-mitre-id">${escHtml(technique)}</div>
            <div class="ueba-mitre-count">${count} ${count === 1 ? 'entity' : 'entities'}</div>
        </div>`;
    }
    html += '</div>';

    // Also show as a table
    html += `<div class="table-responsive mt-3"><table class="soc-table"><thead><tr>
        <th>MITRE Technique</th><th>Entity Count</th><th>Affected Entities</th>
    </tr></thead><tbody>`;
    for (const [technique, count] of sorted) {
        const entList = (mitreEntities[technique] || []).slice(0, 5);
        const entBadges = entList.map(e => `<code class="ueba-indicator" style="cursor:pointer" onclick="event.stopPropagation();showUEBAEntityDetail('${escHtml(e)}')">${escHtml(e)}</code>`).join(' ');
        const extra = (mitreEntities[technique] || []).length > 5 ? ` <span class="text-muted">+${mitreEntities[technique].length - 5}</span>` : '';
        html += `<tr><td><span class="mitre-tag" style="font-size:0.8rem">${escHtml(technique)}</span></td><td>${count}</td><td>${entBadges}${extra}</td></tr>`;
    }
    html += '</tbody></table></div>';

    return html;
}

// --- Shared entity table renderer ---
function _renderEntityTable(entities, type) {
    let html = `<div class="table-responsive"><table class="soc-table ueba-entity-tbl"><thead><tr>
        <th style="width:50px">Risk</th><th>Entity</th><th>Type</th><th>Risk Level</th><th>Alerts</th><th>Anomalies</th><th>ML</th><th>MITRE ATT&CK</th><th>Activity</th>
    </tr></thead><tbody>`;

    for (const entity of entities) {
        const riskColor = _uebaRiskColor(entity.risk_score);
        const riskBg = _uebaRiskBg(entity.risk_score);
        const sparkId = 'spark-' + entity.name.replace(/[^a-zA-Z0-9]/g, '_');
        const clickFn = type === 'user' ? `showUEBAUserDetail('${escHtml(entity.name)}')` : `showUEBAEntityDetail('${escHtml(entity.name)}')`;

        let mitreTags = (entity.mitre || []).slice(0, 3).map(m => `<span class="mitre-tag">${escHtml(m)}</span>`).join(' ');
        if ((entity.mitre || []).length > 3) mitreTags += ` <span class="text-muted">+${entity.mitre.length - 3}</span>`;

        let anomBadges = '';
        for (const a of (entity.anomalies || []).slice(0, 2)) {
            const aColor = a.severity === 'Critical' ? '#ff1744' : a.severity === 'High' ? '#ff6d00' : '#ffc107';
            anomBadges += `<span class="ueba-anom-badge" style="color:${aColor};border-color:${aColor}" title="${escHtml(a.description)}">${escHtml(a.type)}</span> `;
        }
        if ((entity.anomalies || []).length > 2) anomBadges += `<span class="text-muted">+${entity.anomalies.length - 2}</span>`;
        if (!entity.anomalies?.length) anomBadges = '<span class="text-muted">None</span>';

        // ML anomaly indicator
        let mlCol = '<span class="text-muted">-</span>';
        if (entity.ml_anomaly_count > 0) {
            const mlGrade = entity.ml_max_grade || 0;
            const mlColor = mlGrade >= 0.8 ? '#ff1744' : mlGrade >= 0.5 ? '#ff6d00' : '#ffc107';
            mlCol = `<span class="ueba-ml-badge" style="color:${mlColor}" title="${entity.ml_top_detector||'RCF'} — Grade: ${(mlGrade*100).toFixed(0)}%"><i class="bi bi-cpu"></i> ${entity.ml_anomaly_count} <small>(${(mlGrade*100).toFixed(0)}%)</small></span>`;
        }

        html += `<tr class="ueba-entity-row" data-entity="${escHtml(entity.name)}" onclick="${clickFn}" style="cursor:pointer">
            <td><div class="ueba-risk-gauge" style="background:${riskBg};color:${riskColor}">${entity.risk_score}</div></td>
            <td><div class="d-flex align-items-center gap-2"><i class="bi bi-${entity.type_icon || 'server'}" style="color:${riskColor};font-size:1.1rem"></i><strong>${escHtml(entity.name)}</strong></div></td>
            <td><span class="ueba-type-badge">${entity.entity_type}</span></td>
            <td><span class="sev-badge sev-${entity.risk_level.toLowerCase()}">${entity.risk_level}</span></td>
            <td>${entity.total_alerts}</td>
            <td>${anomBadges}</td>
            <td>${mlCol}</td>
            <td>${mitreTags || '<span class="text-muted">-</span>'}</td>
            <td><canvas id="${sparkId}" width="120" height="30"></canvas></td>
        </tr>`;
    }

    if (!entities.length) {
        html += `<tr><td colspan="9" class="text-center text-muted py-4">No entities match the current filter</td></tr>`;
    }

    html += '</tbody></table></div>';
    return html;
}

// --- Charts ---
function renderUEBARiskTrend(trend) {
    destroyChart('ueba-risk-trend');
    const canvas = document.getElementById('ueba-risk-trend-chart');
    if (!canvas || !trend.length) return;

    const labels = trend.map(t => {
        const d = new Date(t.time);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });

    chartInstances['ueba-risk-trend'] = new Chart(canvas, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Total Alerts',
                    data: trend.map(t => t.total),
                    borderColor: '#2196f3',
                    backgroundColor: 'rgba(33,150,243,0.1)',
                    fill: true,
                    tension: 0.3,
                },
                {
                    label: 'High Severity',
                    data: trend.map(t => t.high_severity),
                    borderColor: '#ff1744',
                    backgroundColor: 'rgba(255,23,68,0.1)',
                    fill: true,
                    tension: 0.3,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (evt, elements) => {
                if (elements.length) {
                    const idx = elements[0].index;
                    const dateLabel = labels[idx];
                    showToast(`Trend point: ${dateLabel} — ${trend[idx].total} alerts, ${trend[idx].high_severity} high severity`, 'info');
                }
            },
            plugins: { legend: { labels: { color: '#aaa', font: { size: 11 } } } },
            scales: {
                x: { ticks: { color: '#888', maxTicksLimit: 10 }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#888' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
            },
        },
    });
}

function renderUEBAAnomalyDonut(anomalyTypes) {
    destroyChart('ueba-anomaly-donut');
    const canvas = document.getElementById('ueba-anomaly-donut');
    if (!canvas) return;

    const labels = Object.keys(anomalyTypes);
    const values = Object.values(anomalyTypes);
    const colors = ['#ff1744', '#ff6d00', '#ffc107', '#9c27b0', '#2196f3', '#4caf50', '#00bcd4'];

    if (!labels.length) {
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#666';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No anomalies detected', canvas.width / 2, canvas.height / 2);
        return;
    }

    chartInstances['ueba-anomaly-donut'] = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{ data: values, backgroundColor: colors.slice(0, labels.length), borderWidth: 0 }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (evt, elements) => {
                if (elements.length) {
                    const idx = elements[0].index;
                    const clickedType = labels[idx];
                    if (uebaAnomalyFilter === clickedType) {
                        uebaAnomalyFilter = null;
                    } else {
                        uebaAnomalyFilter = clickedType;
                    }
                    updateDonutFilterBadge();
                    renderUEBAMainSection();
                }
            },
            plugins: {
                legend: { position: 'right', labels: { color: '#ccc', font: { size: 11 }, padding: 12 } },
            },
            cutout: '55%',
        },
    });
    updateDonutFilterBadge();
}

function updateDonutFilterBadge() {
    const badge = document.getElementById('ueba-donut-filter-badge');
    if (!badge) return;
    if (uebaAnomalyFilter) {
        badge.innerHTML = `<span class="ueba-filter-active" onclick="event.stopPropagation();uebaAnomalyFilter=null;updateDonutFilterBadge();renderUEBAMainSection()">
            <i class="bi bi-funnel-fill"></i> ${escHtml(uebaAnomalyFilter)} <i class="bi bi-x-lg ms-1"></i></span>`;
    } else {
        badge.innerHTML = '';
    }
}

function renderUEBASparkline(canvasId, activity) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !activity.length) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const values = activity.map(a => a.count);
    const max = Math.max(...values, 1);

    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = '#2196f3';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    for (let i = 0; i < values.length; i++) {
        const x = (i / (values.length - 1 || 1)) * w;
        const y = h - (values[i] / max) * (h - 4) - 2;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();
}

// --- Filters ---
function filterUEBATable() {
    const search = (document.getElementById('ueba-entity-search')?.value || '').toLowerCase();
    document.querySelectorAll('.ueba-entity-tbl tbody tr').forEach(row => {
        const name = (row.dataset.entity || '').toLowerCase();
        row.style.display = name.includes(search) ? '' : 'none';
    });
}

function filterUEBAUserTable() {
    const search = (document.getElementById('ueba-user-search')?.value || '').toLowerCase();
    document.querySelectorAll('#ueba-user-table tbody tr').forEach(row => {
        const name = (row.dataset.entity || '').toLowerCase();
        row.style.display = name.includes(search) ? '' : 'none';
    });
}

// --- Detail Modals ---

async function showUEBAEntityDetail(entityName) {
    const modal = new bootstrap.Modal(document.getElementById('agentDetailModal'));
    document.getElementById('agent-detail-title').innerHTML = `<i class="bi bi-person-bounding-box me-2"></i>UEBA Entity: ${escHtml(entityName)}`;
    const body = document.getElementById('agent-detail-body');
    body.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-warning"></div></div>';
    modal.show();

    const entity = (uebaData?.entities || []).find(e => e.name === entityName);
    if (!entity) {
        body.innerHTML = '<div class="text-center text-muted py-4">Entity not found</div>';
        return;
    }

    const trSel = document.getElementById('ueba-timerange');
    const timerange = trSel ? trSel.value : '7d';
    let detailData = { alerts: [] };
    try {
        detailData = await api(`/api/ueba/entity/${encodeURIComponent(entityName)}?timerange=${timerange}`);
    } catch (e) { /* use empty */ }

    body.innerHTML = _buildEntityDetailHTML(entity, detailData);
}

async function showUEBAUserDetail(userName) {
    const modal = new bootstrap.Modal(document.getElementById('agentDetailModal'));
    document.getElementById('agent-detail-title').innerHTML = `<i class="bi bi-person-fill me-2"></i>UEBA User: ${escHtml(userName)}`;
    const body = document.getElementById('agent-detail-body');
    body.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-warning"></div></div>';
    modal.show();

    const entity = (uebaData?.user_entities || []).find(e => e.name === userName);
    if (!entity) {
        body.innerHTML = '<div class="text-center text-muted py-4">User entity not found</div>';
        return;
    }

    const trSel = document.getElementById('ueba-timerange');
    const timerange = trSel ? trSel.value : '7d';
    let detailData = { alerts: [] };
    try {
        detailData = await api(`/api/ueba/user/${encodeURIComponent(userName)}?timerange=${timerange}`);
    } catch (e) { /* use empty */ }

    let html = _buildEntityDetailHTML(entity, detailData);

    // Add user-specific section: hosts accessed
    if (entity.hosts?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-hdd-stack me-1"></i> Hosts Accessed (${entity.hosts.length})</h6>`;
        html += `<div class="d-flex gap-2 flex-wrap mb-3">`;
        for (const host of entity.hosts) {
            html += `<code class="ueba-indicator" style="cursor:pointer" onclick="bootstrap.Modal.getInstance(document.getElementById('agentDetailModal')).hide();setTimeout(()=>showUEBAEntityDetail('${escHtml(host)}'),300)">${escHtml(host)}</code>`;
        }
        html += `</div>`;
    }

    body.innerHTML = html;
}

async function showUEBACorrelationDetail(sourceIp) {
    const modal = new bootstrap.Modal(document.getElementById('agentDetailModal'));
    document.getElementById('agent-detail-title').innerHTML = `<i class="bi bi-diagram-3 me-2"></i>Cross-Entity Correlation: ${escHtml(sourceIp)}`;
    const body = document.getElementById('agent-detail-body');
    body.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-warning"></div></div>';
    modal.show();

    const corr = (uebaData?.correlations || []).find(c => c.source_ip === sourceIp);
    const trSel = document.getElementById('ueba-timerange');
    const timerange = trSel ? trSel.value : '7d';
    let detailData = { alerts: [] };
    try {
        detailData = await api(`/api/ueba/correlation/${encodeURIComponent(sourceIp)}?timerange=${timerange}`);
    } catch (e) { /* use empty */ }

    let html = '';

    // Header
    const sevColor = corr ? (corr.severity === 'Critical' ? '#ff1744' : corr.severity === 'High' ? '#ff6d00' : '#ffc107') : '#ff6d00';
    html += `<div class="ueba-detail-header">
        <div class="ueba-detail-risk-circle" style="border-color:${sevColor};color:${sevColor}">
            <div class="ueba-risk-number">${corr ? corr.target_count : '?'}</div>
            <div class="ueba-risk-label">TARGETS</div>
        </div>
        <div class="ueba-detail-info">
            <h4><i class="bi bi-globe me-2"></i>${escHtml(sourceIp)}</h4>
            <div class="d-flex gap-3 mb-2">
                ${corr ? `<span class="sev-badge sev-${corr.severity.toLowerCase()}">${corr.severity}</span>` : ''}
                <span class="text-muted">${corr ? corr.total_alerts : '?'} total alerts</span>
            </div>
            <div class="d-flex gap-2 flex-wrap">
                ${(corr?.mitre || []).map(m => `<span class="mitre-tag">${escHtml(m)}</span>`).join('')}
            </div>
        </div>
    </div>`;

    // Target hosts
    if (corr?.targets?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-hdd-stack me-1"></i> Targeted Hosts (${corr.targets.length})</h6>`;
        html += `<div class="d-flex gap-2 flex-wrap mb-3">`;
        for (const host of corr.targets) {
            html += `<code class="ueba-indicator" style="cursor:pointer" onclick="bootstrap.Modal.getInstance(document.getElementById('agentDetailModal')).hide();setTimeout(()=>showUEBAEntityDetail('${escHtml(host)}'),300)">${escHtml(host)}</code>`;
        }
        html += `</div>`;
    }

    // Users involved
    if (corr?.users?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-people me-1"></i> Users Involved</h6>`;
        html += `<div class="d-flex gap-2 flex-wrap mb-3">`;
        for (const u of corr.users) {
            html += `<code class="ueba-indicator">${escHtml(u)}</code>`;
        }
        html += `</div>`;
    }

    // Recent alerts
    if (detailData.alerts?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-clock-history me-1"></i> Recent Alerts (${detailData.alerts.length})</h6>`;
        html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
            <th>Severity</th><th>Time</th><th>Target Host</th><th>Description</th><th>User</th>
        </tr></thead><tbody>`;
        for (const a of detailData.alerts.slice(0, 25)) {
            const mitre = (a.mitre?.id || []).map(m => `<span class="mitre-tag">${m}</span>`).join(' ');
            html += `<tr>
                <td><span class="sev-badge sev-${(a.severity||'').toLowerCase()}">${a.severity}</span></td>
                <td class="ts-cell">${formatTimestamp(a.timestamp)}</td>
                <td><code>${escHtml(a.target_host || '-')}</code></td>
                <td>${escHtml(a.description)} ${mitre}</td>
                <td>${escHtml(a.src_user || '-')}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;
    }

    body.innerHTML = html;
}

function showUEBAMitreDetail(technique) {
    const entities = (uebaData?.entities || []).filter(e => (e.mitre || []).includes(technique));
    if (!entities.length) { showToast('No entities found for ' + technique, 'info'); return; }

    const modal = new bootstrap.Modal(document.getElementById('agentDetailModal'));
    document.getElementById('agent-detail-title').innerHTML = `<i class="bi bi-shield-lock me-2"></i>MITRE ATT&CK: ${escHtml(technique)}`;
    const body = document.getElementById('agent-detail-body');

    let html = `<div class="mb-3"><span class="mitre-tag" style="font-size:1rem">${escHtml(technique)}</span>
        <span class="text-muted ms-2">${entities.length} affected ${entities.length === 1 ? 'entity' : 'entities'}</span></div>`;

    html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
        <th>Risk</th><th>Entity</th><th>Type</th><th>Risk Level</th><th>Alerts</th>
    </tr></thead><tbody>`;
    for (const e of entities) {
        html += `<tr class="ueba-entity-row" style="cursor:pointer" onclick="bootstrap.Modal.getInstance(document.getElementById('agentDetailModal')).hide();setTimeout(()=>showUEBAEntityDetail('${escHtml(e.name)}'),300)">
            <td><div class="ueba-risk-gauge" style="background:${_uebaRiskBg(e.risk_score)};color:${_uebaRiskColor(e.risk_score)}">${e.risk_score}</div></td>
            <td><strong>${escHtml(e.name)}</strong></td>
            <td><span class="ueba-type-badge">${e.entity_type}</span></td>
            <td><span class="sev-badge sev-${e.risk_level.toLowerCase()}">${e.risk_level}</span></td>
            <td>${e.total_alerts}</td>
        </tr>`;
    }
    html += '</tbody></table></div>';

    body.innerHTML = html;
    modal.show();
}

// --- Shared entity detail HTML builder ---
function _buildEntityDetailHTML(entity, detailData) {
    const riskColor = _uebaRiskColor(entity.risk_score);
    let html = '';

    html += `<div class="ueba-detail-header">
        <div class="ueba-detail-risk-circle" style="border-color:${riskColor};color:${riskColor}">
            <div class="ueba-risk-number">${entity.risk_score}</div>
            <div class="ueba-risk-label">RISK</div>
        </div>
        <div class="ueba-detail-info">
            <h4><i class="bi bi-${entity.type_icon || 'server'} me-2"></i>${escHtml(entity.name)}</h4>
            <div class="d-flex gap-3 mb-2">
                <span class="ueba-type-badge">${entity.entity_type}</span>
                <span class="sev-badge sev-${entity.risk_level.toLowerCase()}">${entity.risk_level} Risk</span>
                <span class="text-muted">${entity.total_alerts} total alerts</span>
            </div>
            <div class="d-flex gap-2 flex-wrap">
                ${(entity.mitre||[]).map(m => `<span class="mitre-tag">${escHtml(m)}</span>`).join('')}
            </div>
        </div>
    </div>`;

    // Severity breakdown
    const sev = entity.severity || {};
    html += `<div class="row g-3 mb-3">
        <div class="col-md-3"><div class="ueba-sev-card" style="border-color:#ff1744"><span class="ueba-sev-val" style="color:#ff1744">${sev.critical||0}</span><span class="ueba-sev-lbl">Critical</span></div></div>
        <div class="col-md-3"><div class="ueba-sev-card" style="border-color:#ff6d00"><span class="ueba-sev-val" style="color:#ff6d00">${sev.high||0}</span><span class="ueba-sev-lbl">High</span></div></div>
        <div class="col-md-3"><div class="ueba-sev-card" style="border-color:#ffc107"><span class="ueba-sev-val" style="color:#ffc107">${sev.medium||0}</span><span class="ueba-sev-lbl">Medium</span></div></div>
        <div class="col-md-3"><div class="ueba-sev-card" style="border-color:#4caf50"><span class="ueba-sev-val" style="color:#4caf50">${sev.low||0}</span><span class="ueba-sev-lbl">Low</span></div></div>
    </div>`;

    // Anomalies
    if (entity.anomalies?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-bug me-1"></i> Anomalies Detected (${entity.anomalies.length})</h6><div class="mb-3">`;
        for (const a of entity.anomalies) {
            const aColor = a.severity === 'Critical' ? '#ff1744' : a.severity === 'High' ? '#ff6d00' : '#ffc107';
            html += `<div class="ueba-anomaly-card" style="border-left:3px solid ${aColor}">
                <div class="d-flex justify-content-between align-items-center mb-1">
                    <strong style="color:${aColor}">${escHtml(a.type)}</strong>
                    <span class="sev-badge sev-${a.severity.toLowerCase()}">${a.severity}</span>
                </div>
                <div class="text-muted mb-1">${escHtml(a.description)}</div>
                <div class="d-flex gap-1 flex-wrap">${(a.indicators||[]).map(i => `<code class="ueba-indicator">${escHtml(i)}</code>`).join('')}</div>
            </div>`;
        }
        html += `</div>`;
    }

    // Top rules
    if (entity.top_rules?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-list-check me-1"></i> Top Behavioral Indicators</h6>`;
        html += `<table class="soc-table mb-3"><thead><tr><th>Rule Description</th><th>Count</th></tr></thead><tbody>`;
        for (const r of entity.top_rules) {
            html += `<tr><td>${escHtml(r.description)}</td><td>${r.count}</td></tr>`;
        }
        html += `</tbody></table>`;
    }

    // Source IPs
    if (entity.src_ips?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-globe me-1"></i> Associated Source IPs</h6>`;
        html += `<div class="d-flex gap-2 flex-wrap mb-3">`;
        for (const ip of entity.src_ips) {
            html += `<code class="ueba-indicator">${escHtml(ip)}</code>`;
        }
        html += `</div>`;
    }

    // Recent alerts
    if (detailData.alerts?.length) {
        html += `<h6 class="mb-2"><i class="bi bi-clock-history me-1"></i> Recent Alerts (${detailData.alerts.length})</h6>`;
        html += `<div class="table-responsive"><table class="soc-table"><thead><tr>
            <th>Severity</th><th>Time</th><th>Description</th><th>Source IP</th><th>User</th>
        </tr></thead><tbody>`;
        for (const a of detailData.alerts.slice(0, 20)) {
            const mitre = (a.mitre?.id || []).map(m => `<span class="mitre-tag">${m}</span>`).join(' ');
            html += `<tr>
                <td><span class="sev-badge sev-${(a.severity||'').toLowerCase()}">${a.severity}</span></td>
                <td class="ts-cell">${formatTimestamp(a.timestamp)}</td>
                <td>${escHtml(a.description)} ${mitre}</td>
                <td><code>${escHtml(a.src_ip || '-')}</code></td>
                <td>${escHtml(a.src_user || '-')}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;
    }

    return html;
}

function escHtml(s) {
    if (!s) return '';
    const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'};
    return String(s).replace(/[&<>"']/g, c => map[c]);
}

function formatTimestamp(ts) {
    if (!ts) return '-';
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleString('en-US', {
            month: 'short', day: '2-digit', hour: '2-digit',
            minute: '2-digit', second: '2-digit', hour12: false,
        });
    } catch { return ts; }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function buildHealthBar(pct) {
    const p = parseFloat(pct);
    if (isNaN(p)) return '';
    const color = p >= 90 ? 'health-red' : p >= 70 ? 'health-yellow' : 'health-green';
    return `<div class="health-bar-container"><div class="health-bar ${color}" style="width:${Math.min(p,100)}%"></div></div>`;
}

function destroyChart(key) {
    if (chartInstances[key]) {
        chartInstances[key].destroy();
        delete chartInstances[key];
    }
}

function getFilterVal(id) {
    const el = document.getElementById(id);
    return el ? el.value : '';
}

// ============================================================
// CASES — Incident Investigation & Case Management (FortiSIEM-style)
// ============================================================
let _casesData = null;
let _activeCaseId = null;
let _casePlaybackTimer = null;
let _casePlaybackIdx = 0;
let _casePlaybackAuto = true;

async function loadCasesOverview() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const trSel = document.getElementById('cases-timerange');
    const timerange = trSel ? trSel.value : '7d';
    const sevFilter = getFilterVal('cases-severity-filter');

    try {
        const data = await api('/api/cases?timerange=' + timerange);
        _casesData = data;
        const summary = data.summary || {};
        let cases = data.cases || [];
        if (sevFilter) cases = cases.filter(c => c.severity === sevFilter);

        let html = '';
        // Summary cards
        html += `<div class="stat-grid">
            <div class="stat-card-v2" onclick="filterCasesBySeverity('')" style="cursor:pointer">
                <div class="stat-icon-circle" style="background:rgba(33,150,243,0.15);color:#2196f3"><i class="bi bi-folder2-open"></i></div>
                <div><div class="stat-value">${summary.total_cases||0}</div><div class="stat-label">Total Cases</div></div>
            </div>
            <div class="stat-card-v2" onclick="filterCasesBySeverity('Critical')" style="cursor:pointer">
                <div class="stat-icon-circle" style="background:rgba(255,23,68,0.15);color:#ff1744"><i class="bi bi-exclamation-octagon-fill"></i></div>
                <div><div class="stat-value">${summary.critical||0}</div><div class="stat-label">Critical</div></div>
            </div>
            <div class="stat-card-v2" onclick="filterCasesBySeverity('High')" style="cursor:pointer">
                <div class="stat-icon-circle" style="background:rgba(255,109,0,0.15);color:#ff6d00"><i class="bi bi-exclamation-triangle-fill"></i></div>
                <div><div class="stat-value">${summary.high||0}</div><div class="stat-label">High</div></div>
            </div>
            <div class="stat-card-v2" onclick="filterCasesBySeverity('Medium')" style="cursor:pointer">
                <div class="stat-icon-circle" style="background:rgba(255,193,7,0.15);color:#ffc107"><i class="bi bi-exclamation-circle-fill"></i></div>
                <div><div class="stat-value">${summary.medium||0}</div><div class="stat-label">Medium</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(156,39,176,0.15);color:#9c27b0"><i class="bi bi-diagram-3-fill"></i></div>
                <div><div class="stat-value">${summary.total_incidents||0}</div><div class="stat-label">Total Incidents</div></div>
            </div>
            <div class="stat-card-v2">
                <div class="stat-icon-circle" style="background:rgba(0,188,212,0.15);color:#00bcd4"><i class="bi bi-lightning-fill"></i></div>
                <div><div class="stat-value">${(summary.total_events||0).toLocaleString()}</div><div class="stat-label">Total Events</div></div>
            </div>
        </div>`;

        // Case cards (top 12)
        html += `<div class="row g-3 mt-2">`;
        for (const c of cases.slice(0, 12)) {
            const sevColor = c.severity==='Critical'?'#ff1744':c.severity==='High'?'#ff6d00':c.severity==='Medium'?'#ffc107':'#4caf50';
            const mitre = c.mitre_tactics.length ? c.mitre_tactics[0] : '';
            const technique = c.mitre_techniques.length ? c.mitre_techniques[0] : '';
            html += `<div class="col-lg-4 col-md-6">
                <div class="soc-card p-3" onclick="openCaseDetail(${c.case_id})" style="cursor:pointer;border-left:3px solid ${sevColor}">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <span class="badge" style="background:${sevColor};font-size:.7rem">${c.severity}</span>
                        <span class="text-muted" style="font-size:.7rem">Case #${c.case_id}</span>
                    </div>
                    <div style="font-weight:600;font-size:.85rem;margin-bottom:6px;line-height:1.3">${escHtml(c.title)}</div>
                    <div style="font-size:.75rem;color:#8b949e">
                        <i class="bi bi-diagram-3"></i> ${c.incident_count} incident${c.incident_count!==1?'s':''} &nbsp;
                        <i class="bi bi-lightning"></i> ${c.total_events.toLocaleString()} events &nbsp;
                        <i class="bi bi-pc-display"></i> ${c.agents.length} agent${c.agents.length!==1?'s':''}
                    </div>
                    ${mitre ? `<div style="font-size:.7rem;margin-top:4px"><span class="mitre-tag">${escHtml(mitre)}</span>${technique?` <span class="mitre-tag">${escHtml(technique)}</span>`:''}</div>` : ''}
                    <div style="font-size:.7rem;color:#6c757d;margin-top:4px">
                        ${c.first_occurred ? new Date(c.first_occurred).toLocaleDateString() : ''} — ${c.last_occurred ? new Date(c.last_occurred).toLocaleDateString() : ''}
                    </div>
                </div>
            </div>`;
        }
        html += `</div>`;

        if (cases.length > 12) {
            html += `<div class="text-center mt-3"><button class="btn btn-sm btn-outline-info" onclick="navigateTo('cases','list')">View all ${cases.length} cases <i class="bi bi-arrow-right"></i></button></div>`;
        }

        content.innerHTML = html;
    } catch (e) {
        content.innerHTML = `<div class="alert alert-danger">Error loading cases: ${escHtml(e.message)}</div>`;
    }
}

async function loadCasesList() {
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const trSel = document.getElementById('cases-timerange');
    const timerange = trSel ? trSel.value : '7d';
    const sevFilter = getFilterVal('cases-severity-filter');

    try {
        const data = await api('/api/cases?timerange=' + timerange);
        _casesData = data;
        let cases = data.cases || [];
        if (sevFilter) cases = cases.filter(c => c.severity === sevFilter);

        let html = `<div class="soc-card mt-2">
            <div class="soc-card-title"><i class="bi bi-folder2-open"></i> All Cases (${cases.length})</div>
            <div class="table-responsive"><table class="soc-table"><thead><tr>
                <th style="width:50px">Sev</th><th>Case ID</th><th>Title</th><th>MITRE</th><th>Incidents</th><th>Events</th><th>Agents</th><th>First Seen</th><th>Last Seen</th><th>Status</th>
            </tr></thead><tbody>`;

        for (const c of cases) {
            const sevColor = c.severity==='Critical'?'#ff1744':c.severity==='High'?'#ff6d00':c.severity==='Medium'?'#ffc107':'#4caf50';
            const mitre = c.mitre_tactics.slice(0, 2).map(t => `<span class="mitre-tag">${escHtml(t)}</span>`).join(' ');
            html += `<tr onclick="openCaseDetail(${c.case_id})" style="cursor:pointer">
                <td><span class="badge" style="background:${sevColor};font-size:.65rem">${c.severity.charAt(0)}</span></td>
                <td style="font-size:.8rem">${c.case_id}</td>
                <td style="font-size:.8rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(c.title)}</td>
                <td>${mitre||'<span class="text-muted">—</span>'}</td>
                <td>${c.incident_count}</td>
                <td>${c.total_events.toLocaleString()}</td>
                <td>${c.agents.length}</td>
                <td style="font-size:.75rem">${c.first_occurred?new Date(c.first_occurred).toLocaleString():''}</td>
                <td style="font-size:.75rem">${c.last_occurred?new Date(c.last_occurred).toLocaleString():''}</td>
                <td><span class="badge bg-success" style="font-size:.65rem">${c.status}</span></td>
            </tr>`;
        }
        html += `</tbody></table></div></div>`;
        content.innerHTML = html;
    } catch (e) {
        content.innerHTML = `<div class="alert alert-danger">Error loading cases: ${escHtml(e.message)}</div>`;
    }
}

function filterCasesBySeverity(sev) {
    const sel = document.getElementById('cases-severity-filter');
    if (sel) sel.value = sev;
    loadCurrentPage();
}

async function openCaseDetail(caseId) {
    _activeCaseId = caseId;
    stopCasePlayback();
    const content = document.getElementById('main-content');
    content.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-warning"></div></div>';

    const trSel = document.getElementById('cases-timerange');
    const timerange = trSel ? trSel.value : '7d';

    try {
        const c = await api(`/api/cases/${caseId}?timerange=${timerange}`);
        _caseGraphData = c;
        const sevColor = c.severity==='Critical'?'#ff1744':c.severity==='High'?'#ff6d00':c.severity==='Medium'?'#ffc107':'#4caf50';

        let html = `<div class="mb-2"><button class="btn btn-sm btn-outline-secondary" onclick="loadCurrentPage()"><i class="bi bi-arrow-left"></i> Back to Cases</button></div>`;
        html += `<div class="case-detail-header" style="border-left:4px solid ${sevColor};padding-left:12px;margin-bottom:16px">
            <h5 style="margin:0;font-size:1rem;color:#e0e0e0">Case ${c.case_id}: ${escHtml(c.title)}</h5>
        </div>`;

        // 3-panel layout
        html += `<div class="row g-3">`;

        // LEFT PANEL — Details
        html += `<div class="col-lg-3 col-md-4">
            <div class="soc-card p-3" id="case-detail-panel">
                <div class="case-detail-section">
                    <div class="case-detail-icon" style="color:${sevColor}"><i class="bi bi-exclamation-triangle-fill"></i></div>
                    <h6 style="color:#e0e0e0;font-size:.85rem">${escHtml(c.title)}</h6>
                </div>
                <div class="case-detail-tabs mb-2">
                    <button class="btn btn-xs btn-outline-info active" onclick="showCaseTab('details',this)"><i class="bi bi-info-circle"></i> Details</button>
                    <button class="btn btn-xs btn-outline-info" onclick="showCaseTab('events',this);loadCaseEventsTab(${c.case_id})"><i class="bi bi-list-task"></i> Events</button>
                    <button class="btn btn-xs btn-outline-info" onclick="showCaseTab('context',this)"><i class="bi bi-diagram-2"></i> Context</button>
                </div>
                <div id="case-tab-details">
                    <table class="case-meta-table">
                        <tr><td class="case-meta-label">Incident ID:</td><td>${c.case_id}</td></tr>
                        <tr><td class="case-meta-label">Rule Name:</td><td>${escHtml(c.title)}</td></tr>
                        <tr><td class="case-meta-label">Rule ID:</td><td>${c.rule_id}</td></tr>
                        <tr><td class="case-meta-label">Severity:</td><td><span class="badge" style="background:${sevColor}">${c.severity}</span></td></tr>
                        <tr><td class="case-meta-label">Tactic:</td><td>${c.mitre_tactics.map(t=>`<span class="mitre-tag">${escHtml(t)}</span>`).join(' ')||'—'}</td></tr>
                        <tr><td class="case-meta-label">Technique:</td><td>${c.mitre_techniques.map(t=>`<span class="mitre-tag">${escHtml(t)}</span>`).join(' ')||'—'}</td></tr>
                        <tr><td class="case-meta-label">MITRE ID:</td><td>${c.mitre_ids.join(', ')||'—'}</td></tr>
                        <tr><td class="case-meta-label" style="color:#4caf50">First Occurred:</td><td>${c.first_occurred?new Date(c.first_occurred).toLocaleString():''}</td></tr>
                        <tr><td class="case-meta-label" style="color:#ff6d00">Last Occurred:</td><td>${c.last_occurred?new Date(c.last_occurred).toLocaleString():''}</td></tr>
                        <tr><td class="case-meta-label">Reporting Agent:</td><td>${c.agents.map(a=>a.name).join(', ')}</td></tr>
                        <tr><td class="case-meta-label">Incident Status:</td><td><span class="badge bg-success">${c.status}</span></td></tr>
                    </table>
                </div>
                <div id="case-tab-events" style="display:none">
                    <div class="text-center py-2"><div class="spinner-border spinner-border-sm text-info"></div> Getting Trigger Events...</div>
                </div>
                <div id="case-tab-context" style="display:none">
                    <p style="font-size:.78rem;color:#8b949e">Rule Groups: ${c.rule_groups.map(g=>`<code>${escHtml(g)}</code>`).join(', ')}</p>
                    <p style="font-size:.78rem;color:#8b949e">Agents Involved: ${c.agents.map(a=>`<strong>${escHtml(a.name)}</strong> (${a.count} events)`).join(', ')}</p>
                </div>
            </div>
        </div>`;

        // CENTER PANEL — Timeline
        html += `<div class="col-lg-4 col-md-4">
            <div class="soc-card p-3">
                <div class="d-flex align-items-center mb-2">
                    <strong style="font-size:.9rem;color:#e0e0e0">Timeline</strong>
                    <span class="ms-auto text-muted" style="font-size:.75rem">Total: ${c.incidents.length}</span>
                </div>
                <div class="case-timeline-controls mb-2">
                    <button class="btn btn-xs btn-outline-success" id="case-play-btn" onclick="toggleCasePlayback(${c.case_id})"><i class="bi bi-play-fill"></i></button>
                    <button class="btn btn-xs btn-outline-secondary" onclick="stopCasePlayback()"><i class="bi bi-stop-fill"></i></button>
                    <label style="font-size:.7rem;color:#8b949e;margin-left:8px"><input type="checkbox" checked id="case-auto-play" onchange="_casePlaybackAuto=this.checked"> Auto</label>
                    <label style="font-size:.7rem;color:#8b949e;margin-left:8px"><input type="checkbox" id="case-recenter" checked> Recenter</label>
                    <span class="ms-auto" style="font-size:.75rem;color:#aaa" id="case-playing-label"></span>
                </div>
                <div id="case-timeline-list" style="max-height:400px;overflow-y:auto">`;

        for (let i = 0; i < c.incidents.length; i++) {
            const inc = c.incidents[i];
            const geo = inc.geo || {};
            const geoStr = geo.city ? `${geo.city}, ${geo.country}` : (geo.country || '');
            const isAgent = inc.entity_type === 'agent';
            const entityLabel = isAgent ? (inc.agent_name||'Unknown Agent') : inc.src_ip;
            const entityIcon = isAgent ? 'pc-display' : 'globe';
            const entityDetail = isAgent ? `${inc.count.toLocaleString()} events` : (geoStr || `${inc.count} events`);
            html += `<div class="case-timeline-item" id="case-tl-${i}" onclick="highlightCaseIncident(${i});loadCaseIncidentEvents(${c.case_id},${i})" data-ip="${escHtml(inc.src_ip||'')}" data-agent="${escHtml(inc.agent_name||'')}">
                <div class="case-tl-bar" style="background:${sevColor}"></div>
                <div class="case-tl-content">
                    <div style="font-size:.78rem;font-weight:600">${escHtml(c.title)} (ID: ${inc.incident_id})</div>
                    <div style="font-size:.7rem;color:#8b949e"><i class="bi bi-${entityIcon}"></i> ${escHtml(entityLabel)} ${entityDetail ? '— '+escHtml(entityDetail) : ''}</div>
                </div>
                <span class="case-tl-info" title="Click to load events"><i class="bi bi-info-circle"></i></span>
            </div>`;
        }

        html += `</div></div></div>`;

        // RIGHT PANEL — Topology Graph
        html += `<div class="col-lg-5 col-md-4">
            <div class="soc-card p-3" style="position:relative;min-height:450px">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <div style="font-size:.75rem;color:#8b949e">
                        <span>Start Time: <strong>${c.first_occurred?new Date(c.first_occurred).toLocaleString():''}</strong></span><br>
                        <span>End Time: <strong>${c.last_occurred?new Date(c.last_occurred).toLocaleString():''}</strong></span>
                    </div>
                    <div>
                        <span style="font-size:.7rem;color:#8b949e">Layout:</span>
                        <select class="form-select form-select-sm" style="width:auto;display:inline-block;font-size:.7rem;background:#1a1a2e;color:#e0e0e0;border-color:#333" id="case-graph-layout" onchange="redrawCaseGraph()">
                            <option value="force">Force</option>
                            <option value="radial">Radial</option>
                        </select>
                    </div>
                </div>
                <div id="case-topology-graph" style="width:100%;height:380px;background:#0d1117;border-radius:8px;position:relative;overflow:hidden"></div>
            </div>
        </div>`;

        html += `</div>`;

        // Activity timeline bar chart at bottom
        if (c.timeline && c.timeline.length) {
            html += `<div class="soc-card mt-3 p-3">
                <div style="font-size:.8rem;color:#8b949e;margin-bottom:8px">Activity Timeline</div>
                <div id="case-activity-chart" style="height:60px;display:flex;align-items:flex-end;gap:2px">`;
            const maxCount = Math.max(...c.timeline.map(t => t.count), 1);
            for (const t of c.timeline) {
                const pct = (t.count / maxCount) * 100;
                const dateLabel = t.date ? new Date(t.date).toLocaleDateString('en-US', {month:'short', day:'numeric'}) : '';
                html += `<div style="flex:1;display:flex;flex-direction:column;align-items:center">
                    <div style="width:100%;background:${sevColor};border-radius:2px 2px 0 0;height:${Math.max(pct,2)}%;min-height:${t.count>0?'4px':'1px'};opacity:${t.count>0?1:0.3}" title="${dateLabel}: ${t.count} events"></div>
                    <div style="font-size:.6rem;color:#6c757d;margin-top:2px;writing-mode:vertical-rl;transform:rotate(180deg);height:35px;overflow:hidden">${dateLabel}</div>
                </div>`;
            }
            html += `</div></div>`;
        }

        content.innerHTML = html;

        // Initialize topology graph
        setTimeout(() => initCaseTopologyGraph(c), 100);

    } catch (e) {
        content.innerHTML = `<div class="alert alert-danger">Error loading case: ${escHtml(e.message)}</div>`;
    }
}

function showCaseTab(tab, btn) {
    document.getElementById('case-tab-details').style.display = tab==='details'?'':'none';
    document.getElementById('case-tab-events').style.display = tab==='events'?'':'none';
    document.getElementById('case-tab-context').style.display = tab==='context'?'':'none';
    btn.closest('.case-detail-tabs').querySelectorAll('.btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
}

async function loadCaseEventsTab(caseId) {
    const panel = document.getElementById('case-tab-events');
    panel.innerHTML = '<div class="text-center py-2"><div class="spinner-border spinner-border-sm text-info"></div> Getting Trigger Events...</div>';

    const trSel = document.getElementById('cases-timerange');
    const timerange = trSel ? trSel.value : '7d';

    try {
        const data = await api(`/api/cases/${caseId}/events?timerange=${timerange}&page=1`);
        const events = data.events || [];
        let html = `<div style="font-size:.7rem;color:#8b949e;margin-bottom:4px">Displaying ${events.length} of ${data.total} events</div>`;
        html += `<div style="max-height:300px;overflow-y:auto">`;
        for (const ev of events.slice(0, 50)) {
            const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '';
            html += `<div class="case-event-item">
                <div style="font-size:.7rem;color:#64b5f6">${ts}</div>
                <div style="font-size:.75rem;color:#e0e0e0">${escHtml(ev.rule_description)}</div>
                <div style="font-size:.68rem;color:#8b949e">${ev.src_ip?'<i class="bi bi-globe"></i> '+escHtml(ev.src_ip):''} ${ev.agent?'<i class="bi bi-pc-display"></i> '+escHtml(ev.agent):''} ${ev.src_user?'<i class="bi bi-person"></i> '+escHtml(ev.src_user):''}</div>
            </div>`;
        }
        html += `</div>`;
        if (data.total > 50) {
            html += `<div style="font-size:.7rem;color:#8b949e;margin-top:4px;text-align:center">Showing first 50 events of ${data.total}</div>`;
        }
        panel.innerHTML = html;
    } catch (e) {
        panel.innerHTML = `<div class="text-danger" style="font-size:.75rem">Error: ${escHtml(e.message)}</div>`;
    }
}

async function loadCaseIncidentEvents(caseId, incidentIdx) {
    if (!_caseGraphData) return;
    const inc = _caseGraphData.incidents[incidentIdx];
    if (!inc) return;

    // Switch to events tab automatically
    const evTab = document.getElementById('case-tab-events');
    const detTab = document.getElementById('case-tab-details');
    const ctxTab = document.getElementById('case-tab-context');
    if (evTab) evTab.style.display = '';
    if (detTab) detTab.style.display = 'none';
    if (ctxTab) ctxTab.style.display = 'none';
    const tabBtns = document.querySelectorAll('.case-detail-tabs .btn');
    tabBtns.forEach((b, i) => b.classList.toggle('active', i === 1));

    const panel = document.getElementById('case-tab-events');
    if (!panel) return;

    const entityLabel = inc.entity_type === 'agent' ? (inc.agent_name || 'Agent') : inc.src_ip;
    panel.innerHTML = `<div class="text-center py-2"><div class="spinner-border spinner-border-sm text-info"></div> Getting Trigger Events for <strong>${escHtml(entityLabel)}</strong>...</div>`;

    const trSel = document.getElementById('cases-timerange');
    const timerange = trSel ? trSel.value : '7d';

    let url = `/api/cases/${caseId}/events?timerange=${timerange}&page=1`;
    if (inc.src_ip) url += `&src_ip=${encodeURIComponent(inc.src_ip)}`;
    if (inc.agent_name) url += `&agent_name=${encodeURIComponent(inc.agent_name)}`;

    try {
        const data = await api(url);
        const events = data.events || [];
        let html = `<div style="font-size:.72rem;color:#64b5f6;margin-bottom:6px;padding:4px 8px;background:rgba(33,150,243,0.1);border-radius:4px">
            <i class="bi bi-funnel"></i> Filtered: <strong>${escHtml(entityLabel)}</strong> — ${data.total} event${data.total!==1?'s':''}
        </div>`;
        html += `<div style="max-height:280px;overflow-y:auto">`;
        for (const ev of events.slice(0, 50)) {
            const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '';
            html += `<div class="case-event-item">
                <div style="font-size:.7rem;color:#64b5f6">${ts}</div>
                <div style="font-size:.75rem;color:#e0e0e0">${escHtml(ev.rule_description||'')}</div>
                <div style="font-size:.68rem;color:#8b949e">${ev.src_ip?'<i class="bi bi-globe"></i> '+escHtml(ev.src_ip)+' ':''} ${ev.agent?'<i class="bi bi-pc-display"></i> '+escHtml(ev.agent)+' ':''} ${ev.src_user?'<i class="bi bi-person"></i> '+escHtml(ev.src_user):''}</div>
                ${ev.full_log ? `<details style="font-size:.65rem;color:#6c757d;margin-top:2px"><summary style="cursor:pointer">Raw Log</summary><pre style="white-space:pre-wrap;word-break:break-all;max-height:80px;overflow-y:auto;margin:2px 0;padding:4px;background:#0a0a1a;border-radius:3px">${escHtml(ev.full_log)}</pre></details>` : ''}
            </div>`;
        }
        html += `</div>`;
        if (data.total > 50) {
            html += `<div style="font-size:.7rem;color:#8b949e;margin-top:4px;text-align:center">Showing first 50 of ${data.total} events</div>`;
        }
        panel.innerHTML = html;
    } catch (e) {
        panel.innerHTML = `<div class="text-danger" style="font-size:.75rem">Error: ${escHtml(e.message)}</div>`;
    }
}

// --- Topology Graph (SVG-based force-directed) ---

let _caseGraphData = null;
let _caseGraphSvg = null;

function initCaseTopologyGraph(caseData) {
    const container = document.getElementById('case-topology-graph');
    if (!container) return;
    _caseGraphData = caseData;

    const width = container.clientWidth;
    const height = container.clientHeight || 380;

    // Build nodes and links
    const nodes = [];
    const links = [];
    const nodeMap = {};

    // Central incident/rule node
    const ruleNodeId = 'rule-' + caseData.rule_id;
    nodes.push({ id: ruleNodeId, type: 'rule', label: caseData.title, severity: caseData.severity });
    nodeMap[ruleNodeId] = true;

    // Determine if incidents are IP-based or agent-based
    const hasIPs = caseData.incidents.some(inc => inc.entity_type === 'ip' && inc.src_ip);

    if (hasIPs) {
        // IP-based: show IPs → rule → agents
        for (const agent of caseData.agents) {
            const agentNodeId = 'agent-' + agent.name;
            if (!nodeMap[agentNodeId]) {
                nodes.push({ id: agentNodeId, type: 'agent', label: agent.name, count: agent.count });
                nodeMap[agentNodeId] = true;
            }
            links.push({ source: ruleNodeId, target: agentNodeId });
        }
        for (let i = 0; i < caseData.incidents.length; i++) {
            const inc = caseData.incidents[i];
            if (!inc.src_ip) continue;
            const ipNodeId = 'ip-' + inc.src_ip;
            if (!nodeMap[ipNodeId]) {
                nodes.push({ id: ipNodeId, type: 'ip', label: inc.src_ip, geo: inc.geo, incident_id: inc.incident_id, idx: i });
                nodeMap[ipNodeId] = true;
            }
            links.push({ source: ipNodeId, target: ruleNodeId });
        }
    } else {
        // Agent-based: show agents as main incident nodes around rule
        for (let i = 0; i < caseData.incidents.length; i++) {
            const inc = caseData.incidents[i];
            const agentNodeId = 'incident-agent-' + (inc.agent_name || i);
            if (!nodeMap[agentNodeId]) {
                nodes.push({ id: agentNodeId, type: 'incident-agent', label: inc.agent_name || 'Agent', count: inc.count, idx: i, incident_id: inc.incident_id });
                nodeMap[agentNodeId] = true;
            }
            links.push({ source: ruleNodeId, target: agentNodeId });
        }
    }

    // Create SVG
    let svg = `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" id="case-graph-svg" style="width:100%;height:100%">`;
    svg += `<defs>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="20" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#555"/></marker>
    </defs>`;

    const cx = width / 2;
    const cy = height / 2;
    const positions = {};
    positions[ruleNodeId] = { x: cx, y: cy };

    // Position outer nodes in a circle
    const outerNodes = nodes.filter(n => n.id !== ruleNodeId);
    const ipNodes = outerNodes.filter(n => n.type === 'ip');
    const agentNodes = outerNodes.filter(n => n.type === 'agent');
    const incAgentNodes = outerNodes.filter(n => n.type === 'incident-agent');

    // IP nodes in outer ring
    for (let i = 0; i < ipNodes.length; i++) {
        const angle = (2 * Math.PI * i / Math.max(ipNodes.length, 1)) - Math.PI / 2;
        const radius = Math.min(width, height) * 0.35;
        positions[ipNodes[i].id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
    }

    // Agent nodes in inner ring (for IP-based cases)
    for (let i = 0; i < agentNodes.length; i++) {
        const angle = (2 * Math.PI * i / Math.max(agentNodes.length, 1)) + Math.PI / 4;
        const radius = Math.min(width, height) * 0.18;
        positions[agentNodes[i].id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
    }

    // Incident-agent nodes in outer ring (for agent-based cases)
    for (let i = 0; i < incAgentNodes.length; i++) {
        const angle = (2 * Math.PI * i / Math.max(incAgentNodes.length, 1)) - Math.PI / 2;
        const radius = Math.min(width, height) * 0.30;
        positions[incAgentNodes[i].id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
    }

    // Draw links
    for (const link of links) {
        const src = positions[link.source];
        const tgt = positions[link.target];
        if (src && tgt) {
            svg += `<line x1="${src.x}" y1="${src.y}" x2="${tgt.x}" y2="${tgt.y}" stroke="#444" stroke-width="1.5" stroke-dasharray="4,3" marker-end="url(#arrow)"/>`;
        }
    }

    // Draw nodes
    for (const node of nodes) {
        const pos = positions[node.id];
        if (!pos) continue;

        if (node.type === 'rule') {
            const sColor = node.severity==='Critical'?'#ff1744':node.severity==='High'?'#ff6d00':'#ffc107';
            svg += `<g class="case-node" data-id="${node.id}">
                <circle cx="${pos.x}" cy="${pos.y}" r="24" fill="#1a1a2e" stroke="${sColor}" stroke-width="2.5"/>
                <text x="${pos.x}" y="${pos.y+5}" text-anchor="middle" fill="${sColor}" font-size="16" font-weight="bold">⚠</text>
            </g>`;
        } else if (node.type === 'ip') {
            svg += `<g class="case-node case-ip-node" id="case-gnode-${node.idx}" data-id="${node.id}" data-ip="${node.label}" onclick="highlightCaseIncident(${node.idx});loadCaseIncidentEvents(${caseData.case_id},${node.idx})">
                <circle cx="${pos.x}" cy="${pos.y}" r="18" fill="#0d1117" stroke="#555" stroke-width="1.5"/>
                <text x="${pos.x}" y="${pos.y+4}" text-anchor="middle" fill="#8b949e" font-size="12">🖥</text>
                <text x="${pos.x}" y="${pos.y+32}" text-anchor="middle" fill="#aaa" font-size="9">${node.label}</text>`;
            if (node.geo && node.geo.country) {
                svg += `<text x="${pos.x}" y="${pos.y+43}" text-anchor="middle" fill="#6c757d" font-size="7.5">${escHtml(node.geo.city||'')}${node.geo.city&&node.geo.country?', ':''}${escHtml(node.geo.country||'')}</text>`;
            }
            svg += `</g>`;
        } else if (node.type === 'agent') {
            svg += `<g class="case-node" data-id="${node.id}">
                <circle cx="${pos.x}" cy="${pos.y}" r="15" fill="#0d1117" stroke="#2196f3" stroke-width="1.5"/>
                <text x="${pos.x}" y="${pos.y+4}" text-anchor="middle" fill="#2196f3" font-size="11">👤</text>
                <text x="${pos.x}" y="${pos.y+28}" text-anchor="middle" fill="#64b5f6" font-size="8">${escHtml(node.label)}</text>
            </g>`;
        } else if (node.type === 'incident-agent') {
            // Agent-as-incident node (larger, clickable)
            svg += `<g class="case-node case-ip-node" id="case-gnode-${node.idx}" data-id="${node.id}" data-agent="${node.label}" onclick="highlightCaseIncident(${node.idx});loadCaseIncidentEvents(${caseData.case_id},${node.idx})">
                <circle cx="${pos.x}" cy="${pos.y}" r="20" fill="#0d1117" stroke="#2196f3" stroke-width="2"/>
                <text x="${pos.x}" y="${pos.y+4}" text-anchor="middle" fill="#64b5f6" font-size="13">🖥</text>
                <text x="${pos.x}" y="${pos.y+34}" text-anchor="middle" fill="#64b5f6" font-size="9">${escHtml(node.label)}</text>
                <text x="${pos.x}" y="${pos.y+45}" text-anchor="middle" fill="#8b949e" font-size="7.5">${node.count.toLocaleString()} events</text>
            </g>`;
        }
    }

    // Tooltip overlay
    svg += `<g id="case-graph-tooltip" style="display:none">
        <rect x="0" y="0" width="220" height="90" rx="4" fill="#1e1e2e" stroke="#444" opacity="0.95"/>
        <text id="case-tooltip-text" x="10" y="20" fill="#e0e0e0" font-size="10"></text>
    </g>`;

    svg += `</svg>`;
    container.innerHTML = svg;

    // Add hover events for IP and incident-agent nodes
    container.querySelectorAll('.case-ip-node').forEach(node => {
        node.addEventListener('mouseenter', (e) => showCaseNodeTooltip(e, node));
        node.addEventListener('mouseleave', hideCaseNodeTooltip);
    });
}

function showCaseNodeTooltip(e, node) {
    if (!_caseGraphData) return;
    const ip = node.dataset.ip;
    const agentName = node.dataset.agent;
    let inc = null;
    if (ip) {
        inc = _caseGraphData.incidents.find(i => i.src_ip === ip);
    } else if (agentName) {
        inc = _caseGraphData.incidents.find(i => i.agent_name === agentName);
    }
    if (!inc) return;

    const tooltip = document.getElementById('case-graph-tooltip');
    if (!tooltip) return;

    const geo = inc.geo || {};
    const textEl = document.getElementById('case-tooltip-text');
    if (textEl) {
        textEl.innerHTML = '';
        const lines = [];
        if (inc.entity_type === 'agent') {
            lines.push(`Agent: ${inc.agent_name}`);
            lines.push(`Events: ${inc.count.toLocaleString()}`);
        } else {
            lines.push(`IP: ${inc.src_ip}`);
            if (geo.city) lines.push(`Location: ${geo.city}, ${geo.region||''}, ${geo.country||''}`);
            lines.push(`Events: ${inc.count}`);
        }
        if (inc.first_seen) lines.push(`First: ${new Date(inc.first_seen).toLocaleString()}`);
        if (inc.last_seen) lines.push(`Last: ${new Date(inc.last_seen).toLocaleString()}`);

        lines.filter(Boolean).forEach((line, i) => {
            const tspan = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
            tspan.setAttribute('x', '10');
            tspan.setAttribute('dy', i === 0 ? '0' : '14');
            tspan.textContent = line;
            textEl.appendChild(tspan);
        });
    }

    const rect = node.querySelector('circle');
    if (rect) {
        const cx = parseFloat(rect.getAttribute('cx'));
        const cy = parseFloat(rect.getAttribute('cy'));
        tooltip.setAttribute('transform', `translate(${cx + 25}, ${cy - 40})`);
        tooltip.style.display = '';
    }
}

function hideCaseNodeTooltip() {
    const tooltip = document.getElementById('case-graph-tooltip');
    if (tooltip) tooltip.style.display = 'none';
}

function highlightCaseIncident(idx) {
    // Highlight timeline item
    document.querySelectorAll('.case-timeline-item').forEach((el, i) => {
        el.classList.toggle('active', i === idx);
    });
    // Highlight graph node
    document.querySelectorAll('.case-ip-node circle').forEach(c => {
        c.setAttribute('stroke', '#555');
        c.setAttribute('stroke-width', '1.5');
    });
    const gNode = document.getElementById(`case-gnode-${idx}`);
    if (gNode) {
        const circle = gNode.querySelector('circle');
        if (circle) {
            circle.setAttribute('stroke', '#ffc107');
            circle.setAttribute('stroke-width', '3');
        }
    }
    // Update playing label
    const label = document.getElementById('case-playing-label');
    if (label && _caseGraphData) {
        label.textContent = `Playing: ${idx+1} / ${_caseGraphData.incidents.length}`;
    }
}

function toggleCasePlayback(caseId) {
    if (_casePlaybackTimer) {
        stopCasePlayback();
        return;
    }
    _casePlaybackIdx = 0;
    const playBtn = document.getElementById('case-play-btn');
    if (playBtn) playBtn.innerHTML = '<i class="bi bi-pause-fill"></i>';
    highlightCaseIncident(0);

    _casePlaybackTimer = setInterval(() => {
        if (!_caseGraphData) { stopCasePlayback(); return; }
        _casePlaybackIdx++;
        if (_casePlaybackIdx >= _caseGraphData.incidents.length) {
            _casePlaybackIdx = 0;
            if (!_casePlaybackAuto) { stopCasePlayback(); return; }
        }
        highlightCaseIncident(_casePlaybackIdx);
    }, 2500);
}

function stopCasePlayback() {
    if (_casePlaybackTimer) {
        clearInterval(_casePlaybackTimer);
        _casePlaybackTimer = null;
    }
    const playBtn = document.getElementById('case-play-btn');
    if (playBtn) playBtn.innerHTML = '<i class="bi bi-play-fill"></i>';
    const label = document.getElementById('case-playing-label');
    if (label) label.textContent = '';
}

function redrawCaseGraph() {
    if (_caseGraphData) initCaseTopologyGraph(_caseGraphData);
}


function showToast(msg, type) {
    const container = document.getElementById('toast-container');
    const bgClass = type === 'success' ? 'bg-success' : type === 'danger' ? 'bg-danger' : 'bg-info';
    const id = 'toast-' + Date.now();
    container.innerHTML += `<div id="${id}" class="toast align-items-center ${bgClass} text-white border-0 show" role="alert">
        <div class="d-flex"><div class="toast-body">${msg}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>`;
    setTimeout(() => document.getElementById(id)?.remove(), 4000);
}

function showChangePasswordModal() {
    new bootstrap.Modal(document.getElementById('changePasswordModal')).show();
}

async function changePassword() {
    const current = document.getElementById('cp-current').value;
    const newPass = document.getElementById('cp-new').value;
    const confirm = document.getElementById('cp-confirm').value;
    if (newPass !== confirm) { showToast('Passwords do not match', 'danger'); return; }
    try {
        const resp = await fetch('/api/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: current, new_password: newPass }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Password changed successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('changePasswordModal')).hide();
        } else {
            showToast(data.error || 'Failed to change password', 'danger');
        }
    } catch (err) { showToast('Error: ' + err.message, 'danger'); }
}
