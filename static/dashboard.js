/* ============================================================
   TRUST WATCH — DASHBOARD CLIENT
   ============================================================ */

let dashboardLoading = false;


/* ---------- helpers ---------- */

function escapeHTML(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatDate(value) {
    if (!value) return "-";
    try {
        let dateString = String(value);
        if (dateString.includes(" ") && !dateString.includes("T")) {
            dateString = dateString.replace(" ", "T");
        }
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return value;
        return date.toLocaleString();
    } catch (error) {
        return value;
    }
}


/* ---------- dashboard orchestration ---------- */

async function loadDashboard() {
    if (dashboardLoading) return;
    dashboardLoading = true;

    try {
        await Promise.allSettled([
            loadStats(),
            loadAlerts(),
            loadActivities(),
            loadIncidents(),
            loadAnalytics(),
            loadReports()
        ]);
    } catch (error) {
        console.error("Dashboard loading error:", error);
    } finally {
        dashboardLoading = false;
        updateLastUpdated();
    }
}


/* ---------- stats + security score ---------- */

async function loadStats() {
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) throw new Error("Unable to load statistics");

        const data = await response.json();

        const users = data.users || {};
        const alerts = data.alerts || {};
        const activities = data.activities || {};

        document.getElementById("totalUsers").textContent =
            users.total ?? data.total_users ?? 0;

        document.getElementById("totalAlerts").textContent =
            alerts.total ?? data.total_alerts ?? 0;

        document.getElementById("totalActivities").textContent =
            activities.total ?? data.total_activities ?? 0;

        document.getElementById("criticalAlerts").textContent =
            alerts.critical ?? data.critical_alerts ?? 0;

        calculateSecurityScore(users, alerts, activities);

    } catch (error) {
        console.error("Stats error:", error);
    }
}

function calculateSecurityScore(users, alerts) {
    const restrictedUsers  = Number(users.restricted || 0);
    const suspendedUsers   = Number(users.suspended || 0);
    const criticalAlerts   = Number(alerts.critical || 0);
    const highAlerts       = Number(alerts.high || 0);

    let score = 100;
    score -= criticalAlerts * 8;
    score -= highAlerts * 4;
    score -= restrictedUsers * 2;
    score -= suspendedUsers * 3;
    score = Math.max(0, Math.min(100, score));

    document.getElementById("securityScore").textContent = score;

    const ring = document.getElementById("scoreRing");
    if (ring) {
        ring.style.setProperty("--score", score);

        const ringColor =
            score >= 80 ? "var(--good)" :
            score >= 50 ? "var(--med)"  :
                          "var(--crit)";

        ring.style.setProperty("--ring-color", ringColor);
    }
}


/* ---------- alerts ---------- */

async function loadAlerts() {
    const table = document.getElementById("alertsTable");

    try {
        const response = await fetch("/api/alerts");
        if (!response.ok) throw new Error("Unable to load alerts");

        const alerts = await response.json();

        if (!Array.isArray(alerts) || alerts.length === 0) {
            table.innerHTML = `
                <tr><td colspan="7" class="empty">No security alerts found.</td></tr>
            `;
            return;
        }

        table.innerHTML = "";

        alerts.forEach(alert => {
            const row = document.createElement("tr");
            const severity = String(alert.severity || "Low").toLowerCase();

            row.innerHTML = `
                <td>#${escapeHTML(alert.alert_id)}</td>
                <td>${escapeHTML(alert.user_name || alert.name || "Unknown")}</td>
                <td>${escapeHTML(alert.alert_type || "Security Alert")}</td>
                <td><span class="severity ${severity}">${escapeHTML(alert.severity || "Low")}</span></td>
                <td class="description-cell">${escapeHTML(alert.description || "No description")}</td>
                <td>${formatDate(alert.alert_time)}</td>
                <td>
                    <button class="action-btn view view-alert-btn">View</button>
                    <button class="action-btn incident create-incident-btn">Incident</button>
                    <button class="action-btn restrict restrict-user-btn">Restrict</button>
                    <button class="action-btn suspend suspend-user-btn">Suspend</button>
                </td>
            `;

            row.querySelector(".view-alert-btn")
                .addEventListener("click", () => openAlertModal(alert));

            row.querySelector(".create-incident-btn")
                .addEventListener("click", () => createIncident(alert.alert_id));

            row.querySelector(".restrict-user-btn")
                .addEventListener("click", () => protectUser(alert.user_id, "Restricted"));

            row.querySelector(".suspend-user-btn")
                .addEventListener("click", () => protectUser(alert.user_id, "Suspended"));

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Alerts error:", error);
        table.innerHTML = `
            <tr><td colspan="7" class="empty">Unable to load security alerts.</td></tr>
        `;
    }
}


/* ---------- alert modal ---------- */

function openAlertModal(alert) {
    const modal = document.getElementById("alertModal");
    const body = document.getElementById("alertModalBody");
    const severity = String(alert.severity || "Low").toLowerCase();

    body.innerHTML = `
        <div class="modal-detail">
            <div><span>Alert ID</span><strong>#${escapeHTML(alert.alert_id)}</strong></div>
            <div><span>User</span><strong>${escapeHTML(alert.user_name || alert.name || "Unknown")}</strong></div>
            <div><span>Severity</span><strong><span class="severity ${severity}">${escapeHTML(alert.severity || "Low")}</span></strong></div>
            <div><span>Alert Type</span><strong>${escapeHTML(alert.alert_type || "Security Alert")}</strong></div>
            <div><span>Alert Time</span><strong>${formatDate(alert.alert_time)}</strong></div>
            <div><span>Status</span><strong>${escapeHTML(alert.status || "Open")}</strong></div>
            <div class="modal-description">
                <span>Description</span>
                <p>${escapeHTML(alert.description || "No description available.")}</p>
            </div>
        </div>
    `;

    modal.classList.add("show");
}

function closeAlertModal() {
    document.getElementById("alertModal").classList.remove("show");
}


/* ---------- user status actions ---------- */

async function protectUser(userId, status) {
    if (!userId) {
        alert("User ID is not available.");
        return;
    }

    const message = status === "Suspended"
        ? "Are you sure you want to suspend this user?"
        : "Are you sure you want to restrict this user?";

    if (!confirm(message)) return;

    try {
        const response = await fetch(`/api/users/${userId}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Unable to update user status.");

        alert(data.message || `User status changed to ${status}.`);

        await loadStats();
        await loadAnalytics();
        await loadAlerts();

    } catch (error) {
        console.error("User protection error:", error);
        alert(error.message || "Unable to update user status.");
    }
}


/* ---------- incidents ---------- */

async function createIncident(alertId) {
    if (!alertId) {
        alert("Alert ID is not available.");
        return;
    }

    if (!confirm("Create an incident for this security alert?")) return;

    try {
        const response = await fetch(`/api/incidents/create/${alertId}`, { method: "POST" });
        const data = await response.json();

        if (!response.ok) throw new Error(data.error || "Unable to create incident.");

        alert(data.message || "Incident created successfully.");

        await loadIncidents();
        await loadAnalytics();

    } catch (error) {
        console.error("Incident creation error:", error);
        alert(error.message || "Unable to create incident.");
    }
}

async function loadIncidents() {
    const table = document.getElementById("incidentsTable");

    try {
        const response = await fetch("/api/incidents");
        if (!response.ok) throw new Error("Unable to load incidents");

        const incidents = await response.json();

        if (!Array.isArray(incidents) || incidents.length === 0) {
            table.innerHTML = `
                <tr><td colspan="7" class="empty">No incidents found.</td></tr>
            `;
            return;
        }

        table.innerHTML = "";

        incidents.forEach(incident => {
            const row = document.createElement("tr");
            const status = String(incident.incident_status || "Open").toLowerCase();
            const severity = String(incident.severity || "Low").toLowerCase();

            row.innerHTML = `
                <td>#${escapeHTML(incident.incident_id)}</td>
                <td>#${escapeHTML(incident.alert_id)}</td>
                <td>${escapeHTML(incident.user_name || "Unknown")}</td>
                <td><span class="severity ${severity}">${escapeHTML(incident.severity || "Low")}</span></td>
                <td><span class="incident-status ${status}">${escapeHTML(incident.incident_status || "Open")}</span></td>
                <td class="description-cell">${escapeHTML(incident.action_taken || "No action recorded")}</td>
                <td>
                    <div class="incident-actions">
                        ${incident.incident_status !== "Investigating" && incident.incident_status !== "Resolved"
                            ? `<button class="action-btn investigate investigate-btn">Investigate</button>` : ""}
                        ${incident.incident_status !== "Resolved"
                            ? `<button class="action-btn resolve resolve-btn">Resolve</button>` : ""}
                    </div>
                </td>
            `;

            const investigateBtn = row.querySelector(".investigate-btn");
            if (investigateBtn) {
                investigateBtn.addEventListener("click", () =>
                    changeIncidentStatus(incident.incident_id, "Investigating"));
            }

            const resolveBtn = row.querySelector(".resolve-btn");
            if (resolveBtn) {
                resolveBtn.addEventListener("click", () =>
                    changeIncidentStatus(incident.incident_id, "Resolved"));
            }

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Incident error:", error);
        table.innerHTML = `
            <tr><td colspan="7" class="empty">Unable to load incidents.</td></tr>
        `;
    }
}

async function changeIncidentStatus(incidentId, status) {
    if (!incidentId) return;

    if (status === "Resolved" && !confirm("Mark this incident as resolved?")) return;

    try {
        const response = await fetch(`/api/incidents/${incidentId}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Unable to update incident.");

        alert(data.message || "Incident status updated.");

        await loadIncidents();
        await loadAnalytics();

    } catch (error) {
        console.error("Incident status error:", error);
        alert(error.message || "Unable to update incident.");
    }
}


/* ---------- activity monitor ---------- */

async function loadActivities() {
    const table = document.getElementById("activitiesTable");

    try {
        const response = await fetch("/api/activities");
        if (!response.ok) throw new Error("Unable to load activities");

        const activities = await response.json();

        if (!Array.isArray(activities) || activities.length === 0) {
            table.innerHTML = `
                <tr><td colspan="7" class="empty">No activity logs found.</td></tr>
            `;
            return;
        }

        table.innerHTML = "";

        activities.forEach(activity => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>#${escapeHTML(activity.log_id)}</td>
                <td>${escapeHTML(activity.user_name || activity.name || "Unknown")}</td>
                <td>${escapeHTML(activity.activity_type || "-")}</td>
                <td>${escapeHTML(activity.resource || "-")}</td>
                <td>${escapeHTML(activity.action || "-")}</td>
                <td>${escapeHTML(activity.ip_address || "-")}</td>
                <td>${formatDate(activity.timestamp)}</td>
            `;

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Activity error:", error);
        table.innerHTML = `
            <tr><td colspan="7" class="empty">Unable to load activity logs.</td></tr>
        `;
    }
}


/* ---------- analytics ---------- */

async function loadAnalytics() {
    try {
        const response = await fetch("/api/analytics");
        if (!response.ok) throw new Error("Unable to load analytics");

        const data = await response.json();

        const users = data.users || {};
        const activities = data.activities || {};
        const alerts = data.alerts || {};
        const incidents = data.incidents || {};

        document.getElementById("analyticsTotalUsers").textContent = users.total || 0;
        document.getElementById("analyticsActiveUsers").textContent = users.active || 0;
        document.getElementById("analyticsRestrictedUsers").textContent = users.restricted || 0;
        document.getElementById("analyticsSuspendedUsers").textContent = users.suspended || 0;

        document.getElementById("analyticsActivities").textContent = activities.total || 0;

        document.getElementById("analyticsAlerts").textContent = alerts.total || 0;
        document.getElementById("analyticsCritical").textContent = alerts.critical || 0;
        document.getElementById("analyticsHigh").textContent = alerts.high || 0;
        document.getElementById("analyticsMedium").textContent = alerts.medium || 0;

        document.getElementById("analyticsOpenIncidents").textContent = incidents.open || 0;
        document.getElementById("analyticsInvestigating").textContent = incidents.investigating || 0;
        document.getElementById("analyticsResolved").textContent = incidents.resolved || 0;

    } catch (error) {
        console.error("Analytics error:", error);
    }
}


/* ---------- reports ---------- */

async function loadReports() {
    const table = document.getElementById("reportsTable");

    try {
        const response = await fetch("/api/reports");
        if (!response.ok) throw new Error("Unable to load reports");

        const reports = await response.json();

        if (!Array.isArray(reports) || reports.length === 0) {
            table.innerHTML = `
                <tr><td colspan="6" class="empty">No reports generated yet.</td></tr>
            `;
            return;
        }

        table.innerHTML = "";

        reports.forEach(report => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>#${escapeHTML(report.report_id)}</td>
                <td>${escapeHTML(report.report_type || "Security Summary")}</td>
                <td>${escapeHTML(report.generated_by_name || report.generated_by || "Admin")}</td>
                <td>${formatDate(report.generated_on)}</td>
                <td class="description-cell">${escapeHTML(report.description || "-")}</td>
                <td><button class="action-btn view download-report-btn">Download</button></td>
            `;

            row.querySelector(".download-report-btn")
                .addEventListener("click", () => downloadReport(report.file_path));

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Reports error:", error);
        table.innerHTML = `
            <tr><td colspan="6" class="empty">Unable to load reports.</td></tr>
        `;
    }
}

async function generateSecurityReport() {
    const button = document.getElementById("generateReportBtn");
    const originalText = button.textContent;

    button.disabled = true;
    button.textContent = "Generating...";

    try {
        const response = await fetch("/api/reports/generate", { method: "POST" });
        const data = await response.json();

        if (!response.ok) throw new Error(data.error || "Unable to generate report.");

        alert(data.message || "Security report generated successfully.");

        await loadReports();
        await loadAnalytics();

    } catch (error) {
        console.error("Report generation error:", error);
        alert(error.message || "Unable to generate security report.");
    } finally {
        button.disabled = false;
        button.textContent = originalText;
    }
}

function downloadReport(filePath) {
    if (!filePath) {
        alert("Report file is not available.");
        return;
    }

    const filename = String(filePath).split(/[\\/]/).pop();

    if (!filename) {
        alert("Invalid report file.");
        return;
    }

    window.location.href = `/api/reports/download/${encodeURIComponent(filename)}`;
}


/* ---------- misc UI wiring ---------- */

function updateLastUpdated() {
    const element = document.getElementById("lastUpdated");
    if (element) {
        element.textContent = "Last updated: " + new Date().toLocaleTimeString();
    }
}

function setupNavigation() {
    const navItems = document.querySelectorAll(".nav-item[href^='#']");

    navItems.forEach(item => {
        item.addEventListener("click", function () {
            navItems.forEach(nav => nav.classList.remove("active"));
            this.classList.add("active");
        });
    });
}

function setupModal() {
    const modal = document.getElementById("alertModal");
    const closeButton = document.getElementById("modalClose");

    closeButton.addEventListener("click", closeAlertModal);

    modal.addEventListener("click", function (event) {
        if (event.target === modal) closeAlertModal();
    });
}

function setupRefreshButton() {
    const refreshButton = document.getElementById("refreshBtn");

    refreshButton.addEventListener("click", async function () {
        const originalText = this.textContent;
        this.textContent = "↻ Refreshing...";
        await loadDashboard();
        this.textContent = originalText;
    });
}

function setupReportButton() {
    document.getElementById("generateReportBtn")
        .addEventListener("click", generateSecurityReport);
}


/* ---------- init ---------- */

document.addEventListener("DOMContentLoaded", function () {
    setupNavigation();
    setupModal();
    setupRefreshButton();
    setupReportButton();

    loadDashboard();

    setInterval(loadDashboard, 5000);
});