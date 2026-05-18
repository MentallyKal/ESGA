/*
 * dashboard.js — ESGA Dashboard Client Logic
 * Vanilla JS + Chart.js (CDN). Calls ESGA API endpoints.
 */

// Chart instances (global so we can destroy & recreate)
var gaugeChart = null;
var severityChart = null;
var gradeChart = null;

// On page load
document.addEventListener("DOMContentLoaded", function () {
    loadDashboard();
    setupUploadForm();
    document.getElementById("close-findings").addEventListener("click", function () {
        document.getElementById("findings-section").style.display = "none";
    });
});

// ── Load dashboard data ─────────────────────────────────────────

async function loadDashboard() {
    try {
        var resp = await fetch("/api/dashboard/summary");
        if (!resp.ok) throw new Error("Failed to load dashboard");
        var data = await resp.json();
        renderSummaryCards(data);
        renderGaugeChart(data.average_score);
        renderSeverityChart(data.severity_counts);
        renderGradeChart(data.grade_distribution);
        renderScansTable(data.recent_scans);
    } catch (err) {
        console.error("Dashboard load error:", err);
    }
}

// ── Summary cards ───────────────────────────────────────────────

function renderSummaryCards(data) {
    document.getElementById("total-scans").textContent = data.total_scans;
    document.getElementById("total-findings").textContent = data.total_findings;
    document.getElementById("avg-score").textContent = data.average_score.toFixed(1);
}

// ── Risk gauge (half-doughnut) ──────────────────────────────────

function renderGaugeChart(score) {
    if (gaugeChart) gaugeChart.destroy();
    var ctx = document.getElementById("risk-gauge").getContext("2d");
    var color = score <= 10 ? "#27ae60"
              : score <= 25 ? "#2ecc71"
              : score <= 50 ? "#f39c12"
              : score <= 75 ? "#e67e22"
              : "#e74c3c";
    gaugeChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [color, "#e0e0e0"],
                borderWidth: 0
            }]
        },
        options: {
            cutout: "75%",
            rotation: -90,
            circumference: 180,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            },
            responsive: false
        }
    });
    var label = document.getElementById("gauge-label");
    label.textContent = score.toFixed(1) + " / 100";
    label.style.color = color;
}

// ── Severity pie chart ──────────────────────────────────────────

function renderSeverityChart(counts) {
    if (severityChart) severityChart.destroy();
    var ctx = document.getElementById("severity-chart").getContext("2d");
    severityChart = new Chart(ctx, {
        type: "pie",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [
                    counts.CRITICAL || 0,
                    counts.HIGH || 0,
                    counts.MEDIUM || 0,
                    counts.LOW || 0
                ],
                backgroundColor: ["#e74c3c", "#e67e22", "#f39c12", "#27ae60"]
            }]
        },
        options: {
            responsive: false,
            plugins: {
                legend: { position: "bottom" }
            }
        }
    });
}

// ── Grade distribution bar chart ────────────────────────────────

function renderGradeChart(dist) {
    if (gradeChart) gradeChart.destroy();
    var ctx = document.getElementById("grade-chart").getContext("2d");
    var grades = ["A", "B", "C", "D", "F"];
    var colors = ["#27ae60", "#2ecc71", "#f39c12", "#e67e22", "#e74c3c"];
    gradeChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: grades,
            datasets: [{
                label: "Scans",
                data: grades.map(function (g) { return dist[g] || 0; }),
                backgroundColor: colors
            }]
        },
        options: {
            responsive: false,
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// ── Recent scans table ──────────────────────────────────────────

function renderScansTable(scans) {
    var tbody = document.getElementById("scans-tbody");
    tbody.innerHTML = "";
    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#999;">'
            + 'No scans yet. Upload a .tf file to get started.</td></tr>';
        return;
    }
    scans.forEach(function (scan) {
        var score = scan.risk_score ? scan.risk_score.score.toFixed(1) : "N/A";
        var grade = scan.risk_score ? scan.risk_score.grade : "N/A";
        var gradeClass = scan.risk_score ? "grade-" + grade : "";
        var date = new Date(scan.created_at).toLocaleString();
        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + scan.id + "</td>"
            + "<td>" + escapeHtml(scan.filename) + "</td>"
            + "<td>" + scan.total_resources + "</td>"
            + "<td>" + scan.total_findings + "</td>"
            + "<td>" + score + "</td>"
            + '<td class="' + gradeClass + '">' + grade + "</td>"
            + "<td>" + date + "</td>"
            + '<td><button class="btn-detail" onclick="showFindings('
            + scan.id + ')">Details</button></td>';
        tbody.appendChild(tr);
    });
}

// ── Findings drill-down ─────────────────────────────────────────

async function showFindings(scanId) {
    try {
        var resp = await fetch("/api/scans/" + scanId);
        if (!resp.ok) throw new Error("Failed to load scan");
        var scan = await resp.json();

        document.getElementById("findings-title").textContent =
            scan.filename + " (Score: "
            + (scan.risk_score ? scan.risk_score.score.toFixed(1) : "N/A") + ")";

        var tbody = document.getElementById("findings-tbody");
        tbody.innerHTML = "";

        if (scan.findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#27ae60;">'
                + 'No findings — this file is clean!</td></tr>';
        } else {
            scan.findings.forEach(function (f) {
                var tr = document.createElement("tr");
                var sevClass = "severity-" + f.severity.toLowerCase();
                tr.innerHTML =
                    '<td><span class="' + sevClass + '">' + f.severity + "</span></td>"
                    + "<td>" + escapeHtml(f.resource_name) + "</td>"
                    + "<td>" + escapeHtml(f.message) + "</td>";
                tbody.appendChild(tr);
            });
        }

        var section = document.getElementById("findings-section");
        section.style.display = "block";
        section.scrollIntoView({ behavior: "smooth" });
    } catch (err) {
        console.error("Error loading findings:", err);
    }
}

// ── Upload form ─────────────────────────────────────────────────

function setupUploadForm() {
    document.getElementById("upload-form").addEventListener("submit", async function (e) {
        e.preventDefault();
        var fileInput = document.getElementById("tf-file");
        if (!fileInput.files.length) return;

        var formData = new FormData();
        formData.append("file", fileInput.files[0]);

        var btn = document.getElementById("scan-btn");
        var status = document.getElementById("upload-status");
        btn.disabled = true;
        btn.textContent = "Scanning...";
        status.textContent = "";

        try {
            var resp = await fetch("/api/scans/", {
                method: "POST",
                body: formData
            });
            if (!resp.ok) {
                var err = await resp.json();
                throw new Error(err.detail || "Scan failed");
            }
            var result = await resp.json();
            var riskScore = result.risk_score;
            status.textContent = "Scan complete! Score: "
                + riskScore.score.toFixed(1)
                + " (Grade: " + riskScore.grade + ")";
            status.style.color = riskScore.score <= 25 ? "#27ae60" : "#e74c3c";
            loadDashboard();  // Refresh all data
        } catch (err) {
            status.textContent = "Error: " + err.message;
            status.style.color = "#e74c3c";
        } finally {
            btn.disabled = false;
            btn.textContent = "Run Scan";
            fileInput.value = "";
        }
    });
}

// ── Utility ─────────────────────────────────────────────────────

function escapeHtml(text) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}
