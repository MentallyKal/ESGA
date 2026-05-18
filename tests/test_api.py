"""Tests for the API endpoints."""

from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_list_rules(client):
    resp = client.get("/api/rules/")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 10
    # All rules should have required fields
    for rule in rules:
        assert "rule_id" in rule
        assert "severity" in rule
        assert rule["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_dashboard_summary_empty(client):
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scans"] == 0
    assert data["total_findings"] == 0
    assert data["average_score"] == 0.0


def test_scan_clean_file(client):
    clean_tf = (SAMPLES_DIR / "clean.tf").read_text()
    resp = client.post(
        "/api/scans/",
        files={"file": ("clean.tf", clean_tf, "text/plain")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "completed"
    assert data["total_resources"] == 4
    assert data["total_findings"] == 0
    assert data["risk_score"]["score"] == 0.0
    assert data["risk_score"]["grade"] == "A"


def test_scan_vulnerable_file(client):
    vuln_tf = (SAMPLES_DIR / "vulnerable.tf").read_text()
    resp = client.post(
        "/api/scans/",
        files={"file": ("vulnerable.tf", vuln_tf, "text/plain")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "completed"
    assert data["total_findings"] > 0
    assert data["risk_score"]["score"] > 50
    assert data["risk_score"]["grade"] in ("D", "F")
    # Check findings are present
    assert len(data["findings"]) == data["total_findings"]


def test_list_scans_after_upload(client):
    # Upload a file first
    clean_tf = (SAMPLES_DIR / "clean.tf").read_text()
    client.post(
        "/api/scans/",
        files={"file": ("clean.tf", clean_tf, "text/plain")},
    )
    resp = client.get("/api/scans/")
    assert resp.status_code == 200
    scans = resp.json()
    assert len(scans) >= 1


def test_get_scan_detail(client):
    clean_tf = (SAMPLES_DIR / "clean.tf").read_text()
    create_resp = client.post(
        "/api/scans/",
        files={"file": ("clean.tf", clean_tf, "text/plain")},
    )
    scan_id = create_resp.json()["id"]
    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan_id
    assert "findings" in data
    assert "risk_score" in data


def test_get_scan_not_found(client):
    resp = client.get("/api/scans/99999")
    assert resp.status_code == 404


def test_upload_non_tf_file(client):
    resp = client.post(
        "/api/scans/",
        files={"file": ("readme.md", "# Hello", "text/plain")},
    )
    assert resp.status_code == 400


def test_dashboard_after_scans(client):
    # Upload both files
    clean_tf = (SAMPLES_DIR / "clean.tf").read_text()
    vuln_tf = (SAMPLES_DIR / "vulnerable.tf").read_text()
    client.post(
        "/api/scans/",
        files={"file": ("clean.tf", clean_tf, "text/plain")},
    )
    client.post(
        "/api/scans/",
        files={"file": ("vulnerable.tf", vuln_tf, "text/plain")},
    )
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scans"] == 2
    assert data["total_findings"] > 0
    assert len(data["recent_scans"]) == 2
