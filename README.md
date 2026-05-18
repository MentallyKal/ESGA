# ESGA — Enterprise Security Guardrail Auditor

A Python-based, API-first Terraform security scanner that audits infrastructure configuration files against a comprehensive security baseline and presents visual risk analysis through an interactive dashboard.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136+-green.svg)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0+-orange.svg)](https://www.sqlalchemy.org)

## Features

### Core Capabilities
- ✅ **10 Built-in Security Rules** — Scans for critical misconfigurations in Azure and AWS resources
- 📊 **Risk Scoring Algorithm** — Weighted severity scoring (0-100) with letter grades (A-F)
- 🎯 **Terraform HCL Parser** — Native support for `.tf` files using `python-hcl2`
- 💾 **SQLite Database** — Persistent storage of scans, findings, and rules
- 🚀 **REST API** — Full programmatic access to all functionality
- 📈 **Visual Dashboard** — Interactive charts and drill-down capabilities

### Security Rules Coverage

| Rule ID | Resource Type | Severity | Description |
|---------|---------------|----------|-------------|
| `AZURE_STORAGE_PUBLIC_ACCESS` | `azurerm_storage_account` | CRITICAL | Public blob access enabled |
| `AZURE_NSG_SSH_OPEN` | `azurerm_network_security_group` | CRITICAL | SSH port 22 open to 0.0.0.0/0 |
| `AWS_S3_PUBLIC_ACL` | `aws_s3_bucket` | CRITICAL | Public ACL (public-read/write) |
| `AWS_SG_SSH_OPEN` | `aws_security_group` | CRITICAL | Ingress SSH from 0.0.0.0/0 |
| `AWS_IAM_OVERLY_PERMISSIVE` | `aws_iam_policy` | CRITICAL | Wildcard Action: "*" |
| `AZURE_STORAGE_NO_HTTPS` | `azurerm_storage_account` | HIGH | HTTPS not enforced |
| `AWS_S3_NO_ENCRYPTION` | `aws_s3_bucket` | HIGH | Missing server-side encryption |
| `AZURE_STORAGE_LOW_TLS` | `azurerm_storage_account` | MEDIUM | TLS version below 1.2 |
| `AZURE_STORAGE_NO_ENCRYPTION` | `azurerm_storage_account` | MEDIUM | Missing customer-managed encryption |
| `AWS_S3_NO_VERSIONING` | `aws_s3_bucket` | LOW | Versioning not enabled |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ESGA Dashboard                            │
│  (HTML + Chart.js + Vanilla JS)                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI REST API                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │  Scans   │  │  Rules   │  │Dashboard │  │  Static  │       │
│  │ Endpoints│  │ Endpoints│  │ Endpoints│  │  Files   │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Scanner Orchestrator                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ HCL2 Parser  │→ │ Rule Engine  │→ │Risk Scoring  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SQLite Database                             │
│  [rules] [scans] [findings] [risk_scores]                       │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | FastAPI 0.136+ | Async web framework |
| Database | SQLite + SQLAlchemy 2.0 | ORM and persistence |
| Parser | python-hcl2 4.3+ | Terraform HCL parsing |
| Validation | Pydantic 2.0+ | Request/response schemas |
| Frontend | Vanilla JS + Chart.js 4.4 | Dashboard visualization |
| Testing | pytest + httpx | Unit and integration tests |

---

## Quick Start

### Prerequisites

- Python 3.11 or higher
- Poetry (for dependency management)

### Installation

```bash
# Clone the repository
cd /path/to/ESGA

# Install dependencies
poetry install

# Verify installation
poetry run pytest tests/ -v
```

### Running the Server

```bash
# Start the FastAPI server
poetry run uvicorn esga.main:app --host 0.0.0.0 --port 8000

# Server will be available at:
# - Dashboard: http://localhost:8000/
# - API Docs: http://localhost:8000/docs
# - OpenAPI JSON: http://localhost:8000/openapi.json
```

On first startup, you should see:
```
[ESGA] Seeded 10 security rules into database.
INFO:     Application startup complete.
```

---

## Usage

### 1. Visual Dashboard

Navigate to `http://localhost:8000/` to access the interactive dashboard.

**Features:**
- Upload `.tf` files for scanning
- View aggregate metrics (total scans, findings, average score)
- Interactive charts (risk gauge, severity distribution, grade breakdown)
- Recent scans table with drill-down into individual findings

**Workflow:**
1. Click "Choose File" → select a Terraform file
2. Click "Run Scan"
3. View results: risk score, grade, and severity breakdown
4. Click "Details" on any scan to see individual findings

### 2. REST API

#### Upload and Scan

```bash
# Scan a Terraform file
curl -X POST http://localhost:8000/api/scans/ \
  -F "file=@/path/to/main.tf"

# Response:
{
  "id": 1,
  "filename": "main.tf",
  "status": "completed",
  "total_resources": 4,
  "total_findings": 0,
  "risk_score": {
    "score": 0.0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "grade": "A"
  },
  "findings": [],
  "created_at": "2026-05-18T12:34:56"
}
```

#### List All Scans

```bash
# Get all scans (paginated)
curl http://localhost:8000/api/scans/?skip=0&limit=50
```

#### Get Scan Details

```bash
# Get detailed scan results including all findings
curl http://localhost:8000/api/scans/1
```

#### List Security Rules

```bash
# Get all active security rules
curl http://localhost:8000/api/rules/
```

#### Dashboard Summary

```bash
# Get aggregated dashboard data
curl http://localhost:8000/api/dashboard/summary

# Response includes:
# - total_scans, total_findings
# - average_score, worst_score, best_score
# - severity_counts (breakdown by CRITICAL/HIGH/MEDIUM/LOW)
# - grade_distribution (A/B/C/D/F counts)
# - recent_scans (last 10 scans)
```

---

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scans/` | Upload and scan a Terraform file |
| `GET` | `/api/scans/` | List all scans (paginated) |
| `GET` | `/api/scans/{id}` | Get scan details with findings |
| `GET` | `/api/rules/` | List all security rules |
| `GET` | `/api/dashboard/summary` | Get dashboard metrics |
| `GET` | `/` | Serve the dashboard UI |

### Request/Response Schemas

#### ScanDetail

```json
{
  "id": 1,
  "filename": "main.tf",
  "status": "completed",
  "total_resources": 4,
  "total_findings": 2,
  "created_at": "2026-05-18T12:34:56",
  "risk_score": {
    "score": 50.0,
    "critical_count": 2,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "grade": "C"
  },
  "findings": [
    {
      "id": 1,
      "rule_id": 1,
      "resource_name": "azurerm_storage_account.bad_storage",
      "resource_type": "azurerm_storage_account",
      "severity": "CRITICAL",
      "message": "[AZURE_STORAGE_PUBLIC_ACCESS] Azure Storage Public Blob Access: ...",
      "file_path": "main.tf",
      "created_at": "2026-05-18T12:34:56"
    }
  ]
}
```

#### RuleOut

```json
{
  "id": 1,
  "rule_id": "AZURE_STORAGE_PUBLIC_ACCESS",
  "name": "Azure Storage Public Blob Access",
  "description": "The azurerm_storage_account has allow_blob_public_access set to true...",
  "resource_type": "azurerm_storage_account",
  "severity": "CRITICAL",
  "attribute_path": "allow_blob_public_access",
  "condition": "equals",
  "expected_value": "true",
  "enabled": true
}
```

---

## Risk Scoring Algorithm

### Severity Weights

| Severity | Weight (Points) | Example |
|----------|-----------------|---------|
| CRITICAL | 25 | Public S3 bucket, SSH open to world |
| HIGH | 15 | Missing encryption, no HTTPS enforcement |
| MEDIUM | 8 | Low TLS version, missing CMK |
| LOW | 3 | Versioning not enabled |

### Score Calculation

```
Raw Score = Σ (count × weight) for each severity
Final Score = min(100, Raw Score)
```

**Examples:**
- 4 CRITICAL findings = 100 points → Grade F
- 1 CRITICAL + 1 HIGH = 40 points → Grade C
- 3 LOW findings = 9 points → Grade A

### Grade Mapping

| Score Range | Grade | Interpretation |
|-------------|-------|----------------|
| 0 - 10 | A | Excellent — minimal risk |
| 11 - 25 | B | Good — minor issues |
| 26 - 50 | C | Fair — notable concerns |
| 51 - 75 | D | Poor — significant risk |
| 76 - 100 | F | Failing — critical exposure |

---

## Testing

### Run All Tests

```bash
# Run all 40 tests with verbose output
poetry run pytest tests/ -v

# Expected output:
# 40 passed in ~3s
```

### Test Structure

```
tests/
├── conftest.py          # Shared fixtures (db_session, client)
├── test_parser.py       # Terraform HCL parsing (6 tests)
├── test_engine.py       # Rule evaluation logic (15 tests)
├── test_scoring.py      # Risk scoring algorithm (10 tests)
└── test_api.py          # API endpoints (9 tests)
```

### Sample Test Data

```bash
# Test with provided samples
poetry run uvicorn esga.main:app &

# Clean file (expect score 0, grade A)
curl -X POST http://localhost:8000/api/scans/ \
  -F "file=@samples/clean.tf"

# Vulnerable file (expect score 100, grade F)
curl -X POST http://localhost:8000/api/scans/ \
  -F "file=@samples/vulnerable.tf"
```

---

## Database Schema

### Tables

#### `rules`
Stores security rule definitions.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment ID |
| rule_id | String(100) UNIQUE | Machine-readable ID |
| name | String(255) | Human-readable name |
| description | Text | Full explanation |
| resource_type | String(255) | Terraform resource type |
| severity | String(20) | CRITICAL/HIGH/MEDIUM/LOW |
| attribute_path | String(500) | Dot-path into resource |
| condition | String(50) | Evaluation logic |
| expected_value | Text nullable | Comparison value |
| enabled | Boolean | Rule active flag |
| created_at | DateTime | Creation timestamp |

#### `scans`
Stores scan execution metadata.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment ID |
| filename | String(500) | Original filename |
| status | String(20) | completed/failed |
| total_resources | Integer | Resource count |
| total_findings | Integer | Violation count |
| created_at | DateTime | Scan timestamp |

#### `findings`
Stores individual security violations.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment ID |
| scan_id | FK → scans.id | Parent scan |
| rule_id | FK → rules.id | Violated rule |
| resource_name | String(500) | Resource identifier |
| resource_type | String(255) | Resource type |
| severity | String(20) | Denormalized severity |
| message | Text | Human-readable finding |
| file_path | String(500) | Source file |
| created_at | DateTime | Finding timestamp |

#### `risk_scores`
Stores computed risk metrics for each scan.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment ID |
| scan_id | FK → scans.id UNIQUE | One score per scan |
| score | Float | 0.0 - 100.0 |
| critical_count | Integer | CRITICAL finding count |
| high_count | Integer | HIGH finding count |
| medium_count | Integer | MEDIUM finding count |
| low_count | Integer | LOW finding count |
| grade | String(1) | A/B/C/D/F |
| created_at | DateTime | Score timestamp |

---

## Project Structure

```
ESGA/
├── pyproject.toml              # Poetry dependencies
├── README.md                   # This file
├── esga.db                     # SQLite database (created on first run)
├── esga/                       # Main package
│   ├── __init__.py
│   ├── main.py                 # FastAPI app + lifespan
│   ├── config.py               # Settings (DB URL, upload dir)
│   ├── database.py             # SQLAlchemy setup
│   ├── models.py               # ORM models
│   ├── schemas.py              # Pydantic schemas
│   ├── api/                    # API endpoints
│   │   ├── scans.py
│   │   ├── rules.py
│   │   ├── dashboard.py
│   │   └── router.py
│   ├── parser/                 # Terraform parser
│   │   └── terraform.py
│   ├── rules/                  # Security rules
│   │   ├── definitions.py      # 10 rule definitions
│   │   ├── engine.py           # Rule evaluation
│   │   └── seed.py             # DB seeder
│   ├── scanner/                # Scan orchestration
│   │   ├── scanner.py          # Main scanner
│   │   └── scoring.py          # Risk scoring
│   ├── static/                 # Frontend assets
│   │   ├── css/style.css
│   │   └── js/dashboard.js
│   └── templates/              # HTML templates
│       └── dashboard.html
├── samples/                    # Test Terraform files
│   ├── clean.tf                # Secure configuration
│   └── vulnerable.tf           # Insecure configuration
├── tests/                      # Test suite
│   ├── conftest.py
│   ├── test_parser.py
│   ├── test_engine.py
│   ├── test_scoring.py
│   └── test_api.py
└── uploads/                    # Runtime upload directory
```

---

## Extending ESGA

### Adding New Security Rules

1. **Define the rule** in `esga/rules/definitions.py`:

```python
{
    "rule_id": "AWS_RDS_PUBLIC_ACCESS",
    "name": "AWS RDS Public Access",
    "description": "RDS instance is publicly accessible...",
    "resource_type": "aws_db_instance",
    "severity": "CRITICAL",
    "attribute_path": "publicly_accessible",
    "condition": "equals",
    "expected_value": "true",
}
```

2. **Restart the server** — the seeder will insert new rules automatically.

3. **Test the rule** — upload a Terraform file with the target resource.

### Custom Conditions

For complex logic, add a custom condition handler in `esga/rules/engine.py`:

```python
def _check_my_custom_condition(attrs: dict) -> bool:
    """Custom evaluation logic."""
    # Your logic here
    return violation_detected

# Register in evaluate_resource():
elif condition == "my_custom_condition":
    violated = _check_my_custom_condition(attrs)
```

### Adjusting Severity Weights

Modify the weights in `esga/scanner/scoring.py`:

```python
SEVERITY_WEIGHTS = {
    "CRITICAL": 30,  # Increase from 25
    "HIGH": 20,      # Increase from 15
    "MEDIUM": 10,    # Increase from 8
    "LOW": 5,        # Increase from 3
}
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find and kill the process
lsof -ti:8000 | xargs kill -9

# Or use a different port
poetry run uvicorn esga.main:app --port 8001
```

### Database Locked Error

```bash
# Stop all uvicorn processes
pkill -f uvicorn

# Remove the database file
rm esga.db

# Restart server (will recreate DB)
poetry run uvicorn esga.main:app --host 0.0.0.0 --port 8000
```

### Tests Failing

```bash
# Ensure virtual environment is active
poetry shell

# Reinstall dependencies
poetry install

# Run tests with verbose output
poetry run pytest tests/ -v -s
```

### Dashboard Not Loading

Check browser console for errors. Common issues:
- Chart.js CDN blocked (firewall/proxy)
- CORS issues (use same-origin requests)
- Static files not mounted (check `esga/main.py`)

---

## Performance Considerations

### Scalability

- **Current limit:** SQLite handles up to ~10,000 scans efficiently
- **For production:** Replace SQLite with PostgreSQL/MySQL
  - Update `DATABASE_URL` in `esga/config.py`
  - Remove `connect_args={"check_same_thread": False}`

### Optimization Tips

1. **Indexing:** Add indexes on frequently queried columns:
   ```python
   scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
   ```

2. **Batch uploads:** Use background tasks for multiple files:
   ```python
   from fastapi import BackgroundTasks
   background_tasks.add_task(run_scan, db, filename, content)
   ```

3. **Caching:** Cache rules in memory (they rarely change):
   ```python
   from functools import lru_cache
   @lru_cache(maxsize=1)
   def get_rules(db: Session):
       return db.query(Rule).filter(Rule.enabled == True).all()
   ```

---

## Security Notes

### Input Validation

- `.tf` file uploads are validated by extension
- `python-hcl2` handles malformed HCL gracefully
- SQL injection prevented by SQLAlchemy ORM

### Authentication

This MVP does not include authentication. For production:

1. Add OAuth2/JWT authentication:
   ```python
   from fastapi.security import OAuth2PasswordBearer
   oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
   ```

2. Protect endpoints:
   ```python
   @router.post("/api/scans/")
   async def create_scan(token: str = Depends(oauth2_scheme)):
       # Verify token
   ```

---

## License

MIT License — See LICENSE file for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Make changes and add tests
4. Run test suite (`poetry run pytest tests/ -v`)
5. Commit with descriptive message
6. Push and create a Pull Request

---

## Changelog

### v0.1.0 (2026-05-18)
- Initial release
- 10 security rules (Azure + AWS)
- REST API with 6 endpoints
- Interactive dashboard with Chart.js
- SQLite database with full ORM
- 40 passing tests
- Complete API documentation

---

## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Review test cases in `tests/` for examples

---

**Built with Python 3.11, FastAPI, SQLAlchemy 2.0, and Chart.js**
