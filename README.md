# 🔒 Security Agent

A comprehensive, multi-scanner security tool that automates vulnerability detection in your codebase. Combines **Bandit** (SAST), **osv-scanner** (SCA), and **TruffleHog** (secrets detection) with AI-powered insights.

## Features

✅ **Multi-Scanner Support**
- Static Application Security Testing (SAST) with Bandit
- Software Composition Analysis (SCA) with osv-scanner
- Secret/credential scanning with TruffleHog

✅ **Unified Reporting**
- Aggregated JSON reports with normalized findings
- Severity scoring and prioritization
- Detailed file locations and line numbers

✅ **AI-Powered Insights**
- Google Generative AI integration for vulnerability analysis
- Contextual remediation suggestions
- Automated risk assessment

✅ **CI/CD Ready**
- GitHub Actions workflow included
- Automatic PR comments with security summaries
- Artifact retention for compliance

✅ **Enterprise Features**
- Database support (PostgreSQL) for findings storage
- Flask REST API for integrations
- CORS-enabled for cross-origin requests

## Installation

### Prerequisites
- Python 3.10+
- pip or conda

### From Source

```bash
git clone https://github.com/Diald/security-agent.git
cd security-agent
pip install -e .
```

### Required External Tools

The following tools are installed automatically in CI/CD:
- `bandit` - Python code analysis
- `osv-scanner` - Dependency vulnerability scanning
- `trufflehog` - Secret detection

## Quick Start

### Command Line Usage

```bash
# Run security scan on current directory
security-agent --repo-path . --format json

# Scan specific folder
security-agent --repo-path ./src --format json --output reports/

# With verbosity
security-agent --repo-path . --verbose
```

### CLI Options

```
--repo-path PATH          Path to scan (default: current directory)
--format FORMAT           Output format: json, html, csv (default: json)
--output PATH             Output directory (default: reports/)
--verbose, -v             Enable verbose logging
--config FILE             Path to config file
--api-key KEY            Gemini API key (or set GEMINI_API_KEY env var)
```

## Configuration

### Environment Variables

```bash
# Required for AI insights
export GEMINI_API_KEY=your_gemini_api_key

# Optional: Database
export DATABASE_URL=postgresql://user:pass@localhost/security_agent
```

### Tool Configuration

Create a `.security-agent.yml` in your project root:

```yaml
bandit:
  exclude_dirs:
    - tests
    - venv
    - node_modules
  severity: MEDIUM

osv-scanner:
  lockfile: requirements.txt
  skip_git: false

trufflehog:
  only_verified: true
  json: true
```

## GitHub Actions Integration

Add to your workflow (`.github/workflows/security-scan.yml`):

```yaml
- name: Run Security Agent
  env:
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
  run: |
    security-agent --repo-path . --format json
```

## Output

### JSON Report Structure

```json
{
  "summary": {
    "status": "FAIL",
    "score": 42,
    "total_findings": 5,
    "timestamp": "2026-05-08T10:30:00Z"
  },
  "findings": [
    {
      "id": "bandit.B101",
      "severity": "HIGH",
      "type": "hardcoded_password",
      "message": "Possible hardcoded password",
      "file_path": "src/config.py",
      "line_start": 15,
      "line_end": 15,
      "remediation": "Use environment variables or secrets manager",
      "ai_insight": "This hardcoded credential poses a significant security risk..."
    }
  ]
}
```

## Architecture

### Components

- **CLI Module** (`cli.py`) - Command-line interface
- **Scanner Module** (`scanners/`) - Integration with security tools
- **Reporter Module** (`reporters/`) - Report generation
- **API Module** (`api/`) - REST endpoints
- **Database Module** (`db/`) - Vulnerability storage

### Data Flow

```
Repository → [Bandit, osv-scanner, TruffleHog] → Aggregation → AI Analysis → JSON Report → PR Comment
```

## Severity Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Immediate exploitation risk, deploy hotfix |
| HIGH | Significant vulnerability, fix in next sprint |
| MEDIUM | Notable issue, schedule for fixing |
| LOW | Minor issue or hardening recommendation |
| INFO | Informational findings |

## API Usage

Start the Flask REST API:

```bash
security-agent --api --port 5000
```

### Endpoints

```
POST /api/scan          - Scan a repository
GET  /api/findings      - Get recent findings
GET  /api/health        - Health check
```

## Troubleshooting

### Gemini API key not found
```bash
export GEMINI_API_KEY=your_key
```

### osv-scanner fails
Ensure `pip install -e .` was run and tool is in PATH

### Permission denied on TruffleHog install
The CI/CD workflow handles permissions automatically

## Contributing

Pull requests are welcome! Please follow:
1. PEP 8 style guidelines
2. Add tests for new features
3. Update documentation

## License

MIT License - see LICENSE file

## Support

- 📖 [Issues](https://github.com/Diald/security-agent/issues)
- 💬 [Discussions](https://github.com/Diald/security-agent/discussions)

---

**Maintained by:** Diald  
**Latest Version:** 0.1.0  
**Python:** 3.10+