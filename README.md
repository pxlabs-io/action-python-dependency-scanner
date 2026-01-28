# Python Dependency Scanner

Scans Python dependencies for known security vulnerabilities using safety and pip-audit tools.

## Usage

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: owner/python-dependency-scanner@v1
        with:
          requirements-file: requirements.txt
          fail-on-vulnerabilities: true
          output-format: text
```

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `requirements-file` | Path to requirements file | No | `requirements.txt` |
| `ignore-vulnerabilities` | Comma-separated list of vulnerability IDs to ignore | No | `` |
| `fail-on-vulnerabilities` | Fail the action if vulnerabilities are found | No | `true` |
| `output-format` | Output format (json, text, sarif) | No | `text` |
| `working-directory` | Working directory to scan | No | `.` |

## Outputs

| Name | Description |
|------|-------------|
| `vulnerabilities-found` | Number of vulnerabilities found |
| `report-file` | Path to the generated security report |
| `exit-code` | Exit code of the scan (0 = no vulnerabilities, 1 = vulnerabilities found) |

## Requirements

- Python 3.9+
- pip package manager
- Requirements file with Python dependencies

## License

MIT License - see [LICENSE](LICENSE) file for details.