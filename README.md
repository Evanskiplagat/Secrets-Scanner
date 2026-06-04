# Secret Scanner

Secret Scanner is a production-oriented Python CLI for detecting exposed credentials, tokens, keys, and other sensitive data in source repositories. It is designed for Cloud Engineers, Security Engineers, and DevSecOps teams that need fast repository scanning, secure reporting, and practical CI integration.

## Features

- Recursive scanning for Python, JavaScript, TypeScript, Java, YAML, JSON, `.env`, Terraform, and `.tfvars` files
- Secret detection for AWS, Azure, Google, GitHub, JWT, Stripe, bearer tokens, passwords, API keys, private keys, SSH keys, and database connection strings
- Hardcoded credential detection and entropy-based heuristics for suspicious secrets
- Risk classification with `Critical`, `High`, `Medium`, and `Low`
- Rich terminal output with progress indicator and masked previews
- JSON, CSV, and HTML report generation
- Directory exclusions with built-in defaults and custom additions
- Multi-threaded scanning suitable for large repositories
- Exit codes suitable for CI pipelines

## Project Structure

```text
secret-scanner/
├── scanner/
│   ├── detectors/
│   ├── core/
│   ├── reports/
│   └── utils/
├── tests/
├── docs/
├── main.py
├── requirements.txt
├── Dockerfile
└── README.md
```

## Installation

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Run a scan:

```bash
python main.py scan ./project
```

Generate reports:

```bash
python main.py scan ./project --json
python main.py scan ./project --csv findings.csv
python main.py scan ./project --html findings.html
```

Filter by severity and add exclusions:

```bash
python main.py scan ./project --severity high --exclude vendor --exclude coverage
```

## Exit Codes

- `0`: No findings at `High` or above
- `1`: At least one `High` or `Critical` finding detected
- `2`: Invalid or missing target

## Supported Secret Types

- AWS Access Keys
- AWS Secret Keys
- Azure Keys
- Google API Keys
- GitHub Tokens
- JWT Tokens
- Stripe Keys
- Database Connection Strings
- API Keys
- Passwords
- Private Keys
- SSH Keys
- Bearer Tokens
- Hardcoded Credentials
- High Entropy Secrets

## Security Model

- Full secret values are never printed to the terminal
- Reports include only masked previews
- Detection results omit raw secret material from persisted output
- File decoding uses safe UTF-8 fallback behavior

## CI and Container Support

GitHub Actions workflow:

```bash
pytest
python main.py scan .
```

Docker usage:

```bash
docker build -t secret-scanner .
docker run --rm -v "$PWD:/workspace" secret-scanner scan /workspace
```

## Development

```bash
pytest
python main.py scan tests --severity low
```

## Limitations

- Regex-based scanning can produce false positives in synthetic fixtures or test data
- Entropy heuristics intentionally bias toward surfacing suspicious tokens rather than minimizing every false positive
- This scanner inspects working tree files; it does not scan git history

## License

Use and adapt within your internal security tooling or delivery pipelines as needed.

