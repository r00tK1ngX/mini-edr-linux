# Mini EDR for Linux

An educational Mini Endpoint Detection and Response (EDR) system for monitoring Linux endpoints, detecting suspicious activity through explainable rules, and displaying security alerts in a centralized web dashboard.

> **Project status:** Initial development. Features and test coverage will be updated as implementation progresses.

## Objectives

- Collect basic Linux endpoint telemetry.
- Monitor running processes and system resource usage.
- Detect file changes in designated protected directories using SHA-256 hashes.
- Generate and manage security alerts through a centralized Flask server.
- Display endpoint status, telemetry, and alerts in a web dashboard.

## Architecture

The project consists of four main components:

1. **Linux Agent:** Collects endpoint telemetry and reports it to the server.
2. **Flask API Server:** Receives and validates agent data.
3. **Detection Engine:** Evaluates telemetry against configurable detection rules.
4. **SQLite Database and Web Dashboard:** Stores records and presents endpoints, events, and alerts.

## Technology Stack

- Python
- Flask
- SQLite
- psutil
- HTML, CSS, and JavaScript
- pytest

## Development Environment

The project is developed and tested in a Linux virtual machine running in VirtualBox.

During early development, the Agent and Server may run on the same virtual machine. Additional virtual machines can be used later to simulate multiple endpoints.

## Project Structure

```text
mini-edr-linux/
├── agent/
├── server/
├── detection/
├── config/
├── templates/
├── static/
├── tests/
├── docs/
├── data/
├── logs/
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Runtime configuration, database initialization, and startup commands will be documented as the corresponding features are implemented.

## Scope and Limitations

This is an educational security project, not a production-grade EDR product.

- Detection is based on explicit rules, not machine learning.
- A file hash change is an indicator for investigation, not proof of malware.
- Initial development targets Linux endpoints.
- Automated process termination, malware sandboxing, and production deployment are outside the initial scope.

## Security

- Never commit real credentials, API tokens, private keys, or sensitive telemetry.
- Use isolated lab environments for security testing.
- HTTP may be used only in an isolated local lab; use HTTPS and stronger deployment controls outside that environment.

## Testing

Automated API and detection-rule tests will be added as implementation progresses.

## License

License not yet selected.

