# VaultSecure Password Manager

VaultSecure is a desktop-based password and secrets management application developed as a Master's capstone project in Computer Science. The project demonstrates secure software design, encrypted credential storage, multi-factor authentication, password management workflows, backup/restore functionality, and applied DevSecOps principles.

## Project Overview

VaultSecure is designed as a local desktop application for securely storing and managing user credentials. The application uses a Python/PyQt interface with a SQLite backend and cryptographic controls for password protection and vault encryption.

This repository is intended as a portfolio and academic software artifact. It is not currently intended for production use without additional security review, hardening, and deployment testing.

## Key Features

- User registration and login
- Password hashing with per-user salts
- Multi-factor authentication using TOTP
- Encrypted password storage
- Password add, view, update, and delete workflows
- Re-authentication requirements for sensitive actions
- Password strength evaluation
- Password history and reuse checks
- Backup and restore support
- Unit, integration, and security-oriented tests

## Technology Stack

- Python
- PyQt5
- SQLite
- cryptography
- PyOTP
- qrcode
- pytest
- Bandit and Safety for security testing support

## Repository Structure

```text
.
├── main.py                    # Application entry point
├── main_window.py             # Main application window
├── login_screen.py            # Login UI
├── register_screen.py         # Registration UI
├── dashboard_ui.py            # Dashboard and vault management UI
├── vault_ui.py                # Vault-related interface components
├── mfa_ui.py                  # MFA verification UI
├── vaultsecure_backend.py     # Database, authentication, encryption, MFA, and vault logic
├── run_tests.py               # Test runner helper
├── tests/                     # Unit, integration, and security tests
├── requirements.txt           # Python dependencies
├── SECURITY.md                # Security policy and responsible disclosure notes
├── CONTRIBUTING.md            # Contribution guidelines
├── NOTICE.md                  # Project/IP notice
└── LICENSE                    # Open-source license
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/vaultsecure-password-manager.git
cd vaultsecure-password-manager
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the application

```bash
python main.py
```

The application creates a local SQLite database at runtime. The database file is intentionally excluded from version control.

## Running Tests

Run the full test suite with:

```bash
pytest
```

Or use the included helper:

```bash
python run_tests.py
```

Security-oriented checks can be run with tools such as:

```bash
bandit -r .
safety check
```

## Security Notes

VaultSecure is an academic and portfolio project. Before using it for real credential storage, additional production-grade hardening should be completed, including but not limited to:

- Independent security review
- Threat modeling
- Secure key management redesign
- Stronger authenticated encryption design
- Database protection and tamper resistance
- Secure logging review
- Dependency vulnerability monitoring
- Packaging and distribution hardening

Do not store real production credentials in this project without additional security review.

## Academic Context

This project was created as a Master's-level Computer Science capstone project focused on secure software architecture, password management, encryption, MFA, and practical cybersecurity engineering.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
