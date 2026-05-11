# Security Policy

## Project Status

VaultSecure is an academic and portfolio project created to demonstrate secure software design concepts. It should not be treated as production-ready password management software without additional security review and hardening.

## Supported Versions

This repository is maintained as a portfolio project. Security fixes may be applied to the latest version of the main branch.

## Reporting Security Issues

If you identify a security issue, please avoid opening a public issue that contains exploit details. Instead, contact the repository owner privately through the contact method listed on the GitHub profile.

Please include:

- A summary of the issue
- Steps to reproduce
- Potential impact
- Suggested remediation, if available

## Known Security Considerations

Before any production use, the project should undergo additional review for:

- Encryption mode and key management design
- Secure database storage and local file protections
- MFA recovery and reset flows
- Input validation and error handling
- Dependency vulnerabilities
- Secure packaging and distribution
- Threat modeling and abuse-case testing

Do not use this project to store real secrets or production credentials without independent security validation.
