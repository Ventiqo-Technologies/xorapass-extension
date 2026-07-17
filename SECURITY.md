# Security Policy

We take the security of XoraPass seriously. If you believe you have found a security vulnerability, please report it to us responsibly as detailed below.

---

## 1. Supported Versions

We actively support and apply security patches to the following versions of XoraPass:

| Version | Supported |
|---------|-----------|
| >= 1.0.0 | ✅ Yes |
| < 1.0.0  | ❌ No  |

---

## 2. Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

Instead, please send all security vulnerability reports directly via email to:

👉 **[security@xorapass.com](mailto:security@xorapass.com)**

### Please include the following details in your report:
1. **Description:** A detailed description of the vulnerability and its potential impact.
2. **Steps to Reproduce:** Clear, step-by-step instructions or proof-of-concept (PoC) code to reproduce the issue.
3. **Environment Details:** Operating System, browser version, extension version, or API endpoint details where applicable.
4. **Encryption Keys:** If referencing specific vault payloads, remember that we do not hold your master password or encryption keys.

---

## 3. Our Security Response Process

Once a vulnerability report is received, the XoraPass Security Team will:
1. **Acknowledge:** Confirm receipt of your report within **48 hours**.
2. **Validate:** Investigate and reproduce the issue to determine severity.
3. **Remediate:** Work on a fix. We aim to resolve all validated high-severity vulnerabilities within **30 days**.
4. **Publish:** Release the security patch and optionally coordinate a public advisory acknowledging your contribution (if requested).

---

## 4. Responsible Disclosure Guidelines

To protect our users, we ask that you follow these responsible disclosure principles:
* Give us reasonable time to investigate and fix the issue before sharing details publicly.
* Do not attempt to access, modify, or delete user vault data that does not belong to you.
* Do not perform Denial of Service (DoS) attacks or run automated brute-force scans against production servers.
