> **Dynamic HTTP Security Header Analyzer & Pentest CLI Tool**  
> Automatically fetches live HTTP security header guidelines directly from the official **OWASP CheatSheet Series** and evaluates web application header defenses.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP Sync](https://img.shields.io/badge/OWASP-Live%20Sync-orange.svg)](https://cheatsheetseries.owasp.org/)

## ✨ Key Features

* 🔄 **Live OWASP CheatSheet Sync:** Dynamically fetches and parses up-to-date header security recommendations directly from OWASP.
* 📊 **Automated Security Scoring Engine:** Evaluates target defenses on a 0–100 point scale and assigns an enterprise grade (`A+` to `F`).
* 🚨 **Categorized Vulnerability Assessment:**
  * **Missing Mandatory Security Headers:** Detects absence of `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, and isolation headers.
  * **Information Disclosure Detection:** Identifies fingerprinting headers such as `Server`, `X-Powered-By`, and `X-AspNet-Version`.
  * **Configuration Flaws:** Audits directive weaknesses like `unsafe-inline` in CSP and unsafe wildcards in CORS.
  * **Set-Cookie Attribute Audit:** Verifies presence of essential security flags (`HttpOnly`, `Secure`, and `SameSite`).
* 🌐 **Cross-Origin & Isolation Policy Audit:** Evaluates modern isolation defenses including `COOP`, `COEP`, `CORP`, and `CORS`.
* 🎨 **Rich Cyber Dashboard UI:** Clean, color-coded, SOC-style terminal display designed for security analysts and sysadmins.

---

## 🎯 Scoring & Grading Criteria

| Grade | Score Range | Description |
| :---: | :---: | :--- |
| **A+** | 90 - 100 | Exceptional security posture; all mandatory headers & hardening flags enforced. |
| **A** | 80 - 89 | Strong defenses; minor non-critical security headers missing. |
| **B** | 70 - 79 | Moderate security; basic protections active but key directives missing. |
| **C** | 50 - 69 | Weak posture; missing critical headers like CSP or HSTS. |
| **D** | 30 - 49 | Highly vulnerable; multiple mandatory security headers absent. |
| **F** | 0 - 29 | Critical security failure; severe vulnerability to injection/clickjacking/fingerprinting. |

---

## 🛠️ Installation & Execution

### Prerequisites
* Python 3.8 or higher
* `pip` package manager

### Quick Start

```bash
# Clone the repository
git clone https://github.com/rootlayer/SecHeaderScope.git
cd SecHeaderScope

# Install required packages
pip install -r requirements.txt

# Run a scan against any target
python3 secheader_scope.py target.com
