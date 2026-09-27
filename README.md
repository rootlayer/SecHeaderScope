# 🛡️ SecHeaderScope v1.0

> **Dynamic HTTP Security Header Analyzer & Pentest CLI Tool**
> Automatically fetches live HTTP security header guidelines directly from the official OWASP CheatSheet Series and evaluates web application header defenses.

## ✨ Features

* 🔄 **Live OWASP Sync:** Dynamically syncs with the latest OWASP HTTP Headers Cheat Sheet.
* 📊 **Security Scoring Engine:** Calculates a 0–100 security score and assigns a security grade (A+ to F).
* 🚨 **Categorized Findings:** Missing Security Headers, Information Disclosure, Weak Configs.
* 🍪 **Set-Cookie Inspection:** Verifies HttpOnly, Secure, and SameSite flags.
* 🌐 **Cross-Origin Security:** Analyzes COOP, COEP, CORP, and CORS policies.
* 🎨 **Rich Cyber Terminal UI:** Clean, color-coded dashboard output built for security analysts.

## 🚀 Installation & Usage

```bash
git clone [https://github.com/rootlayer/SecHeaderScope.git](https://github.com/rootlayer/SecHeaderScope.git)
cd SecHeaderScope
pip install -r requirements.txt
python3 secheader_scope.py target.com
```
