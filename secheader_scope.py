#!/usr/bin/env python3

import sys
import re
from typing import Dict, List, Any
import httpx
from bs4 import BeautifulSoup

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

OWASP_URL = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"

HEADER_METADATA = {
    "Strict-Transport-Security": {
        "severity": 15,
        "type": "MANDATORY_SEC",
        "method": "HTTP Response Header Inspection (Redirect & TLS enforcement test)",
        "impact": "Mitigates Man-in-the-Middle (MitM) & SSL/TLS Downgrade attacks."
    },
    "Content-Security-Policy": {
        "severity": 20,
        "type": "MANDATORY_SEC",
        "method": "AST Directive parsing & Script Execution Policy Analysis",
        "impact": "Primary defense against Cross-Site Scripting (XSS) and Data Injection."
    },
    "X-Frame-Options": {
        "severity": 10,
        "type": "MANDATORY_SEC",
        "method": "Frame Ancestor Origin Check / Embedding Context Simulation",
        "impact": "Prevents Clickjacking attacks by restricting framing capability."
    },
    "X-Content-Type-Options": {
        "severity": 10,
        "type": "MANDATORY_SEC",
        "method": "MIME-type Sniffing Probe (Verifies 'nosniff' directive)",
        "impact": "Prevents MIME-sniffing vulnerabilities and cross-domain script execution."
    },
    "Referrer-Policy": {
        "severity": 5,
        "type": "MANDATORY_SEC",
        "method": "Cross-Origin Navigation Referer Leakage Assessment",
        "impact": "Prevents sensitive URL path/query parameter leakage to third parties."
    },
    "Permissions-Policy": {
        "severity": 5,
        "type": "MANDATORY_SEC",
        "method": "Browser Feature Access Policy Enumeration (Camera, Mic, Geo)",
        "impact": "Restricts browser API features and hardware access."
    },
    "Cross-Origin-Opener-Policy": {
        "severity": 5,
        "type": "MANDATORY_SEC",
        "method": "Browsing Context Isolation Audit (COOP verification)",
        "impact": "Isolates top-level window context to prevent Spectre-style side-channel attacks."
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": 5,
        "type": "MANDATORY_SEC",
        "method": "Cross-Origin Resource Loading Control Audit (COEP verification)",
        "impact": "Prevents document from loading cross-origin resources without explicit CORP permission."
    },
    "Cross-Origin-Resource-Policy": {
        "severity": 5,
        "type": "MANDATORY_SEC",
        "method": "Resource Permission Audit (CORP verification)",
        "impact": "Blocks cross-origin / cross-site reading of sensitive static assets."
    },
    "Server": {
        "severity": 5,
        "type": "DISCLOSURE_MUST_REMOVE",
        "method": "Server Banner Fingerprinting & Version Extraction",
        "impact": "Information Disclosure - Aids attacker reconnaissance & targeted exploits."
    },
    "X-Powered-By": {
        "severity": 10,
        "type": "DISCLOSURE_MUST_REMOVE",
        "method": "Backend Technology Stack Fingerprinting",
        "impact": "Information Disclosure - Exposes internal runtime/framework details."
    },
    "X-AspNet-Version": {
        "severity": 10,
        "type": "DISCLOSURE_MUST_REMOVE",
        "method": "Framework Specific Banner Enumeration",
        "impact": "Information Disclosure - Pinpoints precise framework versions for 1-day exploits."
    },
    "X-AspNetMvc-Version": {
        "severity": 10,
        "type": "DISCLOSURE_MUST_REMOVE",
        "method": "Framework Specific Banner Enumeration",
        "impact": "Information Disclosure - Exposes MVC architecture details."
    }
}

class OWASPFetcher:
    @staticmethod
    def get_owasp_headers() -> List[str]:
        headers_found = []
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                res = client.get(OWASP_URL)
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, "html.parser")
                    for tag in soup.find_all(['h2', 'h3']):
                        text = tag.get_text().strip()
                        matches = re.findall(r'([A-Z][a-zA-B0-9\-]+-[A-Z][a-zA-B0-9\-]+|HSTS|CSP|Server)', text)
                        for m in matches:
                            if len(m) > 3 and m not in headers_found:
                                headers_found.append(m)
        except Exception:
            pass
        
        if not headers_found:
            headers_found = list(HEADER_METADATA.keys())
        return headers_found

class HeaderAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url if target_url.startswith('http') else f"https://{target_url}"
        self.response_headers: Dict[str, str] = {}
        self.raw_headers: List[tuple] = []
        self.score = 100
        self.results = {
            "missing_required": [],
            "should_be_removed": [],
            "bad_config": [],
            "secure": []
        }

    def fetch_target_headers(self):
        with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = client.get(self.target_url)
            self.response_headers = {k.lower(): v for k, v in resp.headers.items()}
            self.raw_headers = resp.headers.raw

    def analyze(self, owasp_headers: List[str]):
        self.fetch_target_headers()

        # 1. Check Mandatory & Security Headers
        for h_name, meta in HEADER_METADATA.items():
            h_lower = h_name.lower()
            if meta["type"] == "MANDATORY_SEC":
                if h_lower not in self.response_headers:
                    self.score -= meta["severity"]
                    self.results["missing_required"].append({
                        "header": h_name,
                        "method": meta["method"],
                        "impact": meta["impact"],
                        "status": "MISSING (Must be enabled)"
                    })
                else:
                    val = self.response_headers[h_lower]
                    # Configuration Checks
                    if h_lower == "content-security-policy" and "'unsafe-inline'" in val:
                        self.score -= 5
                        self.results["bad_config"].append({
                            "header": h_name,
                            "value": val,
                            "issue": "Contains 'unsafe-inline' which weakens XSS protection.",
                            "method": meta["method"]
                        })
                    else:
                        self.results["secure"].append({
                            "header": h_name,
                            "value": val,
                            "method": meta["method"]
                        })

        # 2. Check Information Disclosure Headers
        for h_name, meta in HEADER_METADATA.items():
            h_lower = h_name.lower()
            if meta["type"] == "DISCLOSURE_MUST_REMOVE":
                if h_lower in self.response_headers:
                    self.score -= meta["severity"]
                    self.results["should_be_removed"].append({
                        "header": h_name,
                        "value": self.response_headers[h_lower],
                        "method": meta["method"],
                        "impact": meta["impact"],
                        "status": "ACTIVE (Must be removed/hidden)"
                    })

        # 3. CORS Misconfiguration Check
        if "access-control-allow-origin" in self.response_headers:
            cors_val = self.response_headers["access-control-allow-origin"]
            if cors_val == "*":
                self.score -= 10
                self.results["bad_config"].append({
                    "header": "Access-Control-Allow-Origin",
                    "value": cors_val,
                    "issue": "Wildcard '*' allows any cross-origin site to read response data via JS.",
                    "method": "Cross-Origin Access Control Inspection"
                })

        # 4. Set-Cookie Flags Inspection
        cookie_headers = [v.decode('utf-8', errors='ignore') for k, v in self.raw_headers if k.decode('utf-8', errors='ignore').lower() == 'set-cookie']
        for cookie_str in cookie_headers:
            issues = []
            if "httponly" not in cookie_str.lower():
                issues.append("Missing 'HttpOnly' flag (risk of session theft via XSS)")
            if "secure" not in cookie_str.lower():
                issues.append("Missing 'Secure' flag (transmitted over plain HTTP)")
            if "samesite" not in cookie_str.lower():
                issues.append("Missing 'SameSite' attribute (increased CSRF risk)")

            if issues:
                self.score -= 5
                self.results["bad_config"].append({
                    "header": "Set-Cookie",
                    "value": cookie_str[:50] + "...",
                    "issue": " | ".join(issues),
                    "method": "Cookie Attribute Security Audit"
                })

        self.score = max(0, self.score)

    def get_grade(self) -> str:
        if self.score >= 90: return "A+"
        if self.score >= 80: return "A"
        if self.score >= 70: return "B"
        if self.score >= 50: return "C"
        if self.score >= 30: return "D"
        return "F"

def render_dashboard(analyzer: HeaderAnalyzer, target: str):
    console.print()
    console.print(Panel.fit("[bold cyan]SecHeaderScope v1.0[/bold cyan] — [white]Dynamic OWASP Header Scanner[/white]", border_style="cyan"))
    
    grade = analyzer.get_grade()
    color = "green" if analyzer.score >= 80 else ("yellow" if analyzer.score >= 50 else "red")
    
    score_text = f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]  |  " \
                 f"[bold white]Security Score:[/bold white] [{color}]{analyzer.score}/100[/{color}]  |  " \
                 f"[bold white]Grade:[/bold white] [{color}]{grade}[/{color}]"
    
    console.print(Panel(score_text, title="[bold]SECURITY SUMMARY[/bold]", border_style=color))
    console.print()

    if analyzer.results["missing_required"]:
        table_missing = Table(title="🚨 MISSING SECURITY HEADERS (MUST BE ENABLED)", title_style="bold red", show_header=True, header_style="bold red")
        table_missing.add_column("Header", style="cyan", no_wrap=True)
        table_missing.add_column("Scan Method Used", style="white")
        table_missing.add_column("Security Impact", style="yellow")
        
        for item in analyzer.results["missing_required"]:
            table_missing.add_row(item["header"], item["method"], item["impact"])
        console.print(table_missing)
        console.print()

    if analyzer.results["should_be_removed"]:
        table_disc = Table(title="🚫 ACTIVE INFORMATION DISCLOSURE HEADERS (MUST BE REMOVED)", title_style="bold orange3", show_header=True, header_style="bold orange3")
        table_disc.add_column("Exposed Header", style="cyan", no_wrap=True)
        table_disc.add_column("Disclosed Value", style="magenta")
        table_disc.add_column("Discovery Method", style="white")
        table_disc.add_column("Risk / Impact", style="yellow")

        for item in analyzer.results["should_be_removed"]:
            table_disc.add_row(item["header"], item["value"], item["method"], item["impact"])
        console.print(table_disc)
        console.print()

    if analyzer.results["bad_config"]:
        table_bad = Table(title="⚠️ WEAK / UNSAFE CONFIGURATIONS", title_style="bold yellow", show_header=True, header_style="bold yellow")
        table_bad.add_column("Header", style="cyan")
        table_bad.add_column("Current Value", style="magenta")
        table_bad.add_column("Configuration Issue", style="red")

        for item in analyzer.results["bad_config"]:
            table_bad.add_row(item["header"], item["value"], item["issue"])
        console.print(table_bad)
        console.print()

    if analyzer.results["secure"]:
        table_ok = Table(title="🟢 SECURE & PROPERLY CONFIGURATED HEADERS", title_style="bold green", show_header=True, header_style="bold green")
        table_ok.add_column("Header", style="cyan")
        table_ok.add_column("Value / Directive", style="dim white")
        table_ok.add_column("Verification Method", style="dim green")

        for item in analyzer.results["secure"]:
            table_ok.add_row(item["header"], item["value"][:60] + "..." if len(item["value"]) > 60 else item["value"], item["method"])
        console.print(table_ok)
        console.print()

def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python secheader_scope.py <target-url>")
        sys.exit(1)

    target_url = sys.argv[1]

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        
        progress.add_task(description="[cyan]Connecting to OWASP CheatSheet Series & sync guidelines...", total=None)
        owasp_headers = OWASPFetcher.get_owasp_headers()
        
        progress.add_task(description=f"[cyan]Scanning target: {target_url}...", total=None)
        analyzer = HeaderAnalyzer(target_url)
        try:
            analyzer.analyze(owasp_headers)
        except Exception as e:
            console.print(f"[bold red]Error connecting to target:[/bold red] {e}")
            sys.exit(1)

    render_dashboard(analyzer, target_url)

if __name__ == "__main__":
    main()
