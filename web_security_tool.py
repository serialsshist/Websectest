import requests
import re
import threading
import json
from urllib.parse import urljoin

# Core Framework for Web Security Testing Tool
class WebAppSecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.vulnerabilities = []

    def log_vulnerability(self, vuln_type, details):
        print(f"[VULNERABILITY FOUND] {vuln_type}: {details}")
        self.vulnerabilities.append({"type": vuln_type, "details": details})

    def sql_injection_test(self, params):
        """Test for SQL Injection vulnerabilities."""
        print("[INFO] Testing for SQL Injection...")
        payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1"]
        for param in params:
            for payload in payloads:
                # Construct test URL
                test_url = self.base_url + "?"
                test_params = {key: (payload if key == param else value) for key, value in params.items()}
                response = requests.get(test_url, params=test_params)

                # Simple heuristic to check for SQLi vulnerability
                if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                    self.log_vulnerability("SQL Injection", f"Parameter: {param}, Payload: {payload}")
                    break

    def xss_test(self, params):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        print("[INFO] Testing for XSS...")
        payload = "<script>alert(1)</script>"
        for param in params:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            response = requests.get(self.base_url, params=test_params)

            if payload in response.text:
                self.log_vulnerability("XSS", f"Parameter: {param}, Payload: {payload}")

    def directory_traversal_test(self):
        """Test for Directory Traversal vulnerabilities."""
        print("[INFO] Testing for Directory Traversal...")
        payloads = ["../../../../etc/passwd", "../..//../..//../etc/passwd"]
        for payload in payloads:
            test_url = urljoin(self.base_url, payload)
            response = requests.get(test_url)

            if "root:x:" in response.text:  # Typical content in /etc/passwd
                self.log_vulnerability("Directory Traversal", f"Payload: {payload}")
                break

    def local_file_inclusion_test(self, params):
        """Test for Local File Inclusion (LFI) vulnerabilities."""
        print("[INFO] Testing for Local File Inclusion...")
        payloads = ["../../../../etc/passwd", "../..//../..//../etc/passwd"]
        for param in params:
            for payload in payloads:
                test_params = {key: (payload if key == param else value) for key, value in params.items()}
                response = requests.get(self.base_url, params=test_params)

                if "root:x:" in response.text:  # Typical content in /etc/passwd
                    self.log_vulnerability("Local File Inclusion", f"Parameter: {param}, Payload: {payload}")

    def open_url_redirect_test(self, params):
        """Test for Open URL Redirect vulnerabilities."""
        print("[INFO] Testing for Open URL Redirect...")
        payload = "http://malicious.com"
        for param in params:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            response = requests.get(self.base_url, params=test_params, allow_redirects=False)

            if response.status_code in [301, 302] and "malicious.com" in response.headers.get("Location", ""):
                self.log_vulnerability("Open URL Redirect", f"Parameter: {param}, Payload: {payload}")

    def ldap_injection_test(self, params):
        """Test for LDAP Injection vulnerabilities."""
        print("[INFO] Testing for LDAP Injection...")
        payloads = ["*)(&", "(objectClass=*)"]
        for param in params:
            for payload in payloads:
                test_params = {key: (payload if key == param else value) for key, value in params.items()}
                response = requests.get(self.base_url, params=test_params)

                if "ldap" in response.text.lower():
                    self.log_vulnerability("LDAP Injection", f"Parameter: {param}, Payload: {payload}")

    def hidden_directory_scan(self):
        """Scan for hidden directories."""
        print("[INFO] Scanning for hidden directories...")
        wordlist = ["admin", "backup", "hidden", "test"]  # Example wordlist; extend as needed
        for word in wordlist:
            test_url = urljoin(self.base_url, word)
            response = requests.get(test_url)

            if response.status_code == 200:
                self.log_vulnerability("Hidden Directory", f"Found: {test_url}")

    def subdomain_enumeration(self):
        """Enumerate subdomains (mock implementation)."""
        print("[INFO] Enumerating subdomains...")
        # Mock example; replace with real DNS/bruteforce enumeration
        subdomains = ["test", "dev", "staging"]
        for subdomain in subdomains:
            test_url = f"http://{subdomain}.example.com"
            try:
                response = requests.get(test_url)
                if response.status_code == 200:
                    self.log_vulnerability("Subdomain Enumeration", f"Found: {test_url}")
            except requests.exceptions.RequestException:
                pass

    def nmap_scan(self):
        """Perform Nmap scan (mock implementation)."""
        print("[INFO] Performing Nmap scan...")
        # Mock example; replace with subprocess call to actual Nmap if available
        open_ports = ["80", "443", "22"]
        for port in open_ports:
            self.log_vulnerability("Nmap Scan", f"Open Port: {port}")

    def run_tests(self, params):
        """Run all security tests."""
        threads = []
        tests = [
            self.sql_injection_test, 
            self.xss_test, 
            self.directory_traversal_test, 
            self.local_file_inclusion_test, 
            self.open_url_redirect_test, 
            self.ldap_injection_test, 
            self.hidden_directory_scan, 
            self.subdomain_enumeration, 
            self.nmap_scan
        ]

        for test in tests:
            thread = threading.Thread(target=test, args=(params,)) if test in [self.sql_injection_test, self.xss_test, self.local_file_inclusion_test, self.open_url_redirect_test, self.ldap_injection_test] else threading.Thread(target=test)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        print("[INFO] Testing complete. Generating report...")
        self.generate_report()

    def generate_report(self):
        """Generate a vulnerability report."""
        if not self.vulnerabilities:
            print("[INFO] No vulnerabilities found.")
        else:
            print("[INFO] Vulnerabilities detected:")
            for vuln in self.vulnerabilities:
                print(f"- {vuln['type']}: {vuln['details']}")
            # Save to JSON file
            with open("reports/vulnerability_report.json", "w") as report_file:
                json.dump(self.vulnerabilities, report_file, indent=4)
            print("[INFO] Report saved to reports/vulnerability_report.json")

# Example Usage
if __name__ == "__main__":
    print("[INFO] Starting Web Application Security Tester...")
    base_url = input("Enter the base URL of the web application (e.g., https://example.com): ")
    params = {
        "id": "1",  # Example query parameter; extendable for real-world usage
    }
    tester = WebAppSecurityTester(base_url)
    tester.run_tests(params)
