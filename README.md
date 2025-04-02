# Websectest
The Web Application Security Testing Tool is an automated testing framework designed to identify common vulnerabilities in web applications. 
Web Application Security Testing Tool
Overview

The Web Application Security Testing Tool is an automated testing framework designed to identify common vulnerabilities in web applications. It supports detecting:

    SQL Injection
    Cross-Site Scripting (XSS)
    Directory Traversal
    Local File Inclusion (LFI)
    LDAP Injection
    Open URL Redirect
    Hidden Directories
    Subdomain Enumeration
    Nmap-like Open Port Scanning

This tool provides a user-friendly web interface and generates detailed reports of vulnerabilities detected during the scan.
Features

    Automated Vulnerability Detection:
        Tests for common security vulnerabilities using predefined payloads.
    Reconnaissance Capabilities:
        Identifies hidden directories and subdomains.
        Simulates Nmap functionality to scan for open ports.
    Web Interface:
        Input a target URL and parameters through an easy-to-use form.
        View results dynamically in the browser.
    Detailed Reports:
        Generates a JSON file summarizing vulnerabilities found.

Installation
Prerequisites

    Python 3.7+ installed on your system.
    A virtual environment is recommended for isolating dependencies.

Setup Instructions

    Clone the Repository:

git clone https://github.com/serialsshist/web-security-tester.git

cd web-security-tester

Set Up a Virtual Environment:

python3 -m venv myenv
source myenv/bin/activate       # For Linux/Mac
myenv\\Scripts\\activate        # For Windows

Install Dependencies: Install the required libraries using pip:

pip install flask requests

Project Directory Structure: Make sure the following directories and files exist:

web-security-tester/
├── templates/
│   └── index.html                # Web interface HTML file
├── reports/                      # Directory for saving JSON reports
├── web_security_tool.py          # Python backend for the tool
└── README.md                     # Documentation file

    If the reports/ directory doesn’t exist, create it manually:

        mkdir reports

Usage
Running the Tool

    Start the Flask server:

python web_security_tool.py

Open your browser and navigate to:

    http://127.0.0.1:5000

Using the Web Interface

    Base URL:
        Enter the target web application URL (e.g., https://example.com).
    Parameters (JSON):
        If the application uses query parameters (e.g., ?id=1), specify them in JSON format:

        {
          "id": "1",
          "name": "test"
        }

        Leave empty if no parameters are required.
    Run Tests:
        Click the "Run Tests" button to start scanning.
        The results are displayed on the page and saved as reports/vulnerability_report.json.

Troubleshooting
1. Common Issues

    Missing index.html File:
        Ensure the index.html file is in the templates/ directory.
    Dependencies Not Installed:
        Install Flask and Requests using pip install flask requests.
    AttributeError: 'NoneType' Object Has No Attribute 'rstrip':
        Ensure the "Base URL" field is filled correctly in the form.
        Validate that the backend function includes proper error handling:

        if not base_url:
            return jsonify({"error": "Base URL is required"}), 400

2. Debugging

    Run the tool in debug mode for detailed logs:

    python web_security_tool.py

How It Works

    Core Functionality:
        The backend uses Python to send payloads to the specified URL and check the server's response for vulnerability patterns.
    Reconnaissance:
        Hidden directories and subdomains are identified using brute force methods.
        Open port scanning is simulated with predefined port data.
    Web Interface:
        Built with Flask for input handling and result display.
        The index.html file provides a Bootstrap-styled frontend.

Generated Reports

    All detected vulnerabilities are saved in the reports/vulnerability_report.json file.
    Example report:

    [
        {
            "type": "Nmap Scan",
            "details": "Open Port: 80"
        },
        {
            "type": "Open URL Redirect",
            "details": "Parameter: id, Payload: http://malicious.com"
        }
    ]

Future Enhancements

    Expand payload lists for broader vulnerability coverage.
    Add support for advanced authentication mechanisms (e.g., cookies, tokens).
    Generate downloadable PDF reports.
