TLS and HTTP Security Scanner

This script performs security checks for:
1. HTTP security headers
2. Weak TLS cipher suites
3. Weak TLS certificate configurations

Dependencies: nuclei, nmap, testssl

Usage: ./http_tls_basic_checks.sh http://<target> <output_directory>