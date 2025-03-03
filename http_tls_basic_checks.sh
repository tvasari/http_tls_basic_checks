#!/usr/bin/bash

# TLS and HTTP Security Scanner
# This script performs security checks for:
# 1. HTTP security headers
# 2. Weak TLS cipher suites
# 3. Weak TLS certificate configurations

# Exit on error
set -e

# Check if required tools are installed
check_dependencies() {
    local missing_deps=0
    
    if ! command -v nuclei 1>/dev/null; then
        echo "Error: nuclei is not installed. Install it from: https://github.com/projectdiscovery/nuclei"
        missing_deps=1
    fi
    
    if ! command -v nmap 1>/dev/null; then
        echo "Error: nmap is not installed. Install it with: sudo apt install nmap (or equivalent)"
        missing_deps=1
    fi
    
    if ! command -v testssl 1>/dev/null; then
        echo "Error: testssl is not installed. Install it from: https://github.com/drwetter/testssl.sh"
        missing_deps=1
    fi
    
    if [ $missing_deps -eq 1 ]; then
        exit 1
    fi
}

# Parse arguments
parse_args() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <target> [output_dir]"
        echo "  target    - URL or IP address to scan"
        echo "  output_dir - Directory for scan results (default: ./scan_results)"
        exit 1
    fi
    
    TARGET="$1"
    OUTPUT_DIR="${2:-./scan_results}"
    
    # Format target for different tools
    # Remove protocol prefix and trailing forward slash for tools that don't need it
    TARGET_DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's/\/$//')
    
    # Add protocol prefix if missing for tools that need it
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        TARGET_URL="https://$TARGET"
    else
        TARGET_URL="$TARGET"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    echo "Results will be saved to: $OUTPUT_DIR"
}

# Scan for HTTP security headers using nuclei
scan_http_headers() {
    echo "Running nuclei HTTP security headers scan..."
    
    # Create nuclei output directory
    mkdir -p "$OUTPUT_DIR/nuclei"
    
    # Run nuclei with HTTP security templates
    nuclei -u "$TARGET_URL" \
        -t http/misconfiguration/http-missing-security-headers.yaml \
        -rl 10 \
        -o "$OUTPUT_DIR/nuclei/headers_scan.txt" \
        -silent
    
    echo "Nuclei scan completed. Results saved to: $OUTPUT_DIR/nuclei/headers_scan.txt"
}

# Scan for weak TLS cipher suites using nmap
scan_tls_ciphers() {
    echo "Running nmap TLS cipher suite scan..."
    
    # Create nmap output directory
    mkdir -p "$OUTPUT_DIR/nmap"
    
    # Run nmap with ssl-enum-ciphers script
    nmap --script=ssl-enum-ciphers -p 443 "$TARGET_DOMAIN" \
        -oN "$OUTPUT_DIR/nmap/cipher_scan.txt"
    
    echo "Nmap TLS cipher scan completed. Results saved to: $OUTPUT_DIR/nmap/cipher_scan.txt"
}

# Scan for weak TLS certificate configurations using testssl.sh
scan_tls_config() {
    echo "Running testssl certificate and TLS configuration scan..."
    
    # Create testssl output directory
    mkdir -p "$OUTPUT_DIR/testssl"
    
    # Run testssl with HTML and JSON output
    testssl --htmlfile "$OUTPUT_DIR/testssl/ssl_scan.html" \
        --jsonfile "$OUTPUT_DIR/testssl/ssl_scan.json" \
        --logfile "$OUTPUT_DIR/testssl/ssl_scan.log" \
        "$TARGET_URL"
    
    echo "TestSSL scan completed. Results saved to:"
    echo "  HTML: $OUTPUT_DIR/testssl/ssl_scan.html"
    echo "  JSON: $OUTPUT_DIR/testssl/ssl_scan.json"
    echo "  Log: $OUTPUT_DIR/testssl/ssl_scan.log"
}

# Main execution
main() {
    check_dependencies
    parse_args "$@"
    
    echo "Starting security scan for: $TARGET"
    echo "==================================="
    
    scan_http_headers
    scan_tls_ciphers
    scan_tls_config
    
    echo "==================================="
    echo "All scans completed!"
    echo "Results are available in: $OUTPUT_DIR"
}

# Execute the script
main "$@"
