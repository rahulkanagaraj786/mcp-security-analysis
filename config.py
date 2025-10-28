"""
Configuration file for MCP Security Testing Project
"""
import os

# Server configurations
VULNERABLE_MCP_SERVER_PORT = 8000
MALICIOUS_HTTP_SERVICE_PORT = 8001
MALICIOUS_SERVICE_PORT = 8002

# Network configurations
LOCALHOST = "127.0.0.1"
ALLOWED_HOSTS = ["*"]  # Vulnerable configuration for testing

# Attack simulation settings
ENABLE_SSRF_ATTACKS = True
ENABLE_FILE_ACCESS_ATTACKS = True
ENABLE_INTERNAL_NETWORK_SCANNING = True

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "security_test.log"

# Test data
TEST_FILES = {
    "sensitive_file": "/etc/passwd",
    "config_file": "/etc/hosts",
    "ssh_key": "~/.ssh/id_rsa"
}

# Internal services to target (for SSRF testing)
INTERNAL_SERVICES = [
    "http://127.0.0.1:22",      # SSH
    "http://127.0.0.1:80",      # HTTP
    "http://127.0.0.1:443",     # HTTPS
    "http://127.0.0.1:3306",    # MySQL
    "http://127.0.0.1:5432",    # PostgreSQL
    "http://127.0.0.1:6379",    # Redis
    "http://127.0.0.1:9200",    # Elasticsearch
    "http://127.0.0.1:8080",    # Common web port
]

