#!/bin/bash
TARGET="http://192.168.1.147:8080"

echo "========================================="
echo "   LIVE WAF PEN-TEST FROM MAC OS X       "
echo "========================================="

test_payload() {
    local payload="$1"
    local desc="$2"
    echo -n "Testing: $desc... "
    
    # Use --path-as-is for traversal and proper URL encoding
    STATUS=$(curl -s --path-as-is -o /dev/null -w "%{http_code}" "$TARGET$payload")
    
    if [ "$STATUS" == "403" ]; then
        echo -e "\033[0;31m[BLOCKED by ML WAF]\033[0m"
    elif [ "$STATUS" == "200" ]; then
        echo -e "\033[0;32m[PASSED - Normal Traffic]\033[0m"
    else
        echo "[STATUS: $STATUS]"
    fi
}

echo -e "\n--- Sending Benign Traffic ---"
test_payload "/api/v1/status" "Normal API Check"
test_payload "/login?user=eldemaster" "Standard Login"

echo -e "\n--- Sending Cyber Attacks ---"
test_payload "/?q='%20OR%201=1--" "SQL Injection"
test_payload "/?q=<script>alert('XSS')</script>" "Cross-Site Scripting"
test_payload "/../../../../etc/passwd" "Path Traversal"

echo -e "\n========================================="
