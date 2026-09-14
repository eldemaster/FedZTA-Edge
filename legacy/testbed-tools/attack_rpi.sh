#!/bin/bash
echo "=== 1. Legitimate Request ==="
curl -s -w "\nHTTP Status: %{http_code}\n" "http://192.168.1.147:8080/api/v1/sensors/temp"

echo -e "\n=== 2. Zero-Day SQL Injection ==="
curl -s -w "\nHTTP Status: %{http_code}\n" "http://192.168.1.147:8080/search?q=%27%20UNION%20SELECT%20password%20FROM%20admins--"

echo -e "\n=== 3. XSS Bypass (BruteLogic) ==="
curl -s -w "\nHTTP Status: %{http_code}\n" "http://192.168.1.147:8080/profile?name=%3Csvg/onload=alert()%3E"
