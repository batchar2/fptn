#!/bin/bash

while true; do
    if ! timeout 3 dig @127.0.0.1 google.com >/dev/null 2>&1; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS FAILED - restarting dnsmasq"
        supervisorctl restart dnsmasq
    fi
    sleep 5
done
