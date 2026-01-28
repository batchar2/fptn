#!/bin/bash

CONFIG_FILE="/etc/dnsmasq.conf"

rm -f "$CONFIG_FILE"

if [ -n "$DNS_IPV4_PRIMARY" ]; then
    echo "server=$DNS_IPV4_PRIMARY" >> "$CONFIG_FILE"
fi

if [ -n "$DNS_IPV4_SECONDARY" ]; then
    echo "server=$DNS_IPV4_SECONDARY" >> "$CONFIG_FILE"
fi

if [ -n "$DNS_IPV6_PRIMARY" ]; then
    echo "server=$DNS_IPV6_PRIMARY" >> "$CONFIG_FILE"
fi

if [ -n "$DNS_IPV6_SECONDARY" ]; then
    echo "server=$DNS_IPV6_SECONDARY" >> "$CONFIG_FILE"
fi

# default value
if [ ! -s "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << EOF
server=8.8.8.8
server=8.8.4.4
server=2001:4860:4860::8888
server=2001:4860:4860::8844
EOF
fi

# Additional options
cat >> "$CONFIG_FILE" << EOF
dns-forward-max=512
cache-size=16384
local-ttl=14400
neg-ttl=120
no-resolv
no-poll

EOF

exec /usr/sbin/dnsmasq --no-daemon
