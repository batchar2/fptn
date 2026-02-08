#!/bin/bash

CONFIG_FILE="/etc/unbound/unbound.conf"
ROOT_HINTS="/etc/unbound/root.hints"

cat > "$CONFIG_FILE" << 'EOF'
server:
    interface: 0.0.0.0
    interface: ::0
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow

    root-hints: "/etc/unbound/root.hints"

    cache-max-ttl: 86400
    cache-min-ttl: 3600

    hide-identity: yes
    hide-version: yes
EOF

wget -q -O "$ROOT_HINTS" https://www.internic.net/domain/named.root

exec unbound -d -c "$CONFIG_FILE"
