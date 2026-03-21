#!/bin/bash

CONFIG_FILE="/etc/unbound/unbound.conf"
ROOT_HINTS="/etc/unbound/root.hints"

cat > "$CONFIG_FILE" << 'EOF'
server:
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    access-control: 0.0.0.0/0 allow

    root-hints: "/etc/unbound/root.hints"

    cache-max-ttl: 86400
    cache-min-ttl: 3600

    hide-identity: yes
    hide-version: yes

    prefer-ip4: yes
    prefer-ip6: no

    private-address: ::/0
    do-not-query-localhost: no
    unwanted-reply-threshold: 0
EOF


wget -q -O "$ROOT_HINTS" https://www.internic.net/domain/named.root

exec unbound -d -c "$CONFIG_FILE"
