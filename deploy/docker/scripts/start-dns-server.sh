#!/bin/bash

start_unbound() {
    echo "Starting unbound..."

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
}

start_dnsmasq() {
    echo "Starting dnsmasq..."

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

    echo "Using DNS servers:"
    echo "  IPv4 Primary: $DNS_IPV4_PRIMARY"
    echo "  IPv4 Secondary: $DNS_IPV4_SECONDARY"
    echo "  IPv6 Primary: $DNS_IPV6_PRIMARY"
    echo "  IPv6 Secondary: $DNS_IPV6_SECONDARY"

    exec /usr/sbin/dnsmasq --no-daemon
}

case "$USING_DNS_SERVER" in
    "unbound")
        start_unbound
        ;;
    "dnsmasq")
        start_dnsmasq
        ;;
    *)
        echo "Unknown USING_DNS_SERVER: $USING_DNS_SERVER, using dnsmasq"
        start_dnsmasq
        ;;
esac
exit 0
