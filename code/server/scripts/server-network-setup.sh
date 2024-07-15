#!/usr/bin/env bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <external_interface>"
    exit 1
fi
INTERFACE_OUT=$1

# DONT TOUCH!!!!
INTERFACE_IN=tun0
INTERFACE_NETWORK=1.1.1.1
VIRTUAL_VPN_NETWORK=2.2.0.0/16

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -F -t nat
iptables -F -t mangle
iptables -X
iptables -t nat -X
iptables -t mangle -X
# allow all
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
# routing
iptables -A FORWARD -i "${INTERFACE_IN}" -o "${INTERFACE_OUT}" -j ACCEPT
iptables -A FORWARD -i "${INTERFACE_OUT}" -o "${INTERFACE_IN}" -j ACCEPT
iptables -t nat -A POSTROUTING -o "${INTERFACE_OUT}" -j MASQUERADE
# virtual VPN network
sudo ip route add "${VIRTUAL_VPN_NETWORK}" dev "${INTERFACE_IN}"
