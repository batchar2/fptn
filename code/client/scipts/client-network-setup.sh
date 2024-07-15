#!/usr/bin/env bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <external_interface> <gateway_ip> <vpn_server_ip>"
    exit 1
fi

INTERFACE_ETH=$1
GATEWAY_IP=$2
VPN_SERVER_IP=$3

INTERFACE_TUN=tun0

iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X

# Set up NAT for outgoing traffic through enp0s5
iptables -t nat -A POSTROUTING -o "${INTERFACE_ETH}" -j MASQUERADE
# Allow traffic from enp0s5 to tun0 and back
iptables -A FORWARD -i "${INTERFACE_ETH}" -o "${INTERFACE_TUN}" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "${INTERFACE_TUN}" -o "${INTERFACE_ETH}" -j ACCEPT
# Allow traffic to VPN server through enp0s5
iptables -A OUTPUT -o "${INTERFACE_ETH}" -d "${VPN_SERVER_IP}" -j ACCEPT
iptables -A INPUT -i "${INTERFACE_ETH}" -s "${VPN_SERVER_IP}" -j ACCEPT

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
ip route add default dev $INTERFACE_TUN
ip route add $VPN_SERVER_IP via $GATEWAY_IP dev $INTERFACE_ETH
