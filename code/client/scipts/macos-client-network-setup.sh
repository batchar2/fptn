#!/usr/bin/env bash

#!/usr/bin/env bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <external_interface> <gateway_ip> <vpn_server_ip>"
    exit 1
fi

INTERFACE_ETH=$1
GATEWAY_IP=$2
VPN_SERVER_IP=$3

INTERFACE_TUN=tun0

# Enable IP forwarding
sysctl -w net.inet.ip.forwarding=1

# Create pf.conf rules
cat <<EOF > /tmp/pf.conf
nat on $INTERFACE_ETH from $INTERFACE_TUN:network to any -> ($INTERFACE_ETH)
pass out on $INTERFACE_ETH proto tcp from any to $VPN_SERVER_IP
pass in on $INTERFACE_ETH proto tcp from $VPN_SERVER_IP to any
pass in on $INTERFACE_TUN proto tcp from any to any
pass out on $INTERFACE_TUN proto tcp from any to any
EOF

# Apply pf.conf rules
pfctl -ef /tmp/pf.conf

# Add routes
route add -net 0.0.0.0/1 -interface $INTERFACE_TUN
route add -net 128.0.0.0/1 -interface $INTERFACE_TUN
route add $VPN_SERVER_IP $GATEWAY_IP

echo "Routing and firewall rules applied successfully."


# INTERFACE_TUN=tun0


# sysctl -w net.inet.ip.forwarding=1

# # route add -host 54.81.143.201 -interface en0

# route add -net 8.8.8.0/24 -interface "${INTERFACE_TUN}"


# # route add -host 54.81.143.201 -interface en0