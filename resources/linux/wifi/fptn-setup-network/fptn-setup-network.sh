## /usr/sbin/fptn-setup-network.sh

#replace to your
WIFI_INTERFACE=wlan0

#replace to your
ETH_INTERFACE=eth0





echo "Telling kernel to turn on ipv4 ip_forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "Done. Setting up iptables rules to allow FORWARDING"

iptables -A FORWARD -i $WIFI_INTERFACE -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o $WIFI_INTERFACE -j ACCEPT

iptables -A FORWARD -i tun0 -o $ETH_INTERFACE -j ACCEPT
iptables -A FORWARD -i $ETH_INTERFACE -o tun0 -j ACCEPT

iptables -t nat -A POSTROUTING -o $ETH_INTERFACE -j MASQUERADE
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

ip addr add 192.168.180.1/24 dev $WIFI_INTERFACE


sleep 60
echo "Done setting up iptables rules. Forwarding enabled"
