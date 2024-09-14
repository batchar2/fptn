#!/usr/bin/env bash

# Function to print usage
print_usage() {
    echo "Usage: $0 <fptn-client-cli-path> <version>"
    exit 1
}

# Check if the correct number of arguments are provided
if [ "$#" -ne 2 ]; then
    print_usage
fi

CLIENT_CLI="$1"
VERSION="$2"
MAINTAINER="FPTN Project"

OS_NAME=$(lsb_release -i | awk -F':\t' '{print $2}' | tr '[:upper:]' '[:lower:]')
OS_VERSION=$(lsb_release -r | awk -F':\t' '{print $2}')

CLIENT_TMP_DIR=$(mktemp -d -t fptn-client-cli-XXXXXX)

mkdir -p "$CLIENT_TMP_DIR/DEBIAN"
mkdir -p "$CLIENT_TMP_DIR/usr/bin"
mkdir -p "$CLIENT_TMP_DIR/etc/fptn-client"
mkdir -p "$CLIENT_TMP_DIR/lib/systemd/system"

# Copy client binary
cp "$CLIENT_CLI" "$CLIENT_TMP_DIR/usr/bin/"
chmod 755 "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"

# Create client configuration file
cat <<EOL > "$CLIENT_TMP_DIR/etc/fptn-client/client.conf"
# Configuration for fptn client
USERNAME=
PASSWORD=
NETWORK_INTERFACE=
VPN_SERVER_IP=
GATEWAY_IP=
VPN_SERVER_PORT=443
EOL

# Create systemd service file for client
cat <<EOL > "$CLIENT_TMP_DIR/lib/systemd/system/fptn-client.service"
[Unit]
Description=FPTN Client Service
After=network.target

[Service]
EnvironmentFile=/etc/fptn-client/client.conf
ExecStart=/usr/bin/$(basename "$CLIENT_CLI") --vpn-server-ip=\${VPN_SERVER_IP} --vpn-server-port=\${VPN_SERVER_PORT} --out-network-interface=\${NETWORK_INTERFACE} --username=\${USERNAME} --password=\${PASSWORD} --gateway-ip=\${GATEWAY_IP}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOL

# Create control file for client package
INSTALLED_SIZE=$(du -s "$CLIENT_TMP_DIR/usr" | cut -f1)
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/control"
Package: fptn-client-cli
Version: ${VERSION}
Architecture: $(dpkg --print-architecture)
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: iptables, iproute2, net-tools
Section: admin
Priority: optional
Description: fptn client
EOL

# Create postrm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/postrm"
#!/bin/bash
set -e

systemctl stop fptn-client || true
systemctl disable fptn-client.service || true
systemctl daemon-reload || true
rm -rf /etc/fptn-client || true
rm -f /lib/systemd/system/fptn-client.service || true
EOL

chmod 755 "$CLIENT_TMP_DIR/DEBIAN/postrm"

# Build the Debian package
dpkg-deb --build "$CLIENT_TMP_DIR" "fptn-client-cli-${VERSION}-${OS_NAME}${OS_VERSION}-$(dpkg --print-architecture).deb"

# Clean up temporary directories
rm -rf "$CLIENT_TMP_DIR"

echo "Client Debian package created successfully."
