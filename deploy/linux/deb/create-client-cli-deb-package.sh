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
# Configuration for FPTN client (required)
ACCESS_TOKEN=

# Required: Fake VPN domain name for SNI
SNI=tv.telecom.kz

# Optional: Specify the network interface
NETWORK_INTERFACE=
# Optional: Specify the gateway IP (e.g., router IP)
GATEWAY_IP=

EOL

# Create systemd service file for client
cat <<EOL > "$CLIENT_TMP_DIR/lib/systemd/system/fptn-client.service"
[Unit]
Description=FPTN Client Service
After=network.target

[Service]
EnvironmentFile=/etc/fptn-client/client.conf
ExecStart=/usr/bin/$(basename "$CLIENT_CLI") --access-token=\${ACCESS_TOKEN} --out-network-interface=\${NETWORK_INTERFACE} --gateway-ip=\${GATEWAY_IP} --sni=\${SNI}
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
Replaces: fptn-client-cli
Conflicts: fptn-client-cli
Provides: fptn-client-cli
Priority: optional
Description: fptn client
EOL


# Create prerm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/prerm"
#!/bin/bash

systemctl daemon-reload || echo "Failed to reload"
systemctl stop fptn-client 2>/dev/null || echo "Failed to stop"
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/prerm"


# Create postrm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/postrm"
#!/bin/bash

if [ "\$1" != "upgrade" ]; then
    systemctl disable fptn-client.service 2>/dev/null || true
    rm -f /lib/systemd/system/fptn-client.service 2>/dev/null || echo "Failed to remove"
fi
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/postrm"



# Build the Debian package
dpkg-deb --build "$CLIENT_TMP_DIR" "fptn-client-cli-${VERSION}-${OS_NAME}${OS_VERSION}-$(dpkg --print-architecture).deb"

# Clean up temporary directories
rm -rf "$CLIENT_TMP_DIR"

echo "Client Debian package created successfully."
