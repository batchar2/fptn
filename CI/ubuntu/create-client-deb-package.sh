#!/bin/bash

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

CLIENT_TMP_DIR=$(mktemp -d -t fptn-client-cli-XXXXXX)

mkdir -p "$CLIENT_TMP_DIR/DEBIAN"
mkdir -p "$CLIENT_TMP_DIR/usr/bin"
mkdir -p "$CLIENT_TMP_DIR/etc/fptn"
mkdir -p "$CLIENT_TMP_DIR/lib/systemd/system"

cp "$CLIENT_CLI" "$CLIENT_TMP_DIR/usr/bin/"
chmod 755 "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"

# Create client configuration file
cat <<EOL > "$CLIENT_TMP_DIR/etc/fptn/client.conf"
# Configuration for fptn client
USERNAME=
PASSWORD=
NETWORK_INTERFACE=
VPN_SERVER_IP=
VPN_SERVER_PORT=443
GATEWAY_IP=
EOL

# Create systemd service file for client
cat <<EOL > "$CLIENT_TMP_DIR/lib/systemd/system/fptn-client.service"
[Unit]
Description=FPTN Client Service
After=network.target

[Service]
EnvironmentFile=-/etc/fptn/client.conf
ExecStart=/usr/bin/$(basename "$CLIENT_CLI") --vpn-server-ip=\$VPN_SERVER_IP --vpn-server-port=\$VPN_SERVER_PORT --out-network-interface=\$NETWORK_INTERFACE --username=\$USERNAME --password=\$PASSWORD --gateway-ip=\$GATEWAY_IP
Restart=always
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
Depends: iptables, iproute2
Section: admin
Priority: optional
Description: fptn client
EOL

dpkg-deb --build "$CLIENT_TMP_DIR" "fptn-client-cli-${VERSION}-$(dpkg --print-architecture).deb"

mkdir -p result
mv "fptn-client-cli-${VERSION}-$(dpkg --print-architecture).deb" result/
rm -rf "$CLIENT_TMP_DIR"
echo "Client Debian package created successfully in the 'result' directory."
