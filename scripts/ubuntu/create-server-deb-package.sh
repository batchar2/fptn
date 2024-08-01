#!/bin/env bash

# Function to print usage
print_usage() {
    echo "Usage: $0 <fptn-server-path> <fptn-passwd-path> <version>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    print_usage
fi

SERVER_BIN="$1"
PASSWD_BIN="$2"
VERSION="$3"
MAINTAINER="FPTN Project"

SERVER_TMP_DIR=$(mktemp -d -t fptn-server-XXXXXX)

mkdir -p "$SERVER_TMP_DIR/DEBIAN"
mkdir -p "$SERVER_TMP_DIR/usr/bin"
mkdir -p "$SERVER_TMP_DIR/etc/fptn"
mkdir -p "$SERVER_TMP_DIR/lib/systemd/system"

# Copy server files
cp "$SERVER_BIN" "$SERVER_TMP_DIR/usr/bin/"
chmod 755 "$SERVER_TMP_DIR/usr/bin/$(basename "$SERVER_BIN")"
cp "$PASSWD_BIN" "$SERVER_TMP_DIR/usr/bin/"
chmod 755 "$SERVER_TMP_DIR/usr/bin/$(basename "$PASSWD_BIN")"

# Create server configuration file
cat <<EOL > "$SERVER_TMP_DIR/etc/fptn/server.conf"
# Configuration for fptn server

OUT_NETWORK_INTERFACE=

# KEYS
SERVER_KEY=
SERVER_CRT=
SERVER_PUB=

PORT=443
TUN_INTERFACE_NAME=fptn0

LOG_FILE=/var/log/fptn-server.log
EOL

# Create systemd service file for server
cat <<EOL > "$SERVER_TMP_DIR/lib/systemd/system/fptn-server.service"
[Unit]
Description=FPTN Server Service
After=network.target

[Service]
EnvironmentFile=-/etc/fptn/server.conf
ExecStart=/usr/bin/$(basename "$SERVER_BIN") --server-key=\${SERVER_KEY} --server-crt=\${SERVER_CRT} --server-pub=\${SERVER_PUB} --out-network-interface=\${OUT_NETWORK_INTERFACE} --server-port=\${PORT} --tun-interface-name=\${TUN_INTERFACE_NAME}
Restart=always
WorkingDirectory=/etc/fptn
User=root

[Install]
WantedBy=multi-user.target
EOL

# Create control file for server package
INSTALLED_SIZE=$(du -s "$SERVER_TMP_DIR/usr" | cut -f1)
cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/control"
Package: fptn-server
Version: ${VERSION}
Architecture: $(dpkg --print-architecture)
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: iptables, iproute2
Section: admin
Priority: optional
Description: fptn server
EOL


cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/postrm"
#!/bin/bash
set -e

# Remove configuration directory if empty
rm -rf /etc/fptn
systemctl daemon-reload
EOL

chmod 755 "$SERVER_TMP_DIR/DEBIAN/postrm"

# Build the Debian package
dpkg-deb --build "$SERVER_TMP_DIR" "fptn-server-${VERSION}-$(dpkg --print-architecture).deb"

# Clean up temporary directory
rm -rf "$SERVER_TMP_DIR"


chmod 644 "fptn-server-${VERSION}-$(dpkg --print-architecture).deb"

echo "Server Debian package created successfully."