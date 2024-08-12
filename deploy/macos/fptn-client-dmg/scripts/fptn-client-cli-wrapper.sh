#!/bin/bash

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This operation requires root privileges."
    exit 1
fi

# Define paths
KEXT_LIBRARY_EXTENSION="/Library/Extensions"
KEXT_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/tun.kext"
KEXT_PATH="$KEXT_LIBRARY_EXTENSION/tun.kext"

TUN_PLIST_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"
TUN_PLIST_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/net.tunnelblick.tun.plist"

# Copy KEXT if not already present
if [ ! -d "$KEXT_PATH" ]; then
    echo "Copying Kext to $KEXT_LIBRARY_EXTENSION..."
    cp -rv "$KEXT_PATH_INSIDE_APPLICATION" "$KEXT_LIBRARY_EXTENSION"
    kextcache -i /
fi

# Copy and load LaunchDaemon plist
if [ ! -f "$TUN_PLIST_PATH" ]; then
    echo "Copying LaunchDaemon plist to /Library/LaunchDaemons/"
    cp -rv "$TUN_PLIST_PATH_INSIDE_APPLICATION" "/Library/LaunchDaemons/"
    kextcache -i /
fi

# Check if the driver is loaded
if ! kextstat | grep -q "$(basename "$KEXT_PATH" .kext)"; then
    echo "Driver not loaded. Attempting to load..."
    if kextload "$KEXT_PATH"; then
        echo "Driver loaded successfully."
    else
        echo "Failed to load the driver. Please check the system extension. You need to allow the use of the TUN driver to use this application."
        exit 1
    fi
else
    echo "Driver is already loaded."
fi

cd /tmp/

/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli "$@"
