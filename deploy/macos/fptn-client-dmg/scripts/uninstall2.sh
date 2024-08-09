#!/bin/bash

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This operation requires root privileges."
    exit 1
fi

# Define paths
KEXT_LIBRARY_EXTENSION="/Library/Extensions"
KEXT_PATH="$KEXT_LIBRARY_EXTENSION/tun.kext"

TUN_PLIST_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"

# Remove KEXT if it exists
if [ -d "$KEXT_PATH" ]; then
    echo "Removing Kext from $KEXT_LIBRARY_EXTENSION..."
    rm -rf "$KEXT_PATH"
else
    echo "Kext not found: $KEXT_PATH"
fi

# Remove LaunchDaemon plist if it exists
if [ -f "$TUN_PLIST_PATH" ]; then
    echo "Removing LaunchDaemon plist from /Library/LaunchDaemons/"
    rm -f "$TUN_PLIST_PATH"
else
    echo "LaunchDaemon plist not found: $TUN_PLIST_PATH"
fi

# Update kextcache
echo "Updating kextcache..."
kextcache -i /

echo "Cleanup complete. The system should now be fresh."
