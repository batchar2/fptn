#!/bin/bash

# Path to the driver
KEXT_PATH="/Library/Extensions/tunnelblick-tun.kext"

if [ "$(id -u)" -ne 0 ]; then
    echo "This operation requires root privileges."
    exit 1
fi

# Check if the driver is loaded
if ! kextstat | grep -q "$(basename "$KEXT_PATH" .kext)"; then
    echo "Driver not loaded. Attempting to load..."
    kextload "$KEXT_PATH"
    if [ $? -ne 0 ]; then
        echo "Failed to load the driver."
        exit 1
    else
        echo "Driver loaded successfully."
    fi
else
    echo "Driver is already loaded."
fi

/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli "$@"
