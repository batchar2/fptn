#!/bin/bash

# Function to show an error message
show_error() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon stop
EOF
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This operation requires root privileges."
    osascript <<EOF
do shell script "$0" with administrator privileges
EOF
    exit 1
fi

# Copy KEXT if not already present
KEXT_LIBRARY_EXTENSION="/Library/Extensions"
KEXT_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/tun.kext"
KEXT_PATH="$KEXT_LIBRARY_EXTENSION/tun.kext"
if [ ! -d "$KEXT_PATH" ]; then
    echo "Copying Kext to $KEXT_LIBRARY_EXTENSION..."
    if cp -rv "$KEXT_PATH_INSIDE_APPLICATION" "$KEXT_LIBRARY_EXTENSION"; then
        kextcache -i /
        echo "Kext copied successfully to $KEXT_LIBRARY_EXTENSION."
    else
        show_error "Failed to copy Kext to $KEXT_LIBRARY_EXTENSION."
        exit 1
    fi
fi

# Copy and load LaunchDaemon plist
TUN_PLIST_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"
TUN_PLIST_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/net.tunnelblick.tun.plist"
if [ ! -f "$TUN_PLIST_PATH" ]; then
    echo "Copying LaunchDaemon plist to /Library/LaunchDaemons/"
    if cp -rv "$TUN_PLIST_PATH_INSIDE_APPLICATION" "/Library/LaunchDaemons/"; then
        kextcache -i /
        echo "LaunchDaemon plist copied successfully."
    else
        show_error "Failed to copy LaunchDaemon plist."
        exit 1
    fi
fi


# Check if the driver is loaded
if ! kextstat | grep -q "$(basename "$KEXT_PATH" .kext)"; then
    echo "Driver not loaded. Attempting to load..."
    if kextload "$KEXT_PATH"; then
        echo "Driver loaded successfully."
    else
        show_error "Failed to load the driver. Please check the system extension. You need to allow the use of the TUN driver to use this application."
        exit 1
    fi
else
    echo "Driver is already loaded."
fi

cd /tmp/

export QT_PLUGIN_PATH=/Applications/FptnClient.app/Contents/Frameworks/plugins
export QT_QPA_PLATFORM_PLUGIN_PATH=/Applications/FptnClient.app/Contents/Frameworks/plugins/platforms
export LD_LIBRARY_PATH=/Applications/FptnClient.app/Contents/Frameworks

exec /Applications/FptnClient.app/Contents/MacOS/fptn-client-gui "$@" &
