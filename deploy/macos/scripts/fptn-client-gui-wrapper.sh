#!/bin/bash

# Function to show an error message
show_error() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon stop
EOF
}

# Function to install driver (requires root)
install_driver() {
    # Copy KEXT if not already present
    KEXT_LIBRARY_EXTENSION="/Library/Extensions"
    KEXT_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/tun.kext"
    KEXT_PATH="$KEXT_LIBRARY_EXTENSION/tun.kext"

    if [ ! -d "$KEXT_PATH" ]; then
        echo "Copying Kext to $KEXT_LIBRARY_EXTENSION..."
        if ! cp -rv "$KEXT_PATH_INSIDE_APPLICATION" "$KEXT_LIBRARY_EXTENSION"; then
            show_error "Failed to copy Kext to $KEXT_LIBRARY_EXTENSION."
            return 1
        fi
        kextcache -i /
        echo "Kext copied successfully to $KEXT_LIBRARY_EXTENSION."
    fi

    # Copy and load LaunchDaemon plist
    TUN_PLIST_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"
    TUN_PLIST_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/net.tunnelblick.tun.plist"
    if [ ! -f "$TUN_PLIST_PATH" ]; then
        echo "Copying LaunchDaemon plist to /Library/LaunchDaemons/"
        if ! cp -rv "$TUN_PLIST_PATH_INSIDE_APPLICATION" "/Library/LaunchDaemons/"; then
            show_error "Failed to copy LaunchDaemon plist."
            return 1
        fi
        kextcache -i /
        echo "LaunchDaemon plist copied successfully."
    fi

    # Check if the driver is loaded
    if ! kextstat | grep -q "$(basename "$KEXT_PATH" .kext)"; then
        echo "Driver not loaded. Attempting to load..."
        if ! kextload "$KEXT_PATH"; then
            show_error "Failed to load the driver. Please check the system extension. You need to allow the use of the TUN driver to use this application."
            return 1
        fi
        echo "Driver loaded successfully."
    else
        echo "Driver is already loaded."
    fi

    return 0
}

# Function to clean DNS settings
cleanup_dns() {
    echo "Cleaning up DNS settings..."
    networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {} networksetup -setdnsservers "{}" empty
}

# First check if driver installation is needed
DRIVER_NEEDED=false
KEXT_PATH="/Library/Extensions/tun.kext"
if [ ! -d "$KEXT_PATH" ] || ! kextstat | grep -q "$(basename "$KEXT_PATH" .kext)"; then
    DRIVER_NEEDED=true
fi

# If driver installation is needed, request root privileges
if $DRIVER_NEEDED; then
    echo "Driver installation required. Requesting root privileges..."
    osascript <<EOF
do shell script "echo 'Starting driver installation'; '$0' --install-driver" with administrator privileges
EOF
    # Check if installation was successful
    if [ $? -ne 0 ]; then
        show_error "Driver installation failed. The application may not work properly."
        exit 1
    fi
fi


# Normal execution (without root)
export QT_PLUGIN_PATH=/Applications/FptnClient.app/Contents/Frameworks/plugins
export QT_QPA_PLATFORM_PLUGIN_PATH=/Applications/FptnClient.app/Contents/Frameworks/plugins/platforms
export LD_LIBRARY_PATH=/Applications/FptnClient.app/Contents/Frameworks

# Clean DNS settings
cleanup_dns

# Set trap for cleanup
trap cleanup_dns EXIT

# Launch application
exec /Applications/FptnClient.app/Contents/MacOS/fptn-client-gui "$@"
