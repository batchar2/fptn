#!/bin/bash

set -e

# Function to show an error message
show_error() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon stop
EOF
}

SYMLINK_DIR="/usr/local/bin"
SYMLINK_PATH="$SYMLINK_DIR/fptn-client-cli"
APP_EXECUTABLE="/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli-wrapper.sh"

# create directory
if [ ! -d "$SYMLINK_DIR" ]; then
    mkdir -p "$SYMLINK_DIR"
    echo "Directory $SYMLINK_DIR created."
fi

# Create symbolic link
if [ -L "$SYMLINK_PATH" ]; then
    echo "Symbolic link already exists: $SYMLINK_PATH"
else
    if ln -s "$APP_EXECUTABLE" "$SYMLINK_PATH"; then
        echo "Symbolic link created: $SYMLINK_PATH"
    else
        show_error "Failed to create symbolic link: $SYMLINK_PATH"
        exit 1
    fi
fi

# Copy driver (kext)
KEXT_LIBRARY_EXTENSION="/Library/Extensions"
KEXT_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/tun.kext"
KEXT_PATH="$KEXT_LIBRARY_EXTENSION/tun.kext"

if [ -d "$KEXT_PATH" ]; then
    echo "Kext already exists: $KEXT_PATH"
else
    if cp -rv "$KEXT_PATH_INSIDE_APPLICATION" "$KEXT_LIBRARY_EXTENSION"; then
        echo "Kext copied successfully to $KEXT_LIBRARY_EXTENSION."
    else
        show_error "Failed to copy Kext to $KEXT_LIBRARY_EXTENSION."
        exit 1
    fi
fi
kextcache -i /
