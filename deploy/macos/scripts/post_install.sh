#!/bin/bash

set -e

# Function to show error messages
show_error() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon stop
EOF
    exit 1
}

# Function to show informational messages
show_info() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon note
EOF
}

SYMLINK_DIR="/usr/local/bin"
SYMLINK_PATH="$SYMLINK_DIR/fptn-client-cli"
APP_EXECUTABLE="/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli-wrapper.sh"

# Create directory if it doesn't exist
if [ ! -d "$SYMLINK_DIR" ]; then
    if mkdir -p "$SYMLINK_DIR"; then
        echo "Created directory: $SYMLINK_DIR"
    else
        show_error "Failed to create required directory: $SYMLINK_DIR"
    fi
fi

# Handle existing symlink
if [ -L "$SYMLINK_PATH" ]; then
    echo "Found existing symlink at $SYMLINK_PATH - replacing it..."
    if ! rm -f "$SYMLINK_PATH"; then
        show_error "Failed to remove existing symlink at $SYMLINK_PATH"
    fi
fi

# Create new symlink
if ln -s "$APP_EXECUTABLE" "$SYMLINK_PATH"; then
    echo "Created symlink: $SYMLINK_PATH → $APP_EXECUTABLE"
else
    show_error "Failed to create symlink at $SYMLINK_PATH\n\nPlease check if you have sufficient permissions."
fi

# Driver (kext) installation
KEXT_SRC="/Applications/FptnClient.app/Contents/Resources/tun.kext"
KEXT_DST="/Library/Extensions/tun.kext"

if [ -d "$KEXT_DST" ]; then
    echo "Network driver already installed at $KEXT_DST"
else
    echo "Installing network driver..."

    # Copy the driver
    if cp -r "$KEXT_SRC" "$KEXT_DST"; then
        echo "Driver successfully copied to $KEXT_DST"
    else
        show_error "Failed to install network driver.\n\nPossible causes:\n1. Missing administrator privileges\n2. System Integrity Protection is active\n3. Insufficient disk space"
    fi

    # Update kext cache
    echo "Updating driver cache..."
    if kextcache -i /; then
        show_info "Driver installation complete!\n\nNote: You may need to:\n1. Approve the driver in:\n   System Preferences → Security & Privacy → General\n2. Restart your computer"
    else
        show_error "Driver installation completed but cache update failed.\n\nThe driver might not work until you restart your computer."
    fi
fi

kextcache -i /
