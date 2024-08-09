#!/bin/bash

set -e

# Create symbolic link
APP_EXECUTABLE="/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli-wrapper.sh"
SYMLINK_PATH="/usr/local/bin/fptn-client-cli"
if [ -L "$SYMLINK_PATH" ]; then
    echo "Symbolic link already exists: $SYMLINK_PATH"
else
    ln -s "$APP_EXECUTABLE" "$SYMLINK_PATH"
    echo "Symbolic link created: $SYMLINK_PATH"
fi

# Copy and load driver (kext)
KEXT_LIBRARY_EXTENSION="/Library/Extensions"
KEXT_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/tun.kext"
KEXT_PATH="$KEXT_LIBRARY_EXTENSION/tun.kext"

if [ -d "$KEXT_PATH" ]; then
    echo "Kext already exists: $KEXT_PATH"
else
    cp -rv "$KEXT_PATH_INSIDE_APPLICATION" "$KEXT_LIBRARY_EXTENSION"
fi
kextcache -i /
