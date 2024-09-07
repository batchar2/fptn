#!/bin/bash

KEXT_PATH="/Library/Extensions/tun.kext"
if [ -d "$KEXT_PATH" ]; then
    echo "Unloading kext..."
    sudo kextunload "$KEXT_PATH"
    echo "Deleting kext files..."
    sudo rm -rf "$KEXT_PATH"
else
    echo "Kext not found: $KEXT_PATH"
fi

PLIST_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"
if [ -f "$PLIST_PATH" ]; then
    echo "Unloading LaunchDaemon..."
    sudo launchctl unload "$PLIST_PATH"
    echo "Deleting LaunchDaemon plist..."
    sudo rm -f "$PLIST_PATH"
else
    echo "LaunchDaemon plist not found: $PLIST_PATH"
fi

SYMLINK_PATH="/usr/local/bin/fptn-client-cli"
if [ -L "$SYMLINK_PATH" ]; then
    echo "Deleting symbolic link..."
    sudo rm -f "$SYMLINK_PATH"
else
    echo "Symbolic link not found: $SYMLINK_PATH"
fi

echo "tun.kext and related files have been removed."
