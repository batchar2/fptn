#!/bin/bash


#./resources/macos/fptn-client-dmg/scripts/fptn-client-cli-wrapper.sh
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



# Copy and load LaunchDaemon plist
TUN_PLIST_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"
TUN_PLIST_PATH_INSIDE_APPLICATION="/Applications/FptnClient.app/Contents/Resources/net.tunnelblick.tun.plist"

if [ -f "$TUN_PLIST_PATH" ]; then
    echo "LaunchDaemon plist already exists: $TUN_PLIST_PATH"
else
    cp -rv "$TUN_PLIST_PATH_INSIDE_APPLICATION" "/Library/LaunchDaemons/"
fi

# Load LaunchDaemon plist
if [ -f "$TUN_PLIST_PATH" ]; then
    echo "Loading LaunchDaemon..."
    launchctl load "$TUN_PLIST_PATH"
else
    echo "LaunchDaemon plist not found: $TUN_PLIST_PATH"
fi

# Load kext
if [ -d "$KEXT_PATH" ]; then
    echo "Loading kext..."
    kextload "$KEXT_PATH"
else
    echo "Kext not found: $KEXT_PATH"
fi

#
#
#
#
#
#
#
#
#
#
#APP_EXECUTABLE="/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli"
#SYMLINK_PATH="/usr/local/bin/fptn-client-cli"
#if [ -L "$SYMLINK_PATH" ]; then
#    echo "Symbolic link already exists: $SYMLINK_PATH"
#else
#    ln -s "$APP_EXECUTABLE" "$SYMLINK_PATH"
#    echo "Symbolic link created: $SYMLINK_PATH"
#fi
#LAUNCHD_PATH="/Library/Extensions/tunnelblick-tun.kext"
#Change the name to tap.kext and tap.kext,
#Copy to /Library/Extensions
#add net.tunnelblick.tap.plist and net.tunnelblick.tun.plist to /Library/LaunchDaemons/



#KEXT_PATH="/Library/Extensions/tunnelblick-tun.kext"
#LAUNCHD_PATH="/Library/LaunchDaemons/net.tunnelblick.tun.plist"

#if [ -d "$KEXT_PATH" ]; then
#    echo "Loading kext..."
#    kextload "$KEXT_PATH"
#else
#    echo "Kext not found: $KEXT_PATH"
#fi
#
#if [ -f "$LAUNCHD_PATH" ]; then
#    echo "Loading LaunchDaemon..."
#    launchctl load "$LAUNCHD_PATH"
#else
#    echo "LaunchDaemon plist not found: $LAUNCHD_PATH"
#fi


#

#
##kex --start
