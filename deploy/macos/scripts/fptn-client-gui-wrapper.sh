#!/bin/bash

# Dialog display functions
show_error() {
    osascript -e "display dialog \"$1\" buttons {\"OK\"} default button \"OK\" with icon stop"
    exit 1
}

is_client_running() {
    pgrep -f "fptn-client-gui" > /dev/null
}

show_dialog() {
    local message="$1"
    local buttons="$2"
    local default_button="$3"
    local icon="$4"

    osascript -e "display dialog \"$message\" buttons {$buttons} default button \"$default_button\" with icon $icon"
}

show_driver_failure_dialog() {
    while true; do
        local response
        response=$(osascript <<EOF
try
    set dialogResult to button returned of (display dialog "Failed to load the TUN driver. Here's what to do:

STEP 1: Enable System Extensions
1. Open System Settings → Privacy & Security
2. Scroll down to the 'Security' section
3. Click 'Enable System Extensions' button
4. Restart your computer when prompted

STEP 2: Recovery Mode Setup
1. Shut down your system
2. Press and hold the power button
3. Launch Startup Security Utility
4. Select 'Macintosh HD'
5. Click 'Security Policy...' button
7. Select 'Reduced Security'
8. Check 'Allow user management of kernel extensions'
9. Exit and restart normally

STEP 3: FINAL APPROVAL
1. After restart, check Privacy & Security again
2. Approve any remaining prompts for:
   • Developer 'Jonathan Bullard'
   • System extension loading
3. If you see 'A restart is required':
   • Click 'Restart' to complete installation

STEP 4: VERIFY & TROUBLESHOOT
1. Launch FptnClient and test connection
2. If issues remain:
   • Repeat steps 1-3 carefully
   • Contact @fptn_project on Telegram
   • Include screenshot of any error messages
" \
buttons {"Open Security Settings", "Quit"} \
default button "Open Security Settings" \
with icon stop with title "Driver Installation Required")
    return dialogResult
on error
    return "Quit"
end try
EOF
        )

        case "$response" in
            "Open Security Settings")
                open "x-apple.systempreferences:com.apple.preference.security?General"
                # show again the dialog
                continue
                ;;
            *)
                exit 1
                ;;
        esac
    done
}

show_driver_not_loaded_dialog() {
    local response
    response=$(osascript <<EOF
try
    set dialogResult to button returned of (display dialog "The TUN driver is still not loaded. Please:

1. Open System Settings → Privacy & Security
2. Check the 'Security' section for approval prompts
3. If you just approved the driver, restart your computer

The VPN cannot function without this driver." \
buttons {"Try Again", "Quit"} default button "Try Again" \
with icon stop with title "Driver Not Loaded")
    return dialogResult
on error
    return "Quit"
end try
EOF
    )

    [ "$response" = "Try Again" ] && return 1 || exit 1
}

# Install driver and related components
install_driver() {
    local KEXT_SRC="/Applications/FptnClient.app/Contents/Resources/tun.kext"
    local KEXT_DST="/Library/Extensions/tun.kext"
    local PLIST_SRC="/Applications/FptnClient.app/Contents/Resources/net.tunnelblick.tun.plist"
    local PLIST_DST="/Library/LaunchDaemons/net.tunnelblick.tun.plist"

    # Copy KEXT if missing
    if [ ! -d "$KEXT_DST" ]; then
        echo "Copying KEXT to $KEXT_DST..."
        cp -r "$KEXT_SRC" "$KEXT_DST" || return 1
        kextcache -i / || return 1
    fi

    # Copy plist if missing
    if [ ! -f "$PLIST_DST" ]; then
        echo "Copying plist to $PLIST_DST..."
        cp "$PLIST_SRC" "$PLIST_DST" || return 1
    fi

    # Load driver if not loaded
    if ! kextstat | grep -q "tun"; then
        echo "Loading driver..."
        kextload "$KEXT_DST" || return 1
    fi

    return 0
}

# Reset DNS settings
clean_dns() {
    networksetup -listallnetworkservices | grep -v '^An asterisk' | \
    xargs -I {} networksetup -setdnsservers "{}" empty
}

# Main execution
if [ "$1" = "--install-driver" ]; then
    install_driver
    exit $?
fi

# Check if driver needs installation
if [ ! -d "/Library/Extensions/tun.kext" ] || ! kextstat | grep -q "tun"; then
    echo "Driver installation required. Requesting privileges..."

    if ! osascript -e "do shell script \"'$0' --install-driver\" with administrator privileges"; then
        show_driver_failure_dialog

        # Check again
        if ! kextstat | grep -q "tun"; then
            show_driver_not_loaded_dialog
            [ $? -eq 1 ] && exec "$0" || exit 1
        fi
    fi

    # Final check
    if ! kextstat | grep -q "tun"; then
        show_driver_not_loaded_dialog
        [ $? -eq 1 ] && exec "$0" || exit 1
    fi
fi

# Set environment and launch application
export QT_PLUGIN_PATH=/Applications/FptnClient.app/Contents/Frameworks/plugins
export QT_QPA_PLATFORM_PLUGIN_PATH=$QT_PLUGIN_PATH/platforms
export LD_LIBRARY_PATH=/Applications/FptnClient.app/Contents/Frameworks

clean_dns

# run in background
/Applications/FptnClient.app/Contents/MacOS/fptn-client-gui "$@" &

# wait for end of client
while is_client_running; do
    sleep 1
done

clean_dns
