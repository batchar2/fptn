#pragma once

#include <fstream>
#include <iostream>
#include <filesystem>

#include <fmt/format.h>

#include <common/system/command.h>

#if _WIN32
#include <shlobj.h>
#include <Windows.h>
#endif

namespace fptn::gui::autostart
{

#if __APPLE__
    inline std::string getMacOsPlistPath()
    {
        const char* homeEnv = std::getenv("HOME");
        if (nullptr == homeEnv) {
            return {};
        }
        const std::string home = homeEnv;
        const auto path = std::filesystem::path(home) / "Library" / "LaunchAgents" / "org.fptn.vpn";
        return path.u8string();
    }
#elif __linux__
    inline std::string getLinuxDesktopEntryPath()
    {
        return "/etc/xdg/autostart/fptn-autostart.desktop";
    }
#elif _WIN32
    inline std::string getWindowsFullPath()
    {
        char fptnPath[MAX_PATH] = {};
        if (!SUCCEEDED(GetModuleFileName(nullptr, fptnPath, MAX_PATH))) {
            const DWORD code = GetLastError();
            spdlog::error("Failed to retrieve the path. Error code: {}", code);
            return {};
        }
        
        const std::filesystem::path fptnExe(fptnPath);
        const auto batPath = fptnExe.parent_path() / "FptnClient.bat";
        return batPath.u8string();
    }

    inline std::string getWindowsStartupFolder()
    {
        char path[MAX_PATH] = {};
        if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
            // if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path))) {
            const DWORD code = GetLastError();
            spdlog::error("Failed to retrieve the startup folder path. Error code: {}", code);
            return {};
        }
        return path;
    }
#endif

    inline bool enable()
    {
#if __APPLE__
        const std::string autostartTemplate = R"PLIST(<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0">
                    <dict>
                        <key>Label</key>
                        <string>org.fptn.vpn</string>

                        <key>AssociatedBundleIdentifiers</key>
                        <array>
                            <string>org.fptn.vpn</string>
                        </array>

                        <key>DisplayName</key>
                        <string>FptnClient</string>

                        <key>ProgramArguments</key>
                        <array>
                            <string>{}</string>
                        </array>

                        <key>UserName</key>
                        <string>root</string>

                        <key>RunAtLoad</key>
                        <true/>

                        <key>KeepAlive>
                        <true/>

                        <key>SessionCreate</key>
                        <true/>

                        <key>EnableTransactions</key>
                        <true/>
                    </dict>
                </plist>
        )PLIST";
        const auto scriptPath = std::filesystem::current_path() / "Contents" / "MacOS" / "fptn-client-gui-wrapper.sh";
        const auto plist = fmt::format(autostartTemplate, scriptPath.u8string());
        const std::string plistPath = getMacOsPlistPath();
        if (plistPath.empty()) {
            spdlog::error("Failed to get the macOS plist path.");
            return false;
        }
        spdlog::info("Plist path: {}", plistPath);
        std::ofstream file(plistPath);
        if (file.is_open()) {
            file << plist;
            file.close();
            spdlog::info("Plist file written successfully at {}", plistPath);
        } else {
            spdlog::error("Unable to write to plist file at {}", plistPath);
            return false;
        }
        const std::string command = fmt::format(R"(launchctl load "{}" )", plistPath);
        if (!fptn::common::system::command::run(command)) {
            spdlog::error("Failed to load plist using launchctl. Command: {}", command);
            return false;
        }
#elif __linux__
        const std::string entry = R"PLIST([Desktop Entry]
                Name=FptnClient
                Terminal=false
                Exec=/usr/bin/fptn-client
                Type=Application
                Icon=/path/icon.png
                Categories=Utility;
            )PLIST";

        const auto path = std::filesystem::path(getLinuxDesktopEntryPath());
        if (path.empty()) {
            spdlog::error("Failed to get the macOS plist path.");
            return false;
        }
        spdlog::info("DesktopEntry path: {}", path.u8string());
        std::ofstream file(path);
        if (file.is_open()) {
            file << entry;
            file.close();
            spdlog::info("DesktopEntry file written successfully at {}", path.u8string());
        } else {
            spdlog::error("Unable to write to DesktopEntry file at {}", path.u8string());
            return false;
        }
#elif _WIN32
        // const std::string fptnPath = getWindowsFullPath();
        // const std::string windowsStartupFolder = getWindowsStartupFolder();
        // if (fptnPath.empty() || windowsStartupFolder.empty()) {
        //     return false;
        // }
        // // SET REG
        // const std::string command = fmt::format(
        //     R"(reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "FptnClient" /t REG_SZ /d "{}" /f )",
        //     fptnPath
        // );
        // if (!fptn::common::system::command::run(command)) {
        //     spdlog::error("Error running command: {}", command);
        //     return false;
        // }
        // SET SHORTCUT
        // const std::filesystem::path shortcutPath = std::filesystem::path(windowsStartupFolder) / "FptnClient.lnk";
        // const std::string powershellCommand = fmt::format(
        //     R"(powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('{}'); $s.TargetPath = '{}'; $s.Save();")",
        //     shortcutPath.u8string(), fptnPath
        // );
        // if (!fptn::common::system::command::run(powershellCommand)) {
        //     spdlog::error("Failed to create shortcut: {}", powershellCommand);
        //     return false;
        // }
        // spdlog::info("Shortcut created successfully at: {}", shortcutPath.u8string());
#endif
        spdlog::info("Autostart successfully enabled");
        return true;
    }

    inline bool disable()
    {
#if __APPLE__
        const std::string plistPath = getMacOsPlistPath();
        if (plistPath.empty()) {
            spdlog::error("Failed to get the macOS plist path.");
            return false;
        }
        if (std::filesystem::exists(plistPath)) {
            const std::string command = fmt::format(R"(launchctl unload "{}" )", plistPath);
            if (!fptn::common::system::command::run(command)) {
                return false;
            }
            if (!std::filesystem::remove(plistPath)) {
                return false;
            }
        }
#elif __linux__
        if (std::filesystem::exists(getLinuxDesktopEntryPath())) {
            if (!std::filesystem::remove(getLinuxDesktopEntryPath())) {
                return false;
            }
        }
#elif _WIN32
        // delete reg
        // const std::string command = R"(reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "FptnClient" /f )";
        // if (!fptn::common::system::command::run(command)) {
        //     spdlog::error("Error running command: {}", command);
        // }
        // delete shortcut
        // const std::string windowsStartupFolder = getWindowsStartupFolder();
        // const std::filesystem::path shortcutPath = std::filesystem::path(windowsStartupFolder) / "FptnClient.lnk";
        // if (std::filesystem::exists(shortcutPath) && std::filesystem::remove(shortcutPath)) {
        //     spdlog::info("Shortcut deleted successfully: {}", shortcutPath.u8string());
        // } else {
        //     spdlog::info("No shortcut found to delete at: {}", shortcutPath.u8string());
        // }
#endif
        spdlog::info("Disable autostart");
        return true;
    }
}
