/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <fmt/format.h>  // NOLINT(build/include_order)

#include "common/system/command.h"

#if _WIN32
#include <Windows.h>  // NOLINT(build/include_order)
#include <shlobj.h>   // NOLINT(build/include_order)
#endif

namespace fptn::gui::autostart {

#if __APPLE__
inline std::string GetMacOsPlistPath() {
  const char* home_env = std::getenv("HOME");
  if (nullptr == home_env) {
    return {};
  }
  const std::string home = home_env;
  const auto path =
      std::filesystem::path(home) / "Library" / "LaunchAgents" / "org.fptn.vpn";
  return path.string();
}
#elif __linux__
inline std::string getLinuxDesktopEntryPath() {
  return "/etc/xdg/autostart/fptn-autostart.desktop";
}
#elif _WIN32
inline std::string getWindowsFullPath() {
  char fptn_path[MAX_PATH] = {};
  if (!SUCCEEDED(GetModuleFileName(nullptr, fptn_path, MAX_PATH))) {
    const DWORD code = GetLastError();
    SPDLOG_ERROR("Failed to retrieve the path. Error code: {}", code);
    return {};
  }

  const std::filesystem::path fptnExe(fptn_path);
  const auto batPath = fptnExe.parent_path() / "FptnClient.bat";
  return batPath.string();
}

inline std::string getWindowsStartupFolder() {
  char path[MAX_PATH] = {};
  if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
    // if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path))) {
    const DWORD code = GetLastError();
    SPDLOG_ERROR(
        "Failed to retrieve the startup folder path. Error code: {}", code);
    return {};
  }
  return path;
}
#endif

inline bool enable() {
#if __APPLE__
//  const std::string autostart_template =
//      R"PLIST(<?xml version="1.0" encoding="UTF-8"?>
//            <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
//            "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
//                <plist version="1.0">
//                    <dict>
//                        <key>Label</key>
//                        <string>org.fptn.vpn</string>
//
//                        <key>AssociatedBundleIdentifiers</key>
//                        <array>
//                            <string>org.fptn.vpn</string>
//                        </array>
//
//                        <key>DisplayName</key>
//                        <string>FptnClient</string>
//
//                        <key>ProgramArguments</key>
//                        <array>
//                            <string>{}</string>
//                        </array>
//
//                        <key>UserName</key>
//                        <string>root</string>
//
//                        <key>RunAtLoad</key>
//                        <true/>
//
//                        <key>KeepAlive>
//                        <true/>
//
//                        <key>SessionCreate</key>
//                        <true/>
//
//                        <key>EnableTransactions</key>
//                        <true/>
//                    </dict>
//                </plist>
//        )PLIST";
//  const auto script_path = std::filesystem::current_path() / "Contents" /
//                          "MacOS" / "fptn-client-gui-wrapper.sh";
//  const auto plist = fmt::format(autostart_template, script_path.u8string());
//  const std::string plist_path = GetMacOsPlistPath();
//  if (plist_path.empty()) {
//    SPDLOG_ERROR("Failed to get the macOS plist path.");
//    return false;
//  }
//  SPDLOG_INFO("Plist path: {}", plist_path);
//  std::ofstream file(plist_path);
//  if (file.is_open()) {
//    file << plist;
//    file.close();
//    SPDLOG_INFO("Plist file written successfully at {}", plist_path);
//  } else {
//    SPDLOG_ERROR("Unable to write to plist file at {}", plist_path);
//    return false;
//  }
//  const std::string command =
//  fmt::format(R"(launchctl load "{}" )", plist_path);
//  if (!fptn::common::system::command::run(command)) {
//    SPDLOG_ERROR("Failed to load plist using launchctl.
//    Command: {}", command);
//    return false;
//  }
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
    SPDLOG_ERROR("Failed to get the macOS plist path.");
    return false;
  }
  std::ofstream file(path);
  if (file.is_open()) {
    file << entry;
    file.close();
  } else {
    return false;
  }
#elif _WIN32
  // const std::string fptn_path = getWindowsFullPath();
  // const std::string windowsStartupFolder = getWindowsStartupFolder();
  // if (fptn_path.empty() || windowsStartupFolder.empty()) {
  //     return false;
  // }
  // // SET REG
  // const std::string command = fmt::format(
  //     R"(reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v
  //     "FptnClient" /t REG_SZ /d "{}" /f )", fptn_path
  // );
  // if (!fptn::common::system::command::run(command)) {
  //     SPDLOG_ERROR("Error running command: {}", command);
  //     return false;
  // }
  // SET SHORTCUT
  // const std::filesystem::path shortcutPath =
  // std::filesystem::path(windowsStartupFolder) / "FptnClient.lnk"; const
  // std::string powershellCommand = fmt::format(
  //     R"(powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s =
  //     $ws.CreateShortcut('{}'); $s.TargetPath = '{}'; $s.Save();")",
  //     shortcutPath.u8string(), fptn_path
  // );
  // if (!fptn::common::system::command::run(powershellCommand)) {
  //     SPDLOG_ERROR("Failed to create shortcut: {}", powershellCommand);
  //     return false;
  // }
  // SPDLOG_INFO("Shortcut created successfully at: {}",
  // shortcutPath.u8string());
#endif
  SPDLOG_INFO("Autostart successfully enabled");
  return true;
}

inline bool disable() {
#if __APPLE__
  const std::string plist_path = GetMacOsPlistPath();
  if (plist_path.empty()) {
    SPDLOG_ERROR("Failed to get the macOS plist path.");
    return false;
  }
  if (std::filesystem::exists(plist_path)) {
    const std::string command =
        fmt::format(R"(launchctl unload "{}" )", plist_path);
    if (!fptn::common::system::command::run(command)) {
      return false;
    }
    if (!std::filesystem::remove(plist_path)) {
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
  // const std::string command = R"(reg delete
  // "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "FptnClient" /f )";
  // if (!fptn::common::system::command::run(command)) {
  //     SPDLOG_ERROR("Error running command: {}", command);
  // }
  // delete shortcut
  // const std::string windowsStartupFolder = getWindowsStartupFolder();
  // const std::filesystem::path shortcutPath =
  // std::filesystem::path(windowsStartupFolder) / "FptnClient.lnk"; if
  // (std::filesystem::exists(shortcutPath) &&
  // std::filesystem::remove(shortcutPath)) {
  //     SPDLOG_INFO("Shortcut deleted successfully: {}",
  //     shortcutPath.u8string());
  // } else {
  //     SPDLOG_INFO("No shortcut found to delete at: {}",
  //     shortcutPath.u8string());
  // }
#endif
  SPDLOG_INFO("Disable autostart");
  return true;
}
}  // namespace fptn::gui::autostart
