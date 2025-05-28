/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifdef __ANDROID__
#include "spdlog/sinks/android_sink.h"  // NOLINT(build/include_order)
#endif
#include <spdlog/sinks/rotating_file_sink.h>  // NOLINT(build/include_order)
#include <spdlog/sinks/stdout_color_sinks.h>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>                    // NOLINT(build/include_order)

namespace fptn::logger {

inline bool init(const std::string& app_name) {
#if defined(__linux__) || defined(__APPLE__)
  const std::filesystem::path log_dir = "/var/log/fptn/";
#elif _WIN32
  const std::filesystem::path log_dir = "./logs/";
#else
#error "Unsupported system!"
#endif
  try {
#ifdef __ANDROID__
    auto logger = spdlog::android_logger_mt("android", app_name);
#else
    // Set locale
    std::locale::global(std::locale::classic());
    std::setlocale(LC_ALL, "C");

    const std::filesystem::path log_file = log_dir / (appName + ".log");
    if (!std::filesystem::exists(log_dir)) {
      try {
        std::filesystem::create_directories(log_dir);
      } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Failed to create log directory: " << e.what()
                  << std::endl;
        return false;
      }
    }
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        logFile.string(), 12 * 1024 * 1024, 3, true);
    auto logger = std::make_shared<spdlog::logger>(
        appName, spdlog::sinks_init_list{consoleSink, fileSink});
    logger->flush_on(spdlog::level::debug);
    spdlog::flush_every(std::chrono::seconds(3));
#endif
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] [%s:%#] %v");
#ifdef __ANDROID__
    spdlog::info("Logger inited");
#else
    spdlog::info("Log file: {}", log_file.string());
#endif
    return true;
  } catch (const spdlog::spdlog_ex& ex) {
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_ERROR, "FPTN",
        "Logger initialization failed: %s", ex.what());
#else
    std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
#endif
  }
  return false;
}
}  // namespace fptn::logger
