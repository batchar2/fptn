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

#include <spdlog/sinks/rotating_file_sink.h>  // NOLINT(build/include_order)
#include <spdlog/sinks/stdout_color_sinks.h>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>                    // NOLINT(build/include_order)

namespace fptn::logger {
inline bool init(const std::string& appName) {
#if defined(__linux__) || defined(__APPLE__)
  const std::filesystem::path logDir = "/var/log/fptn/";
#elif _WIN32
  const std::filesystem::path logDir = "./logs/";
#else
#error "Unsupported system!"
#endif
  // Set locale
  std::locale::global(std::locale::classic());
  std::setlocale(LC_ALL, "C");

  if (!std::filesystem::exists(logDir)) {
    try {
      std::filesystem::create_directories(logDir);
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Failed to create log directory: " << e.what() << std::endl;
      return false;
    }
  }
  const std::filesystem::path logFile = logDir / (appName + ".log");
  try {
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        logFile.string(), 12 * 1024 * 1024, 3, true);

    auto logger = std::make_shared<spdlog::logger>(
        appName, spdlog::sinks_init_list{consoleSink, fileSink});
    logger->flush_on(spdlog::level::debug);
    spdlog::flush_every(std::chrono::seconds(3));

    spdlog::set_default_logger(logger);

    spdlog::set_level(spdlog::level::info);
    spdlog::info("Log file: {}", logFile.string());

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] [%s:%#] %v");
    return true;
  } catch (const spdlog::spdlog_ex& ex) {
    std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
  }
  return false;
}
}  // namespace fptn::logger
