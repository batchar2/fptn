/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#if _WIN32
#include <VersionHelpers.h>  // NOLINT(build/include_order)
#endif

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/process.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)
#if _WIN32
#include <boost/process/windows.hpp>
#endif

namespace fptn::common::system::command {
inline bool run(const std::string& command) {
  try {
#ifdef _WIN32
    boost::process::child child(command, boost::process::std_out > stdout,
        boost::process::std_err > stderr, ::boost::process::windows::hide);
#elif defined(__APPLE__) || defined(__linux__)
    boost::process::child child(command, boost::process::std_out > stdout,
        boost::process::std_err > stderr);
#else
#error "Unsupported platform"
#endif
    child.wait();
    return child.exit_code() == 0;
  } catch (const std::exception& e) {
    const std::string msg = e.what();
    spdlog::error("Command error: " + msg);
  } catch (...) {
    spdlog::error("Command error: undefined error");
  }
  return false;
}

inline bool run(
    const std::string& command, std::vector<std::string>& stdoutput) {
  try {
    boost::process::ipstream pipe;
#ifdef _WIN32
    boost::process::child child(command, boost::process::std_out > pipe,
        ::boost::process::windows::hide);
#elif defined(__APPLE__) || defined(__linux__)
    boost::process::child child(boost::process::search_path("bash"), "-c",
        command, boost::process::std_out > pipe);
#else
#error "Unsupported platform"
#endif
    std::string line;
    while (std::getline(pipe, line)) {
      stdoutput.emplace_back(line);
    }
    child.wait();
    return child.exit_code() == 0;
  } catch (const std::exception& ex) {
    spdlog::error(
        "Error: failed to run command '{}'. Error: {}", command, ex.what());
  }
  return false;
}
}  // namespace fptn::common::system::command
