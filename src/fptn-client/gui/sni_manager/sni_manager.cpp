/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/sni_manager/sni_manager.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace fptn::gui {

SNIManager::SNIManager(std::string sni_folder)
    : sni_folder_(std::move(sni_folder)) {
  std::error_code ec;
  std::filesystem::create_directories(sni_folder_, ec);
}

std::vector<std::string> SNIManager::SniFileList() const {
  std::vector<std::string> result;

  std::error_code ec;
  auto dir_iter = std::filesystem::directory_iterator(sni_folder_, ec);
  if (ec) {
    return {};
  }
  for (const auto& entry : dir_iter) {
    if (entry.is_regular_file() && entry.path().extension() == ".sni") {
      result.push_back(entry.path().filename().string());
    }
  }

  std::ranges::sort(result);
  return result;
}

bool SNIManager::AddSniFile(const std::string& path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    return false;
  }

  std::filesystem::path source(path);
  std::filesystem::path dest = sni_folder_ + "/" + source.filename().string();

  std::filesystem::copy_file(
      source, dest, std::filesystem::copy_options::overwrite_existing, ec);
  return !ec;
}

bool SNIManager::RemoveFile(const std::string& file_name) {
  std::filesystem::path file_path = sni_folder_ + "/" + file_name;
  std::error_code ec;
  return std::filesystem::remove(file_path, ec) && !ec;
}

std::vector<std::string> SNIManager::GetSniList(
    const std::string& file_name) const {
  std::vector<std::string> result;

  std::filesystem::path file_path = sni_folder_ + "/" + file_name;
  std::ifstream file(file_path);

  if (!file.is_open()) {
    return result;
  }

  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty()) {
      result.push_back(line);
    }
  }

  return result;
}

}  // namespace fptn::gui
