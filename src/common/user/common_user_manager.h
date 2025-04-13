/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include <openssl/evp.h>  // NOLINT(build/include_order)

namespace fptn::common::user {
class CommonUserManager final {
 public:
  explicit CommonUserManager(std::string filePath)
      : file_path_(std::move(filePath)) {
    CreateFileIfNotExists(file_path_);
    LoadUsers();
  }

  bool AddUser(
      const std::string& username, const std::string& password, int bandwidth) {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    if (!ValidateUsername(username)) {
      std::cerr << "Invalid username." << std::endl;
      return false;
    }

    if (bandwidth < 0) {
      std::cerr << "Invalid bandwidth value. It should be a positive number."
                << std::endl;
      return false;
    }

    if (users_.find(username) != users_.end()) {
      std::cout << "User " << username << " already exists." << std::endl;
      return false;
    }
    std::string hash = HashPassword(password);
    users_[username] = {hash, bandwidth};
    SaveUsers();
    std::cout << "User " << username << " added with bandwidth " << bandwidth
              << " MB." << std::endl;
    return true;
  }

  bool DeleteUser(const std::string& username) {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    if (users_.find(username) == users_.end()) {
      return false;
    }
    users_.erase(username);
    SaveUsers();
    return true;
  }

  void ListUsers() const {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress unassignedVariable
    for (const auto& [username, credentials] : users_) {
      std::cout << username << " "
                << std::string(credentials.first.length(), 'X') << " "
                << credentials.second << " MB" << std::endl;
    }
  }

  bool Authenticate(const std::string& username, const std::string& password) {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    LoadUsers();

    auto it = users_.find(username);
    if (it != users_.end()) {
      std::string hash = HashPassword(password);
      return it->second.first == hash;
    }
    return false;
  }

  int GetUserBandwidthBit(const std::string& username) const {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    auto it = users_.find(username);
    if (it != users_.end()) {
      return it->second.second * 1024 * 1024;
    }
    return 0;
  }
  int GetUserBandwidth(const std::string& username) const {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    auto it = users_.find(username);
    if (it != users_.end()) {
      return it->second.second;
    }
    return 0;
  }

 protected:
  void LoadUsers() {
    // FIXIT
    // update
    users_.clear();

    std::ifstream file(file_path_);
    if (file.is_open()) {
      std::string line;
      while (std::getline(file, line)) {
        std::string username;
        std::string passwordHash;
        int bandwidth;

        std::istringstream iss(line);
        if (iss >> username >> passwordHash >> bandwidth) {
          users_[username] = {passwordHash, bandwidth};
        } else {
          std::cerr << "Skipping invalid line: " << line << std::endl;
        }
      }
    } else {
      std::cerr << "Unable to open file: " << file_path_ << std::endl;
    }
  }

  void SaveUsers() const {
    std::ofstream file(file_path_);
    if (file.is_open()) {
      // cppcheck-suppress unassignedVariable
      for (const auto& [username, credentials] : users_) {
        file << username << " " << credentials.first << " "
             << credentials.second << "\n";
      }
    } else {
      std::cerr << "Unable to open file: " << file_path_ << std::endl;
    }
  }

  std::string HashPassword(const std::string& password) const {
    unsigned int length = 0;
    unsigned char hash[EVP_MAX_MD_SIZE] = {0};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
      std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
      return "";
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
      std::cerr << "Failed to initialize digest" << std::endl;
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    if (1 != EVP_DigestUpdate(mdctx, password.c_str(), password.size())) {
      std::cerr << "Failed to update digest" << std::endl;
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &length)) {
      std::cerr << "Failed to finalize digest" << std::endl;
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < length; ++i) {
      oss << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(hash[i]);
    }
    return oss.str();
  }

  bool ValidateUsername(const std::string& username) const {
    return !username.empty() &&
           std::all_of(username.begin(), username.end(), ::isalnum);
  }

  void CreateFileIfNotExists(const std::string& filePath) {
    std::filesystem::path path(filePath);
    std::filesystem::path directoryPath = path.parent_path();
    if (!directoryPath.empty() && !std::filesystem::exists(directoryPath)) {
      std::error_code ec;
      if (!std::filesystem::create_directories(directoryPath, ec)) {
        std::cerr << "Failed to create directories: " << ec.message()
                  << std::endl;
        return;
      }
    }
    if (!std::filesystem::exists(filePath)) {
      std::ofstream file(filePath);
      if (!file.is_open()) {
        std::cerr << "Failed to create file: " << filePath << std::endl;
      }
    }
  }

 private:
  std::unordered_map<std::string, std::pair<std::string, int>> users_;
  mutable std::mutex mutex_;
  std::string file_path_;
};

using CommonUserManagerPtr = std::unique_ptr<CommonUserManager>;
}  // namespace fptn::common::user
