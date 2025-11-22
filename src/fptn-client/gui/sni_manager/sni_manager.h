/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

namespace fptn::gui {

class SNIManager {
 public:
  explicit SNIManager(std::string sni_folder);

  std::vector<std::string> SniFileList() const;
  bool AddSniFile(const std::string& path);
  bool RemoveFile(const std::string& file_name);
  std::vector<std::string> GetSniList(const std::string& file_name) const;

 private:
  const std::string sni_folder_;
};

using SNIManagerSPtr = std::shared_ptr<SNIManager>;

}  // namespace fptn::gui
