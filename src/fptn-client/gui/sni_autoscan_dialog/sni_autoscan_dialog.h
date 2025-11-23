/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <QComboBox>    // NOLINT(build/include_order)
#include <QDialog>      // NOLINT(build/include_order)
#include <QLabel>       // NOLINT(build/include_order)
#include <QPushButton>  // NOLINT(build/include_order)
#include <QTextEdit>    // NOLINT(build/include_order)
#include <QTimer>       // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"
#include "gui/settingsmodel/settingsmodel.h"

namespace fptn::gui {

class SniAutoscanDialog : public QDialog {
  Q_OBJECT

 public:
  explicit SniAutoscanDialog(
      SettingsModelPtr settings, QWidget* parent = nullptr);
  ~SniAutoscanDialog() override;

  // cppcheck-suppress unknownMacro
 public slots:
  void onStartStopClicked();
  void onUpdateProgress();

 protected:
  void SetupUi();

  void StartScanning();
  void StopScanning();
  void WorkerThread(int thread_id);

  std::vector<std::string> CollectAllSni() const;
  std::vector<std::string> CollectSniFromSelectedFile() const;
  QVector<ServerConfig> CollectTargetServers() const;
  std::string GetNextSni();

  void AddLogEntry(const QString& server,
      const QString& sni,
      bool handshake_ok,
      bool http_ok);

 private:
  mutable std::mutex mutex_;

  std::vector<std::string> sni_vector_;
  std::size_t current_sni_index_ = 0;

  std::atomic<bool> is_scanning_{false};
  std::atomic<bool> stop_requested_{false};
  std::atomic<int> tested_count_{0};
  std::atomic<int> working_sni_found_{0};
  std::string found_working_sni_;

  QVector<ServerConfig> target_servers_;
  std::vector<std::thread> worker_threads_;

  SettingsModelPtr settings_;

  QComboBox* server_combo_box_ = nullptr;
  QComboBox* sni_file_combo_box_ = nullptr;
  QLabel* progress_label_ = nullptr;
  QPushButton* start_stop_button_ = nullptr;
  QPushButton* close_button_ = nullptr;
  QTextEdit* log_text_edit_ = nullptr;
  QTimer* progress_timer_ = nullptr;

  bool auto_scroll_ = true;
};

}  // namespace fptn::gui
