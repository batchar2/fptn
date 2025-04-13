/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QToolButton>
#include <QWidget>

#include "gui/settingsmodel/settingsmodel.h"

namespace fptn::gui {
class SettingsWidget : public QDialog {
  Q_OBJECT

 public:
  explicit SettingsWidget(SettingsModelPtr settings, QWidget* parent = nullptr);

 protected:
  void closeEvent(QCloseEvent* event) override;
  void SetupUi();
 private slots:
  void onExit();
  void onLoadNewConfig();
  void onRemoveServer(int row);
  void onLanguageChanged(const QString& new_language);
  void onInterfaceChanged(const QString& new_language);
  void onAutostartChanged(bool checked);
  void onAutoGatewayChanged(bool checked);

 private:
  SettingsModelPtr settings_;

  QTabWidget* tab_widget_ = nullptr;
  QWidget* settings_tab_ = nullptr;
  QWidget* about_tab_ = nullptr;
  QTableWidget* server_table_ = nullptr;

// AUTOSTART (show only for Linux)
#if defined(__linux__)
  QLabel* autostart_label_ = nullptr;
  QCheckBox* autostart_checkbox_ = nullptr;
#endif
  QLabel* language_label_ = nullptr;
  QComboBox* language_combo_box_ = nullptr;

  QComboBox* interface_combo_box_ = nullptr;
  QLabel* interface_label_ = nullptr;

  QLineEdit* gateway_line_edit_ = nullptr;
  QCheckBox* gateway_auto_checkbox_ = nullptr;
  QLabel* gateway_label_ = nullptr;

  QLabel* sni_label_ = nullptr;
  QLineEdit* sni_line_edit_ = nullptr;

  QPushButton* load_new_token_button_ = nullptr;

  QPushButton* exit_button_ = nullptr;

  QLabel* version_label_ = nullptr;

  QLabel* project_info_label_ = nullptr;
  QLabel* website_link_label_ = nullptr;
  QLabel* telegram_group_lLabel_ = nullptr;
};
}  // namespace fptn::gui
