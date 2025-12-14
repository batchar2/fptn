/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/settingswidget/settings.h"

#include "gui/sni_autoscan_dialog/sni_autoscan_dialog.h"

#if _WIN32
#include <Ws2tcpip.h>  // NOLINT(build/include_order)
#include <windows.h>   // NOLINT(build/include_order)
#endif

#include <utility>

#include <QFileDialog>       // NOLINT(build/include_order)
#include <QGridLayout>       // NOLINT(build/include_order)
#include <QHeaderView>       // NOLINT(build/include_order)
#include <QLabel>            // NOLINT(build/include_order)
#include <QLineEdit>         // NOLINT(build/include_order)
#include <QMessageBox>       // NOLINT(build/include_order)
#include <QPushButton>       // NOLINT(build/include_order)
#include <QSystemTrayIcon>   // NOLINT(build/include_order)
#include <QTableWidgetItem>  // NOLINT(build/include_order)

#include "gui/autostart/autostart.h"
#include "gui/tokendialog/tokendialog.h"
#include "gui/translations/translations.h"

namespace {
QString CleanDomain(const QString& domain) {
  if (domain.isEmpty()) {
    return domain;
  }

  QString cleaned;
  cleaned.reserve(domain.length());

  static QRegularExpression valid_chars("[a-zA-Z0-9.-]");

  for (int i = 0; i < domain.length(); ++i) {
    QChar ch = domain[i];

    if (valid_chars.match(ch).hasMatch()) {
      cleaned.append(ch.toLower());
    }
  }
  return cleaned;
}
}  // namespace

using fptn::gui::SettingsWidget;

SettingsWidget::SettingsWidget(SettingsModelPtr settings, QWidget* parent)
    : QDialog(parent), settings_(std::move(settings)) {
  SetupUi();
  setWindowIcon(QIcon(":/icons/app.ico"));
  // show on top
  setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
  setModal(true);
  show();
  activateWindow();
  raise();
  setWindowTitle(QObject::tr("Settings"));
}

void SettingsWidget::SetupUi() {
  tab_widget_ = new QTabWidget(this);
  tab_widget_->setContextMenuPolicy(Qt::ActionsContextMenu);

  // Settings tab
  settings_tab_ = new QWidget();
  auto* settings_layout = new QVBoxLayout(settings_tab_);
  settings_layout->setContentsMargins(10, 10, 10, 10);

  // Grid Layout for settings
  grid_layout_ = new QGridLayout();
  grid_layout_->setContentsMargins(0, 0, 0, 0);
  grid_layout_->setHorizontalSpacing(10);
  grid_layout_->setVerticalSpacing(10);

  // Adjust column stretching
  grid_layout_->setColumnStretch(0, 1);  // Label column
  grid_layout_->setColumnStretch(1, 4);  // Field column

  // AUTOSTART (show only for Linux)
#ifdef __linux__
  autostart_label_ = new QLabel(QObject::tr("Autostart"), this);
  autostart_checkbox_ = new QCheckBox(" ", this);
  autostart_checkbox_->setChecked(settings_->Autostart());
  connect(autostart_checkbox_, &QCheckBox::toggled, this,
      &SettingsWidget::onAutostartChanged);
  grid_layout_->addWidget(autostart_label_, 0, 0, Qt::AlignLeft);
  grid_layout_->addWidget(autostart_checkbox_, 0, 1, Qt::AlignLeft);
#endif

  // LANGUAGE
  language_label_ = new QLabel(QObject::tr("Language"), this);
  language_combo_box_ = new QComboBox(this);
  language_combo_box_->addItems(settings_->GetLanguages());
  language_combo_box_->setCurrentText(settings_->LanguageName());
  connect(language_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onLanguageChanged);
  grid_layout_->addWidget(language_label_, 1, 0, Qt::AlignLeft);
  grid_layout_->addWidget(language_combo_box_, 1, 1, Qt::AlignLeft);

  // INTERFACE
  interface_label_ =
      new QLabel(QObject::tr("Network Interface (adapter)") + ":  ", this);
  interface_combo_box_ = new QComboBox(this);
  interface_combo_box_->addItems(settings_->GetNetworkInterfaces());
  interface_combo_box_->setCurrentText(settings_->UsingNetworkInterface());
  connect(interface_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onInterfaceChanged);
  grid_layout_->addWidget(interface_label_, 2, 0, Qt::AlignLeft);
  grid_layout_->addWidget(interface_combo_box_, 2, 1, Qt::AlignLeft);

  // GATEWAY
  gateway_label_ = new QLabel(
      QObject::tr("Gateway IP Address (typically your router's address)") + ":",
      this);
  gateway_auto_checkbox_ = new QCheckBox(QObject::tr("Auto"), this);
  gateway_line_edit_ = new QLineEdit(this);
  if (settings_->GatewayIp().toLower() != "auto") {
    gateway_auto_checkbox_->setChecked(false);
    gateway_line_edit_->setText(settings_->GatewayIp());
    gateway_line_edit_->setEnabled(true);
  } else {
    gateway_auto_checkbox_->setChecked(true);
    gateway_line_edit_->setDisabled(true);
  }
  connect(gateway_auto_checkbox_, &QCheckBox::toggled, this,
      &SettingsWidget::onAutoGatewayChanged);

  auto* gateway_layout = new QHBoxLayout();
  gateway_layout->addWidget(gateway_auto_checkbox_, Qt::AlignLeft);
  gateway_layout->setStretch(0, 1);

  gateway_layout->addWidget(gateway_line_edit_, Qt::AlignLeft);
  gateway_layout->setStretch(1, 4);

  grid_layout_->addWidget(gateway_label_, 3, 0);
  grid_layout_->addLayout(gateway_layout, 3, 1, 1, 2);
  settings_layout->addLayout(grid_layout_);

  // Bypass blocking method
  bypass_method_label_ =
      new QLabel(QObject::tr("Bypass blocking method"), this);
  bypass_method_combo_box_ = new QComboBox(this);
  bypass_method_combo_box_->addItem(QObject::tr("SNI"), "SNI");
  bypass_method_combo_box_->addItem(QObject::tr("OBFUSCATION"), "OBFUSCATION");
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY"), "SNI-REALITY");
  bypass_method_combo_box_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  if (settings_->BypassMethod() == "OBFUSCATION") {
    bypass_method_combo_box_->setCurrentText(QObject::tr("OBFUSCATION"));
  } else if (settings_->BypassMethod() == "SNI-REALITY") {
    bypass_method_combo_box_->setCurrentText(QObject::tr("SNI-REALITY"));
  } else {
    bypass_method_combo_box_->setCurrentText(QObject::tr("SNI"));
  }
  connect(bypass_method_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onBypassMethodChanged);

  grid_layout_->addWidget(bypass_method_label_, 4, 0, Qt::AlignLeft);
  grid_layout_->addWidget(bypass_method_combo_box_, 4, 1, 1, 2);

  sni_label_ =
      new QLabel(QObject::tr("Fake domain to bypass blocking") + ": ", this);
  sni_line_edit_ = new QLineEdit(this);
  sni_line_edit_->setText(settings_->SNI());
  sni_label_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  sni_line_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  connect(sni_line_edit_, &QLineEdit::textChanged, this,
      [this](const QString& text) {
        if (text.isEmpty()) {
          settings_->SetSNI(FPTN_DEFAULT_SNI);
          return;
        }
        QString normalized = CleanDomain(text.toLower());
        if (normalized != text) {
          sni_line_edit_->blockSignals(true);
          sni_line_edit_->setText(normalized);
          sni_line_edit_->blockSignals(false);
        }
        settings_->SetSNI(normalized);
      });

  grid_layout_->addWidget(sni_label_, 5, 0, Qt::AlignLeft | Qt::AlignVCenter);
  grid_layout_->addWidget(sni_line_edit_, 5, 1, 1, 2);

  // SNI Files - placed right under SNI field
  sni_files_list_widget_ = new QListWidget(this);
  sni_files_list_widget_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
  sni_files_list_widget_->setMaximumHeight(80);

  sni_buttons_layout_ = new QHBoxLayout();

  sni_autoscan_button_ = new QPushButton(QObject::tr("Autoscan sni"), this);
  sni_import_button_ = new QPushButton(QObject::tr("Import SNI file"), this);

  sni_buttons_layout_->addWidget(sni_autoscan_button_, 0, Qt::AlignLeft);
  sni_buttons_layout_->addWidget(sni_import_button_, 0, Qt::AlignRight);

  grid_layout_->addLayout(sni_buttons_layout_, 7, 0);
  grid_layout_->addWidget(sni_files_list_widget_, 7, 1, 1, 2);
  connect(sni_autoscan_button_, &QPushButton::clicked, this,
      &SettingsWidget::onAutoscanClicked);

  connect(sni_import_button_, &QPushButton::clicked, this,
      &SettingsWidget::onImportSniFile);

  settings_layout->addLayout(grid_layout_);
  settings_layout->addStretch(0);

  // Server Table
  server_table_ = new QTableWidget(0, 4, this);
  server_table_->setHorizontalHeaderLabels({QObject::tr("Name"),
      QObject::tr("User"), QObject::tr("Servers"), QObject::tr("Action")});
  server_table_->horizontalHeader()->setStretchLastSection(true);
  server_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  server_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  server_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  server_table_->verticalHeader()->setSectionResizeMode(
      QHeaderView::ResizeToContents);
  server_table_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

  settings_layout->addWidget(server_table_, 1);

  // Buttons
  auto* button_layout = new QHBoxLayout();
  button_layout->addStretch();

  load_new_token_button_ =
      new QPushButton("  " + QObject::tr("Add token") + "  ", this);
  connect(load_new_token_button_, &QPushButton::clicked, this,
      &SettingsWidget::onLoadNewConfig);
  button_layout->addWidget(load_new_token_button_);

  exit_button_ = new QPushButton("  " + QObject::tr("Close") + "  ", this);
  connect(exit_button_, &QPushButton::clicked, this, &SettingsWidget::onExit);
  button_layout->addWidget(exit_button_);

  settings_layout->addLayout(button_layout);

  tab_widget_->addTab(settings_tab_, QObject::tr("Settings"));

  // About tab
  about_tab_ = new QWidget();
  auto* about_layout = new QVBoxLayout(about_tab_);
  about_layout->setContentsMargins(10, 10, 10, 10);
  about_layout->setSpacing(10);
  // FPTN label
  auto* fptn_label = new QLabel("FPTN", this);
  fptn_label->setAlignment(Qt::AlignCenter);
  about_layout->addWidget(fptn_label);
  // Version Label - centered horizontally
  version_label_ = new QLabel(
      QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION), this);
  version_label_->setAlignment(Qt::AlignCenter);
  about_layout->addWidget(version_label_);
  // Project Information - justified
  project_info_label_ = new QLabel(QObject::tr("FPTN_DESCRIPTION"), this);
  project_info_label_->setWordWrap(true);
  project_info_label_->setAlignment(Qt::AlignJustify);
  about_layout->addWidget(project_info_label_);
  // Add a link (optional)
  website_link_label_ =
      new QLabel(QObject::tr("FPTN_WEBSITE_DESCRIPTION"), this);
  website_link_label_->setOpenExternalLinks(true);
  about_layout->addWidget(website_link_label_);
  // Add group information (optional)
  telegram_group_label_ =
      new QLabel(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"), this);
  telegram_group_label_->setOpenExternalLinks(true);
  about_layout->addWidget(telegram_group_label_);

  // Sponsors section
  boosty_link_label_ =
      new QLabel(QObject::tr("Support the project on") +
                     " <a href=\"https://boosty.to/fptn\">Boosty</a>",
          this);
  boosty_link_label_->setOpenExternalLinks(true);
  boosty_link_label_->setAlignment(Qt::AlignLeft);
  about_layout->addWidget(boosty_link_label_);

  sponsors_label_ = new QLabel(QObject::tr("Project Sponsors") + ":", this);
  sponsors_label_->setAlignment(Qt::AlignLeft);
  about_layout->addWidget(sponsors_label_);

  const QString sponsors_list =
      "  - Brebor<br>"
      "  - miklefox<br>"
      "  - usrbb<br>"
      "  - Secret_Agent_001<br>"
      "  - ragdollmaster<br>"
      "  - slimefrozik<br>"
      "  - HooLigaN<br>"
      "  - Dima<br>"
      "  - Kori<br>"
      "  - DrowASD<br>"
      "  - GΣG 5952<br>"
      "  - NikVas<br>"
      "  - Сергей<br>"
      "  - Frizgy<br>"
      "  - Tired Smi1e<br>"
      "  - Teya Aster<br>"
      "  - loftynite<br>";
  sponsors_names_label_ = new QLabel(sponsors_list, this);
  sponsors_names_label_->setAlignment(Qt::AlignLeft);
  sponsors_names_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  about_layout->addWidget(sponsors_names_label_);

  // stretch
  about_layout->addStretch(1);
  // Add About Tab to TabWidget
  tab_widget_->addTab(about_tab_, QObject::tr("About"));

  // Main Layout
  auto* main_layout = new QVBoxLayout(this);
  main_layout->setContentsMargins(0, 0, 0, 0);
  main_layout->addWidget(tab_widget_);
  setMinimumSize(600, 400);
  setLayout(main_layout);

  // Populate server table with data
  const QVector<ServiceConfig>& services = settings_->Services();
  server_table_->setRowCount(services.size());
  for (int i = 0; i < services.size(); ++i) {
    const ServiceConfig& service = services[i];
    server_table_->setItem(i, 0, new QTableWidgetItem(service.service_name));
    server_table_->setItem(i, 1, new QTableWidgetItem(service.username));

    QString servers_text_list = "";
    for (const auto& s : service.servers) {
      servers_text_list += QString("%1\n").arg(s.name);
    }
    auto* item = new QTableWidgetItem(servers_text_list);
    item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    item->setFlags(item->flags() | Qt::ItemIsEnabled);
    item->setData(Qt::DisplayRole, servers_text_list);
    server_table_->setItem(i, 2, item);

    auto* delete_button = new QPushButton(QObject::tr("X"), this);
    delete_button->setFixedSize(24, 24);
    delete_button->setStyleSheet(R"(
        QPushButton {
            background-color: #444444;
            color: white;
            border: none;
            border-radius: 12px;
            font-weight: bold;
            padding: 0px;
        }
        QPushButton:hover {
            background-color: #cc0000;
        }
        QPushButton:pressed {
            background-color: #990000;
        }
    )");
    delete_button->setToolTip(QObject::tr("Delete"));
    connect(delete_button, &QPushButton::clicked,
        [this, i]() { onRemoveServer(i); });

    auto* button_container = new QWidget(this);
    auto* action_layout = new QHBoxLayout(button_container);
    action_layout->setContentsMargins(0, 0, 0, 0);
    action_layout->setAlignment(Qt::AlignCenter);
    action_layout->addWidget(delete_button);
    server_table_->setCellWidget(i, 3, button_container);
  }

  // show current method
  onBypassMethodChanged(bypass_method_combo_box_->currentText());

  UpdateSniFilesList();
}

void SettingsWidget::onExit() {
  settings_->SetUsingNetworkInterface(interface_combo_box_->currentText());
  settings_->SetLanguage(language_combo_box_->currentText());
  settings_->SetGatewayIp(gateway_line_edit_->text());
  settings_->SetSNI(sni_line_edit_->text());

  if (bypass_method_combo_box_->currentText() == QObject::tr("OBFUSCATION") ||
      bypass_method_combo_box_->currentText() == "OBFUSCATION") {
    settings_->SetBypassMethod("OBFUSCATION");
  } else if (bypass_method_combo_box_->currentText() ==
                 QObject::tr("SNI-REALITY") ||
             bypass_method_combo_box_->currentText() == "SNI-REALITY") {
    settings_->SetBypassMethod("SNI-REALITY");
  } else {
    settings_->SetBypassMethod("SNI");
  }
  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }
  this->close();
}

void SettingsWidget::onLoadNewConfig() {
  TokenDialog dialog(this);
  dialog.exec();
  const QString token = dialog.Token();

  // show on top
  show();
  activateWindow();
  raise();

  if (!token.isEmpty()) {
    try {
      ServiceConfig config = settings_->ParseToken(token);
      int exists_index = settings_->GetExistServiceIndex(config.service_name);
      if (exists_index != -1) {
        // remove previous settings
        settings_->RemoveServer(exists_index);
        server_table_->removeRow(exists_index);
      }
      settings_->AddService(config);
      const bool saving_status = settings_->Save();
      if (saving_status) {
        // Insert a new row into the server table
        const int new_row = server_table_->rowCount();
        server_table_->insertRow(new_row);

        server_table_->setItem(
            new_row, 0, new QTableWidgetItem(config.service_name));
        server_table_->setItem(
            new_row, 1, new QTableWidgetItem(config.username));

        QString servers_text_list = "";
        for (const auto& s : config.servers) {
          servers_text_list += QString("%1\n").arg(s.name);
        }

        for (const auto& s : config.censored_zone_servers) {
          servers_text_list += QString("* %1\n").arg(s.name);
        }

        auto* item = new QTableWidgetItem(servers_text_list);
        item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        item->setFlags(item->flags() | Qt::ItemIsEnabled);
        item->setData(Qt::DisplayRole, servers_text_list);
        server_table_->setItem(new_row, 2, item);

        auto* delete_button = new QPushButton(QObject::tr("X"), this);
        delete_button->setFixedSize(24, 24);
        delete_button->setStyleSheet(R"(
            QPushButton {
                background-color: #444444;
                color: white;
                border: none;
                border-radius: 12px;
                font-weight: bold;
                padding: 0px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
            QPushButton:pressed {
                background-color: #990000;
            }
        )");
        delete_button->setToolTip(QObject::tr("Delete"));

        auto* button_container = new QWidget();
        auto* button_layout = new QHBoxLayout(button_container);
        button_layout->setContentsMargins(0, 0, 0, 0);
        button_layout->setAlignment(Qt::AlignCenter);
        button_layout->addWidget(delete_button);
        server_table_->setCellWidget(new_row, 3, button_container);

        QMessageBox::information(this, QObject::tr("Save Successful"),
            QObject::tr("Data has been successfully saved."));
      } else {
        QMessageBox::critical(this, QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data."));
      }
    } catch (const std::exception& err) {
      QMessageBox::critical(this, QObject::tr("Error!"), err.what());
    }
  }
}

void SettingsWidget::onRemoveServer(int row) {
  if (row >= 0 && row < server_table_->rowCount()) {
    server_table_->removeRow(row);
    settings_->RemoveServer(row);
    QMessageBox::information(this, QObject::tr("Delete Successful"),
        QObject::tr("The data has been successfully removed"));
  }
}

void SettingsWidget::closeEvent(QCloseEvent* event) {
  onExit();
  event->accept();  // Accept the event to proceed with the closing
}

void SettingsWidget::onLanguageChanged(const QString&) {
  // set language
  settings_->SetLanguage(language_combo_box_->currentText());
  fptn::gui::SetTranslation(settings_->LanguageCode());
  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }

  setWindowTitle(QObject::tr("Settings"));
  if (tab_widget_) {
    tab_widget_->setTabText(0, QObject::tr("Settings"));
    tab_widget_->setTabText(1, QObject::tr("About"));
  }
  if (language_label_) {
    language_label_->setText(QObject::tr("Language"));
  }
  if (interface_label_) {
    interface_label_->setText(
        QObject::tr("Network Interface (adapter)") + ":  ");
  }
  if (gateway_label_) {
    gateway_label_->setText(
        QObject::tr("Gateway IP Address (typically your router's address)") +
        ":");
  }
  if (server_table_) {
    server_table_->setHorizontalHeaderLabels({QObject::tr("Name"),
        QObject::tr("User"), QObject::tr("Servers"), QObject::tr("Action")});
  }
  if (load_new_token_button_) {
    load_new_token_button_->setText("  " + QObject::tr("Add token") + "  ");
  }
  if (exit_button_) {
    exit_button_->setText("  " + QObject::tr("Close") + "  ");
  }
  if (gateway_auto_checkbox_) {
    gateway_auto_checkbox_->setText(QObject::tr("Auto"));
  }
  // AUTOSTART (show only for Linux)
#ifdef __linux__
  if (autostart_label_) {
    autostart_label_->setText(QObject::tr("Autostart"));
  }
#endif

  // Bypass blocking
  if (bypass_method_label_) {
    bypass_method_label_->setText(QObject::tr("Bypass blocking method"));
  }
  if (bypass_method_combo_box_) {
    QString current_method = bypass_method_combo_box_->currentText();
    bypass_method_combo_box_->clear();
    bypass_method_combo_box_->addItem("SNI", "SNI");
    bypass_method_combo_box_->addItem(
        QObject::tr("OBFUSCATION"), "OBFUSCATION");
    bypass_method_combo_box_->addItem(
        QObject::tr("SNI-REALITY"), "SNI-REALITY");

    if (current_method == "SNI" || current_method == QObject::tr("SNI")) {
      bypass_method_combo_box_->setCurrentText(QObject::tr("SNI"));
    } else if (current_method == "OBFUSCATION" ||
               current_method == QObject::tr("OBFUSCATION")) {
      bypass_method_combo_box_->setCurrentText(QObject::tr("OBFUSCATION"));
    } else {
      bypass_method_combo_box_->setCurrentText(QObject::tr("SNI-REALITY"));
    }
  }

  if (sni_label_) {
    sni_label_->setText(QObject::tr("Fake domain to bypass blocking") + ": ");
  }
  if (sni_autoscan_button_) {
    sni_autoscan_button_->setText(QObject::tr("Autoscan SNI"));
  }
  if (sni_import_button_) {
    sni_import_button_->setText(QObject::tr("Import SNI file"));
  }

  // about
  if (version_label_) {
    version_label_->setText(
        QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION));
  }
  if (project_info_label_) {
    project_info_label_->setText(QObject::tr("FPTN_DESCRIPTION"));
  }
  if (website_link_label_) {
    website_link_label_->setText(QObject::tr("FPTN_WEBSITE_DESCRIPTION"));
  }
  if (telegram_group_label_) {
    telegram_group_label_->setText(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"));
  }
  // sponsors section
  if (boosty_link_label_) {
    boosty_link_label_->setText(
        QObject::tr("Support the project on") +
        " <a href=\"https://boosty.to/fptn\">Boosty</a>");
  }
  if (sponsors_label_) {
    sponsors_label_->setText(QObject::tr("Project Sponsors") + ":");
  }
}

void SettingsWidget::onInterfaceChanged(const QString&) {
  settings_->SetUsingNetworkInterface(interface_combo_box_->currentText());
  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }
}

void SettingsWidget::onAutostartChanged(bool checked) {
  if (checked) {
    fptn::gui::autostart::enable();
    settings_->SetAutostart(true);
  } else {
    fptn::gui::autostart::disable();
    settings_->SetAutostart(false);
  }
}

void SettingsWidget::onAutoGatewayChanged(bool checked) {
  if (checked) {
    gateway_line_edit_->setDisabled(true);
    gateway_line_edit_->setText("");
    settings_->SetGatewayIp("auto");
  } else {
    gateway_line_edit_->setEnabled(true);
  }
}

void SettingsWidget::onBypassMethodChanged(const QString& method) {
  const bool is_sni_mode = (method == QObject::tr("SNI") || method == "SNI");
  const bool is_reality_mode =
      method == QObject::tr("SNI-REALITY") || method == "SNI-REALITY";

  // Show/hide SNI field
  sni_label_->setVisible(is_sni_mode || is_reality_mode);
  sni_line_edit_->setVisible(is_sni_mode || is_reality_mode);

  // Show/hide SNI files section based on mode
  sni_files_list_widget_->setVisible(is_sni_mode);
  sni_autoscan_button_->setVisible(is_sni_mode);
  sni_import_button_->setVisible(is_sni_mode);

  if (is_sni_mode || is_reality_mode) {
    grid_layout_->addWidget(sni_label_, 5, 0, Qt::AlignLeft | Qt::AlignVCenter);
    grid_layout_->addWidget(sni_line_edit_, 5, 1, 1, 2);
    grid_layout_->addLayout(sni_buttons_layout_, 7, 0);
    grid_layout_->addWidget(sni_files_list_widget_, 7, 1, 1, 2);
  } else {
    grid_layout_->removeWidget(sni_label_);
    grid_layout_->removeWidget(sni_line_edit_);
    grid_layout_->removeItem(sni_buttons_layout_);
    grid_layout_->removeWidget(sni_files_list_widget_);
  }

  if (method == QObject::tr("OBFUSCATION") || method == "OBFUSCATION") {
    settings_->SetBypassMethod("OBFUSCATION");
  } else if (method == QObject::tr("SNI-REALITY") || method == "SNI-REALITY") {
    settings_->SetBypassMethod("SNI-REALITY");
  } else {
    settings_->SetBypassMethod("SNI");
  }
}

void SettingsWidget::UpdateSniFilesList() {
  sni_files_list_widget_->clear();

  auto files = settings_->SniManager()->SniFileList();
  for (const auto& file : files) {
    QString file_name = QString::fromStdString(file);

    auto* item_widget = new QWidget(this);
    auto* layout = new QHBoxLayout(item_widget);
    layout->setContentsMargins(10, 5, 10, 5);
    layout->setSpacing(10);

    auto* name_label = new QLabel(file_name);
    name_label->setStyleSheet("QLabel { font-weight: bold; }");
    name_label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    layout->addWidget(name_label);

    item_widget->setLayout(layout);

    auto* item = new QListWidgetItem(sni_files_list_widget_);
    item->setSizeHint(item_widget->sizeHint());
    sni_files_list_widget_->setItemWidget(item, item_widget);
  }

  if (files.empty()) {
    auto* empty_item = new QListWidgetItem(
        QObject::tr("No SNI files imported"), sni_files_list_widget_);
    empty_item->setFlags(empty_item->flags() & ~Qt::ItemIsEnabled);
    empty_item->setTextAlignment(Qt::AlignCenter);
  }
}

void SettingsWidget::onImportSniFile() {
  QString file_path =
      QFileDialog::getOpenFileName(this, QObject::tr("Select SNI file"), "",
          QObject::tr("SNI files (*.sni);;All files (*)"));

  if (!file_path.isEmpty()) {
    QFileInfo file_info(file_path);
    QString file_name = file_info.fileName();

    auto existing_files = settings_->SniManager()->SniFileList();
    bool file_exists = false;
    for (const auto& existing_file : existing_files) {
      if (QString::fromStdString(existing_file) == file_name) {
        file_exists = true;
        break;
      }
    }

    if (file_exists) {
      QMessageBox::StandardButton reply = QMessageBox::question(this,
          QObject::tr("File exists"),
          QObject::tr("File \"%1\" already exists. Overwrite?").arg(file_name),
          QMessageBox::Yes | QMessageBox::No);
      if (reply != QMessageBox::Yes) {
        return;
      }
    }

    if (settings_->SniManager()->AddSniFile(file_path.toStdString())) {
      UpdateSniFilesList();
      QMessageBox::information(this, QObject::tr("Success"),
          QObject::tr("SNI file imported successfully"));
    } else {
      QMessageBox::warning(
          this, QObject::tr("Error"), QObject::tr("Failed to import SNI file"));
    }
  }
}

void SettingsWidget::onAutoscanClicked() {
  SniAutoscanDialog dialog(settings_, this);
  dialog.exec();
  sni_line_edit_->setText(settings_->SNI());
}
