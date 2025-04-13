/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/settingswidget/settings.h"

#if _WIN32
#include <Ws2tcpip.h>  // NOLINT(build/include_order)
#include <windows.h>   // NOLINT(build/include_order)
#endif

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

using fptn::gui::SettingsWidget;

SettingsWidget::SettingsWidget(
    const SettingsModelPtr& settings, QWidget* parent)
    : QDialog(parent), settings_(settings) {
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
  QVBoxLayout* settings_layout = new QVBoxLayout(settings_tab_);
  settings_layout->setContentsMargins(10, 10, 10, 10);

  // Grid Layout for settings
  QGridLayout* grid_layout = new QGridLayout();
  grid_layout->setContentsMargins(0, 0, 0, 0);
  grid_layout->setHorizontalSpacing(10);
  grid_layout->setVerticalSpacing(10);

  // Adjust column stretching
  grid_layout->setColumnStretch(0, 1);  // Label column
  grid_layout->setColumnStretch(1, 4);  // Field column

  // AUTOSTART (show only for Linux)
#if defined(__linux__)
  autostart_label_ = new QLabel(QObject::tr("Autostart"), this);
  autostart_checkbox_ = new QCheckBox(" ", this);
  autostart_checkbox_->setChecked(settings_->Autostart());
  connect(autostart_checkbox_, &QCheckBox::toggled, this,
      &SettingsWidget::onAutostartChanged);
  grid_layout->addWidget(autostart_label_, 0, 0, Qt::AlignLeft);
  grid_layout->addWidget(autostart_checkbox_, 0, 1, Qt::AlignLeft);
#endif

  // LANGUAGE
  language_label_ = new QLabel(QObject::tr("Language"), this);
  language_combo_box_ = new QComboBox(this);
  language_combo_box_->addItems(settings_->GetLanguages());
  language_combo_box_->setCurrentText(settings_->LanguageName());
  connect(language_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onLanguageChanged);
  grid_layout->addWidget(language_label_, 1, 0, Qt::AlignLeft);
  grid_layout->addWidget(language_combo_box_, 1, 1, Qt::AlignLeft);

  // INTERFACE
  interface_label_ =
      new QLabel(QObject::tr("Network Interface (adapter)") + ":  ", this);
  interface_combo_box_ = new QComboBox(this);
  interface_combo_box_->addItems(settings_->GetNetworkInterfaces());
  interface_combo_box_->setCurrentText(settings_->UsingNetworkInterface());
  connect(interface_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onInterfaceChanged);
  grid_layout->addWidget(interface_label_, 2, 0, Qt::AlignLeft);
  grid_layout->addWidget(interface_combo_box_, 2, 1, Qt::AlignLeft);

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

  QHBoxLayout* gateway_layout = new QHBoxLayout();
  gateway_layout->addWidget(gateway_auto_checkbox_, Qt::AlignLeft);
  gateway_layout->setStretch(0, 1);

  gateway_layout->addWidget(gateway_line_edit_, Qt::AlignLeft);
  gateway_layout->setStretch(1, 4);

  grid_layout->addWidget(gateway_label_, 3, 0);
  grid_layout->addLayout(gateway_layout, 3, 1, 1, 2);
  settings_layout->addLayout(grid_layout);

  // SNI
  sni_label_ = new QLabel(
      QObject::tr("Fake SNI to bypass censorship (hides the VPN)") + ": ",
      this);
  sni_line_edit_ = new QLineEdit(this);
  sni_line_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  sni_line_edit_->setText(settings_->SNI());
  connect(sni_line_edit_, &QLineEdit::textChanged, this,
      [this](const QString& sni) { settings_->SetSNI(sni); });

  grid_layout->addWidget(sni_label_, 4, 0, Qt::AlignLeft);
  grid_layout->addWidget(sni_line_edit_, 4, 1, 1, 2);
  settings_->SetSNI(sni_line_edit_->text());

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

  settings_layout->addWidget(server_table_);

  // Buttons
  QHBoxLayout* button_layout = new QHBoxLayout();
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
  QVBoxLayout* aboutLayout = new QVBoxLayout(about_tab_);
  aboutLayout->setContentsMargins(10, 10, 10, 10);
  aboutLayout->setSpacing(10);
  // FPTN label
  QLabel* fptnLabel_ = new QLabel("FPTN", this);
  fptnLabel_->setAlignment(Qt::AlignCenter);
  aboutLayout->addWidget(fptnLabel_);
  // Version Label - centered horizontally
  version_label_ = new QLabel(
      QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION), this);
  version_label_->setAlignment(Qt::AlignCenter);
  aboutLayout->addWidget(version_label_);
  // Project Information - justified
  project_info_label_ = new QLabel(QObject::tr("FPTN_DESCRIPTION"), this);
  project_info_label_->setWordWrap(true);
  project_info_label_->setAlignment(Qt::AlignJustify);
  aboutLayout->addWidget(project_info_label_);
  // Add a link (optional)
  website_link_label_ =
      new QLabel(QObject::tr("FPTN_WEBSITE_DESCRIPTION"), this);
  website_link_label_->setOpenExternalLinks(true);
  aboutLayout->addWidget(website_link_label_);
  // Add group information (optional)
  telegram_group_lLabel_ =
      new QLabel(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"), this);
  telegram_group_lLabel_->setOpenExternalLinks(true);
  aboutLayout->addWidget(telegram_group_lLabel_);
  // stretch
  aboutLayout->addStretch(1);
  // Add About Tab to TabWidget
  tab_widget_->addTab(about_tab_, QObject::tr("About"));

  // Main Layout
  QVBoxLayout* mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(0, 0, 0, 0);
  mainLayout->addWidget(tab_widget_);
  setMinimumSize(600, 400);
  setLayout(mainLayout);

  // Populate server table with data
  const QVector<ServiceConfig>& services = settings_->Services();
  server_table_->setRowCount(services.size());
  for (int i = 0; i < services.size(); ++i) {
    const ServiceConfig& service = services[i];
    server_table_->setItem(i, 0, new QTableWidgetItem(service.service_name));
    server_table_->setItem(i, 1, new QTableWidgetItem(service.username));

    QString serversTextList = "";
    for (const auto& s : service.servers) {
      serversTextList += QString("%1\n").arg(s.name);
    }
    auto item = new QTableWidgetItem(serversTextList);
    item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    item->setFlags(item->flags() | Qt::ItemIsEnabled);
    item->setData(Qt::DisplayRole, serversTextList);
    server_table_->setItem(i, 2, item);

    auto delete_button = new QPushButton(QObject::tr("Delete"), this);
    connect(delete_button, &QPushButton::clicked,
        [this, i]() { onRemoveServer(i); });

    auto button_container = new QWidget();
    auto actionLayout = new QHBoxLayout(button_container);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setAlignment(Qt::AlignCenter);
    actionLayout->addWidget(delete_button);
    server_table_->setCellWidget(i, 3, button_container);
  }
}

void SettingsWidget::onExit() {
  settings_->SetUsingNetworkInterface(interface_combo_box_->currentText());
  settings_->SetLanguage(language_combo_box_->currentText());
  settings_->SetGatewayIp(gateway_line_edit_->text());
  settings_->SetSNI(sni_line_edit_->text());
  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }
  this->close();
}

void SettingsWidget::onLoadNewConfig() {
#if __APPLE__  // show modal window only for mac
  const QString filePath =
      QFileDialog::getOpenFileName(this, QObject::tr("Open FPTN Service File"),
          QDir::homePath(), "FPTN Files (*.fptn);;All files (*)", nullptr,
          QFileDialog::DontUseNativeDialog);
  QString token;
  if (!filePath.isEmpty()) {
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
      QTextStream in(&file);
      token = in.readAll();
      file.close();
    }
  }
#else
  TokenDialog dialog(this);
  dialog.exec();
  const QString token = dialog.Token();
#endif
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
        auto item = new QTableWidgetItem(servers_text_list);
        item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        item->setFlags(item->flags() | Qt::ItemIsEnabled);
        item->setData(Qt::DisplayRole, servers_text_list);
        server_table_->setItem(new_row, 2, item);

        auto delete_button = new QPushButton(QObject::tr("Delete"), this);
        connect(delete_button, &QPushButton::clicked,
            [this, new_row]() { onRemoveServer(new_row); });

        auto button_container = new QWidget();
        auto* button_layout = new QHBoxLayout(button_container);
        button_layout->setContentsMargins(0, 0, 0, 0);
        button_layout->setAlignment(Qt::AlignCenter);
        button_layout->addWidget(delete_button);
        server_table_->setCellWidget(new_row, 3, button_container);

        if (exists_index != -1) {
          // update data
          QMessageBox::information(this, QObject::tr("Save Successful"),
              QObject::tr("Data has been successfully saved."));
        } else {
          // new data
          QMessageBox::information(this, QObject::tr("Save Successful"),
              QObject::tr("Data has been successfully saved."));
        }
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
#if defined(__linux__)
  if (autostart_label_) {
    autostart_label_->setText(QObject::tr("Autostart"));
  }
#endif
  if (sni_label_) {
    sni_label_->setText(
        QObject::tr("Fake SNI to bypass censorship (hides the VPN)") + ": ");
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
  if (telegram_group_lLabel_) {
    telegram_group_lLabel_->setText(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"));
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
