/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/tray/tray.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QDesktopServices>  // NOLINT(build/include_order)
#include <QIcon>             // NOLINT(build/include_order)
#include <QMessageBox>       // NOLINT(build/include_order)
#include <QStyleFactory>     // NOLINT(build/include_order)
#include <QStyleHints>       // NOLINT(build/include_order)

#include "common/system/command.h"

#include "gui/autoupdate/autoupdate.h"
#include "gui/style/style.h"
#include "gui/translations/translations.h"

using fptn::gui::TrayApp;

inline void showError(const QString& title, const QString& msg) {
  QWidget tempWidget;
  QMessageBox::critical(&tempWidget, title, msg);
}

TrayApp::TrayApp(const SettingsModelPtr& settings, QObject* parent)
    : QWidget(),
      settings_(settings),
      tray_icon_(new QSystemTrayIcon(this)),
      tray_menu_(new QMenu(this)),
      connect_menu_(new QMenu(QObject::tr("Connect") + "    ", tray_menu_)),
      speed_widget_(new SpeedWidget(tray_menu_)),
      update_timer_(new QTimer(this)),
      active_icon_path_(":/icons/active.ico"),
      inactive_icon_path_(":/icons/inactive.ico") {
  (void)parent;
#ifdef __linux__
  qApp->setStyleSheet(fptn::gui::ubuntuStyleSheet);
#elif __APPLE__
  qApp->setStyleSheet(fptn::gui::macStyleSheet);
#elif _WIN32
  qApp->setStyleSheet(fptn::gui::windowsStyleSheet);
#else
#error "Unsupported system!"
#endif

#if __linux__
  connect(tray_icon_, &QSystemTrayIcon::activated,
      [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Context) {
          tray_menu_->popup(tray_icon_->geometry().bottomLeft());
        } else {
          tray_menu_->close();
        }
      });
#elif _WIN32
  connect(tray_icon_, &QSystemTrayIcon::activated,
      [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Context) {
          tray_menu_->show();
          tray_menu_->exec(QCursor::pos());
        } else {
          tray_menu_->close();
        }
      });
#endif
  // Also connect clicking on the icon to the signal processor of this press
  //    connect(tray_icon_,
  //    SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
  //            this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

  const QString selected_language = settings->LanguageCode();
  if (selected_language.isEmpty()) {  // save default language for first start
    const QString system_language = GetSystemLanguageCode();
    if (settings->ExistsTranslation(system_language)) {
      settings->SetLanguageCode(system_language);
    } else {
      settings->SetLanguageCode(settings->DefaultLanguageCode());
    }
  } else {
    fptn::gui::SetTranslation(selected_language);
  }

  // State
  connect(this, &TrayApp::defaultState, this, &TrayApp::handleDefaultState);
  connect(this, &TrayApp::connecting, this, &TrayApp::handleConnecting);
  connect(this, &TrayApp::connected, this, &TrayApp::handleConnected);
  connect(this, &TrayApp::disconnecting, this, &TrayApp::handleDisconnecting);

  // Settings
  connect(settings_.get(), &SettingsModel::dataChanged, this,
      &TrayApp::UpdateTrayMenu);
  connect(
      update_timer_, &QTimer::timeout, this, &TrayApp::handleUpdateSpeedWidget);
  update_timer_->start(1000);

  // Settings
  settings_action_ = new QAction(QObject::tr("Settings"), this);
  connect(
      settings_action_, &QAction::triggered, this, &TrayApp::onShowSettings);

  // Autoupdate
  auto_update_action_ = new QAction(
      QObject::tr("New version available") + " " + auto_available_version_,
      this);
  connect(auto_update_action_, &QAction::triggered, this,
      [this] { OpenWebBrowser(FPTN_GITHUB_PAGE_LINK); });
  auto_update_action_->setVisible(false);

  // Quit
  quit_action_ = new QAction(QObject::tr("Quit"), this);
  connect(quit_action_, &QAction::triggered, this, &QCoreApplication::quit);

  // Show menu
  tray_menu_->addSeparator();
  tray_menu_->addAction(settings_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(auto_update_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(quit_action_);

  tray_icon_->setContextMenu(tray_menu_);

  UpdateTrayMenu();
  tray_icon_->show();

  // check update
  update_version_future_ =
      std::async(std::launch::async, fptn::gui::autoupdate::Check);
}

void TrayApp::UpdateTrayMenu() {
  if (connect_menu_) {
    connect_menu_->clear();
  }
  if (tray_menu_ && connect_menu_) {
    tray_menu_->removeAction(connect_menu_->menuAction());
    smart_connect_action_ = nullptr;
    empty_configuration_action_ = nullptr;
  }

  switch (connection_state_) {
    case ConnectionState::None: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      const auto& services = settings_->Services();
      if (services.length()) {
        smart_connect_action_ =
            new QAction(QObject::tr("Smart Connect"), connect_menu_);
        connect(smart_connect_action_, &QAction::triggered, [this]() {
          smart_connect_ = true;
          onConnectToServer();
        });
        connect_menu_->addAction(smart_connect_action_);
        connect_menu_->addSeparator();
        // servers
        for (const auto& service : services) {
          for (const auto& server : service.servers) {
            auto serverConnect = new QAction(server.name, connect_menu_);
            connect(
                serverConnect, &QAction::triggered, [this, server, service]() {
                  smart_connect_ = false;
                  fptn::config::ConfigFile::Server cfgServer;
                  {
                    cfgServer.name = server.name.toStdString();
                    cfgServer.host = server.host.toStdString();
                    cfgServer.port = server.port;
                    cfgServer.is_using = server.is_using;
                    cfgServer.service_name = service.service_name.toStdString();
                    cfgServer.username = service.username.toStdString();
                    cfgServer.password = service.password.toStdString();
                  }
                  selected_server_ = cfgServer;
                  onConnectToServer();
                });
            connect_menu_->addAction(serverConnect);
          }
        }
      } else {
        empty_configuration_action_ =
            new QAction(QObject::tr("No servers"), connect_menu_);
        connect_menu_->addAction(empty_configuration_action_);
        empty_configuration_action_->setEnabled(false);
      }
      tray_menu_->insertMenu(settings_action_, connect_menu_);

      if (connect_menu_) {
        connect_menu_->setVisible(false);
      }
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(true);
      }
      if (connecting_action_) {
        connecting_action_->setVisible(false);
      }
      if (speed_widget_) {
        speed_widget_->setVisible(false);
      }
      break;
    }
    case ConnectionState::Connecting: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      if (!connecting_action_) {
        connecting_action_ = new QAction(QObject::tr("Connecting..."), this);
        tray_menu_->insertAction(settings_action_, connecting_action_);
      }
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      break;
    }
    case ConnectionState::Connected: {
      tray_icon_->setIcon(QIcon(active_icon_path_));
      if (!disconnect_action_) {
        disconnect_action_ = new QAction(this);
        connect(disconnect_action_, &QAction::triggered, this,
            &TrayApp::onDisconnectFromServer);
        tray_menu_->insertAction(settings_action_, disconnect_action_);
      }
      if (disconnect_action_) {
        disconnect_action_->setText(
            QString(QObject::tr("Disconnect") + ": %1 (%2)")
                .arg(QString::fromStdString(selected_server_.name))
                .arg(QString::fromStdString(selected_server_.service_name)));
        disconnect_action_->setVisible(true);
      }
      if (connecting_action_) {
        connecting_action_->setVisible(false);
      }
      if (!speed_widget_action_) {
        speed_widget_action_ = new QWidgetAction(this);
        speed_widget_action_->setDefaultWidget(speed_widget_);
        tray_menu_->insertAction(settings_action_, speed_widget_action_);
      }
      if (speed_widget_) {
        speed_widget_->setVisible(true);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(true);
      }
      break;
    }
    case ConnectionState::Disconnecting: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (!connecting_action_) {
        connecting_action_ = new QAction(QObject::tr("Disconnecting..."), this);
        tray_menu_->insertAction(settings_action_, connecting_action_);
      } else {
        connecting_action_->setText(QObject::tr("Disconnecting... "));
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (connecting_action_) {
        connecting_action_->setVisible(true);
      }
      break;
    }
  }

  // Apply the language translation based on the user's settings
  QString selectedLanguage = settings_->LanguageCode();
  if (!selectedLanguage.isEmpty()) {
    fptn::gui::SetTranslation(selectedLanguage);
  }
  RetranslateUi();
}

void TrayApp::onConnectToServer() {
  connection_state_ = ConnectionState::Connecting;
  UpdateTrayMenu();
  emit connecting();
}

void TrayApp::onDisconnectFromServer() {
  if (vpn_client_) {
    vpn_client_->Stop();
    vpn_client_.reset();
  }
  if (ip_tables_) {
    ip_tables_->Clean();
    ip_tables_.reset();
  }
  connection_state_ = ConnectionState::None;
  UpdateTrayMenu();
}

void TrayApp::onShowSettings() {
  auto dialog = std::make_unique<SettingsWidget>(settings_);
  QMetaObject::invokeMethod(dialog.get(), "setFocus", Qt::QueuedConnection);
  dialog->exec();
}

void TrayApp::handleDefaultState() {
  if (vpn_client_) {
    vpn_client_->Stop();
    vpn_client_.reset();
  }
  if (ip_tables_) {
    ip_tables_->Clean();
    ip_tables_.reset();
  }
  UpdateTrayMenu();
}

void TrayApp::handleConnecting() {
  SPDLOG_DEBUG("Handling connecting state");
  UpdateTrayMenu();

  tray_icon_->setIcon(QIcon(inactive_icon_path_));

  const pcpp::IPv4Address tun_interface_address_ipv4(
      FPTN_CLIENT_DEFAULT_ADDRESS_IP4);
  const pcpp::IPv6Address tun_interface_address_ipv6(
      FPTN_CLIENT_DEFAULT_ADDRESS_IP6);
  const std::string tun_interface_name = "tun0";

  /* check gateway address */
  const auto gateway_ip =
      (settings_->GatewayIp() == "auto"
              ? fptn::routing::GetDefaultGatewayIPAddress()
              : pcpp::IPv4Address(settings_->GatewayIp().toStdString()));

  if (gateway_ip == pcpp::IPv4Address("0.0.0.0")) {
    showError(QObject::tr("Connection Error"),
        QObject::tr("Unable to find the default gateway IP address. "
                    "Please check your connection and make sure no other VPN "
                    "is active. "
                    "If the error persists, specify the gateway address in the "
                    "FPTN settings using your router's IP address, "
                    "and ensure that an active internet interface (adapter) is "
                    "selected. If the issue remains unresolved, "
                    "please contact the developer via Telegram @fptn_chat."));
    connection_state_ = ConnectionState::None;
    UpdateTrayMenu();
    return;
  }

  /* config */
  const std::string network_interface =
      (settings_->UsingNetworkInterface() == "auto"
              ? ""
              : settings_->UsingNetworkInterface().toStdString());

  const std::string sni = !settings_->SNI().isEmpty()
                              ? settings_->SNI().toStdString()
                              : FPTN_DEFAULT_SNI;
  fptn::config::ConfigFile config(sni);  // SET SNI
  if (smart_connect_) {                  // find the best server
    for (const auto& service : settings_->Services()) {
      for (const auto& s : service.servers) {
        fptn::config::ConfigFile::Server cfg_server;
        {
          cfg_server.name = s.name.toStdString();
          cfg_server.host = s.host.toStdString();
          cfg_server.port = s.port;
          cfg_server.is_using = s.is_using;
          cfg_server.service_name = service.service_name.toStdString();
          cfg_server.username = service.username.toStdString();
          cfg_server.password = service.password.toStdString();
        }
        config.AddServer(cfg_server);
      }
    }
    try {
      selected_server_ = config.FindFastestServer();
    } catch (std::runtime_error& err) {
      showError(QObject::tr("Config error"), err.what());
      connection_state_ = ConnectionState::None;
      UpdateTrayMenu();
      return;
    }
  } else {
    // check connection to selected server
    const std::uint64_t time = config.GetDownloadTimeMs(selected_server_);
    if (time == static_cast<std::uint64_t>(-1)) {
      showError(QObject::tr("Connection Error"),
          QString(QObject::tr(
                      "The server is unavailable. Please select another server "
                      "or use Auto-connect to find the best available server."))
              .arg(QString::fromStdString(selected_server_.host)));
      connection_state_ = ConnectionState::None;
      UpdateTrayMenu();
      return;
    }
  }

  const int server_port = selected_server_.port;
  const auto server_ip = fptn::routing::ResolveDomain(selected_server_.host);
  if (server_ip == pcpp::IPv4Address("0.0.0.0")) {
    showError(QObject::tr("DNS resolution error"),
        QString(QObject::tr("DNS resolution error") + ": %1")
            .arg(QString::fromStdString(selected_server_.host)));
    connection_state_ = ConnectionState::None;
    UpdateTrayMenu();
    return;
  }

  auto http_client = std::make_unique<fptn::http::Client>(server_ip,
      server_port, tun_interface_address_ipv4, tun_interface_address_ipv6, sni);
  // login
  bool login_status =
      http_client->Login(selected_server_.username, selected_server_.password);
  if (!login_status) {
    showError(QObject::tr("Connection Error"),
        QObject::tr("Connection error to the server! Please download the "
                    "latest file with your personal settings through the "
                    "Telegram bot and try again."));
    connection_state_ = ConnectionState::None;
    UpdateTrayMenu();
    return;
  }

  // get dns
  const auto [dns_server_ipv4, dns_server_ipv6] = http_client->GetDns();
  if (dns_server_ipv4 == pcpp::IPv4Address("0.0.0.0") ||
      dns_server_ipv6 == pcpp::IPv6Address("")) {
    showError(QObject::tr("Connection error"),
        QObject::tr("DNS server error! Check your connection!"));
    connection_state_ = ConnectionState::None;
    UpdateTrayMenu();
    return;
  }

  // setup ip tables
  ip_tables_ = std::make_unique<fptn::routing::IPTables>(network_interface,
      tun_interface_name, server_ip, dns_server_ipv4, dns_server_ipv6,
      gateway_ip, tun_interface_address_ipv4, tun_interface_address_ipv6);

  // setup tun interface
  auto virtual_network_interface =
      std::make_unique<fptn::common::network::TunInterface>(tun_interface_name,
          /* IPv4 */
          tun_interface_address_ipv4, 30,
          /* IPv6 */
          tun_interface_address_ipv6, 126);

  // setup vpn client
  vpn_client_ = std::make_unique<fptn::vpn::VpnClient>(std::move(http_client),
      std::move(virtual_network_interface), dns_server_ipv4, dns_server_ipv6);

  // Wait for the WebSocket tunnel to establish
  vpn_client_->Start();
  constexpr auto TIMEOUT = std::chrono::seconds(5);
  const auto start = std::chrono::steady_clock::now();
  while (!vpn_client_->IsStarted()) {
    if (std::chrono::steady_clock::now() - start > TIMEOUT) {
      showError(QObject::tr("Connection error"),
          QObject::tr("Couldn't open websocket tunnel!"));
      connection_state_ = ConnectionState::None;
      UpdateTrayMenu();
      return;
    }
    std::this_thread::sleep_for(std::chrono::microseconds(200));
  }

  ip_tables_->Apply();

  connection_state_ = ConnectionState::Connected;
  UpdateTrayMenu();

  emit connected();
}

void TrayApp::handleConnected() {
  connection_state_ = ConnectionState::Connected;
  UpdateTrayMenu();
}

void TrayApp::handleDisconnecting() {
  if (vpn_client_) {
    vpn_client_->Stop();
    vpn_client_.reset();
  }
  if (ip_tables_) {
    ip_tables_->Clean();
    ip_tables_.reset();
  }
  connection_state_ = ConnectionState::None;
  UpdateTrayMenu();
  emit defaultState();
}

void TrayApp::handleUpdateSpeedWidget() {
  if (vpn_client_ && speed_widget_ &&
      connection_state_ == ConnectionState::Connected) {
    speed_widget_->UpdateSpeed(
        vpn_client_->GetReceiveRate(), vpn_client_->GetSendRate());
  }

  if (update_version_future_.valid()) {
    const auto updateResult = update_version_future_.get();
    const bool isNewVersion = updateResult.first;
    const std::string versionName = updateResult.second;
    if (isNewVersion) {
      auto_available_version_ = QString::fromStdString(versionName);
      auto_update_action_->setVisible(true);
      RetranslateUi();
    }
  }
}

QString TrayApp::GetSystemLanguageCode() const {
  const QLocale locale;
  const QString locale_name = locale.name();
  if (locale_name.contains('_')) {
    const QString language_code = locale.name().split('_').first();
    return language_code;
  }
  return "en";
}

void TrayApp::RetranslateUi() {
  if (connect_menu_) {
    connect_menu_->setTitle(QObject::tr("Connect") + "    ");
  }
  if (settings_action_) {
    settings_action_->setText(QObject::tr("Settings"));
  }
  if (quit_action_) {
    quit_action_->setText(QObject::tr("Quit"));
  }
  if (connecting_action_) {
    connecting_action_->setText(QObject::tr("Connecting..."));
  }
  if (empty_configuration_action_) {
    empty_configuration_action_->setText(QObject::tr("No servers"));
  }
  if (smart_connect_action_) {
    smart_connect_action_->setText(QObject::tr("Smart Connect"));
  }
  if (disconnect_action_) {
    const QString disconnectText =
        QString(QObject::tr("Disconnect") + ": %1 (%2)")
            .arg(QString::fromStdString(selected_server_.name))
            .arg(QString::fromStdString(selected_server_.service_name));
    disconnect_action_->setText(disconnectText);
  }
  if (auto_update_action_) {
    auto_update_action_->setText(
        QObject::tr("New version available") + " " + auto_available_version_);
  }
}

void TrayApp::stop() {
  if (vpn_client_) {
    vpn_client_->Stop();
    vpn_client_.reset();
  }
  if (ip_tables_) {
    ip_tables_->Clean();
    ip_tables_.reset();
  }
}

void TrayApp::OpenWebBrowser(const std::string& url) {
#if __APPLE__
  QDesktopServices::openUrl(QString::fromStdString(url));
#elif __linux__
  const std::string command = fmt::format(
      R"(bash -c "xhost +SI:localuser:root && (xdg-open \"{0}\" || sensible-browser \"{0}\" || x-www-browser \"{0}\" || gnome-open \"{0}\" ) "  )",
      url);
  fptn::common::system::command::run(command);
#elif _WIN32
  const std::string command = fmt::format(R"(explorer "{}" )", url);
  fptn::common::system::command::run(command);
#endif
}
