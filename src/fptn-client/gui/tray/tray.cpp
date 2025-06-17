/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/tray/tray.h"

#include <memory>
#include <numeric>
#include <string>
#include <tuple>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QDesktopServices>  // NOLINT(build/include_order)
#include <QFuture>           // NOLINT(build/include_order)
#include <QFutureWatcher>    // NOLINT(build/include_order)
#include <QIcon>             // NOLINT(build/include_order)
#include <QMessageBox>       // NOLINT(build/include_order)
#include <QStyleFactory>     // NOLINT(build/include_order)
#include <QStyleHints>       // NOLINT(build/include_order)
#include <QtConcurrent>      // NOLINT(build/include_order)

#include "common/system/command.h"

#include "gui/autoupdate/autoupdate.h"
#include "gui/style/style.h"
#include "gui/translations/translations.h"

using fptn::gui::TrayApp;

namespace {
void showError(const QString& title, const QString& msg) {
  QWidget temp_widget;
  QMessageBox::critical(&temp_widget, title, msg);
}
}  // namespace

TrayApp::TrayApp(const SettingsModelPtr& settings, QObject* parent)
    : settings_(settings),
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
  connect(this, &TrayApp::vpnStarted, this, &TrayApp::handleVpnStarted);

  // Show connection... label
  connecting_label_action_ = new QAction(QObject::tr("Connecting..."), this);
  // Show Disconnecting... label
  disconnecting_label_action_ =
      new QAction(QObject::tr("Disconnecting..."), this);

  // Disconect
  disconnect_action_ = new QAction(QObject::tr("Disconnect"), this);
  connect(disconnect_action_, &QAction::triggered, this,
      &TrayApp::onDisconnectFromServer);

  speed_widget_action_ = new QWidgetAction(this);
  speed_widget_action_->setDefaultWidget(speed_widget_);

  // Settings
  connect(settings_.get(), &SettingsModel::dataChanged, this,
      &TrayApp::UpdateTrayMenu);
  connect(update_timer_, &QTimer::timeout, this, &TrayApp::handleTimer);
  update_timer_->start(300);

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
  // tray_menu_->addAction(connecting_action_);
  tray_menu_->addAction(disconnect_action_);
  tray_menu_->addAction(connecting_label_action_);
  tray_menu_->addAction(disconnecting_label_action_);
  tray_menu_->addAction(speed_widget_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(settings_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(auto_update_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(quit_action_);

  tray_icon_->setContextMenu(tray_menu_);

  tray_icon_->show();

  // check update
  update_version_future_ =
      std::async(std::launch::async, fptn::gui::autoupdate::Check);

  try {
    settings_->Load(false);  // use this to show notification about change
                             // structure v1 and v2 config
  } catch (std::runtime_error& err) {
    showError(QObject::tr("Settings"), err.what());
  }
  UpdateTrayMenu();
}

void TrayApp::UpdateTrayMenu() {
  if (limited_zone_connect_menu_) {
    limited_zone_connect_menu_->clear();
  }
  if (connect_menu_) {
    connect_menu_->clear();
  }
  if (tray_menu_ && connect_menu_) {
    tray_menu_->removeAction(connect_menu_->menuAction());
    smart_connect_action_ = nullptr;
    empty_configuration_action_ = nullptr;

    limited_zone_connect_menu_ = nullptr;
  }

  switch (connection_state_) {
    case ConnectionState::None: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      const auto& services = settings_->Services();

      // calculate services
      const std::size_t servers_number =
          std::accumulate(services.begin(), services.end(), std::size_t{0},
              [](std::size_t sum, const auto& service) {
                return sum + service.servers.size();
              });

      if (0 != servers_number) {
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
          // usual servers
          for (const auto& server : service.servers) {
            auto* server_connect = new QAction(server.name, connect_menu_);

            // FIXME
            connect(
                server_connect, &QAction::triggered, [this, server, service]() {
                  smart_connect_ = false;
                  fptn::protocol::server::ServerInfo cfg_server;
                  {
                    cfg_server.name = server.name.toStdString();
                    cfg_server.host = server.host.toStdString();
                    cfg_server.port = server.port;
                    cfg_server.is_using = server.is_using;
                    cfg_server.service_name =
                        service.service_name.toStdString();
                    cfg_server.username = service.username.toStdString();
                    cfg_server.password = service.password.toStdString();
                    cfg_server.md5_fingerprint =
                        server.md5_fingerprint.toStdString();
                  }
                  selected_server_ = cfg_server;
                  onConnectToServer();
                });
            connect_menu_->addAction(server_connect);
          }
          // Censored zone servers
          for (const auto& server : service.censored_zone_servers) {
            if (!limited_zone_connect_menu_) {
              limited_zone_connect_menu_ = new QMenu(
                  QObject::tr("Limited access servers") + "  ", connect_menu_);
              connect_menu_->addMenu(limited_zone_connect_menu_);
            }
            auto* server_connect =
                new QAction(server.name, limited_zone_connect_menu_);
            limited_zone_connect_menu_->addAction(server_connect);

            // FIXME
            connect(
                server_connect, &QAction::triggered, [this, server, service]() {
                  smart_connect_ = false;
                  fptn::protocol::server::ServerInfo cfg_server;
                  {
                    cfg_server.name = server.name.toStdString();
                    cfg_server.host = server.host.toStdString();
                    cfg_server.port = server.port;
                    cfg_server.is_using = server.is_using;
                    cfg_server.service_name =
                        service.service_name.toStdString();
                    cfg_server.username = service.username.toStdString();
                    cfg_server.password = service.password.toStdString();
                    cfg_server.md5_fingerprint =
                        server.md5_fingerprint.toStdString();
                  }
                  selected_server_ = cfg_server;
                  onConnectToServer();
                });
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
      if (speed_widget_) {
        speed_widget_->setVisible(false);
      }
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(false);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(false);
      }
      if (quit_action_) {
        quit_action_->setEnabled(true);
      }
      break;
    }
    case ConnectionState::Connecting: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(true);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (quit_action_) {
        quit_action_->setEnabled(false);
      }
      break;
    }
    case ConnectionState::Connected: {
      tray_icon_->setIcon(QIcon(active_icon_path_));
      if (disconnect_action_) {
        disconnect_action_->setText(
            QString(QObject::tr("Disconnect") + ": %1 (%2)")
                .arg(QString::fromStdString(selected_server_.name))
                .arg(QString::fromStdString(selected_server_.service_name)));
        disconnect_action_->setVisible(true);
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
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(false);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(false);
      }
      if (quit_action_) {
        quit_action_->setEnabled(true);
      }
      break;
    }
    case ConnectionState::Disconnecting: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(false);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(true);
      }
      if (quit_action_) {
        quit_action_->setEnabled(false);
      }
      break;
    }
  }

  // Apply the language translation based on the user's settings
  const QString selected_language = settings_->LanguageCode();
  if (!selected_language.isEmpty()) {
    fptn::gui::SetTranslation(selected_language);
  }
  RetranslateUi();
}

void TrayApp::onConnectToServer() {
  SPDLOG_INFO("Signal: connecting to server");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::Connecting;
    UpdateTrayMenu();
  }
  emit connecting();
}

void TrayApp::onDisconnectFromServer() {
  SPDLOG_INFO("Signal: disconnected from server");
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  connection_state_ = ConnectionState::None;

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

void TrayApp::onShowSettings() {
  auto dialog = std::make_unique<SettingsWidget>(settings_);
  QMetaObject::invokeMethod(dialog.get(), "setFocus", Qt::QueuedConnection);
  dialog->exec();
}

void TrayApp::handleDefaultState() {
  SPDLOG_INFO("Signal: entering default state");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::None;
    if (vpn_client_) {
      vpn_client_->Stop();
      vpn_client_.reset();
    }
    if (ip_tables_) {
      ip_tables_->Clean();
      ip_tables_.reset();
    }
  }
  UpdateTrayMenu();
}

void TrayApp::handleConnecting() {
  SPDLOG_INFO("Signal: connecting to server");
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  connection_state_ = ConnectionState::Connecting;
  UpdateTrayMenu();

  if (!connecting_in_progress_) {  // only once!
    connecting_in_progress_ = true;

    QFuture<std::tuple<bool, QString>> future = QtConcurrent::run([this]() {
      QString err_msg;
      auto status = startVpn(err_msg);
      return std::make_tuple(status, std::move(err_msg));
    });

    auto* watcher = new QFutureWatcher<std::tuple<bool, QString>>(this);
    connect(watcher, &QFutureWatcher<std::tuple<bool, QString>>::finished, this,
        [this, watcher]() {
          const std::tuple<bool, QString> result = watcher->result();
          watcher->deleteLater();

          bool status = std::get<0>(result);
          const QString err_msg = std::get<1>(result);
          emit this->vpnStarted(status, err_msg);

          connecting_in_progress_ = false;
        });
    watcher->setFuture(future);
  }
}

void TrayApp::handleConnected() {
  SPDLOG_INFO("Signal: connected to server");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::Connected;
  }
  UpdateTrayMenu();
}

void TrayApp::handleDisconnecting() {
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::None;
    UpdateTrayMenu();

    stopVpn();
  }
  emit defaultState();
}

void TrayApp::handleTimer() {
  // check connection state
  bool is_disconnected = false;
  if (connection_state_ == ConnectionState::Connected) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (connection_state_ == ConnectionState::Connected && vpn_client_) {
      if (!vpn_client_->IsStarted()) {
        // client was disconnected
        is_disconnected = true;
      } else if (speed_widget_) {
        speed_widget_->UpdateSpeed(
            vpn_client_->GetReceiveRate(), vpn_client_->GetSendRate());
      }
    }
  }

  if (is_disconnected) {
    // show error
    showError(QObject::tr("FPTN Connection Error"),
        QObject::tr("The VPN connection was unexpectedly closed."));
    emit disconnecting();
  }

  // show update message
  if (update_version_future_.valid()) {
    const auto update_result = update_version_future_.get();
    const bool is_new_version = update_result.first;
    const std::string version_name = update_result.second;
    if (is_new_version) {
      auto_available_version_ = QString::fromStdString(version_name);
      auto_update_action_->setVisible(true);
      RetranslateUi();
    }
  }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
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
  if (connecting_label_action_) {
    connecting_label_action_->setText(QObject::tr("Connecting..."));
  }
  if (empty_configuration_action_) {
    empty_configuration_action_->setText(QObject::tr("No servers"));
  }
  if (smart_connect_action_) {
    smart_connect_action_->setText(QObject::tr("Smart Connect"));
  }
  if (limited_zone_connect_menu_) {
    limited_zone_connect_menu_->setTitle(
        QObject::tr("Limited access servers") + "  ");
  }
  if (connecting_label_action_) {
    connecting_label_action_->setText(QObject::tr("Connecting..."));
  }
  if (disconnecting_label_action_) {
    disconnecting_label_action_->setText(QObject::tr("Disconnecting..."));
  }

  if (disconnect_action_) {
    const QString disconnect_text =
        QString(QObject::tr("Disconnect") + ": %1 (%2)")
            .arg(QString::fromStdString(selected_server_.name))
            .arg(QString::fromStdString(selected_server_.service_name));
    disconnect_action_->setText(disconnect_text);
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

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
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

bool TrayApp::startVpn(QString& err_msg) {
  SPDLOG_DEBUG("Handling connecting state");

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

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

  if (gateway_ip == pcpp::IPv4Address()) {
    err_msg = QObject::tr(
        "Unable to find the default gateway IP address. "
        "Please check your connection and make sure no other VPN "
        "is active. "
        "If the error persists, specify the gateway address in the "
        "FPTN settings using your router's IP address, "
        "and ensure that an active internet interface (adapter) is "
        "selected. If the issue remains unresolved, "
        "please contact the developer via Telegram @fptn_chat.");
    return false;
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
        fptn::protocol::server::ServerInfo cfg_server;
        {
          cfg_server.name = s.name.toStdString();
          cfg_server.host = s.host.toStdString();
          cfg_server.port = s.port;
          cfg_server.is_using = s.is_using;
          cfg_server.service_name = service.service_name.toStdString();
          cfg_server.username = service.username.toStdString();
          cfg_server.password = service.password.toStdString();
          cfg_server.md5_fingerprint = s.md5_fingerprint.toStdString();
        }
        config.AddServer(cfg_server);
      }
    }
    try {
      selected_server_ = config.FindFastestServer();
    } catch (std::runtime_error& err) {
      err_msg = QObject::tr("Config error: ") + err.what();
      return false;
    }
  } else {
    // check connection to selected server
    const std::uint64_t time = config.GetDownloadTimeMs(
        selected_server_, sni, 5, selected_server_.md5_fingerprint);
    if (time == UINT64_MAX) {
      err_msg = QString(
          QObject::tr("The server is unavailable. Please select another server "
                      "or use Auto-connect to find the best available server."))
                    .arg(QString::fromStdString(selected_server_.host));
      return false;
    }
  }

  const auto server_ip = fptn::routing::ResolveDomain(selected_server_.host);
  if (server_ip == pcpp::IPv4Address()) {
    err_msg = QString(QObject::tr("DNS resolution error") + ": %1")
                  .arg(QString::fromStdString(selected_server_.host));
    return false;
  }

  auto http_client = std::make_unique<fptn::http::Client>(server_ip,
      selected_server_.port, tun_interface_address_ipv4,
      tun_interface_address_ipv6, sni, selected_server_.md5_fingerprint);
  // login
  bool login_status =
      http_client->Login(selected_server_.username, selected_server_.password);
  if (!login_status) {
    const std::string error = http_client->LatestError();
    err_msg = QObject::tr(
                  "Unable to connect to the server. Please use the Telegram "
                  "bot to generate a new TOKEN with your personal settings, "
                  "then try again.") +
              "\n\n" + QObject::tr("Error message: ") +
              QString::fromStdString(error);
    return false;
  }

  // get dns
  const auto [dns_server_ipv4, dns_server_ipv6] = http_client->GetDns();
  if (dns_server_ipv4 == pcpp::IPv4Address() ||
      dns_server_ipv6 == pcpp::IPv6Address()) {
    const std::string error = http_client->LatestError();
    err_msg = QObject::tr("DNS server error! Check your connection!") + "\n\n" +
              QObject::tr("Error message: ") + QString::fromStdString(error);
    return false;
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
  constexpr auto kTimeout = std::chrono::seconds(5);
  const auto start = std::chrono::steady_clock::now();
  while (!vpn_client_->IsStarted()) {
    if (std::chrono::steady_clock::now() - start > kTimeout) {
      err_msg = QObject::tr("Failed to connect to the server!");
      return false;
    }
    std::this_thread::sleep_for(std::chrono::microseconds(300));
  }
  ip_tables_->Apply();

  return true;
}

bool TrayApp::stopVpn() {
  if (vpn_client_) {
    vpn_client_->Stop();
    vpn_client_.reset();
  }
  if (ip_tables_) {
    ip_tables_->Clean();
    ip_tables_.reset();
  }
  return true;
}

void TrayApp::handleVpnStarted(bool success, const QString& err_msg) {
  if (success) {
    emit connected();
  } else {
    showError(QObject::tr("FPTN Connection Error"), err_msg);

    emit disconnecting();
  }
}
