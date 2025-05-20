/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <future>
#include <mutex>
#include <string>
#include <tuple>

#include <QAction>          // NOLINT(build/include_order)
#include <QApplication>     // NOLINT(build/include_order)
#include <QMenu>            // NOLINT(build/include_order)
#include <QMouseEvent>      // NOLINT(build/include_order)
#include <QObject>          // NOLINT(build/include_order)
#include <QString>          // NOLINT(build/include_order)
#include <QSystemTrayIcon>  // NOLINT(build/include_order)
#include <QTimer>           // NOLINT(build/include_order)
#include <QWidgetAction>    // NOLINT(build/include_order)

#include "common/data/channel.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "config/config_file.h"
#include "gui/settingsmodel/settingsmodel.h"
#include "gui/settingswidget/settings.h"
#include "gui/speedwidget/speedwidget.h"
#include "gui/tray/tray.h"
#include "http/client.h"
#include "routing/iptables.h"
#include "vpn/vpn_client.h"

namespace fptn::gui {
class TrayApp : public QWidget {
  Q_OBJECT

 protected:
  enum class ConnectionState { None, Connecting, Connected, Disconnecting };

 public:
  explicit TrayApp(const SettingsModelPtr& settings, QObject* parent = nullptr);
  void stop();

 protected:
  QString GetSystemLanguageCode() const;
  void RetranslateUi();
 signals:
  void defaultState();
  void connecting();
  void connected();
  void disconnecting();
  void vpnStarted(bool success, const QString& err_msg);

 protected slots:
  void onConnectToServer();
  void onDisconnectFromServer();
  void onShowSettings();

 protected slots:
  void handleDefaultState();
  void handleConnecting();
  void handleConnected();
  void handleDisconnecting();
  void handleTimer();
  void handleVpnStarted(bool success, const QString& err_msg);

 protected:
  void UpdateTrayMenu();
  void OpenWebBrowser(const std::string& url);

 protected:
  bool startVpn(QString& err_msg);
  bool stopVpn();

 private:
  mutable std::mutex mutex_;

  bool smart_connect_ = false;
  fptn::protocol::server::ServerInfo selected_server_;

  SettingsModelPtr settings_;

  QSystemTrayIcon* tray_icon_ = nullptr;
  QMenu* tray_menu_ = nullptr;
  QMenu* connect_menu_ = nullptr;
  QAction* smart_connect_action_ = nullptr;
  QMenu* limited_zone_connect_menu_ = nullptr;
  QAction* empty_configuration_action_ = nullptr;
  QAction* disconnect_action_ = nullptr;
  //  QAction* connecting_action_ = nullptr;
  QAction* settings_action_ = nullptr;

  QAction* auto_update_action_ = nullptr;
  QString auto_available_version_;

  QAction* quit_action_ = nullptr;
  QAction* connecting_label_action_ = nullptr;
  QAction* disconnecting_label_action_ = nullptr;
  QWidgetAction* speed_widget_action_ = nullptr;
  SpeedWidget* speed_widget_ = nullptr;
  QTimer* update_timer_ = nullptr;
  ConnectionState connection_state_ = ConnectionState::None;
  QString connected_server_address_;

  QString active_icon_path_;
  QString inactive_icon_path_;

  fptn::vpn::VpnClientPtr vpn_client_;
  fptn::routing::IPTablesPtr ip_tables_;

  std::future<std::pair<bool, std::string>> update_version_future_;
  // connecting
  std::atomic<bool> connecting_in_progress_{false};
  // std::future<bool> connecting_;
};
}  // namespace fptn::gui
