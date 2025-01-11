#pragma once

#include <mutex>

#include <QMenu>
#include <QTimer>
#include <QObject>
#include <QString>
#include <QAction>
#include <QMouseEvent>
#include <QApplication>
#include <QWidgetAction>
#include <QSystemTrayIcon>

#include "gui/speedwidget/speedwidget.h"
#include "gui/settingswidget/settings.h"
#include "gui/settingsmodel/settingsmodel.h"

#include <common/data/channel.h>
#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>

#include "gui/tray/tray.h"
#include "vpn/vpn_client.h"
#include "system/iptables.h"
#include "config/config_file.h"
#include "http/websocket_client.h"


namespace fptn::gui
{
    class TrayApp : public QWidget
    {
        Q_OBJECT
    private:
        enum class ConnectionState {
            None,
            Connecting,
            Connected,
            Disconnecting
        };
    public:
        explicit TrayApp(const SettingsModelPtr &settings, QObject* parent = nullptr);
        virtual ~TrayApp() = default;
    private:
        QString getSystemLanguageCode() const;
        void retranslateUi();
    signals:
        void defaultState();
        void connecting();
        void connected();
        void disconnecting();
    private slots:
        void onConnectToServer();
        void onDisconnectFromServer();
        void onShowSettings();
        void handleDefaultState();
        void handleConnecting();
        void handleConnected();
        void handleDisconnecting();
        void updateSpeedWidget();
        void handleQuit();
    private:
        void setUpTrayIcon();
        void updateTrayMenu();
    private:
        bool smartConnect_ = false;
        fptn::config::ConfigFile::Server selectedServer_;

        SettingsModelPtr settings_;

        QSystemTrayIcon *trayIcon_ = nullptr;
        QMenu *trayMenu_ = nullptr;
        QMenu *connectMenu_ = nullptr;
        QAction *smartConnectAction_ = nullptr;
        QAction *emptyConfigurationAction_ = nullptr;
        QAction *disconnectAction_ = nullptr;
        QAction *settingsAction_ = nullptr;
        QAction *quitAction_ = nullptr;
        QAction *connectingAction_ = nullptr;
        QWidgetAction *speedWidgetAction_ = nullptr;
        SpeedWidget *speedWidget_ = nullptr;
        QTimer *updateTimer_ = nullptr;
        ConnectionState connectionState_ = ConnectionState::None;
        QString connectedServerAddress_;

        QString activeIconPath_;
        QString inactiveIconPath_;

        fptn::vpn::VpnClientPtr vpnClient_;
        fptn::system::IPTablesPtr ipTables_;
    };
}
