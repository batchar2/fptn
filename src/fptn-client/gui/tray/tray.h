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
#include "http/websocket_client.h"

namespace fptn::gui
{


    class TrayApp : public QObject
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
        TrayApp(QObject *parent = nullptr);
        virtual ~TrayApp() = default;
    signals:
        void defaultState();
        void connecting();
        void connected();
        void disconnecting();
    private slots:
        void onConnectToServer(const ServerConnectionInformation &server);
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
        QSystemTrayIcon *trayIcon_ = nullptr;
        QMenu *trayMenu_ = nullptr;
        QMenu *connectMenu_ = nullptr;
        QAction *disconnectAction_ = nullptr;
        QAction *settingsAction_ = nullptr;
        QAction *quitAction_ = nullptr;
        SettingsWidget *settingsWidget_ = nullptr;
        QAction *connectingAction_ = nullptr;
        QWidgetAction *speedWidgetAction_ = nullptr;
        SpeedWidget *speedWidget_ = nullptr;
        QTimer *updateTimer_ = nullptr;
        ConnectionState connectionState_ = ConnectionState::None;
        QString connectedServerAddress_;

        QString activeIconPath_;
        QString inactiveIconPath_;

        SettingsModel serverModel_;
        ServerConnectionInformation selectedServer_;
        fptn::vpn::VpnClientPtr vpnClient_;
        fptn::system::IPTablesPtr ipTables_;
    };
}
