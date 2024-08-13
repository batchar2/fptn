#pragma once

#include <mutex>

#include <QMenu>
#include <QTimer>
#include <QObject>
#include <QString>
#include <QAction>
#include <QApplication>
#include <QWidgetAction>
#include <QSystemTrayIcon>

#include "gui/speedwidget/speedwidget.h"
#include "gui/settingswidget/settings.h"
#include "gui/settingsmodel/settingsmodel.h"

#include <common/data/channel.h>
#include <common/network/ip_packet.h>
#include <common/network/tun_interface.h>

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
        void applyStyles();
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
        QSystemTrayIcon *trayIcon_;
        QMenu *trayMenu_;
        QMenu *connectMenu_;
        QAction *disconnectAction_;
        QAction *settingsAction_;
        QAction *quitAction_;
        SettingsWidget *settingsWidget_;
        QAction *connectingAction_;
        QWidgetAction *speedWidgetAction_;
        SpeedWidget *speedWidget_;
        QTimer *updateTimer_;
        ConnectionState connectionState_ = ConnectionState::None;
        QString connectedServerAddress_;

        SettingsModel serverModel_;
        ServerConnectionInformation selectedServer_;
        fptn::vpn::VpnClientPtr vpnClient_;
        fptn::system::IPTablesPtr ipTables_;
    };
}
