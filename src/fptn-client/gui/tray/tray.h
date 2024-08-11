#pragma once

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
            None,           // No connection
            Connecting,     // Connecting
            Connected,      // Connected
            Disconnecting   // Disconnecting
        };
    public:
        TrayApp(QObject *parent = nullptr);
        void applyStyles(); // Method to apply cross-platform styles

    signals:
        void defaultState(); // Signal for default state
        void connecting(); // Signal for connecting state
        void connected(); // Signal for connected state
        void disconnecting(); // Signal for disconnecting state

    private slots:
        void onConnectToServer(const ServerConnectionInformation &server);
        void onDisconnectFromServer();
        void onShowSettings();
        void handleDefaultState(); // Handler for default state
        void handleConnecting(); // Handler for connecting state
        void handleConnected(); // Handler for connected state
        void handleDisconnecting(); // Handler for disconnecting state
        void updateSpeedWidget(); // Handler for updating the speed widget

    private:
        void setUpTrayIcon();
        void updateTrayMenu();

        QSystemTrayIcon *trayIcon_;
        QMenu *trayMenu_;
        QMenu *connectMenu_;
        QAction *disconnectAction_;
        QAction *settingsAction_;
        QAction *quitAction_;
        SettingsWidget *settingsWidget_;

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