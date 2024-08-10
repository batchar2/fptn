#pragma once

#include <QMenu>
#include <QTimer>
#include <QObject>
#include <QString>
#include <QAction>
#include <QApplication>
#include <QSystemTrayIcon>

#include "gui/servermodel/server_model.h"
#include "gui/settingswidget/settings.h"


namespace fptn::gui {

    class TrayApp : public QObject {
    Q_OBJECT
    public:
        TrayApp(QObject *parent = nullptr);

    private slots:
        void onConnectToServer(const Server &server);
        void onDisconnectFromServer();
        void onShowSettings();
        void onServerActionTriggered();

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
        ServerModel serverModel_;
        QString connectedServerAddress_;
        QString connectedServerPort_;
    };
}