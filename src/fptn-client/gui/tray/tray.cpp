#include <QMenu>
#include <QIcon>
#include <QAction>
#include <QApplication>

#include "tray.h"

using namespace fptn::gui;

const QString activeIconPath = ":/icons/active.ico";
const QString inactiveIconPath = ":/icons/incactive.ico";



fptn::gui::TrayApp::TrayApp(QObject *parent)
        : QObject(parent),
          trayIcon_(new QSystemTrayIcon(this)),
          trayMenu_(new QMenu()),
          connectMenu_(new QMenu("Connect to")),
          settingsWidget_(nullptr)
{
    setUpTrayIcon();
    updateTrayMenu();
}

void fptn::gui::TrayApp::setUpTrayIcon() {
    trayIcon_->setIcon(QIcon(inactiveIconPath));
    trayIcon_->show();
}

void fptn::gui::TrayApp::updateTrayMenu() {
    trayMenu_->clear();
    connectMenu_->clear();

    if (connectedServerAddress_.isEmpty()) {
        // Default state
        for (const Server &server : serverModel_.servers()) {
            QAction *serverAction = new QAction(QString("%1:%2").arg(server.address).arg(server.port), this);
            connect(serverAction, &QAction::triggered, [this, server]() {
                onConnectToServer(server);
            });
            connectMenu_->addAction(serverAction);
        }
        trayMenu_->addMenu(connectMenu_);
        disconnectAction_ = nullptr;
    } else if (connectedServerAddress_ == "CONNECTING") {
        // Connecting state
        trayMenu_->addAction("Connecting...");
        disconnectAction_ = nullptr;
    } else {
        // Connected state
        disconnectAction_ = trayMenu_->addAction("Disconnect");
        connect(disconnectAction_, &QAction::triggered, this, &TrayApp::onDisconnectFromServer);
        trayMenu_->addAction(QString("Status %1:%2").arg(connectedServerAddress_).arg(connectedServerPort_));
    }

    settingsAction_ = trayMenu_->addAction("Settings", this, &TrayApp::onShowSettings);
    quitAction_ = trayMenu_->addAction("Quit", qApp, &QApplication::quit);

    trayIcon_->setContextMenu(trayMenu_);
}

void fptn::gui::TrayApp::onConnectToServer(const Server& server) {
    // Update status to "Connecting"
    connectedServerAddress_ = "CONNECTING";
    updateTrayMenu();

    // Simulate connection attempt (replace with actual connection code)
    bool success = /* attempt to connect */ true; // Replace with actual connection logic
    if (success) {
        connectedServerAddress_ = server.address;
        //connectedServerPort_ = server.port;
    } else {
        connectedServerAddress_.clear();
    }
    updateTrayMenu();
}

void fptn::gui::TrayApp::onShowSettings() {
    if (!settingsWidget_) {
        settingsWidget_ = new SettingsWidget(&serverModel_, nullptr);
    }
    if (!settingsWidget_->isVisible()) {
        settingsWidget_->show();
    } else {
        settingsWidget_->raise();
        settingsWidget_->activateWindow();
    }
}

void fptn::gui::TrayApp::onDisconnectFromServer() {
    connectedServerAddress_.clear();
    connectedServerPort_.clear();
    updateTrayMenu();
}

void fptn::gui::TrayApp::onServerActionTriggered() {
    // Implement server action triggered logic here
}

