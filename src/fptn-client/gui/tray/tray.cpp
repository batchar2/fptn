#include <QMenu>
#include <QIcon>
#include <QAction>
#include <QMessageBox>
#include <QApplication>
#include <QWidgetAction>

#include "tray.h"

using namespace fptn::gui;

const QString activeIconPath = ":/icons/active.ico";
const QString inactiveIconPath = ":/icons/inactive.ico";

static QString styleSheet = R"(
    QMenu {
        background-color: #333;
        color: #fff;
        border: 1px solid #555;
    }
    QMenu::item {
        background-color: #333;
        padding: 5px 15px;
    }
    QMenu::item:selected {
        background-color: #555;
    }
    QMenu::icon {
        margin-right: 10px;
    }
    QAction {
        color: #fff;
    }
    QWidgetAction {
        padding: 5px;
    }
)";

TrayApp::TrayApp(QObject *parent)
        : QObject(parent),
          trayIcon_(new QSystemTrayIcon(this)),
          trayMenu_(new QMenu()),
          connectMenu_(new QMenu("Connect to", trayMenu_)),
          speedWidget_(new SpeedWidget()),
          updateTimer_(new QTimer(this))
{
    qApp->setStyleSheet(styleSheet);

    connect(this, &TrayApp::defaultState, this, &TrayApp::handleDefaultState);
    connect(this, &TrayApp::connecting, this, &TrayApp::handleConnecting);
    connect(this, &TrayApp::connected, this, &TrayApp::handleConnected);
    connect(this, &TrayApp::disconnecting, this, &TrayApp::handleDisconnecting);

    connect(&serverModel_, &SettingsModel::dataChanged, this, &TrayApp::updateTrayMenu);

    connect(updateTimer_, &QTimer::timeout, this, &TrayApp::updateSpeedWidget);
    updateTimer_->start(1000);

    setUpTrayIcon();

    settingsAction_ = new QAction("Settings", this);
    connect(settingsAction_, &QAction::triggered, this, &TrayApp::onShowSettings);

    quitAction_ = new QAction("Quit", this);
    connect(quitAction_, &QAction::triggered, this, &TrayApp::handleQuit);

    trayMenu_->addSeparator();
    trayMenu_->addAction(settingsAction_);
    trayMenu_->addSeparator();
    trayMenu_->addAction(quitAction_);

    trayIcon_->setContextMenu(trayMenu_);
    updateTrayMenu();
}

void TrayApp::setUpTrayIcon()
{
    trayIcon_->setIcon(QIcon(inactiveIconPath));
    trayIcon_->show();
}

void TrayApp::updateTrayMenu()
{
    connectMenu_->clear();
    trayMenu_->removeAction(connectMenu_->menuAction());

    switch (connectionState_) {
        case ConnectionState::None: {
            for (const auto &server : serverModel_.servers()) {
                QAction *serverAction = new QAction(QString("%1:%2").arg(server.address).arg(server.port), this);
                connect(serverAction, &QAction::triggered, [this, server]() {
                    onConnectToServer(server);
                });
                connectMenu_->addAction(serverAction);
            }
            trayMenu_->insertMenu(settingsAction_, connectMenu_);
            if (disconnectAction_) {
                disconnectAction_->setVisible(false);
            }
            if (speedWidgetAction_) {
                speedWidgetAction_->setVisible(false);
            }
            if (settingsAction_) {
                settingsAction_->setEnabled(true);
            }
            break;
        }
        case ConnectionState::Connecting: {
            if (!connectingAction_) {
                connectingAction_ = new QAction("Connecting...", this);
                trayMenu_->insertAction(settingsAction_, connectingAction_);
            }
            if (disconnectAction_) {
                disconnectAction_->setVisible(false);
            }
            if (speedWidgetAction_) {
                speedWidgetAction_->setVisible(false);
            }
            if (settingsAction_) {
                settingsAction_->setEnabled(false);
            }
            break;
        }
        case ConnectionState::Connected: {
            if (!disconnectAction_) {
                disconnectAction_ = new QAction(this);
                connect(disconnectAction_, &QAction::triggered, this, &TrayApp::onDisconnectFromServer);
                trayMenu_->insertAction(settingsAction_, disconnectAction_);
            }
            disconnectAction_->setText(QString("Disconnect: %1:%2").arg(selectedServer_.address).arg(selectedServer_.port));
            disconnectAction_->setVisible(true);
            if (connectingAction_) {
                connectingAction_->setVisible(false);
            }
            if (!speedWidgetAction_) {
                speedWidgetAction_ = new QWidgetAction(this);
                speedWidgetAction_->setDefaultWidget(speedWidget_);
                trayMenu_->insertAction(settingsAction_, speedWidgetAction_);
                speedWidgetAction_->setVisible(true);
            }
            if (settingsAction_) {
                settingsAction_->setEnabled(false);
            }
            break;
        }
        case ConnectionState::Disconnecting: {
            if (disconnectAction_) {
                disconnectAction_->setVisible(false);
            }
            if (!connectingAction_) {
                connectingAction_ = new QAction("Disconnecting...", this);
                trayMenu_->insertAction(settingsAction_, connectingAction_);
            } else {
                connectingAction_->setText("Disconnecting...");
            }
            connectingAction_->setVisible(true);
            if (speedWidgetAction_) {
                speedWidgetAction_->setVisible(false);
            }
            if (settingsAction_) {
                settingsAction_->setEnabled(false);
            }
            break;
        }
    }
}

void TrayApp::onConnectToServer(const ServerConnectionInformation &server)
{
    selectedServer_ = server;
    connectionState_ = ConnectionState::Connecting;
    updateTrayMenu();
    emit connecting();
}

void TrayApp::onDisconnectFromServer()
{
    if (vpnClient_) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_) {
        ipTables_->clean();
        ipTables_.reset();
    }
    connectionState_ = ConnectionState::None;
    updateTrayMenu();
}

void TrayApp::onShowSettings()
{
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

void TrayApp::handleDefaultState()
{
    if (vpnClient_) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_) {
        ipTables_->clean();
        ipTables_.reset();
    }
    trayIcon_->setIcon(QIcon(inactiveIconPath));
    updateTrayMenu();
}

void TrayApp::handleConnecting()
{
    qDebug() << "Handling connecting state";
    updateTrayMenu();

    const std::string tunInterfaceAddress = "10.0.1.1";
    const std::string tunInterfaceName = "tun0";

    const std::string gatewayIP = serverModel_.gatewayIp().toStdString();
    const std::string usingGatewayIP = (!gatewayIP.empty() ? gatewayIP : fptn::system::getDefaultGatewayIPAddress());

    auto webSocketClient = std::make_unique<fptn::http::WebSocketClient>(
            selectedServer_.address.toStdString(),
            selectedServer_.port,
            tunInterfaceAddress,
            true
    );
    bool loginStatus = webSocketClient->login(
            selectedServer_.username.toStdString(),
            selectedServer_.password.toStdString()
    );

    if (!loginStatus) {
        QWidget tempWidget;
        QMessageBox::critical(
                &tempWidget,
                "Connection Error",
                "Failed to connect to the server. Please check your credentials and try again."
        );
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }

    ipTables_ = std::make_unique<fptn::system::IPTables>(
            serverModel_.networkInterface().toStdString(),
            tunInterfaceName,
            selectedServer_.address.toStdString(),
            usingGatewayIP
    );

    auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
            tunInterfaceName, tunInterfaceAddress, 30, nullptr
    );
    vpnClient_ = std::make_unique<fptn::vpn::VpnClient>(
            std::move(webSocketClient),
            std::move(virtualNetworkInterface)
    );
    vpnClient_->start();
    std::this_thread::sleep_for(std::chrono::seconds(1)); // FIX IT!
    ipTables_->apply();

    connectionState_ = ConnectionState::Connected;
    updateTrayMenu();
    emit connected();
}

void TrayApp::handleConnected()
{
    updateTrayMenu();
}

void TrayApp::handleDisconnecting()
{
    if (vpnClient_) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_) {
        ipTables_->clean();
        ipTables_.reset();
    }
    connectionState_ = ConnectionState::None;
    updateTrayMenu();
    emit defaultState();
}

void TrayApp::updateSpeedWidget()
{
    if (vpnClient_ && connectionState_ == ConnectionState::Connected) {
        speedWidget_->updateSpeed(vpnClient_->getReceiveRate(), vpnClient_->getSendRate());
    }
}

void TrayApp::handleQuit()
{
    QApplication::quit();
}
