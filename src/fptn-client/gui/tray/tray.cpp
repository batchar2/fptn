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
          connectMenu_(new QMenu("Connect to")),
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
    updateTrayMenu();
}

void TrayApp::setUpTrayIcon()
{
    trayIcon_->setIcon(QIcon(inactiveIconPath));
    trayIcon_->show();
}

void TrayApp::updateTrayMenu()
{
    qDebug() << "updateTrayMenu";
    serverModel_.load();
    trayMenu_->clear();
    connectMenu_->clear();

    switch (connectionState_) {
        case ConnectionState::None: {
            for (const auto &server: serverModel_.servers()) {
                QAction *serverAction = new QAction(QString("%1:%2").arg(server.address).arg(server.port), this);
                connect(serverAction, &QAction::triggered, [this, server]() {
                    onConnectToServer(server);
                });
                connectMenu_->addAction(serverAction);
            }
            trayMenu_->addMenu(connectMenu_);
            trayMenu_->addSeparator();
            disconnectAction_ = nullptr;
            break;
        }
        case ConnectionState::Connecting: {
            QAction *connectingAction = new QAction("Connecting...", this);
            trayMenu_->addAction(connectingAction);
            trayMenu_->addSeparator();
            disconnectAction_ = nullptr;
            break;
        }
        case ConnectionState::Connected: {
            disconnectAction_ = trayMenu_->addAction(QString("Disconnect: %1:%2").arg(selectedServer_.address).arg(selectedServer_.port));
            connect(disconnectAction_, &QAction::triggered, this, &TrayApp::onDisconnectFromServer);

            trayMenu_->addSeparator(); // Разделитель перед виджетом
            QWidgetAction* speedWidgetAction = new QWidgetAction(this);
            speedWidgetAction->setDefaultWidget(speedWidget_);
            speedWidgetAction->setVisible(true);
            trayMenu_->addAction(speedWidgetAction);
            break;
        }
        case ConnectionState::Disconnecting: {
            QAction *disconnectingAction = new QAction("Disconnecting...", this);
            trayMenu_->addAction(disconnectingAction);
            trayMenu_->addSeparator();
            break;
        }
    }
    trayMenu_->addSeparator();
    settingsAction_ = trayMenu_->addAction("Settings                     ");
    connect(settingsAction_, &QAction::triggered, this, &TrayApp::onShowSettings);

    trayMenu_->addSeparator();
    quitAction_ = trayMenu_->addAction("Quit");
    connect(quitAction_, &QAction::triggered, this, &TrayApp::handleQuit);

    trayIcon_->setContextMenu(trayMenu_);
}

void TrayApp::onConnectToServer(const ServerConnectionInformation &server)
{
    qDebug() << "Click on connect to server";
    selectedServer_ = server;
    connectionState_ = ConnectionState::Connecting;
    updateTrayMenu();
    emit connecting();
}

void TrayApp::onDisconnectFromServer()
{
    qDebug() << "Click on disconnect from server";
    if (vpnClient_ != nullptr) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_ != nullptr) {
        ipTables_->clean();
        ipTables_.reset();
    }
    //emit disconnecting(); // Emit disconnecting state signal
    connectionState_ = ConnectionState::None;
    updateTrayMenu();
}

void TrayApp::onShowSettings()
{
    qDebug() << "onShowSettings";
    if (!settingsWidget_) {
        settingsWidget_ = new SettingsWidget(&serverModel_, nullptr);
    }
    if (!settingsWidget_->isVisible()) {
        settingsWidget_->show();
    } else {
        settingsWidget_->raise();
        settingsWidget_->activateWindow();
    }
//    serverModel_.load();
//    updateTrayMenu();
}

void TrayApp::handleDefaultState()
{
    qDebug() << "Handling default state";
    if (vpnClient_ != nullptr) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_ != nullptr) {
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
    qDebug() << "Handling connected state";
    trayIcon_->setIcon(QIcon(activeIconPath));
    updateTrayMenu();
}

void TrayApp::handleDisconnecting()
{
    if (vpnClient_ != nullptr) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_ != nullptr) {
        ipTables_->clean();
        ipTables_.reset();
    }
    qDebug() << "Handling disconnecting state";
    trayIcon_->setIcon(QIcon(inactiveIconPath));
    updateTrayMenu();
}

void TrayApp::updateSpeedWidget()
{
    if (vpnClient_) {
        speedWidget_->updateSpeed(
                vpnClient_->getReceiveRate(),
                vpnClient_->getSendRate()
        );
    }
}

void TrayApp::handleQuit()
{
    qDebug() << "=============================";
    if (vpnClient_ != nullptr) {
        vpnClient_->stop();
        vpnClient_.reset();
        vpnClient_ = nullptr;
    }
    if (ipTables_ != nullptr) {
        ipTables_->clean();
        ipTables_.reset();
        ipTables_ = nullptr;
    }
    QApplication::quit();
}