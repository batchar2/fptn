#include <QMenu>
#include <QIcon>
#include <QAction>
#include <QStyleHints>
#include <QMessageBox>
#include <QApplication>
#include <QWidgetAction>

#include <spdlog/spdlog.h>

#include "gui/style/style.h"

#include "tray.h"


using namespace fptn::gui;


inline bool isDarkMode()
{
    const auto scheme = QGuiApplication::styleHints()->colorScheme();
    return scheme == Qt::ColorScheme::Dark;
}


inline bool isUbuntu()
{
    QString osName = QSysInfo::prettyProductName();
    return osName.contains("Ubuntu", Qt::CaseInsensitive);
}

inline bool isWindows()
{
    QString osName = QSysInfo::productType();
    return osName.contains("windows", Qt::CaseInsensitive);
}

inline void showError(const QString& title, const QString& msg)
{
    QWidget tempWidget;
    QMessageBox::critical(
        &tempWidget,
        title,
        msg
    );
}

TrayApp::TrayApp(const SettingsModelPtr &settings, QObject *parent)
    :
        settings_(settings),
        QObject(parent),
        trayIcon_(new QSystemTrayIcon(this)),
        trayMenu_(new QMenu()),
        connectMenu_(new QMenu(QObject::tr("Connect") + "    ", trayMenu_)),
        speedWidget_(new SpeedWidget()),
        updateTimer_(new QTimer(this))
{
#ifdef __linux__
    if (isDarkMode() || isUbuntu()) {
        activeIconPath_ = ":/icons/dark/active.ico";
        inactiveIconPath_ = ":/icons/dark/inactive.ico";
    } else {
        activeIconPath_ = ":/icons/white/active.ico";
        inactiveIconPath_ = ":/icons/white/inactive.ico";
    }
    qApp->setStyleSheet(fptn::gui::ubuntuStyleSheet);
#elif __APPLE__
    // hot fix: for mac always dark
    activeIconPath_ = ":/icons/dark/active.ico";
    inactiveIconPath_ = ":/icons/dark/inactive.ico";
    if (isDarkMode()) {
        qApp->setStyleSheet(fptn::gui::darkStyleSheet);
    } else {
        qApp->setStyleSheet(fptn::gui::whiteStyleSheet);
    }
#elif _WIN32
    if (isDarkMode()) {
        activeIconPath_ = ":/icons/dark/active.ico";
        inactiveIconPath_ = ":/icons/dark/inactive.ico";
    } else {
        activeIconPath_ = ":/icons/white/active.ico";
        inactiveIconPath_ = ":/icons/white/inactive.ico";
    }
    qApp->setStyleSheet(fptn::gui::windowsStyleSheet);
    if (trayIcon_ && trayMenu_) {
        QObject::connect(trayIcon_, &QSystemTrayIcon::activated, [this](QSystemTrayIcon::ActivationReason reason) {
            if (trayMenu_->isVisible()) {
                trayMenu_->close(); // Hide the menu if it's visible
            } else {
                trayMenu_->show();
                trayMenu_->exec(QCursor::pos()); // Show the menu if it's not visible
            }
        });
    }
#else
    #error "Unsupported system!"
#endif

    const QString selectedLanguage = settings->languageCode();
    if (selectedLanguage.isEmpty()) { // save default language for first start
        const QString systemLanguage = getSystemLanguageCode();
        if (settings->existsTranslation(systemLanguage)) {
            settings->setLanguage(systemLanguage);
        } else {
            settings->setLanguage(settings->defaultLanguageCode());
        }
    } else {
        setTranslation(selectedLanguage);
    }

    connect(this, &TrayApp::defaultState, this, &TrayApp::handleDefaultState);
    connect(this, &TrayApp::connecting, this, &TrayApp::handleConnecting);
    connect(this, &TrayApp::connected, this, &TrayApp::handleConnected);
    connect(this, &TrayApp::disconnecting, this, &TrayApp::handleDisconnecting);

    connect(settings_.get(), &SettingsModel::dataChanged, this, &TrayApp::updateTrayMenu);
    connect(updateTimer_, &QTimer::timeout, this, &TrayApp::updateSpeedWidget);
    updateTimer_->start(1000);

    setUpTrayIcon();

    settingsAction_ = new QAction(QObject::tr("Settings"), this);
    connect(settingsAction_, &QAction::triggered, this, &TrayApp::onShowSettings);

    quitAction_ = new QAction(QObject::tr("Quit"), this);
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
    trayIcon_->show();
}

void TrayApp::updateTrayMenu()
{
    if (connectMenu_) {
        connectMenu_->clear();
    }
    if (trayMenu_ && connectMenu_) {
        trayMenu_->removeAction(connectMenu_->menuAction());
    }

    switch (connectionState_) {
        case ConnectionState::None: {
            trayIcon_->setIcon(QIcon(inactiveIconPath_));
            const auto& services = settings_->services();
            if (!services.isEmpty()) {
                // auto
                auto smartConnectAction = new QAction(QObject::tr("Smart Connect"), connectMenu_);
                connect(smartConnectAction, &QAction::triggered, [this]() {
                    smartConnect_ = true;
                    onConnectToServer();
                });
                connectMenu_->addAction(smartConnectAction);

                connectMenu_->addSeparator();

                // servers
                for (const auto &service : services) {
                    for (const auto &server : service.servers) {
                        auto serverConnect = new QAction(server.name, connectMenu_);
                        connect(serverConnect, &QAction::triggered, [this, server, service]() {
                            smartConnect_ = false;

                            fptn::config::ConfigFile::Server cfgServer;
                            {
                                cfgServer.name = server.name.toStdString();
                                cfgServer.host = server.host.toStdString();
                                cfgServer.port = server.port;
                                cfgServer.isUsing = server.isUsing;
                                cfgServer.service = service;
                            }
                            selectedServer_ = cfgServer;
                            onConnectToServer();
                        });
                        connectMenu_->addAction(serverConnect);
                    }
                }
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
            if (connectingAction_) {
                connectingAction_->setVisible(false);
            }
            if (speedWidget_) {
                speedWidget_->setVisible(false);
            }
            break;
        }
        case ConnectionState::Connecting: {
            trayIcon_->setIcon(QIcon(inactiveIconPath_));
            if (!connectingAction_) {
                connectingAction_ = new QAction(QObject::tr("Connecting..."), this);
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
            trayIcon_->setIcon(QIcon(activeIconPath_));
            if (!disconnectAction_) {
                disconnectAction_ = new QAction(this);
                connect(disconnectAction_, &QAction::triggered, this, &TrayApp::onDisconnectFromServer);
                trayMenu_->insertAction(settingsAction_, disconnectAction_);
            }
            if (disconnectAction_) {
                disconnectAction_->setText(
                    QString(QObject::tr("Disconnect") + ": %1 (%2)")
                        .arg(QString::fromStdString(selectedServer_.name))
                        .arg(selectedServer_.service.serviceName)
                );
                disconnectAction_->setVisible(true);
            }
            if (connectingAction_) {
                connectingAction_->setVisible(false);
            }
            if (!speedWidgetAction_) {
                speedWidgetAction_ = new QWidgetAction(this);
                speedWidgetAction_->setDefaultWidget(speedWidget_);
                trayMenu_->insertAction(settingsAction_, speedWidgetAction_);
            }
            if (speedWidget_) {
                speedWidget_->setVisible(true);
            }
            if (settingsAction_) {
                settingsAction_->setEnabled(false);
            }
            if (speedWidgetAction_) {
                speedWidgetAction_->setVisible(true);
            }
            break;
        }
        case ConnectionState::Disconnecting: {
            trayIcon_->setIcon(QIcon(inactiveIconPath_));
            if (disconnectAction_) {
                disconnectAction_->setVisible(false);
            }
            if (!connectingAction_) {
                connectingAction_ = new QAction(QObject::tr("Disconnecting..."), this);
                trayMenu_->insertAction(settingsAction_, connectingAction_);
            } else {
                connectingAction_->setText(QObject::tr("Disconnecting... "));
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

    // Apply the language translation based on the user's settings
    QString selectedLanguage = settings_->languageCode();
    if (!selectedLanguage.isEmpty()) {
        setTranslation(selectedLanguage);
    }
    retranslateUi();
}

void TrayApp::onConnectToServer()
{
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
    auto dialog = std::make_unique<SettingsWidget>(settings_);
    QMetaObject::invokeMethod(dialog.get(), "setFocus", Qt::QueuedConnection);
    dialog->exec();
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
    updateTrayMenu();
}

void TrayApp::handleConnecting()
{
    spdlog::info("Handling connecting state");
    updateTrayMenu();
    trayIcon_->setIcon(QIcon(inactiveIconPath_));

    const pcpp::IPv4Address tunInterfaceAddress("10.0.1.1");
    const std::string tunInterfaceName = "tun0";

    /* check gateway address */
    const auto usingGatewayIP = (
        settings_->gatewayIp() == "auto"
        ? fptn::system::getDefaultGatewayIPAddress()
        : pcpp::IPv4Address(settings_->gatewayIp().toStdString())
    );
    if (usingGatewayIP == pcpp::IPv4Address("0.0.0.0")) {
        showError(
            QObject::tr("Connection Error"),
            QObject::tr(
                "Unable to find the default gateway IP address. "
                "Please check your connection and make sure no other VPN is active. "
                "If the error persists, specify the gateway address in the FPTN settings using your router's IP address, "
                "and ensure that an active internet interface (adapter) is selected. If the issue remains unresolved, "
                "please contact the developer via Telegram @fptn_chat."
            )
        );
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }
    /* config */
    const std::string networkInterface = (
        settings_->networkInterface() == "auto"
        ? ""
        : settings_->networkInterface().toStdString()
    );

    fptn::config::ConfigFile config;
    if (smartConnect_) { // find the best server
        for (const auto& service : settings_->services()) {
            for (const auto &s: service.servers) {
                fptn::config::ConfigFile::Server cfgServer;
                {
                    cfgServer.name = s.name.toStdString();
                    cfgServer.host = s.host.toStdString();
                    cfgServer.port = s.port;
                    cfgServer.isUsing = s.isUsing;
                    cfgServer.service = service;
                }
                config.addServer(cfgServer);
            }
        }
        try {
            selectedServer_ = config.findFastestServer();
        } catch (std::runtime_error &err) {
            showError(QObject::tr("Config error"), err.what());
            connectionState_ = ConnectionState::None;
            updateTrayMenu();
            return;
        }
    } else {
        // check connection to selected server
        const std::uint64_t time = config.getDownloadTimeMs(selectedServer_);
        if (time == -1) {
            showError(
                QObject::tr("Connection Error"),
                QString(QObject::tr("The server is unavailable. Please select another server or use Auto-connect to find the best available server."))
                    .arg(QString::fromStdString(selectedServer_.host)));
            connectionState_ = ConnectionState::None;
            updateTrayMenu();
            return;
        }
    }

    const int serverPort = selectedServer_.port;
    const auto serverIP = fptn::system::resolveDomain(selectedServer_.host);
    if (serverIP == pcpp::IPv4Address("0.0.0.0")) {
        showError(
            QObject::tr("DNS resolution error"),
            QString(QObject::tr("DNS resolution error") + ": %1").arg(QString::fromStdString(selectedServer_.host)));
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }


    auto webSocketClient = std::make_unique<fptn::http::WebSocketClient>(
        serverIP,
        serverPort,
        tunInterfaceAddress,
        true
    );

    bool loginStatus = webSocketClient->login(
        selectedServer_.service.username.toStdString(),
        selectedServer_.service.password.toStdString()
    );

    if (!loginStatus) {
        showError(
            QObject::tr("Connection Error"),
            QObject::tr("Connection error to the server! Please download the latest file with your personal settings through the Telegram bot and try again.")
        );
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }

    const auto dnsServer = webSocketClient->getDns();
    if (dnsServer == pcpp::IPv4Address("0.0.0.0")) {
        showError(
            QObject::tr("Connection error"),
            QObject::tr("DNS server error! Check your connection!")
        );
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }

    ipTables_ = std::make_unique<fptn::system::IPTables>(
        networkInterface,
        tunInterfaceName,
        serverIP,
        dnsServer,
        usingGatewayIP,
        tunInterfaceAddress
    );
    auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
        tunInterfaceName, tunInterfaceAddress, 30
    );
    vpnClient_ = std::make_unique<fptn::vpn::VpnClient>(
        std::move(webSocketClient),
        std::move(virtualNetworkInterface),
        dnsServer
    );
    vpnClient_->start();
    std::this_thread::sleep_for(std::chrono::seconds(2)); // FIX IT!
    ipTables_->apply();

    connectionState_ = ConnectionState::Connected;
    updateTrayMenu();
    emit connected();
}

void TrayApp::handleConnected()
{
    connectionState_ = ConnectionState::Connected;
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
    if (vpnClient_ && speedWidget_ && connectionState_ == ConnectionState::Connected) {
        speedWidget_->updateSpeed(vpnClient_->getReceiveRate(), vpnClient_->getSendRate());
    }
}

void TrayApp::handleQuit()
{
    QApplication::quit();
}

bool TrayApp::setTranslation(const QString& languageCode)
{
    const QString translationFile = QString("fptn_%1.qm").arg(languageCode);
    qApp->removeTranslator(&translator_);
    if (translator_.load(translationFile, ":/translations")) {
        if (qApp->installTranslator(&translator_)) {
            spdlog::info("Successfully loaded language: {}", languageCode.toStdString());
            return true;
        } else {
            spdlog::warn("Failed to install translator for language: {}", languageCode.toStdString());
        }
    } else {
        spdlog::warn("Translation file not found: {}", translationFile.toStdString());
    }
    return false;
}

QString TrayApp::getSystemLanguageCode() const
{
    const QLocale locale;
    const QString localeName = locale.name();
    if (localeName.contains('_')) {
        const QString languageCode = locale.name().split('_').first();
        return languageCode;
    }
    return "en";
}

void TrayApp::retranslateUi()
{
    if (connectMenu_) {
        connectMenu_->setTitle(QObject::tr("Connect") + "    ");
    }
    if (settingsAction_) {
        settingsAction_->setText(QObject::tr("Settings"));
    }
    if (quitAction_) {
        quitAction_->setText(QObject::tr("Quit"));
    }
    if (connectingAction_) {
        connectingAction_->setText(QObject::tr("Connecting..."));
    }
    if (disconnectAction_) {
        const QString disconnectText = QString(QObject::tr("Disconnect") + ": %1 (%2)")
            .arg(QString::fromStdString(selectedServer_.name))
            .arg(selectedServer_.service.serviceName);
        disconnectAction_->setText(disconnectText);
    }
}
