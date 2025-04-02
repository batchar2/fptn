#include <QMenu>
#include <QIcon>
#include <QAction>
#include <QStyleHints>
#include <QMessageBox>
#include <QApplication>
#include <QWidgetAction>
#include <QStyleFactory>

#include <spdlog/spdlog.h>
#include <QDesktopServices>

#include <common/system/command.h>

#include "gui/style/style.h"
#include "gui/autoupdate/autoupdate.h"
#include "gui/translations/translations.h"

#include "tray.h"


using namespace fptn::gui;


inline void showError(const QString& title, const QString& msg)
{
    QWidget tempWidget;
    QMessageBox::critical(
        &tempWidget,
        title,
        msg
    );
}


TrayApp::TrayApp(const SettingsModelPtr &settings, QObject* parent)
        :
        QWidget(),
        settings_(settings),
        trayIcon_(new QSystemTrayIcon(this)),
        trayMenu_(new QMenu(this)),
        connectMenu_(new QMenu(QObject::tr("Connect") + "    ", trayMenu_)),
        speedWidget_(new SpeedWidget(trayMenu_)),
        updateTimer_(new QTimer(this)),
        activeIconPath_(":/icons/active.ico"),
        inactiveIconPath_(":/icons/inactive.ico")
{
    (void)parent;
#ifdef __linux__
    qApp->setStyleSheet(fptn::gui::ubuntuStyleSheet);
#elif __APPLE__
    qApp->setStyleSheet(fptn::gui::macStyleSheet);
#elif _WIN32
    qApp->setStyleSheet(fptn::gui::windowsStyleSheet);
#else
    #error "Unsupported system!"
#endif

#if __linux__
    connect(trayIcon_, &QSystemTrayIcon::activated, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Context) {
            trayMenu_->popup(trayIcon_->geometry().bottomLeft());
        } else {
            trayMenu_->close();
        }
    });
#elif _WIN32
    connect(trayIcon_, &QSystemTrayIcon::activated, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Context) {
            trayMenu_->show();
            trayMenu_->exec(QCursor::pos());
        } else {
            trayMenu_->close();
        }
    });
#endif
    // Also connect clicking on the icon to the signal processor of this press
//    connect(trayIcon_, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
//            this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

    const QString selectedLanguage = settings->languageCode();
    if (selectedLanguage.isEmpty()) { // save default language for first start
        const QString systemLanguage = getSystemLanguageCode();
        if (settings->existsTranslation(systemLanguage)) {
            settings->setLanguageCode(systemLanguage);
        } else {
            settings->setLanguageCode(settings->defaultLanguageCode());
        }
    } else {
        fptn::gui::setTranslation(selectedLanguage);
    }

    // State
    connect(this, &TrayApp::defaultState, this, &TrayApp::handleDefaultState);
    connect(this, &TrayApp::connecting, this, &TrayApp::handleConnecting);
    connect(this, &TrayApp::connected, this, &TrayApp::handleConnected);
    connect(this, &TrayApp::disconnecting, this, &TrayApp::handleDisconnecting);

    // Settings
    connect(settings_.get(), &SettingsModel::dataChanged, this, &TrayApp::updateTrayMenu);
    connect(updateTimer_, &QTimer::timeout, this, &TrayApp::updateSpeedWidget);
    updateTimer_->start(1000);

    // Settings
    settingsAction_ = new QAction(QObject::tr("Settings"), this);
    connect(settingsAction_, &QAction::triggered, this, &TrayApp::onShowSettings);

    // Autoupdate
    autoUpdateAction_ = new QAction(QObject::tr("New version available") + " " + autoAvailableVersion_, this);
    connect(autoUpdateAction_, &QAction::triggered, this, [this] {
        openBrowser(FPTN_GITHUB_PAGE_LINK);
    });
    autoUpdateAction_->setVisible(false);

    // Quit
    quitAction_ = new QAction(QObject::tr("Quit"), this);
    connect(quitAction_, &QAction::triggered, this, &QCoreApplication::quit);

    // Show menu
    trayMenu_->addSeparator();
    trayMenu_->addAction(settingsAction_);
    trayMenu_->addSeparator();
    trayMenu_->addAction(autoUpdateAction_);
    trayMenu_->addSeparator();
    trayMenu_->addAction(quitAction_);

    trayIcon_->setContextMenu(trayMenu_);

    updateTrayMenu();
    trayIcon_->show();

    // check update
    updateVersionFuture_ = std::async(std::launch::async, fptn::gui::autoupdate::check);
}

void TrayApp::updateTrayMenu()
{
    if (connectMenu_) {
        connectMenu_->clear();
    }
    if (trayMenu_ && connectMenu_) {
        trayMenu_->removeAction(connectMenu_->menuAction());
        smartConnectAction_ = nullptr;
        emptyConfigurationAction_ = nullptr;
    }

    switch (connectionState_) {
        case ConnectionState::None: {
            trayIcon_->setIcon(QIcon(inactiveIconPath_));
            const auto& services = settings_->services();
            if (services.length()) {
                smartConnectAction_ = new QAction(QObject::tr("Smart Connect"), connectMenu_);
                connect(smartConnectAction_, &QAction::triggered, [this]() {
                    smartConnect_ = true;
                    onConnectToServer();
                });
                connectMenu_->addAction(smartConnectAction_);
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
                                cfgServer.serviceName = service.serviceName.toStdString();
                                cfgServer.username = service.username.toStdString();
                                cfgServer.password = service.password.toStdString();
                            }
                            selectedServer_ = cfgServer;
                            onConnectToServer();
                        });
                        connectMenu_->addAction(serverConnect);
                    }
                }
            } else {
                emptyConfigurationAction_ = new QAction(QObject::tr("No servers"), connectMenu_);
                connectMenu_->addAction(emptyConfigurationAction_);
                emptyConfigurationAction_->setEnabled(false);
            }
            trayMenu_->insertMenu(settingsAction_, connectMenu_);

            if (connectMenu_) {
                connectMenu_->setVisible(false);
            }
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
                        .arg(QString::fromStdString(selectedServer_.serviceName))
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
            if (speedWidgetAction_) {
                speedWidgetAction_->setVisible(false);
            }
            if (settingsAction_) {
                settingsAction_->setEnabled(false);
            }
            if (connectingAction_) {
                connectingAction_->setVisible(true);
            }
            break;
        }
    }

    // Apply the language translation based on the user's settings
    QString selectedLanguage = settings_->languageCode();
    if (!selectedLanguage.isEmpty()) {
        fptn::gui::setTranslation(selectedLanguage);
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
    SPDLOG_DEBUG("Handling connecting state");
    updateTrayMenu();

    trayIcon_->setIcon(QIcon(inactiveIconPath_));

    const pcpp::IPv4Address tunInterfaceAddressIPv4(FPTN_CLIENT_DEFAULT_ADDRESS_IP4);
    const pcpp::IPv6Address tunInterfaceAddressIPv6(FPTN_CLIENT_DEFAULT_ADDRESS_IP6);
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

    const std::string sni = !settings_->SNI().isEmpty() ? settings_->SNI().toStdString() : FPTN_DEFAULT_SNI;
    fptn::config::ConfigFile config(sni); // SET SNI
    if (smartConnect_) { // find the best server
        for (const auto& service : settings_->services()) {
            for (const auto &s: service.servers) {
                fptn::config::ConfigFile::Server cfgServer;
                {
                    cfgServer.name = s.name.toStdString();
                    cfgServer.host = s.host.toStdString();
                    cfgServer.port = s.port;
                    cfgServer.isUsing = s.isUsing;
                    cfgServer.serviceName = service.serviceName.toStdString();
                    cfgServer.username = service.username.toStdString();
                    cfgServer.password = service.password.toStdString();
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
        if (time == static_cast<std::uint64_t>(-1)) {
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

    auto httpClient = std::make_unique<fptn::http::Client>(
        serverIP,
        serverPort,
        tunInterfaceAddressIPv4,
        tunInterfaceAddressIPv6,
        sni
    );
    // login
    bool loginStatus = httpClient->login(selectedServer_.username, selectedServer_.password);
    if (!loginStatus) {
        showError(
            QObject::tr("Connection Error"),
            QObject::tr("Connection error to the server! Please download the latest file with your personal settings through the Telegram bot and try again.")
        );
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }

    // get dns
    const auto [dnsServerIPv4, dnsServerIPv6] = httpClient->getDns();
    if (dnsServerIPv4 == pcpp::IPv4Address("0.0.0.0") || dnsServerIPv6 == pcpp::IPv6Address("")) {
        showError(
            QObject::tr("Connection error"),
            QObject::tr("DNS server error! Check your connection!")
        );
        connectionState_ = ConnectionState::None;
        updateTrayMenu();
        return;
    }

    // setup ip tables
    ipTables_ = std::make_unique<fptn::system::IPTables>(
        networkInterface,
        tunInterfaceName,
        serverIP,
        dnsServerIPv4,
        dnsServerIPv6,
        usingGatewayIP,
        tunInterfaceAddressIPv4,
        tunInterfaceAddressIPv6
    );

    // setup tun interface
    auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
        tunInterfaceName,
        /* IPv4 */
        tunInterfaceAddressIPv4, 30,
        /* IPv6 */
        tunInterfaceAddressIPv6, 126
    );

    // setup vpn client
    vpnClient_ = std::make_unique<fptn::vpn::VpnClient>(
        std::move(httpClient),
        std::move(virtualNetworkInterface),
        dnsServerIPv4,
        dnsServerIPv6
    );

    // Wait for the WebSocket tunnel to establish
    vpnClient_->start();
    constexpr auto TIMEOUT = std::chrono::seconds(5);
    const auto start = std::chrono::steady_clock::now();
    while (!vpnClient_->isStarted()) {
        if (std::chrono::steady_clock::now() - start > TIMEOUT) {
            showError(QObject::tr("Connection error"), QObject::tr("Couldn't open websocket tunnel!"));
            connectionState_ = ConnectionState::None;
            updateTrayMenu();
            return;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

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

    if (updateVersionFuture_.valid()) {
        const auto updateResult = updateVersionFuture_.get();
        const bool isNewVersion = updateResult.first;
        const std::string versionName = updateResult.second;
        if (isNewVersion) {
            autoAvailableVersion_ = QString::fromStdString(versionName);
            autoUpdateAction_->setVisible(true);
            retranslateUi();
        }
    }
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
    if (emptyConfigurationAction_) {
        emptyConfigurationAction_->setText(QObject::tr("No servers"));
    }
    if (smartConnectAction_) {
        smartConnectAction_->setText(QObject::tr("Smart Connect"));
    }
    if (disconnectAction_) {
        const QString disconnectText = QString(QObject::tr("Disconnect") + ": %1 (%2)")
            .arg(QString::fromStdString(selectedServer_.name))
            .arg(QString::fromStdString(selectedServer_.serviceName));
        disconnectAction_->setText(disconnectText);
    }
    if (autoUpdateAction_) {
        autoUpdateAction_->setText(QObject::tr("New version available") + " " + autoAvailableVersion_);
    }
}

void TrayApp::stop()
{
    if (vpnClient_) {
        vpnClient_->stop();
        vpnClient_.reset();
    }
    if (ipTables_) {
        ipTables_->clean();
        ipTables_.reset();
    }
}

void TrayApp::openBrowser(const std::string& url)
{
#if __APPLE__
    QDesktopServices::openUrl(QString::fromStdString(url));
#elif __linux__
    const std::string command = fmt::format(
        R"(bash -c "xhost +SI:localuser:root && (xdg-open \"{0}\" || sensible-browser \"{0}\" || x-www-browser \"{0}\" || gnome-open \"{0}\" ) "  )",
        url
    );
    fptn::common::system::command::run(command);
#elif _WIN32
    const std::string command = fmt::format(R"(explorer "{}" )", url);
    fptn::common::system::command::run(command);
#endif
}
