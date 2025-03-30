#include <QLabel>
#include <QLineEdit>
#include <QFileDialog>
#include <QGridLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <QTableWidgetItem>

#include "settings.h"

#include "gui/autostart/autostart.h"
#include "gui/tokendialog/tokendialog.h"
#include "gui/translations/translations.h"

using namespace fptn::gui;


SettingsWidget::SettingsWidget(const SettingsModelPtr& settings, QWidget *parent)
        : QDialog(parent), settings_(settings)
{
    setupUi();
    setWindowIcon(QIcon(":/icons/app.ico"));
    // show on top
    setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
    setModal(true);
    show();
    activateWindow();
    raise();
    setWindowTitle(QObject::tr("Settings"));
}


void SettingsWidget::setupUi()
{
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setContextMenuPolicy(Qt::ActionsContextMenu);

    // Settings tab
    settingsTab_ = new QWidget();
    QVBoxLayout* settingsLayout = new QVBoxLayout(settingsTab_);
    settingsLayout->setContentsMargins(10, 10, 10, 10);

    // Grid Layout for settings
    QGridLayout* gridLayout = new QGridLayout();
    gridLayout->setContentsMargins(0, 0, 0, 0);
    gridLayout->setHorizontalSpacing(10);
    gridLayout->setVerticalSpacing(10);

    // Adjust column stretching
    gridLayout->setColumnStretch(0, 1); // Label column
    gridLayout->setColumnStretch(1, 4); // Field column

    // AUTOSTART (show only for Linux)
#if defined(__linux__)
    autostartLabel_ = new QLabel(QObject::tr("Autostart"), this);;
    autostartCheckBox_ = new QCheckBox(" ", this);
    autostartCheckBox_->setChecked(settings_->autostart());
    connect(autostartCheckBox_, &QCheckBox::toggled, this, &SettingsWidget::onAutostartChanged);
    gridLayout->addWidget(autostartLabel_, 0, 0, Qt::AlignLeft);
    gridLayout->addWidget(autostartCheckBox_, 0, 1, Qt::AlignLeft);
#endif

    // LANGUAGE
    languageLabel_ = new QLabel(QObject::tr("Language"), this);
    languageComboBox_ = new QComboBox(this);
    languageComboBox_->addItems(settings_->getLanguages());
    languageComboBox_->setCurrentText(settings_->languageName());
    connect(languageComboBox_, &QComboBox::currentTextChanged, this, &SettingsWidget::onLanguageChanged);
    gridLayout->addWidget(languageLabel_, 1, 0, Qt::AlignLeft);
    gridLayout->addWidget(languageComboBox_, 1, 1, Qt::AlignLeft);

    // INTERFACE
    interfaceLabel_ = new QLabel(QObject::tr("Network Interface (adapter)") + ":  ", this);
    interfaceComboBox_ = new QComboBox(this);
    interfaceComboBox_->addItems(settings_->getNetworkInterfaces());
    interfaceComboBox_->setCurrentText(settings_->networkInterface());
    connect(interfaceComboBox_, &QComboBox::currentTextChanged, this, &SettingsWidget::onInterfaceChanged);
    gridLayout->addWidget(interfaceLabel_, 2, 0, Qt::AlignLeft);
    gridLayout->addWidget(interfaceComboBox_, 2, 1, Qt::AlignLeft);

    // GATEWAY
    gatewayLabel_ = new QLabel(QObject::tr("Gateway IP Address (typically your router's address)") + ":", this);
    gatewayAutoCheckbox_ = new QCheckBox(QObject::tr("Auto"), this);
    gatewayLineEdit_ = new QLineEdit(this);
    if (settings_->gatewayIp().toLower() != "auto") {
        gatewayAutoCheckbox_->setChecked(false);
        gatewayLineEdit_->setText(settings_->gatewayIp());
        gatewayLineEdit_->setEnabled(true);
    } else {
        gatewayAutoCheckbox_->setChecked(true);
        gatewayLineEdit_->setDisabled(true);
    }
    connect(gatewayAutoCheckbox_, &QCheckBox::toggled, this, &SettingsWidget::onAutoGatewayChanged);

    QHBoxLayout* gatewayLayout = new QHBoxLayout();
    gatewayLayout->addWidget(gatewayAutoCheckbox_, Qt::AlignLeft);
    gatewayLayout->setStretch(0, 1);

    gatewayLayout->addWidget(gatewayLineEdit_, Qt::AlignLeft);
    gatewayLayout->setStretch(1, 4);

    gridLayout->addWidget(gatewayLabel_, 3, 0);
    gridLayout->addLayout(gatewayLayout, 3, 1, 1, 2);
    settingsLayout->addLayout(gridLayout);

    // SNI
    sniLabel_ = new QLabel(QObject::tr("Fake SNI to bypass censorship (hides the VPN)") + ": ", this);
    sniLineEdit_ = new QLineEdit(this);
    sniLineEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    sniLineEdit_->setText(settings_->SNI());
    connect(sniLineEdit_, &QLineEdit::textChanged, this, [this](const QString &sni) {
        settings_->setSNI(sni);
    });

    gridLayout->addWidget(sniLabel_, 4, 0, Qt::AlignLeft);
    gridLayout->addWidget(sniLineEdit_, 4, 1, 1, 2);
    settings_->setSNI(sniLineEdit_->text());

    // Server Table
    serverTable_ = new QTableWidget(0, 4, this);
    serverTable_->setHorizontalHeaderLabels({
        QObject::tr("Name"),
        QObject::tr("User"),
        QObject::tr("Servers"),
        QObject::tr("Action")
    });
    serverTable_->horizontalHeader()->setStretchLastSection(true);
    serverTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    serverTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    serverTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    serverTable_->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    settingsLayout->addWidget(serverTable_);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    loadNewTokenButton_ = new QPushButton("  " + QObject::tr("Add token") + "  ", this);
    connect(loadNewTokenButton_, &QPushButton::clicked, this, &SettingsWidget::loadNewConfig);
    buttonLayout->addWidget(loadNewTokenButton_);

    exitButton_ = new QPushButton("  " + QObject::tr("Close") + "  ", this);
    connect(exitButton_, &QPushButton::clicked, this, &SettingsWidget::exit);
    buttonLayout->addWidget(exitButton_);

    settingsLayout->addLayout(buttonLayout);

    tabWidget_->addTab(settingsTab_, QObject::tr("Settings"));

    // About tab
    aboutTab_ = new QWidget();
    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab_);
    aboutLayout->setContentsMargins(10, 10, 10, 10);
    aboutLayout->setSpacing(10);
    // FPTN label
    QLabel* fptnLabel_ = new QLabel("FPTN", this);
    fptnLabel_->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(fptnLabel_);
    // Version Label - centered horizontally
    versionLabel_ = new QLabel(QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION), this);
    versionLabel_->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(versionLabel_);
    // Project Information - justified
    projectInfoLabel_ = new QLabel(QObject::tr("FPTN_DESCRIPTION"), this);
    projectInfoLabel_->setWordWrap(true);
    projectInfoLabel_->setAlignment(Qt::AlignJustify);
    aboutLayout->addWidget(projectInfoLabel_);
    // Add a link (optional)
    websiteLinkLabel_ = new QLabel(QObject::tr("FPTN_WEBSITE_DESCRIPTION"), this);
    websiteLinkLabel_->setOpenExternalLinks(true);
    aboutLayout->addWidget(websiteLinkLabel_);
    // Add group information (optional)
    telegramGroupLabel_ = new QLabel(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"), this);
    telegramGroupLabel_->setOpenExternalLinks(true);
    aboutLayout->addWidget(telegramGroupLabel_);
    // stretch
    aboutLayout->addStretch(1);
    // Add About Tab to TabWidget
    tabWidget_->addTab(aboutTab_, QObject::tr("About"));

    // Main Layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->addWidget(tabWidget_);
    setMinimumSize(600, 400);
    setLayout(mainLayout);

    // Populate server table with data
    const QVector<ServiceConfig> &services = settings_->services();
    serverTable_->setRowCount(services.size());
    for (int i = 0; i < services.size(); ++i) {
        const ServiceConfig &service = services[i];
        serverTable_->setItem(i, 0, new QTableWidgetItem(service.serviceName));
        serverTable_->setItem(i, 1, new QTableWidgetItem(service.username));

        QString serversTextList = "";
        for (const auto& s : service.servers) {
            serversTextList += QString("%1\n").arg(s.name);
        }
        QTableWidgetItem* item = new QTableWidgetItem(serversTextList);
        item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        item->setFlags(item->flags() | Qt::ItemIsEnabled);
        item->setData(Qt::DisplayRole, serversTextList);
        serverTable_->setItem(i, 2, item);

        QPushButton *deleteButton = new QPushButton(QObject::tr("Delete"), this);
        connect(deleteButton, &QPushButton::clicked, [this, i]() { removeServer(i); });

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *actionLayout = new QHBoxLayout(buttonContainer);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setAlignment(Qt::AlignCenter);
        actionLayout->addWidget(deleteButton);
        serverTable_->setCellWidget(i, 3, buttonContainer);
    }
}

void SettingsWidget::exit()
{
    settings_->setNetworkInterface(interfaceComboBox_->currentText());
    settings_->setLanguage(languageComboBox_->currentText());
    settings_->setGatewayIp(gatewayLineEdit_->text());
    settings_->setSNI(sniLineEdit_->text());
    if (!settings_->save()) {
        QMessageBox::critical(
            this,
            QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data.")
        );
    }
    this->close();
}

void SettingsWidget::loadNewConfig()
{
#if __APPLE__ // show modal window only for mac
    const QString filePath = QFileDialog::getOpenFileName(
        this,
        QObject::tr("Open FPTN Service File"),
        QDir::homePath(),
        "FPTN Files (*.fptn);;All files (*)",
        nullptr,
        QFileDialog::DontUseNativeDialog
    );
    QString token;
    if (!filePath.isEmpty()) {
        QFile file(filePath);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&file);
            token = in.readAll();
            file.close();
        }
    }
#else
    TokenDialog dialog(this);
    dialog.exec();
    const QString token = dialog.token();
#endif
    // show on top
    show();
    activateWindow();
    raise();

    if (!token.isEmpty()) {
        try {
            ServiceConfig config = settings_->parseToken(token);
            int existsIndex = settings_->getExistServiceIndex(config.serviceName);
            if (existsIndex != -1) {
                // remove previous settings
                settings_->removeServer(existsIndex);
                serverTable_->removeRow(existsIndex);
            }
            settings_->addService(config);
            const bool savingStatus = settings_->save();
            if (savingStatus) {
                // Insert a new row into the server table
                const int newRow = serverTable_->rowCount();
                serverTable_->insertRow(newRow);

                serverTable_->setItem(newRow, 0, new QTableWidgetItem(config.serviceName));
                serverTable_->setItem(newRow, 1, new QTableWidgetItem(config.username));

                QString serversTextList = "";
                for (const auto &s: config.servers) {
                    serversTextList += QString("%1\n").arg(s.name);
                }
                QTableWidgetItem *item = new QTableWidgetItem(serversTextList);
                item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
                item->setFlags(item->flags() | Qt::ItemIsEnabled);
                item->setData(Qt::DisplayRole, serversTextList);
                serverTable_->setItem(newRow, 2, item);

                QPushButton *deleteButton = new QPushButton(QObject::tr("Delete"), this);
                connect(deleteButton, &QPushButton::clicked, [this, newRow]() { removeServer(newRow); });

                QWidget *buttonContainer = new QWidget();
                QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
                buttonLayout->setContentsMargins(0, 0, 0, 0);
                buttonLayout->setAlignment(Qt::AlignCenter);
                buttonLayout->addWidget(deleteButton);
                serverTable_->setCellWidget(newRow, 3, buttonContainer);
            }
            if (savingStatus) {
                if (existsIndex != -1) {
                    // update data
                    QMessageBox::information(
                        this,
                        QObject::tr("Save Successful"),
                        QObject::tr("Data has been successfully saved.")
                    );
                } else {
                    // new data
                    QMessageBox::information(
                        this,
                        QObject::tr("Save Successful"),
                        QObject::tr("Data has been successfully saved.")
                    );
                }
            } else {
                QMessageBox::critical(
                    this,
                    QObject::tr("Save Failed"),
                    QObject::tr("An error occurred while saving the data.")
                );
            }
        } catch(const std::exception &err) {
            QMessageBox::critical(this, QObject::tr("Error!"), err.what());
        }
    }
}

void SettingsWidget::removeServer(int row)
{
    if (row >= 0 && row < serverTable_->rowCount()) {
        serverTable_->removeRow(row);
        settings_->removeServer(row);
        QMessageBox::information(
            this,
            QObject::tr("Delete Successful"),
            QObject::tr("The data has been successfully removed")
        );
    }
}

void SettingsWidget::closeEvent(QCloseEvent* event)
{
    exit();
    event->accept(); // Accept the event to proceed with the closing
}

void SettingsWidget::onLanguageChanged(const QString&)
{
    // set language
    settings_->setLanguage(languageComboBox_->currentText());
    fptn::gui::setTranslation(settings_->languageCode());
    if (!settings_->save()) {
        QMessageBox::critical(
            this,
            QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data.")
        );
    }

    setWindowTitle(QObject::tr("Settings"));
    if (tabWidget_) {
        tabWidget_->setTabText(0, QObject::tr("Settings"));
        tabWidget_->setTabText(1, QObject::tr("About"));
    }
    if (languageLabel_) {
        languageLabel_->setText(QObject::tr("Language"));
    }
    if (interfaceLabel_) {
        interfaceLabel_->setText(QObject::tr("Network Interface (adapter)") + ":  ");
    }
    if (gatewayLabel_) {
        gatewayLabel_->setText(QObject::tr("Gateway IP Address (typically your router's address)") + ":");
    }
    if (serverTable_) {
        serverTable_->setHorizontalHeaderLabels({
            QObject::tr("Name"),
            QObject::tr("User"),
            QObject::tr("Servers"),
            QObject::tr("Action")
        });
    }
    if (loadNewTokenButton_) {
        loadNewTokenButton_->setText("  " + QObject::tr("Add token") + "  ");
    }
    if (exitButton_) {
        exitButton_->setText("  " + QObject::tr("Close") + "  ");
    }
    if (gatewayAutoCheckbox_) {
        gatewayAutoCheckbox_->setText(QObject::tr("Auto"));
    }
    if (autostartLabel_) {
        autostartLabel_->setText(QObject::tr("Autostart"));
    }
    if (sniLabel_) {
        sniLabel_->setText(QObject::tr("Fake SNI to bypass censorship (hides the VPN)") + ": ");
    }
    // about
    if (versionLabel_) {
        versionLabel_->setText(QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION));
    }
    if (projectInfoLabel_) {
        projectInfoLabel_->setText(QObject::tr("FPTN_DESCRIPTION"));
    }
    if (websiteLinkLabel_) {
        websiteLinkLabel_->setText(QObject::tr("FPTN_WEBSITE_DESCRIPTION"));
    }
    if (telegramGroupLabel_) {
        telegramGroupLabel_->setText(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"));
    }
}

void SettingsWidget::onInterfaceChanged(const QString&)
{
    settings_->setNetworkInterface(interfaceComboBox_->currentText());
    if (!settings_->save()) {
        QMessageBox::critical(
            this,
            QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data.")
        );
    }
}

void SettingsWidget::onAutostartChanged(bool checked)
{
    if (checked) {
        fptn::gui::autostart::enable();
        settings_->setAutostart(true);
    } else {
        fptn::gui::autostart::disable();
        settings_->setAutostart(false);
    }
}

void SettingsWidget::onAutoGatewayChanged(bool checked)
{
    if (checked) {
        gatewayLineEdit_->setDisabled(true);
        gatewayLineEdit_->setText("");
        settings_->setGatewayIp("auto");
    } else {
        gatewayLineEdit_->setEnabled(true);
    }
}
