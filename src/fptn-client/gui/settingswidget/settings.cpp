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
}


void SettingsWidget::setupUi()
{
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setContextMenuPolicy(Qt::ActionsContextMenu);

    // Settings tab
    settingsTab_ = new QWidget();
    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab_);
    settingsLayout->setContentsMargins(10, 10, 10, 10);

    // Grid Layout for settings
    QGridLayout *gridLayout = new QGridLayout();
    gridLayout->setContentsMargins(0, 0, 0, 0);
    gridLayout->setHorizontalSpacing(10);
    gridLayout->setVerticalSpacing(10);

    // Adjust column stretching
    gridLayout->setColumnStretch(0, 1); // Label column
    gridLayout->setColumnStretch(1, 4); // Field column

    languageLabel_ = new QLabel(QObject::tr("Language"), this);
    languageComboBox_ = new QComboBox(this);
    languageComboBox_->addItems(settings_->getLanguages());
    languageComboBox_->setCurrentText(settings_->languageName());
    connect(languageComboBox_, &QComboBox::currentTextChanged, this, &SettingsWidget::onLanguageChanged);
    gridLayout->addWidget(languageLabel_, 0, 0, Qt::AlignLeft);
    gridLayout->addWidget(languageComboBox_, 0, 1, Qt::AlignLeft);

    interfaceLabel_ = new QLabel(QObject::tr("Network Interface (adapter)") + ":  ", this);
    interfaceComboBox_ = new QComboBox(this);
    interfaceComboBox_->addItems(settings_->getNetworkInterfaces());
    interfaceComboBox_->setCurrentText(settings_->networkInterface());
    connect(interfaceComboBox_, &QComboBox::currentTextChanged, this, &SettingsWidget::onInterfaceChanged);
    gridLayout->addWidget(interfaceLabel_, 1, 0, Qt::AlignLeft);
    gridLayout->addWidget(interfaceComboBox_, 1, 1, Qt::AlignLeft);

    gatewayLabel_ = new QLabel(QObject::tr("Gateway IP Address (typically your router's address)") + ":", this);
    gatewayLineEdit_ = new QLineEdit(this);
    gatewayLineEdit_->setText(settings_->gatewayIp());
    gridLayout->addWidget(gatewayLabel_, 2, 0, Qt::AlignLeft);
    gridLayout->addWidget(gatewayLineEdit_, 2, 1, Qt::AlignLeft);

    settingsLayout->addLayout(gridLayout);

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
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    loadNewTokenButton_ = new QPushButton("  " + QObject::tr("Add token") + "  ", this);
    connect(loadNewTokenButton_, &QPushButton::clicked, this, &SettingsWidget::loadNewConfig);
    buttonLayout->addWidget(loadNewTokenButton_);

    exitButton_ = new QPushButton("  " + QObject::tr("Exit") + "  ", this);
    connect(exitButton_, &QPushButton::clicked, this, &SettingsWidget::exit);
    buttonLayout->addWidget(exitButton_);

    settingsLayout->addLayout(buttonLayout);

    tabWidget_->addTab(settingsTab_, QObject::tr("Settings"));

    // About tab
    aboutTab_ = new QWidget();
    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab_);
    aboutLayout->setContentsMargins(10, 10, 10, 10);
    aboutLayout->setSpacing(10);

    versionLabel_ = new QLabel(QString(QObject::tr("Application Version") + ": %1").arg(FPTN_VERSION), this);
    versionLabel_->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(versionLabel_);
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
    this->close();
    settings_->setNetworkInterface(interfaceComboBox_->currentText());
    settings_->setLanguage(languageComboBox_->currentText());
    settings_->setGatewayIp(gatewayLineEdit_->text());
    if (!settings_->save()) {
        QMessageBox::critical(
            this,
            QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data.")
        );
    }
}

void SettingsWidget::loadNewConfig()
{
    // show modal window
    TokenDialog dialog(this);
    const int result = dialog.exec();

    // show on top
    show();
    activateWindow();
    raise();

    const QString token = dialog.token();
    if (result == QDialog::Accepted && !token.isEmpty()) {
        try {
            ServiceConfig config = settings_->parseToken(token);
            int existsIndex = settings_->getExistServiceIndex(config.serviceName);
            if (existsIndex != -1) {
                // remove previous settings
                settings_->removeServer(existsIndex);
                serverTable_->removeRow(existsIndex);
            }
            settings_->addService(config);
            settings_->save();
            if (settings_->save() ) {
                QMessageBox::information(
                    this,
                    QObject::tr("Save Successful"),
                    QObject::tr("Data has been successfully saved.")
                );
                this->close();
            } else {
                QMessageBox::critical(
                    this,
                    QObject::tr("Save Failed"),
                    QObject::tr("An error occurred while saving the data.")
                );
            }
            // visualite table
            int newRow = serverTable_->rowCount();
            serverTable_->insertRow(newRow);

            serverTable_->setItem(newRow, 0, new QTableWidgetItem(config.serviceName));
            serverTable_->setItem(newRow, 1, new QTableWidgetItem(config.username));

            QString serversTextList = "";
            for (const auto& s : config.servers) {
                serversTextList += QString("%1\n").arg(s.name);
            }
            QTableWidgetItem* item = new QTableWidgetItem(serversTextList);
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
            QObject::tr("Server has been successfully deleted.")
        );
    }
}

void SettingsWidget::closeEvent(QCloseEvent* event)
{
    qDebug() << "+";
    exit();
    // Accept the event to proceed with the closing
    event->accept();
}

void SettingsWidget::onLanguageChanged(const QString&)
{
    settings_->setLanguage(languageComboBox_->currentText());
    if (!settings_->save()) {
        QMessageBox::critical(
            this,
            QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data.")
        );
    }
    // set language
    fptn::gui::setTranslation(settings_->languageCode());

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
        exitButton_->setText("  " + QObject::tr("Exit") + "  ");
    }
    if (versionLabel_) {
        versionLabel_->setText(QString(QObject::tr("Application Version") + ": %1").arg(FPTN_VERSION));
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
