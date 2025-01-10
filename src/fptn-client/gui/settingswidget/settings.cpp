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

using namespace fptn::gui;


SettingsWidget::SettingsWidget(const SettingsModelPtr& settings, QWidget *parent)
        : QDialog(parent), settings_(settings)
{
    setupUi();
    setModal(true);
    setWindowIcon(QIcon(":/icons/app.ico"));
}


void SettingsWidget::setupUi()
{
    tabWidget = new QTabWidget(this);
    tabWidget->setContextMenuPolicy(Qt::ActionsContextMenu);

    // Settings tab
    settingsTab = new QWidget();
    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
    settingsLayout->setContentsMargins(10, 10, 10, 10);

    // Grid Layout for settings
    QGridLayout *gridLayout = new QGridLayout();
    gridLayout->setContentsMargins(0, 0, 0, 0);
    gridLayout->setHorizontalSpacing(10);
    gridLayout->setVerticalSpacing(10);

    // Adjust column stretching
    gridLayout->setColumnStretch(0, 1); // Label column
    gridLayout->setColumnStretch(1, 4); // Field column

    QLabel *languageLabel = new QLabel(QObject::tr("Language"), this);
    languageComboBox = new QComboBox(this);
    languageComboBox->addItems(settings_->getLanguages());
    languageComboBox->setCurrentText(settings_->languageName());
    gridLayout->addWidget(languageLabel, 0, 0, Qt::AlignLeft);
    gridLayout->addWidget(languageComboBox, 0, 1, Qt::AlignLeft);

    QLabel *interfaceLabel = new QLabel(QObject::tr("Network Interface (adapter)") + ":  ", this);
    interfaceComboBox = new QComboBox(this);
    interfaceComboBox->addItems(settings_->getNetworkInterfaces());
    interfaceComboBox->setCurrentText(settings_->networkInterface());
    gridLayout->addWidget(interfaceLabel, 1, 0, Qt::AlignLeft);
    gridLayout->addWidget(interfaceComboBox, 1, 1, Qt::AlignLeft);

    QLabel *gatewayLabel = new QLabel(QObject::tr("Gateway IP Address (typically your router's address)") + ":", this);
    gatewayLineEdit = new QLineEdit(this);
    gatewayLineEdit->setText(settings_->gatewayIp());
    gridLayout->addWidget(gatewayLabel, 2, 0, Qt::AlignLeft);
    gridLayout->addWidget(gatewayLineEdit, 2, 1, Qt::AlignLeft);

    settingsLayout->addLayout(gridLayout);

    // Server Table
    serverTable = new QTableWidget(0, 4, this);
    serverTable->setHorizontalHeaderLabels({
        QObject::tr("Name"),
        QObject::tr("User"),
        QObject::tr("Servers"),
        QObject::tr("Action")
    });
    serverTable->horizontalHeader()->setStretchLastSection(true);
    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    serverTable->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    settingsLayout->addWidget(serverTable);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton *loadNewConfigButton = new QPushButton("  " + QObject::tr("Select config") + "  ", this);
    connect(loadNewConfigButton, &QPushButton::clicked, this, &SettingsWidget::loadNewConfig);
    buttonLayout->addWidget(loadNewConfigButton);

    saveButton = new QPushButton("  " + QObject::tr("Save") + "  ", this);
    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveModel);
    buttonLayout->addWidget(saveButton);

    settingsLayout->addLayout(buttonLayout);

    tabWidget->addTab(settingsTab, QObject::tr("Settings"));

    // About tab
    aboutTab = new QWidget();
    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
    aboutLayout->setContentsMargins(10, 10, 10, 10);
    aboutLayout->setSpacing(10);

    QLabel *versionLabel = new QLabel(QString(QObject::tr("Application Version") + ": %1").arg(FPTN_VERSION), this);
    versionLabel->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(versionLabel);
    tabWidget->addTab(aboutTab, QObject::tr("About"));

    // Main Layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->addWidget(tabWidget);
    setMinimumSize(600, 400);
    setLayout(mainLayout);

    // Populate server table with data
    const QVector<ServiceConfig> &services = settings_->services();
    serverTable->setRowCount(services.size());
    for (int i = 0; i < services.size(); ++i) {
        const ServiceConfig &service = services[i];
        serverTable->setItem(i, 0, new QTableWidgetItem(service.serviceName));
        serverTable->setItem(i, 1, new QTableWidgetItem(service.username));

        QString serversTextList = "";
        for (const auto& s : service.servers) {
            serversTextList += QString("%1\n").arg(s.name);
        }
        QTableWidgetItem* item = new QTableWidgetItem(serversTextList);
        item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        item->setFlags(item->flags() | Qt::ItemIsEnabled);
        item->setData(Qt::DisplayRole, serversTextList);
        serverTable->setItem(i, 2, item);

        QPushButton *deleteButton = new QPushButton(QObject::tr("Delete"), this);
        connect(deleteButton, &QPushButton::clicked, [this, i]() { removeServer(i); });

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *actionLayout = new QHBoxLayout(buttonContainer);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setAlignment(Qt::AlignCenter);
        actionLayout->addWidget(deleteButton);
        serverTable->setCellWidget(i, 3, buttonContainer);
    }
}

void SettingsWidget::saveModel()
{
    settings_->setNetworkInterface(interfaceComboBox->currentText());
    settings_->setLanguage(languageComboBox->currentText());
    settings_->setGatewayIp(gatewayLineEdit->text());
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
}

void SettingsWidget::loadNewConfig()
{
#if __APPLE__
    // PROBLEM WITH MACOS, NEED TO USE THIS DIALOG
    QString filePath = QFileDialog::getOpenFileName(
        this,
        QObject::tr("Open FPTN Service File"),
        QDir::homePath(),
        "FPTN Files (*.fptn);;All files (*)",
        nullptr,
        QFileDialog::DontUseNativeDialog
    );
#else
    QString filePath = QFileDialog::getOpenFileName(
        this,
        QObject::tr("Open FPTN Service File"),
        QDir::homePath(),
        "FPTN Files (*.fptn);;All files (*)"
    );
#endif
    // Check if a file was selected
    if (!filePath.isEmpty()) {
        try {
            ServiceConfig config = settings_->parseFile(filePath);
            int existsIndex = settings_->getExistServiceIndex(config.serviceName);
            if (existsIndex != -1) {
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(
                    this,
                    QObject::tr("Replace settings"),
                    QObject::tr("Settings file already exists. Do you want to replace it?"),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::Yes
                );
                if (reply == QMessageBox::Yes) {
                    settings_->removeServer(existsIndex);
                    serverTable->removeRow(existsIndex);
                }
            }
            settings_->addService(config);
            settings_->save();

            // visualite table
            int newRow = serverTable->rowCount();
            serverTable->insertRow(newRow);

            serverTable->setItem(newRow, 0, new QTableWidgetItem(config.serviceName));
            serverTable->setItem(newRow, 1, new QTableWidgetItem(config.username));

            QString serversTextList = "";
            for (const auto& s : config.servers) {
                serversTextList += QString("%1\n").arg(s.name);
            }
            QTableWidgetItem* item = new QTableWidgetItem(serversTextList);
            item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            item->setFlags(item->flags() | Qt::ItemIsEnabled);
            item->setData(Qt::DisplayRole, serversTextList);
            serverTable->setItem(newRow, 2, item);

            QPushButton *deleteButton = new QPushButton(QObject::tr("Delete"), this);
            connect(deleteButton, &QPushButton::clicked, [this, newRow]() { removeServer(newRow); });

            QWidget *buttonContainer = new QWidget();
            QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
            buttonLayout->setContentsMargins(0, 0, 0, 0);
            buttonLayout->setAlignment(Qt::AlignCenter);
            buttonLayout->addWidget(deleteButton);
            serverTable->setCellWidget(newRow, 3, buttonContainer);
        } catch(const std::exception &err) {
            QMessageBox::critical(this, QObject::tr("Error!"), err.what());
        }
    }
}

void SettingsWidget::removeServer(int row)
{
    if (row >= 0 && row < serverTable->rowCount()) {
        serverTable->removeRow(row);
        settings_->removeServer(row);
        QMessageBox::information(
            this,
            QObject::tr("Delete Successful"),
            QObject::tr("Server has been successfully deleted.")
        );
    }
}
