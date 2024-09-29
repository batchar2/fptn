#include <QLabel>
#include <QLineEdit>
#include <QFileDialog>
#include <QGridLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QMessageBox>
#include <QFormLayout>
#include <QTableWidgetItem>


#include "settings.h"

using namespace fptn::gui;


SettingsWidget::SettingsWidget(SettingsModel *model, QWidget *parent)
        : QWidget(parent), model_(model)
{
    setupUi();
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

    QLabel *interfaceLabel = new QLabel("Network Interface:                                 ", this);
    interfaceComboBox = new QComboBox(this);
    interfaceComboBox->addItems(model_->getNetworkInterfaces());
    interfaceComboBox->setCurrentText(model_->networkInterface());
    gridLayout->addWidget(interfaceLabel, 0, 0, Qt::AlignLeft);
    gridLayout->addWidget(interfaceComboBox, 0, 1, Qt::AlignLeft);

    QLabel *gatewayLabel = new QLabel("Gateway IP Address (typically your router's address):", this);
    gatewayLineEdit = new QLineEdit(this);
    gatewayLineEdit->setText(model_->gatewayIp());
    gridLayout->addWidget(gatewayLabel, 1, 0, Qt::AlignLeft);
    gridLayout->addWidget(gatewayLineEdit, 1, 1, Qt::AlignLeft);

    settingsLayout->addLayout(gridLayout);

    // Server Table
    serverTable = new QTableWidget(0, 4, this);
    serverTable->setHorizontalHeaderLabels({"Name", "User", "Servers", "Action"});
    serverTable->horizontalHeader()->setStretchLastSection(true);
    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    serverTable->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    settingsLayout->addWidget(serverTable);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton *loadNewConfigButton = new QPushButton("Load config", this);
    connect(loadNewConfigButton, &QPushButton::clicked, this, &SettingsWidget::loadNewConfig);
    buttonLayout->addWidget(loadNewConfigButton);

    saveButton = new QPushButton("Save", this);
    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveModel);
    buttonLayout->addWidget(saveButton);

    settingsLayout->addLayout(buttonLayout);

    tabWidget->addTab(settingsTab, "Settings");

    // About tab
    aboutTab = new QWidget();
    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
    aboutLayout->setContentsMargins(10, 10, 10, 10);
    aboutLayout->setSpacing(10);

    QLabel *versionLabel = new QLabel(QString("App Version: %1").arg(FPTN_VERSION), this);
    versionLabel->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(versionLabel);
    tabWidget->addTab(aboutTab, "About");

    // Main Layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->addWidget(tabWidget);
    setMinimumSize(600, 400);
    setLayout(mainLayout);


    // Populate server table with data
    const QVector<ServiceConfig> &services = model_->services();
    serverTable->setRowCount(services.size());
    for (int i = 0; i < services.size(); ++i) {
        const ServiceConfig &service = services[i];
        serverTable->setItem(i, 0, new QTableWidgetItem(service.serviceName));
        serverTable->setItem(i, 1, new QTableWidgetItem(service.username));

        QString serversTextList = "";
        for (const auto& s : service.servers) {
            serversTextList += QString("%1").arg(s.name);
        }
        QTableWidgetItem* item = new QTableWidgetItem(serversTextList);
        item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        item->setFlags(item->flags() | Qt::ItemIsEnabled);
        item->setData(Qt::DisplayRole, serversTextList);
        serverTable->setItem(i, 2, item);

        QPushButton *deleteButton = new QPushButton("Delete", this);
        connect(deleteButton, &QPushButton::clicked, [this, i]() { removeServer(i); });

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->addWidget(deleteButton);
        serverTable->setCellWidget(i, 3, buttonContainer);
    }
}

void SettingsWidget::saveModel()
{
    model_->setNetworkInterface(interfaceComboBox->currentText());
    model_->setGatewayIp(gatewayLineEdit->text());
    if (model_->save() ) {
        QMessageBox::information(this, "Save Successful", "Data has been successfully saved.");
        this->hide();  // Hide the widget instead of closing the application
    } else {
        QMessageBox::critical(this, "Save Failed", "An error occurred while saving the data.");
    }
}

void SettingsWidget::closeEvent(QCloseEvent *event)
{
    this->hide();
    event->ignore();
}

void SettingsWidget::loadNewConfig()
{
#if __APPLE__
    // PROBLEM WITH MACOS, NEED TO USE THIS DIALOG
    QString filePath = QFileDialog::getOpenFileName(
        this,
        "Open FPTN Service File",
        QDir::homePath(),
        "FPTN Files (*.fptn);;All files (*)",
        nullptr,
        QFileDialog::DontUseNativeDialog
    );
#elif
    QString filePath = QFileDialog::getOpenFileName(
        this,
        "Open FPTN Service File",
        QDir::homePath(),
        "FPTN Files (*.fptn);;All files (*)",
    );
#endif
    // Check if a file was selected
    if (!filePath.isEmpty()) {
        try {
            ServiceConfig config = model_->parseFile(filePath);
            int existsIndex = model_->getExistServiceIndex(config.serviceName);
            if (existsIndex != -1) {
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "Replace Model",
                    "A model already exists. Do you want to replace it?",
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::Yes
                );
                if (reply == QMessageBox::Yes) {
                    model_->removeServer(existsIndex);
                    serverTable->removeRow(existsIndex);
                } else {
                    QMessageBox::information(this, "Cancelled", "The server was not replaced.");
                }
            }
            model_->addService(config);
            model_->save();

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

            QPushButton *deleteButton = new QPushButton("Delete", this);
            connect(deleteButton, &QPushButton::clicked, [this, newRow]() { removeServer(newRow); });

            QWidget *buttonContainer = new QWidget();
            QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
            buttonLayout->setContentsMargins(0, 0, 0, 0);
            buttonLayout->setAlignment(Qt::AlignCenter);
            buttonLayout->addWidget(deleteButton);
            serverTable->setCellWidget(newRow, 3, buttonContainer);

        } catch(const std::exception &err) {
            QMessageBox::critical(this, "Error!", err.what());
        }
    }
}

void SettingsWidget::removeServer(int row)
{
    if (row >= 0 && row < serverTable->rowCount()) {
        serverTable->removeRow(row);
        model_->removeServer(row);
        QMessageBox::information(this, "Delete Successful", "Server has been successfully deleted.");
    }
}
