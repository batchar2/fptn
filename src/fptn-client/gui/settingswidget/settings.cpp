#include <QLabel>
#include <QLineEdit>
#include <QGridLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QMessageBox>
#include <QFormLayout>
#include <QTableWidgetItem>


#include "settings.h"

using namespace fptn::gui;


SettingsWidget::SettingsWidget(SettingsModel *model, QWidget *parent)
        : QWidget(parent), model_(model), editingRow(-1) {
    setupUi();
}


void SettingsWidget::setupUi() {
    tabWidget = new QTabWidget(this);

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
    gridLayout->addWidget(interfaceLabel, 0, 0, Qt::AlignLeft);
    gridLayout->addWidget(interfaceComboBox, 0, 1, Qt::AlignLeft);

    QLabel *gatewayLabel = new QLabel("Gateway IP Address (typically your router's address):", this);
    gatewayLineEdit = new QLineEdit(this);
    gridLayout->addWidget(gatewayLabel, 1, 0, Qt::AlignLeft);
    gridLayout->addWidget(gatewayLineEdit, 1, 1, Qt::AlignLeft);

    settingsLayout->addLayout(gridLayout);

    // Server Table
    serverTable = new QTableWidget(0, 4, this);
    serverTable->setHorizontalHeaderLabels({"Address", "Port", "User", "Action"});
    serverTable->horizontalHeader()->setStretchLastSection(true);
    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    connect(serverTable, &QTableWidget::itemDoubleClicked, this, &SettingsWidget::onItemDoubleClicked);

    settingsLayout->addWidget(serverTable);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    QPushButton *addServerButton = new QPushButton("Add Server", this);
    connect(addServerButton, &QPushButton::clicked, this, &SettingsWidget::addServer);
    buttonLayout->addWidget(addServerButton);

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
    const QVector<ServerConnectionInformation> &servers = model_->servers();
    serverTable->setRowCount(servers.size());
    for (int i = 0; i < servers.size(); ++i) {
        const ServerConnectionInformation &server = servers[i];
        serverTable->setItem(i, 0, new QTableWidgetItem(server.address));
        serverTable->setItem(i, 1, new QTableWidgetItem(QString::number(server.port)));
        serverTable->setItem(i, 2, new QTableWidgetItem(server.username));

        QTableWidgetItem *passwordItem = new QTableWidgetItem();
        passwordItem->setData(Qt::UserRole, server.password);
        serverTable->setItem(i, 3, passwordItem);

        QPushButton *deleteButton = new QPushButton("Delete", this);
        connect(deleteButton, &QPushButton::clicked, [this, i]() { removeServer(i); });

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->addWidget(deleteButton);
        serverTable->setCellWidget(i, 3, buttonContainer);
    }

    interfaceComboBox->setCurrentText(model_->networkInterface());
    gatewayLineEdit->setText(model_->gatewayIp());
}

void SettingsWidget::saveModel() {
    model_->setNetworkInterface(interfaceComboBox->currentText());
    model_->setGatewayIp(gatewayLineEdit->text());

    model_->clear();
    for (int row = 0; row < serverTable->rowCount(); ++row) {
        ServerConnectionInformation server;
        server.address = serverTable->item(row, 0)->text();
        server.port = serverTable->item(row, 1)->text().toInt();
        server.username = serverTable->item(row, 2)->text();

        QTableWidgetItem *passwordItem = serverTable->item(row, 3);
        server.password = passwordItem->data(Qt::UserRole).toString();

        model_->addServer(server);
    }
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


void SettingsWidget::addServer()
{
    openEditDialog(-1);
}

void SettingsWidget::editServer()
{
    openEditDialog(serverTable->currentRow());
}

void SettingsWidget::deleteServer()
{
    int row = serverTable->currentRow();
    if (row >= 0) {
        removeServer(row);
    }
}

void SettingsWidget::saveServer()
{
    if (editingRow == -1) {
        int newRow = serverTable->rowCount();
        serverTable->insertRow(newRow);

        serverTable->setItem(newRow, 0, new QTableWidgetItem(sanitizeString(addressLineEdit->text())));
        serverTable->setItem(newRow, 1, new QTableWidgetItem(sanitizeString(portLineEdit->text())));
        serverTable->setItem(newRow, 2, new QTableWidgetItem(sanitizeString(userLineEdit->text())));

        QTableWidgetItem *passwordItem = new QTableWidgetItem();
        passwordItem->setData(Qt::UserRole, sanitizeString(passwordLineEdit->text()));
        serverTable->setItem(newRow, 3, passwordItem);

        QPushButton *deleteButton = new QPushButton("Delete", this);
        connect(deleteButton, &QPushButton::clicked, [this, newRow]() { removeServer(newRow); });

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->addWidget(deleteButton);
        serverTable->setCellWidget(newRow, 3, buttonContainer);
    } else {
        serverTable->item(editingRow, 0)->setText(sanitizeString(addressLineEdit->text()));
        serverTable->item(editingRow, 1)->setText(sanitizeString(portLineEdit->text()));
        serverTable->item(editingRow, 2)->setText(sanitizeString(userLineEdit->text()));

        QTableWidgetItem *passwordItem = serverTable->item(editingRow, 3);
        passwordItem->setData(Qt::UserRole, sanitizeString(passwordLineEdit->text()));
    }
    editDialog->accept();
}

void SettingsWidget::cancelEditing()
{
    editDialog->reject();
}

void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item)
{
    openEditDialog(item->row());
}

void SettingsWidget::openEditDialog(int row)
{
    editDialog = new QDialog(this);
    editDialog->setFixedWidth(320);
    editDialog->setWindowTitle(row == -1 ? "Add Server" : "Edit Server");

    QGridLayout *gridLayout = new QGridLayout(editDialog);

    gridLayout->addWidget(new QLabel("Address:"), 0, 0);
    addressLineEdit = new QLineEdit();
    addressLineEdit->setEnabled(true);
    addressLineEdit->setContextMenuPolicy(Qt::ActionsContextMenu);
    gridLayout->addWidget(addressLineEdit, 0, 1);

    gridLayout->addWidget(new QLabel("Port:"), 1, 0);
    portLineEdit = new QLineEdit();
    portLineEdit->setEnabled(true);
    portLineEdit->setContextMenuPolicy(Qt::ActionsContextMenu);
    gridLayout->addWidget(portLineEdit, 1, 1);

    gridLayout->addWidget(new QLabel("User:"), 2, 0);
    userLineEdit = new QLineEdit();
    userLineEdit->setEnabled(true);
    userLineEdit->setContextMenuPolicy(Qt::ActionsContextMenu);
    gridLayout->addWidget(userLineEdit, 2, 1);

    gridLayout->addWidget(new QLabel("Password:"), 3, 0);
    passwordLineEdit = new QLineEdit();
    passwordLineEdit->setEnabled(true);
    passwordLineEdit->setContextMenuPolicy(Qt::ActionsContextMenu);
    gridLayout->addWidget(passwordLineEdit, 3, 1);

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &SettingsWidget::saveServer);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &SettingsWidget::cancelEditing);
    gridLayout->addWidget(buttonBox, 4, 0, 1, 2);

    if (row >= 0) {
        addressLineEdit->setText(serverTable->item(row, 0)->text());
        portLineEdit->setText(serverTable->item(row, 1)->text());
        userLineEdit->setText(serverTable->item(row, 2)->text());

        QTableWidgetItem *passwordItem = serverTable->item(row, 3);
        passwordLineEdit->setText(passwordItem->data(Qt::UserRole).toString());

        editingRow = row;
    } else {
        editingRow = -1;
    }

    editDialog->exec();
}

void SettingsWidget::removeServer(int row)
{
    if (row >= 0 && row < serverTable->rowCount()) {
        serverTable->removeRow(row);
        QMessageBox::information(this, "Delete Successful", "Server has been successfully deleted.");
    }
}

QString SettingsWidget::sanitizeString(const QString& input) const noexcept
{
    QString sanitized = input;
    sanitized.remove("http://");
    sanitized.remove("https://");
    sanitized.remove(' ');
    sanitized.remove('/');
    sanitized.remove('\\');
    return sanitized;
}