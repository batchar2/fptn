#include <QLabel>
#include <QLineEdit>
#include <QGridLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QMessageBox>
#include <QTableWidgetItem>


#include "settings.h"

using namespace fptn::gui;



SettingsWidget::SettingsWidget(SettingsModel *model, QWidget *parent)
        : QWidget(parent), model_(model), editingRow(-1) {
    setupUi();
}

void SettingsWidget::setupUi() {
    tabWidget = new QTabWidget(this);

    settingsTab = new QWidget();
    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
    settingsLayout->setContentsMargins(5, 5, 5, 5);

    QHBoxLayout *interfaceLayout = new QHBoxLayout();
    QLabel *interfaceLabel = new QLabel("Network Interface:", this);
    interfaceComboBox = new QComboBox(this);

    interfaceComboBox->addItems(model_->getNetworkInterfaces());
    interfaceLayout->addWidget(interfaceLabel);
    interfaceLayout->addWidget(interfaceComboBox);
    settingsLayout->addLayout(interfaceLayout);

    QHBoxLayout *gatewayLayout = new QHBoxLayout();
    QLabel *gatewayLabel = new QLabel("Gateway IP:", this);
    gatewayLineEdit = new QLineEdit(this);
    gatewayLayout->addWidget(gatewayLabel);
    gatewayLayout->addWidget(gatewayLineEdit);
    settingsLayout->addLayout(gatewayLayout);

    serverTable = new QTableWidget(0, 4, this);
    serverTable->setHorizontalHeaderLabels({"Address", "Port", "User", "Action"});
    serverTable->horizontalHeader()->setStretchLastSection(true);
    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);

    connect(serverTable, &QTableWidget::itemDoubleClicked, this, &SettingsWidget::onItemDoubleClicked);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    saveButton = new QPushButton("Save", this);
    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveModel);
    buttonLayout->addWidget(saveButton);

    settingsLayout->addWidget(serverTable);
    settingsLayout->addLayout(buttonLayout);

    tabWidget->addTab(settingsTab, "Settings");

    aboutTab = new QWidget();
    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
    aboutLayout->setContentsMargins(0, 0, 0, 0);

    QPushButton *versionLabel = new QPushButton("App Version: 1.0.0", this);
    versionLabel->setFlat(true);
    aboutLayout->addWidget(versionLabel);

    tabWidget->addTab(aboutTab, "About");

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->addWidget(tabWidget);
    setMinimumSize(500, 300);
    setLayout(mainLayout);

    const QVector<ServerConnectionInformation> &servers = model_->servers();
    serverTable->setRowCount(servers.size() + 1);
    for (int i = 0; i < servers.size(); ++i) {
        const ServerConnectionInformation &server = servers[i];
        serverTable->setItem(i, 0, new QTableWidgetItem(server.address));
        serverTable->setItem(i, 1, new QTableWidgetItem(QString::number(server.port)));
        serverTable->setItem(i, 2, new QTableWidgetItem(server.username));

        QTableWidgetItem *passwordItem = new QTableWidgetItem();
        passwordItem->setData(Qt::UserRole, server.password);
        serverTable->setItem(i, 3, passwordItem);

        QPushButton *deleteButton = new QPushButton(QIcon::fromTheme("edit-delete"), "", this);
        deleteButton->setFixedSize(24, 24);
        connect(deleteButton, &QPushButton::clicked, [this, i]() { removeServer(i); });

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->addWidget(deleteButton);
        serverTable->setCellWidget(i, 3, buttonContainer);
    }

    QPushButton *addServerButton = new QPushButton(QIcon::fromTheme("list-add"), "", this);
    addServerButton->setFixedSize(24, 24);
    connect(addServerButton, &QPushButton::clicked, this, &SettingsWidget::addServer);

    QWidget *addButtonContainer = new QWidget();
    QHBoxLayout *addButtonLayout = new QHBoxLayout(addButtonContainer);
    addButtonLayout->setContentsMargins(0, 0, 0, 0);
    addButtonLayout->setAlignment(Qt::AlignCenter);
    addButtonLayout->addWidget(addServerButton);
    serverTable->setCellWidget(servers.size(), 3, addButtonContainer);

    interfaceComboBox->setCurrentText(model_->networkInterface());
    gatewayLineEdit->setText(model_->gatewayIp());
}

void SettingsWidget::saveModel() {
    model_->setNetworkInterface(interfaceComboBox->currentText());
    model_->setGatewayIp(gatewayLineEdit->text());

    model_->clear();
    for (int row = 0; row < serverTable->rowCount() - 1; ++row) {
        ServerConnectionInformation server;
        server.address = serverTable->item(row, 0)->text();
        server.port = serverTable->item(row, 1)->text().toInt();
        server.username = serverTable->item(row, 2)->text();

        QTableWidgetItem *passwordItem = serverTable->item(row, 3);
        server.password = passwordItem->data(Qt::UserRole).toString();

        model_->addServer(server);
    }
    model_->save();

    QMessageBox::information(this, "Save Successful", "Data has been successfully saved.");
}

void SettingsWidget::addServer() {
    openEditDialog(-1);
}

void SettingsWidget::editServer() {
    openEditDialog(serverTable->currentRow());
}

void SettingsWidget::deleteServer() {
    int row = serverTable->currentRow();
    if (row >= 0) {
        removeServer(row);
    }
}

void SettingsWidget::saveServer() {
    if (editingRow == -1) {
        int newRow = serverTable->rowCount() - 1;
        serverTable->insertRow(newRow);

        serverTable->setItem(newRow, 0, new QTableWidgetItem(addressLineEdit->text()));
        serverTable->setItem(newRow, 1, new QTableWidgetItem(portLineEdit->text()));
        serverTable->setItem(newRow, 2, new QTableWidgetItem(userLineEdit->text()));

        QTableWidgetItem *passwordItem = new QTableWidgetItem();
        passwordItem->setData(Qt::UserRole, passwordLineEdit->text());
        serverTable->setItem(newRow, 3, passwordItem);
    } else {
        serverTable->item(editingRow, 0)->setText(addressLineEdit->text());
        serverTable->item(editingRow, 1)->setText(portLineEdit->text());
        serverTable->item(editingRow, 2)->setText(userLineEdit->text());

        QTableWidgetItem *passwordItem = serverTable->item(editingRow, 3);
        passwordItem->setData(Qt::UserRole, passwordLineEdit->text());
    }

    editDialog->accept();
}

void SettingsWidget::cancelEditing() {
    editDialog->reject();
}

void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item) {
    openEditDialog(item->row());
}

void SettingsWidget::openEditDialog(int row) {
    editDialog = new QDialog(this);
    editDialog->setWindowTitle(row == -1 ? "Add Server" : "Edit Server");

    QGridLayout *gridLayout = new QGridLayout(editDialog);

    gridLayout->addWidget(new QLabel("Address:"), 0, 0);
    addressLineEdit = new QLineEdit();
    gridLayout->addWidget(addressLineEdit, 0, 1);

    gridLayout->addWidget(new QLabel("Port:"), 1, 0);
    portLineEdit = new QLineEdit();
    gridLayout->addWidget(portLineEdit, 1, 1);

    gridLayout->addWidget(new QLabel("User:"), 2, 0);
    userLineEdit = new QLineEdit();
    gridLayout->addWidget(userLineEdit, 2, 1);

    gridLayout->addWidget(new QLabel("Password:"), 3, 0);
    passwordLineEdit = new QLineEdit();
    passwordLineEdit->setEchoMode(QLineEdit::Password);
    gridLayout->addWidget(passwordLineEdit, 3, 1);

    if (row != -1) {
        addressLineEdit->setText(serverTable->item(row, 0)->text());
        portLineEdit->setText(serverTable->item(row, 1)->text());
        userLineEdit->setText(serverTable->item(row, 2)->text());

        QTableWidgetItem *passwordItem = serverTable->item(row, 3);
        passwordLineEdit->setText(passwordItem->data(Qt::UserRole).toString());
    }

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &SettingsWidget::saveServer);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &SettingsWidget::cancelEditing);

    gridLayout->addWidget(buttonBox, 4, 0, 1, 2);

    editDialog->setLayout(gridLayout);
    editDialog->exec();
}

void SettingsWidget::removeServer(int row) {
    serverTable->removeRow(row);
}
