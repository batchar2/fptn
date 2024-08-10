#include <QVBoxLayout>
#include <QPushButton>
#include <QMessageBox>
#include <QTableWidgetItem>
#include <QGridLayout>
#include <QLineEdit>
#include <QLabel>
#include <QToolButton>

#include <QLabel>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QPushButton>
#include <QMessageBox>
#include <QTableWidgetItem>

#include "settings.h"

using namespace fptn::gui;


SettingsWidget::SettingsWidget(ServerModel *model, QWidget *parent)
        : QWidget(parent), model_(model), editingRow(-1) {
    setupUi();
}

void SettingsWidget::setupUi() {
    tabWidget = new QTabWidget(this);

    settingsTab = new QWidget();
    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
    settingsLayout->setContentsMargins(5, 5, 5, 5);

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

    const QVector<Server> &servers = model_->servers();
    serverTable->setRowCount(servers.size() + 1);
    for (int i = 0; i < servers.size(); ++i) {
        const Server &server = servers[i];
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
}

void SettingsWidget::addServer() {
    editingRow = -1;
    openEditDialog(-1);
}

void SettingsWidget::editServer() {
    int row = serverTable->currentRow();
    if (row >= 0) {
        editingRow = row;
        openEditDialog(row);
    }
}

void SettingsWidget::deleteServer() {
    int row = serverTable->currentRow();
    if (row >= 0) {
        removeServer(row);
    }
}

void SettingsWidget::saveServer() {
    Server server;
    server.address = addressLineEdit->text();
    server.port = portLineEdit->text().toInt();
    server.username = userLineEdit->text();
    server.password = passwordLineEdit->text();

    if (editingRow == -1) {
        int row = serverTable->rowCount() - 1;
        serverTable->insertRow(row);
        serverTable->setItem(row, 0, new QTableWidgetItem(server.address));
        serverTable->setItem(row, 1, new QTableWidgetItem(QString::number(server.port)));
        serverTable->setItem(row, 2, new QTableWidgetItem(server.username));

        QTableWidgetItem *passwordItem = new QTableWidgetItem();
        passwordItem->setData(Qt::UserRole, server.password);
        serverTable->setItem(row, 3, passwordItem);

        QWidget *buttonContainer = new QWidget();
        QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonLayout->setAlignment(Qt::AlignCenter);

        QToolButton *deleteButton = new QToolButton();
        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
        deleteButton->setIconSize(QSize(16, 16));
        connect(deleteButton, &QToolButton::clicked, [this, row]() { removeServer(row); });
        buttonLayout->addWidget(deleteButton);

        serverTable->setCellWidget(row, 3, buttonContainer);
    } else {
        serverTable->setItem(editingRow, 0, new QTableWidgetItem(server.address));
        serverTable->setItem(editingRow, 1, new QTableWidgetItem(QString::number(server.port)));
        serverTable->setItem(editingRow, 2, new QTableWidgetItem(server.username));

        QTableWidgetItem *passwordItem = serverTable->item(editingRow, 3);
        passwordItem->setData(Qt::UserRole, server.password);
    }
    editDialog->accept();
}

void SettingsWidget::saveModel() {
    model_->clear();
    for (int row = 0; row < serverTable->rowCount() - 1; ++row) {
        Server server;
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

void SettingsWidget::cancelEditing() {
    editDialog->reject();
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
    QMessageBox confirmBox;
    confirmBox.setWindowTitle("Confirm Deletion");
    confirmBox.setText("Are you sure you want to delete this server?");
    confirmBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    confirmBox.setDefaultButton(QMessageBox::No);

    int ret = confirmBox.exec();
    if (ret == QMessageBox::Yes) {
        serverTable->removeRow(row);
    }
}

void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item) {
    int row = item->row();
    if (row >= 0) {
        openEditDialog(row);
    }
}




//
//
//SettingsWidget::SettingsWidget(ServerModel *model, QWidget *parent)
//        : QWidget(parent), model_(model), editingRow(-1) {
//    setupUi();
//}
//
//void SettingsWidget::setupUi() {
//    tabWidget = new QTabWidget(this);
//
//    settingsTab = new QWidget();
//    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
//    settingsLayout->setContentsMargins(5, 5, 5, 5);
//
//    serverTable = new QTableWidget(0, 4, this);
//    serverTable->setHorizontalHeaderLabels({"Address", "Port", "User", "Action"});
//    serverTable->horizontalHeader()->setStretchLastSection(true);
//    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
//    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
////    serverTable->setColumnWidth(0, 150);
////    serverTable->setColumnWidth(1, 100);
////    serverTable->setColumnWidth(2, 150);
////    serverTable->setColumnWidth(3, 80);
//
//    connect(serverTable, &QTableWidget::itemDoubleClicked, this, &SettingsWidget::onItemDoubleClicked);
//
//    // Initial button layout
//    QHBoxLayout *buttonLayout = new QHBoxLayout();
//    buttonLayout->addStretch();
//
//    saveButton = new QPushButton("Save", this); // Initialize save button
//    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveModel);
//    buttonLayout->addWidget(saveButton);
//
//    settingsLayout->addWidget(serverTable);
//    settingsLayout->addLayout(buttonLayout);
//
//    tabWidget->addTab(settingsTab, "Settings");
//
//    aboutTab = new QWidget();
//    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
//    aboutLayout->setContentsMargins(0, 0, 0, 0);
//
//    versionLabel = new QPushButton("App Version: 1.0.0", this);
//    versionLabel->setFlat(true);
//    aboutLayout->addWidget(versionLabel);
//
//    tabWidget->addTab(aboutTab, "About");
//
//    QVBoxLayout *mainLayout = new QVBoxLayout(this);
//    mainLayout->setContentsMargins(0, 0, 0, 0);
//    mainLayout->addWidget(tabWidget);
//    setMinimumSize(500, 300);
//    setLayout(mainLayout);
//
//    // Load servers from model
//    const QVector<Server> &servers = model_->servers();
//    serverTable->setRowCount(servers.size() + 1); // Add one extra row for the button
//    for (int i = 0; i < servers.size(); ++i) {
//        const Server &server = servers[i];
//        serverTable->setItem(i, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(i, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(i, 2, new QTableWidgetItem(server.username));
//
//        {
//            QPushButton *deleteButton = new QPushButton(QIcon::fromTheme("edit-delete"), "", this);
//            deleteButton->setFixedSize(16, 16);
//            connect(deleteButton, &QPushButton::clicked, [this, i]() { removeServer(i); });
//            QWidget *buttonContainer = new QWidget();
//            QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
//            buttonLayout->setContentsMargins(0, 0, 0, 0);
//            buttonLayout->setAlignment(Qt::AlignCenter);
//            buttonLayout->addWidget(deleteButton);
//            serverTable->setCellWidget(i, 3, buttonContainer);
//        }
//    }
//
//    // Create a button and add it to the last row of the table
//    QPushButton *addServerButton = new QPushButton(QIcon::fromTheme("list-add"), "", this);
//    addServerButton->setFixedSize(16, 16);
//    connect(addServerButton, &QPushButton::clicked, this, &SettingsWidget::addServer);
//
//    // Add the button to the last row
//    QWidget *addButtonContainer = new QWidget();
//    QHBoxLayout *addButtonLayout = new QHBoxLayout(addButtonContainer);
//    addButtonLayout->setContentsMargins(0, 0, 0, 0);
//    addButtonLayout->setAlignment(Qt::AlignCenter);
//    addButtonLayout->addWidget(addServerButton);
//    serverTable->setCellWidget(servers.size(), 3, addButtonContainer);
//}
//
//void SettingsWidget::addServer() {
//    editingRow = -1;
//    openEditDialog(-1);
//}
//
//void SettingsWidget::editServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        editingRow = row;
//        openEditDialog(row);
//    }
//}
//
//void SettingsWidget::deleteServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        removeServer(row);
//    }
//}
//
//void SettingsWidget::saveServer() {
//    Server server;
//    server.address = addressLineEdit->text();
//    server.port = portLineEdit->text().toInt();
//    server.username = userLineEdit->text();
//    server.password = passwordLineEdit->text();
//
//    if (editingRow == -1) {
//        model_->addServer(server);
//        //model_->save();
//        int row = serverTable->rowCount() - 1; // Use the last row for the new server
//        serverTable->insertRow(row);
//        serverTable->setItem(row, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(row, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(row, 2, new QTableWidgetItem(server.username));
//
//        QWidget *buttonContainer = new QWidget();
//        QHBoxLayout *buttonLayout = new QHBoxLayout(buttonContainer);
//        buttonLayout->setContentsMargins(0, 0, 0, 0);
//        buttonLayout->setAlignment(Qt::AlignCenter);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, row]() { removeServer(row); });
//        buttonLayout->addWidget(deleteButton);
//
//        serverTable->setCellWidget(row, 3, buttonContainer);
//    } else {
//        model_->removeServer(editingRow);
//        //model_->addServer(server);
//        serverTable->setItem(editingRow, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(editingRow, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(editingRow, 2, new QTableWidgetItem(server.username));
//    }
//    editDialog->accept();
//}
//
//void SettingsWidget::saveModel()
//{
//    model_->clear();
//    for (int row = 0; row < serverTable->rowCount() - 1; ++row) {
//        Server server;
//        server.address = serverTable->item(row, 0)->text();
//        server.port = serverTable->item(row, 1)->text().toInt();
//        server.username = serverTable->item(row, 2)->text();
////        server
//        model_->addServer(server);
//    }
//    model_->save();
//}
//
//void SettingsWidget::cancelEditing() {
//    editDialog->reject();
//}
//
//void SettingsWidget::openEditDialog(int row) {
//    editDialog = new QDialog(this);
//    editDialog->setWindowTitle(row == -1 ? "Add Server" : "Edit Server");
//
//    QGridLayout *gridLayout = new QGridLayout(editDialog);
//
//    gridLayout->addWidget(new QLabel("Address:"), 0, 0);
//    addressLineEdit = new QLineEdit();
//    gridLayout->addWidget(addressLineEdit, 0, 1);
//
//    gridLayout->addWidget(new QLabel("Port:"), 1, 0);
//    portLineEdit = new QLineEdit();
//    gridLayout->addWidget(portLineEdit, 1, 1);
//
//    gridLayout->addWidget(new QLabel("User:"), 2, 0);
//    userLineEdit = new QLineEdit();
//    gridLayout->addWidget(userLineEdit, 2, 1);
//
//    gridLayout->addWidget(new QLabel("Password:"), 3, 0);
//    passwordLineEdit = new QLineEdit();
//    gridLayout->addWidget(passwordLineEdit, 3, 1);
//
//    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
//    connect(buttonBox, &QDialogButtonBox::accepted, this, &SettingsWidget::saveServer);
//    connect(buttonBox, &QDialogButtonBox::rejected, this, &SettingsWidget::cancelEditing);
//    gridLayout->addWidget(buttonBox, 4, 0, 1, 2);
//
//    if (row != -1) {
//        addressLineEdit->setText(serverTable->item(row, 0)->text());
//        portLineEdit->setText(serverTable->item(row, 1)->text());
//        userLineEdit->setText(serverTable->item(row, 2)->text());
//        passwordLineEdit->setText(""); // or fetch from somewhere if needed
//        editingRow = row;
//    }
//
//    editDialog->exec();
//}
//
//void SettingsWidget::removeServer(int row) {
////    model_->removeServer(row);
//    serverTable->removeRow(row);
//}
//
//void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item) {
//    int row = item->row();
//    editServer();
//}
//
//
//
//















 // YES1
//
//
//SettingsWidget::SettingsWidget(ServerModel *model, QWidget *parent)
//        : QWidget(parent), model_(model), editingRow(-1) {
//    setupUi();
//}
//
//void SettingsWidget::setupUi() {
//    tabWidget = new QTabWidget(this);
//
//    settingsTab = new QWidget();
//    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
//    settingsLayout->setContentsMargins(5, 5, 5, 5);
//
//    serverTable = new QTableWidget(0, 4, this);
//    serverTable->setHorizontalHeaderLabels({"Address", "Port", "User", "Action"});
//    serverTable->horizontalHeader()->setStretchLastSection(true);
//    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
//    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
//    serverTable->setColumnWidth(0, 150);
//    serverTable->setColumnWidth(1, 100);
//    serverTable->setColumnWidth(2, 150);
//    serverTable->setColumnWidth(3, 80);
//
//    connect(serverTable, &QTableWidget::itemDoubleClicked, this, &SettingsWidget::onItemDoubleClicked);
//
//    // Initial button layout
//    QHBoxLayout *buttonLayout = new QHBoxLayout();
//    buttonLayout->addStretch();
//
//    settingsLayout->addWidget(serverTable);
//    settingsLayout->addLayout(buttonLayout);
//
//    saveButton = new QPushButton("Save", this); // Initialize save button
//    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveServer);
//    settingsLayout->addWidget(saveButton);
//
//    tabWidget->addTab(settingsTab, "Settings");
//
//    aboutTab = new QWidget();
//    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
//    aboutLayout->setContentsMargins(0, 0, 0, 0);
//
//    versionLabel = new QPushButton("App Version: 1.0.0", this);
//    versionLabel->setFlat(true);
//    aboutLayout->addWidget(versionLabel);
//
//    tabWidget->addTab(aboutTab, "About");
//
//    QVBoxLayout *mainLayout = new QVBoxLayout(this);
//    mainLayout->setContentsMargins(0, 0, 0, 0);
//    mainLayout->addWidget(tabWidget);
//    setMinimumSize(500, 300);
//    setLayout(mainLayout);
//
//    // Load servers from model
//    const QVector<Server> &servers = model_->servers();
//    serverTable->setRowCount(servers.size() + 1); // Add one extra row for the button
//    for (int i = 0; i < servers.size(); ++i) {
//        const Server &server = servers[i];
//        serverTable->setItem(i, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(i, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(i, 2, new QTableWidgetItem(server.username));
//
//        QToolButton *editButton = new QToolButton();
//        editButton->setIcon(QIcon::fromTheme("document-edit"));
//        editButton->setIconSize(QSize(16, 16));
//        connect(editButton, &QToolButton::clicked, [this, i]() { editServer(); });
//        serverTable->setCellWidget(i, 3, editButton);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, i]() { removeServer(i); });
//        serverTable->setCellWidget(i, 3, deleteButton);
//    }
//
//    // Create a button and add it to the last row of the table
//    QPushButton *addServerButton = new QPushButton(QIcon::fromTheme("list-add"), "", this);
//    addServerButton->setFixedSize(40, 40);
//    connect(addServerButton, &QPushButton::clicked, this, &SettingsWidget::addServer);
//
//    // Add the button to the last row
//    serverTable->setCellWidget(servers.size(), 3, addServerButton);
//}
//
//void SettingsWidget::addServer() {
//    editingRow = -1;
//    openEditDialog(-1);
//}
//
//void SettingsWidget::editServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        editingRow = row;
//        openEditDialog(row);
//    }
//}
//
//void SettingsWidget::deleteServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        removeServer(row);
//    }
//}
//
//void SettingsWidget::saveServer() {
//    Server server;
//    server.address = addressLineEdit->text();
//    server.port = portLineEdit->text().toInt();
//    server.username = userLineEdit->text();
//    server.password = passwordLineEdit->text();
//
//    if (editingRow == -1) {
//        model_->addServer(server);
//        model_->save();
//        int row = serverTable->rowCount() - 1; // Use the last row for the new server
//        serverTable->insertRow(row);
//        serverTable->setItem(row, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(row, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(row, 2, new QTableWidgetItem(server.username));
//
//        QToolButton *editButton = new QToolButton();
//        editButton->setIcon(QIcon::fromTheme("document-edit"));
//        editButton->setIconSize(QSize(16, 16));
//        connect(editButton, &QToolButton::clicked, [this, row]() { editServer(); });
//        serverTable->setCellWidget(row, 3, editButton);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, row]() { removeServer(row); });
//        serverTable->setCellWidget(row, 3, deleteButton);
//    } else {
//        model_->removeServer(editingRow);
//        model_->addServer(server);
//        serverTable->setItem(editingRow, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(editingRow, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(editingRow, 2, new QTableWidgetItem(server.username));
//    }
//    editDialog->accept();
//}
//
//void SettingsWidget::cancelEditing() {
//    editDialog->reject();
//}
//
//void SettingsWidget::openEditDialog(int row) {
//    editDialog = new QDialog(this);
//    editDialog->setWindowTitle(row == -1 ? "Add Server" : "Edit Server");
//    editDialog->resize(300, 200);
//
//    QGridLayout *gridLayout = new QGridLayout(editDialog);
//    gridLayout->setContentsMargins(10, 10, 10, 10);
//    gridLayout->setSpacing(10);
//
//    addressLineEdit = new QLineEdit(editDialog);
//    portLineEdit = new QLineEdit(editDialog);
//    userLineEdit = new QLineEdit(editDialog);
//    passwordLineEdit = new QLineEdit(editDialog);
//    passwordLineEdit->setEchoMode(QLineEdit::Password);
//
//    if (row >= 0) {
//        addressLineEdit->setText(serverTable->item(row, 0)->text());
//        portLineEdit->setText(serverTable->item(row, 1)->text());
//        userLineEdit->setText(serverTable->item(row, 2)->text());
//    }
//
//    gridLayout->addWidget(new QLabel("Address:", editDialog), 0, 0);
//    gridLayout->addWidget(addressLineEdit, 0, 1);
//    gridLayout->addWidget(new QLabel("Port:", editDialog), 1, 0);
//    gridLayout->addWidget(portLineEdit, 1, 1);
//    gridLayout->addWidget(new QLabel("User:", editDialog), 2, 0);
//    gridLayout->addWidget(userLineEdit, 2, 1);
//    gridLayout->addWidget(new QLabel("Password:", editDialog), 3, 0);
//    gridLayout->addWidget(passwordLineEdit, 3, 1);
//
//    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, editDialog);
//    connect(buttonBox, &QDialogButtonBox::accepted, this, &SettingsWidget::saveServer);
//    connect(buttonBox, &QDialogButtonBox::rejected, this, &SettingsWidget::cancelEditing);
//    gridLayout->addWidget(buttonBox, 4, 0, 1, 2);
//
//    editDialog->exec();
//}
//
//void SettingsWidget::removeServer(int row) {
//    if (row >= 0 && row < serverTable->rowCount() - 1) {
//        model_->removeServer(row);
//        serverTable->removeRow(row);
//    }
//}
//
//void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item) {
//    int row = item->row();
//    if (row >= 0) {
//        openEditDialog(row);
//    }
//}
//
//
//
//
//
//
//
//
//





//
//
//SettingsWidget::SettingsWidget(ServerModel *model, QWidget *parent)
//        : QWidget(parent), model_(model), editingRow(-1) {
//    setupUi();
//}
//
//void SettingsWidget::setupUi() {
//    tabWidget = new QTabWidget(this);
//
//    settingsTab = new QWidget();
//    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
//    settingsLayout->setContentsMargins(5, 5, 5, 5);
//
//    serverTable = new QTableWidget(0, 4, this);
//    serverTable->setHorizontalHeaderLabels({"Address", "Port", "User", "Action"});
//    serverTable->horizontalHeader()->setStretchLastSection(true);
//    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
//    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
//    serverTable->setColumnWidth(0, 150);
//    serverTable->setColumnWidth(1, 100);
//    serverTable->setColumnWidth(2, 150);
//    serverTable->setColumnWidth(3, 80);
//
//    connect(serverTable, &QTableWidget::itemDoubleClicked, this, &SettingsWidget::onItemDoubleClicked);
//
//    addServerButton = new QPushButton(QIcon::fromTheme("list-add"), "", this);
//    addServerButton->setFixedSize(40, 40);
//    connect(addServerButton, &QPushButton::clicked, this, &SettingsWidget::addServer);
//
//    QHBoxLayout *buttonLayout = new QHBoxLayout();
//    buttonLayout->addWidget(addServerButton);
//    buttonLayout->addStretch();
//
//    settingsLayout->addWidget(serverTable);
//    settingsLayout->addLayout(buttonLayout);
//
//    tabWidget->addTab(settingsTab, "Settings");
//
//    aboutTab = new QWidget();
//    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
//    aboutLayout->setContentsMargins(0, 0, 0, 0);
//
//    versionLabel = new QPushButton("App Version: 1.0.0", this);
//    versionLabel->setFlat(true);
//    aboutLayout->addWidget(versionLabel);
//
//    tabWidget->addTab(aboutTab, "About");
//
//    QVBoxLayout *mainLayout = new QVBoxLayout(this);
//    mainLayout->setContentsMargins(0, 0, 0, 0);
//    mainLayout->addWidget(tabWidget);
//    setMinimumSize(500, 300);
//    setLayout(mainLayout);
//
//    // Load servers from model
//    const QVector<Server> &servers = model_->servers();
//    serverTable->setRowCount(servers.size());
//    for (int i = 0; i < servers.size(); ++i) {
//        const Server &server = servers[i];
//        serverTable->setItem(i, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(i, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(i, 2, new QTableWidgetItem(server.username));
//
//        QToolButton *editButton = new QToolButton();
//        editButton->setIcon(QIcon::fromTheme("document-edit"));
//        editButton->setIconSize(QSize(16, 16));
//        connect(editButton, &QToolButton::clicked, [this, i]() { editServer(); });
//        serverTable->setCellWidget(i, 3, editButton);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, i]() { removeServer(i); });
//        serverTable->setCellWidget(i, 3, deleteButton);
//    }
//}
//
//void SettingsWidget::addServer() {
//    editingRow = -1;
//    openEditDialog(-1);
//}
//
//void SettingsWidget::editServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        editingRow = row;
//        openEditDialog(row);
//    }
//}
//
//void SettingsWidget::deleteServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        removeServer(row);
//    }
//}
//
//void SettingsWidget::saveServer() {
//    Server server;
//    server.address = addressLineEdit->text();
//    server.port = portLineEdit->text().toInt();
//    server.username = userLineEdit->text();
//    server.password = passwordLineEdit->text();
//
//    if (editingRow == -1) {
//        model_->addServer(server);
//        model_->save();
//        int row = serverTable->rowCount();
//        serverTable->insertRow(row);
//        serverTable->setItem(row, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(row, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(row, 2, new QTableWidgetItem(server.username));
//
//        QToolButton *editButton = new QToolButton();
//        editButton->setIcon(QIcon::fromTheme("document-edit"));
//        editButton->setIconSize(QSize(16, 16));
//        connect(editButton, &QToolButton::clicked, [this, row]() { editServer(); });
//        serverTable->setCellWidget(row, 3, editButton);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, row]() { removeServer(row); });
//        serverTable->setCellWidget(row, 3, deleteButton);
//    } else {
//        model_->removeServer(editingRow);
//        model_->addServer(server);
//        serverTable->setItem(editingRow, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(editingRow, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(editingRow, 2, new QTableWidgetItem(server.username));
//    }
//    editDialog->accept();
//}
//
//void SettingsWidget::cancelEditing() {
//    editDialog->reject();
//}
//
//void SettingsWidget::openEditDialog(int row) {
//    editDialog = new QDialog(this);
//    editDialog->setWindowTitle(row == -1 ? "Add Server" : "Edit Server");
//    editDialog->resize(300, 200);
//
//    QGridLayout *gridLayout = new QGridLayout(editDialog);
//    gridLayout->setContentsMargins(10, 10, 10, 10);
//    gridLayout->setSpacing(10);
//
//    addressLineEdit = new QLineEdit(editDialog);
//    portLineEdit = new QLineEdit(editDialog);
//    userLineEdit = new QLineEdit(editDialog);
//    passwordLineEdit = new QLineEdit(editDialog);
//    passwordLineEdit->setEchoMode(QLineEdit::Password);
//
//    if (row >= 0) {
//        addressLineEdit->setText(serverTable->item(row, 0)->text());
//        portLineEdit->setText(serverTable->item(row, 1)->text());
//        userLineEdit->setText(serverTable->item(row, 2)->text());
//    }
//
//    gridLayout->addWidget(new QLabel("Address:", editDialog), 0, 0);
//    gridLayout->addWidget(addressLineEdit, 0, 1);
//    gridLayout->addWidget(new QLabel("Port:", editDialog), 1, 0);
//    gridLayout->addWidget(portLineEdit, 1, 1);
//    gridLayout->addWidget(new QLabel("User:", editDialog), 2, 0);
//    gridLayout->addWidget(userLineEdit, 2, 1);
//    gridLayout->addWidget(new QLabel("Password:", editDialog), 3, 0);
//    gridLayout->addWidget(passwordLineEdit, 3, 1);
//
//    QHBoxLayout *buttonLayout = new QHBoxLayout();
//    QPushButton *saveButton = new QPushButton("Save", editDialog);
//    QPushButton *cancelButton = new QPushButton("Cancel", editDialog);
//
//    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveServer);
//    connect(cancelButton, &QPushButton::clicked, this, &SettingsWidget::cancelEditing);
//
//    buttonLayout->addWidget(saveButton);
//    buttonLayout->addWidget(cancelButton);
//
//    gridLayout->addLayout(buttonLayout, 4, 1);
//
//    editDialog->exec();
//}
//
//void SettingsWidget::removeServer(int row) {
//    if (QMessageBox::question(this, "Remove Server", "Are you sure you want to remove this server?") == QMessageBox::Yes) {
//        model_->removeServer(row);
//        model_->save();
//        serverTable->removeRow(row);
//    }
//}
//
//void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item) {
//    int row = item->row();
//    if (row >= 0) {
//        openEditDialog(row);
//    }
//}


















//
//SettingsWidget::SettingsWidget(ServerModel *model, QWidget *parent)
//        : QWidget(parent), model_(model), editingRow(-1) {
//    setupUi();
//}
//
//void SettingsWidget::setupUi() {
//    tabWidget = new QTabWidget(this);
//
//    settingsTab = new QWidget();
//    QVBoxLayout *settingsLayout = new QVBoxLayout(settingsTab);
//    settingsLayout->setContentsMargins(5, 5, 5, 5);
//
//    serverTable = new QTableWidget(0, 4, this);
//    serverTable->setHorizontalHeaderLabels({"Address", "Port", "User", "Action"});
//    serverTable->horizontalHeader()->setStretchLastSection(true);
//    serverTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    serverTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
//    serverTable->setSelectionBehavior(QAbstractItemView::SelectRows);
//    serverTable->setColumnWidth(0, 150);
//    serverTable->setColumnWidth(1, 100);
//    serverTable->setColumnWidth(2, 150);
//    serverTable->setColumnWidth(3, 80);
//
//    connect(serverTable, &QTableWidget::itemDoubleClicked, this, &SettingsWidget::onItemDoubleClicked);
//
//    addServerButton = new QPushButton(QIcon::fromTheme("list-add"), "Add Server", this);
//    addServerButton->setFixedSize(150, 40);
//    connect(addServerButton, &QPushButton::clicked, this, &SettingsWidget::addServer);
//
//    QHBoxLayout *buttonLayout = new QHBoxLayout();
//    buttonLayout->addWidget(addServerButton);
//    buttonLayout->addStretch();
//
//    settingsLayout->addWidget(serverTable);
//    settingsLayout->addLayout(buttonLayout);
//
//    tabWidget->addTab(settingsTab, "Settings");
//
//    aboutTab = new QWidget();
//    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
//    aboutLayout->setContentsMargins(0, 0, 0, 0);
//
//    versionLabel = new QPushButton("App Version: 1.0.0", this);
//    versionLabel->setFlat(true);
//    aboutLayout->addWidget(versionLabel);
//
//    tabWidget->addTab(aboutTab, "About");
//
//    QVBoxLayout *mainLayout = new QVBoxLayout(this);
//    mainLayout->setContentsMargins(0, 0, 0, 0);
//    mainLayout->addWidget(tabWidget);
//    setMinimumSize(500, 300);
//    setLayout(mainLayout);
//
//    // Load servers from model
//    const QVector<Server> &servers = model_->servers();
//    serverTable->setRowCount(servers.size());
//    for (int i = 0; i < servers.size(); ++i) {
//        const Server &server = servers[i];
//        serverTable->setItem(i, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(i, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(i, 2, new QTableWidgetItem(server.username));
//
//        QToolButton *editButton = new QToolButton();
//        editButton->setIcon(QIcon::fromTheme("document-edit"));
//        editButton->setIconSize(QSize(16, 16));
//        connect(editButton, &QToolButton::clicked, [this, i]() { editServer(); });
//        serverTable->setCellWidget(i, 3, editButton);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, i]() { removeServer(i); });
//        serverTable->setCellWidget(i, 3, deleteButton);
//    }
//}
//
//void SettingsWidget::addServer() {
//    editingRow = -1;
//    openEditDialog(-1);
//}
//
//void SettingsWidget::editServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        editingRow = row;
//        openEditDialog(row);
//    }
//}
//
//void SettingsWidget::deleteServer() {
//    int row = serverTable->currentRow();
//    if (row >= 0) {
//        removeServer(row);
//    }
//}
//
//void SettingsWidget::saveServer() {
//    Server server;
//    server.address = addressLineEdit->text();
//    server.port = portLineEdit->text().toInt();
//    server.username = userLineEdit->text();
//    server.password = passwordLineEdit->text();
//
//    if (editingRow == -1) {
//        model_->addServer(server);
//        model_->save();
//        int row = serverTable->rowCount();
//        serverTable->insertRow(row);
//        serverTable->setItem(row, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(row, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(row, 2, new QTableWidgetItem(server.username));
//
//        QToolButton *editButton = new QToolButton();
//        editButton->setIcon(QIcon::fromTheme("document-edit"));
//        editButton->setIconSize(QSize(16, 16));
//        connect(editButton, &QToolButton::clicked, [this, row]() { editServer(); });
//        serverTable->setCellWidget(row, 3, editButton);
//
//        QToolButton *deleteButton = new QToolButton();
//        deleteButton->setIcon(QIcon::fromTheme("edit-delete"));
//        deleteButton->setIconSize(QSize(16, 16));
//        connect(deleteButton, &QToolButton::clicked, [this, row]() { removeServer(row); });
//        serverTable->setCellWidget(row, 3, deleteButton);
//    } else {
//        model_->removeServer(editingRow);
//        model_->addServer(server);
//        serverTable->setItem(editingRow, 0, new QTableWidgetItem(server.address));
//        serverTable->setItem(editingRow, 1, new QTableWidgetItem(QString::number(server.port)));
//        serverTable->setItem(editingRow, 2, new QTableWidgetItem(server.username));
//    }
//    editDialog->accept();
//}
//
//void SettingsWidget::cancelEditing() {
//    editDialog->reject();
//}
//
//void SettingsWidget::openEditDialog(int row) {
//    editDialog = new QDialog(this);
//    editDialog->setWindowTitle(row == -1 ? "Add Server" : "Edit Server");
//    editDialog->resize(300, 200);
//
//    QGridLayout *gridLayout = new QGridLayout(editDialog);
//    gridLayout->setContentsMargins(10, 10, 10, 10);
//    gridLayout->setSpacing(10);
//
//    addressLineEdit = new QLineEdit(editDialog);
//    portLineEdit = new QLineEdit(editDialog);
//    userLineEdit = new QLineEdit(editDialog);
//    passwordLineEdit = new QLineEdit(editDialog);
//    passwordLineEdit->setEchoMode(QLineEdit::Password);
//
//    if (row >= 0) {
//        addressLineEdit->setText(serverTable->item(row, 0)->text());
//        portLineEdit->setText(serverTable->item(row, 1)->text());
//        userLineEdit->setText(serverTable->item(row, 2)->text());
//    }
//
//    gridLayout->addWidget(new QLabel("Address:", editDialog), 0, 0, Qt::AlignRight);
//    gridLayout->addWidget(addressLineEdit, 0, 1);
//    gridLayout->addWidget(new QLabel("Port:", editDialog), 1, 0, Qt::AlignRight);
//    gridLayout->addWidget(portLineEdit, 1, 1);
//    gridLayout->addWidget(new QLabel("User:", editDialog), 2, 0, Qt::AlignRight);
//    gridLayout->addWidget(userLineEdit, 2, 1);
//    gridLayout->addWidget(new QLabel("Password:", editDialog), 3, 0, Qt::AlignRight);
//    gridLayout->addWidget(passwordLineEdit, 3, 1);
//
//    QPushButton *saveButton = new QPushButton("Save", editDialog);
//    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::saveServer);
//    QPushButton *cancelButton = new QPushButton("Cancel", editDialog);
//    connect(cancelButton, &QPushButton::clicked, this, &SettingsWidget::cancelEditing);
//
//    QHBoxLayout *buttonLayout = new QHBoxLayout();
//    buttonLayout->addWidget(saveButton);
//    buttonLayout->addWidget(cancelButton);
//    gridLayout->addLayout(buttonLayout, 4, 0, 1, 2);
//
//    editDialog->exec();
//}
//
//void SettingsWidget::removeServer(int row) {
//    model_->removeServer(row);
//    serverTable->removeRow(row);
//}
//
//void SettingsWidget::onItemDoubleClicked(QTableWidgetItem *item) {
//    if (item->column() == 3) { // Action column
//        editServer();
//    }
//}
