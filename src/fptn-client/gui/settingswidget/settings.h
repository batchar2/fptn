#pragma once

#include <QCloseEvent>
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QDialog>
#include <QToolButton>

#include "gui/servermodel/server_model.h"


namespace fptn::gui {



    class SettingsWidget : public QWidget {
    Q_OBJECT

    public:
        explicit SettingsWidget(ServerModel *model, QWidget *parent = nullptr);
    protected:
        void closeEvent(QCloseEvent* event) override {
            this->hide();
            event->ignore();
        }
    private slots:
        void addServer();
        void editServer();
        void deleteServer();
        void saveServer();
        void cancelEditing();
        void onItemDoubleClicked(QTableWidgetItem *item);
        void saveModel();
    private:
        void setupUi();
        void openEditDialog(int row);
        void removeServer(int row);

        ServerModel *model_;
        QTabWidget *tabWidget;
        QWidget *settingsTab;
        QWidget *aboutTab;
        QTableWidget *serverTable;
        QPushButton *versionLabel;
        QPushButton *saveButton; // Save button

        QDialog *editDialog;
        QLineEdit *addressLineEdit;
        QLineEdit *portLineEdit;
        QLineEdit *userLineEdit;
        QLineEdit *passwordLineEdit;
        int editingRow;
    };



    // YES1
//    class SettingsWidget : public QWidget {
//    Q_OBJECT
//
//    public:
//        explicit SettingsWidget(ServerModel *model, QWidget *parent = nullptr);
//
//    private slots:
//        void addServer();
//        void editServer();
//        void deleteServer();
//        void saveServer();
//        void cancelEditing();
//        void onItemDoubleClicked(QTableWidgetItem *item);
//
//    private:
//        void setupUi();
//        void openEditDialog(int row);
//        void removeServer(int row);
//
//        ServerModel *model_;
//        QTabWidget *tabWidget;
//        QWidget *settingsTab;
//        QWidget *aboutTab;
//        QTableWidget *serverTable;
//        QPushButton *versionLabel;
//        QPushButton *saveButton; // Added save button
//
//        QDialog *editDialog;
//        QLineEdit *addressLineEdit;
//        QLineEdit *portLineEdit;
//        QLineEdit *userLineEdit;
//        QLineEdit *passwordLineEdit;
//        int editingRow;
//    };



//
//    class SettingsWidget : public QWidget {
//    Q_OBJECT
//
//    public:
//        explicit SettingsWidget(ServerModel *model, QWidget *parent = nullptr);
//
//    private slots:
//        void addServer();
//        void editServer();
//        void deleteServer();
//        void saveServer();
//        void cancelEditing();
//        void onItemDoubleClicked(QTableWidgetItem *item);
//
//    private:
//        void setupUi();
//        void openEditDialog(int row);
//        void removeServer(int row);
//
//        ServerModel *model_;
//        QTabWidget *tabWidget;
//        QWidget *settingsTab;
//        QWidget *aboutTab;
//        QTableWidget *serverTable;
//        QPushButton *addServerButton;
//        QPushButton *versionLabel;
//
//        QDialog *editDialog;
//        QLineEdit *addressLineEdit;
//        QLineEdit *portLineEdit;
//        QLineEdit *userLineEdit;
//        QLineEdit *passwordLineEdit;
//        int editingRow;
//    };
//













//    class SettingsWidget : public QWidget {
//    Q_OBJECT
//
//    public:
//        explicit SettingsWidget(ServerModel *model, QWidget *parent = nullptr);
//
//    private slots:
//
//        void addServer();
//
//        void editServer();
//
//        void deleteServer();
//
//        void saveServer();
//
//        void cancelEditing();
//
//        void onItemDoubleClicked(QTableWidgetItem *item);
//
//    private:
//        void setupUi();
//
//        void openEditDialog(int row);
//
//        void removeServer(int row);
//
//        ServerModel *model_;
//        QTabWidget *tabWidget;
//        QWidget *settingsTab;
//        QWidget *aboutTab;
//        QTableWidget *serverTable;
//        QPushButton *addServerButton;
//        QPushButton *versionLabel;
//
//        QDialog *editDialog;
//        QLineEdit *addressLineEdit;
//        QLineEdit *portLineEdit;
//        QLineEdit *userLineEdit;
//        QLineEdit *passwordLineEdit;
//        int editingRow;
//    };

}