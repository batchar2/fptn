#pragma once

#include <QDialog>
#include <QWidget>
#include <QComboBox>
#include <QToolButton>
#include <QPushButton>
#include <QCloseEvent>
#include <QTableWidget>


#include "gui/settingsmodel/settingsmodel.h"


namespace fptn::gui
{

    class SettingsWidget : public QWidget
    {
    Q_OBJECT
    public:
        explicit SettingsWidget(SettingsModel *model, QWidget *parent = nullptr);

    protected:
        void closeEvent(QCloseEvent *event);
    private slots:
        void saveModel();
        void addServer();
        void editServer();
        void deleteServer();
        void saveServer();
        void cancelEditing();
        void onItemDoubleClicked(QTableWidgetItem *item);
        void removeServer(int row);
    private:
        void setupUi();
        void openEditDialog(int row);
        QString sanitizeString(const QString& input) const noexcept;

        SettingsModel *model_;
        QTabWidget *tabWidget;
        QWidget *settingsTab;
        QWidget *aboutTab;
        QTableWidget *serverTable;
        QComboBox *interfaceComboBox;
        QLineEdit *gatewayLineEdit;
        QPushButton *saveButton;

        QDialog *editDialog;
        QLineEdit *addressLineEdit;
        QLineEdit *portLineEdit;
        QLineEdit *userLineEdit;
        QLineEdit *passwordLineEdit;

        int editingRow;
    };
}