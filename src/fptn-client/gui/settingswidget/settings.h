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
        void setupUi();
        void closeEvent(QCloseEvent *event);
    private slots:
        void saveModel();
        void loadNewConfig();
        void removeServer(int row);
    private:
        SettingsModel *model_;
        QTabWidget *tabWidget;
        QWidget *settingsTab;
        QWidget *aboutTab;
        QTableWidget *serverTable;
        QComboBox *interfaceComboBox;
        QLineEdit *gatewayLineEdit;
        QPushButton *saveButton;
    };
}