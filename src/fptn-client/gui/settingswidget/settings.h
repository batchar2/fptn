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
    class SettingsWidget : public QDialog //QWidget
    {
    Q_OBJECT
    public:
        explicit SettingsWidget(const SettingsModelPtr& settings, QWidget *parent = nullptr);
    protected:
        void setupUi();
    private slots:
        void saveModel();
        void loadNewConfig();
        void removeServer(int row);
    private:
        SettingsModelPtr settings_;

        QTabWidget *tabWidget;
        QWidget *settingsTab;
        QWidget *aboutTab;
        QTableWidget *serverTable;

        QComboBox *languageComboBox;

        QComboBox *interfaceComboBox;
        QLineEdit *gatewayLineEdit;
        QPushButton *saveButton;
    };
}