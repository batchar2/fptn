#pragma once

#include <QLabel>
#include <QDialog>
#include <QWidget>
#include <QCheckBox>
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
        void closeEvent(QCloseEvent* event) override;
        void setupUi();
    private slots:
        void exit();
        void loadNewConfig();
        void removeServer(int row);
        void onLanguageChanged(const QString& newLanguage);
        void onInterfaceChanged(const QString& newLanguage);
        void onAutostartChanged(bool checked);
        void onAutoGatewayChanged(bool checked);
    private:
        SettingsModelPtr settings_;

        QTabWidget* tabWidget_ = nullptr;
        QWidget* settingsTab_ = nullptr;
        QWidget* aboutTab_ = nullptr;
        QTableWidget* serverTable_ = nullptr;

        QLabel* autostartLabel_ = nullptr;
        QCheckBox* autostartCheckBox_ = nullptr;

        QLabel* languageLabel_ = nullptr;
        QComboBox* languageComboBox_ = nullptr;

        QComboBox* interfaceComboBox_ = nullptr;
        QLabel* interfaceLabel_ = nullptr;

        QLineEdit* gatewayLineEdit_ = nullptr;
        QCheckBox* gatewayAutoCheckbox_ = nullptr;
        QLabel* gatewayLabel_ = nullptr;

        QLabel* sniLabel_ = nullptr;
        QLineEdit* sniLineEdit_ = nullptr;

        QPushButton *loadNewTokenButton_ = nullptr;

        QPushButton* exitButton_ = nullptr;

        QLabel* versionLabel_ = nullptr;

        QLabel* projectInfoLabel_ = nullptr;
        QLabel* websiteLinkLabel_ = nullptr;
        QLabel* telegramGroupLabel_ = nullptr;
    };
}