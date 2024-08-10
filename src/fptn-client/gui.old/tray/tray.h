#pragma once

#include <string>
#include <iostream>


#include <QApplication>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QMessageBox>
#include <QTimer>
#include <QIcon>
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidgetAction>
#include <QStyle>


#include <QApplication>
#include <QSystemTrayIcon>
// #include <QSvgRenderer>
// #include <QSvgRenderer>
#include <QPixmap>
#include <QIcon>
#include <QPainter>
#include <QFile>
#include <QByteArray>

#include <QMenu>
#include <QSettings>
#include <QDirIterator>
#include <QApplication>
#include <QSystemTrayIcon>


// #include <data/volume.h>
// #include "gui/speedwidget/speedwidget.h"


namespace fptn::gui
{
    // using start_callback = std::function<void()>;
    // using stop_callback = std::function<void()>;

    class TrayApp : public QObject 
    {
        Q_OBJECT
    public:
        TrayApp(
            // const std::shared_ptr<fptn::data::volume>& download,
            // const std::shared_ptr<fptn::data::volume>& upload,
            // start_callback start,
            // stop_callback stop
        ) 
            //:
            // downloadVolume(download),
            // uploadVolume(upload),
            // startCallback(start),
            // stopCallback(stop),
            // connected(false)
        {
            // QPixmap iconPixmap(":/resources/icons/active.ico");
            trayIcon = new QSystemTrayIcon();
            trayIcon->setIcon(QIcon(inactiveIcon.c_str()));

           
            trayMenu = new QMenu();
            connectMenu = new QMenu("Connect to");
            server1Action = connectMenu->addAction("Server 1");
            server2Action = connectMenu->addAction("Server 2");
            trayMenu->addMenu(connectMenu);
            disconnectAction = trayMenu->addAction("Disconnect");
            disconnectAction->setVisible(connected);

            // speedWidget = new fptn::gui::SpeedWidget();
            // speedWidgetAction = new QWidgetAction(trayMenu);
            // speedWidgetAction->setDefaultWidget(speedWidget);
            // speedWidgetAction->setVisible(connected);
            // trayMenu->addAction(speedWidgetAction);

            settingsAction = trayMenu->addAction("Settings");
            quitAction = trayMenu->addAction("Quit", qApp, &QApplication::quit);

            trayIcon->setContextMenu(trayMenu);
            trayIcon->show();

            connect(server1Action, &QAction::triggered, this, &TrayApp::connectToServer);
            connect(server2Action, &QAction::triggered, this, &TrayApp::connectToServer);
            connect(disconnectAction, &QAction::triggered, this, &TrayApp::disconnect);
            connect(settingsAction, &QAction::triggered, this, &TrayApp::showSettings);
            connect(&timer, &QTimer::timeout, this, &TrayApp::updateSpeed);
            timer.start(1000);
        }

        void updateSpeeds(const QString &uploadSpeed, const QString &downloadSpeed) {
            // speedWidget->updateSpeeds(uploadSpeed, downloadSpeed);
        }

    private slots:
        void connectToServer() 
        {
            connected = true;
            updateTrayMenu();
            // startCallback();
        }

        void disconnect() 
        {
            connected = false;
            // stopCallback();
            updateTrayMenu();
        }

        void showSettings() 
        {
            QMessageBox::information(nullptr, "Settings", "Settings dialog");
        }
        
        void updateSpeed() {
            if (connected) {
                // updateSpeeds(formatSpeed(uploadVolume->result()), formatSpeed(downloadVolume->result()));
            } 
            // else {
            //     speedWidgetAction->setVisible(false);
            // }
        }
    private:
        QString formatSpeed(double bytesPerSecond) 
        {
            if (bytesPerSecond == 0) {
                return "0.0 B/s";
            } else if (bytesPerSecond < 1024) {
                return QString::number(bytesPerSecond, 'f', 2) + " B/s";
            } else if (bytesPerSecond < 1048576) { // 1024 * 1024
                return QString::number(bytesPerSecond / 1024, 'f', 2) + " KB/s";
            } else if (bytesPerSecond < 1073741824) { // 1024 * 1024 * 1024
                return QString::number(bytesPerSecond / 1048576, 'f', 2) + " MB/s";
            } 
            return QString::number(bytesPerSecond / 1073741824, 'f', 2) + " GB/s";
        }
    private:
        void updateTrayMenu() 
        {
            if (connected) {
                trayIcon->setIcon(QIcon(activeIcon.c_str()));
                connectMenu->menuAction()->setVisible(false);
                disconnectAction->setVisible(true);
                // speedWidgetAction->setVisible(true);
            } else {
                trayIcon->setIcon(QIcon(inactiveIcon.c_str()));
                connectMenu->menuAction()->setVisible(true);
                disconnectAction->setVisible(false);
                // speedWidgetAction->setVisible(false);
            }
        }
    private:
        const std::string activeIcon="/Users/stanislav/Apps/My/fptn/code/client/resources/icons/active.ico";
        const std::string inactiveIcon="/Users/stanislav/Apps/My/fptn/code/client/resources/icons/incactive.ico";
    private:
        // std::shared_ptr<fptn::data::volume> downloadVolume;
        // std::shared_ptr<fptn::data::volume> uploadVolume;

        // start_callback startCallback;
        // stop_callback stopCallback;

        QSystemTrayIcon *trayIcon;
        QMenu *trayMenu;
    private:
        QMenu *connectMenu;
        QAction *server1Action;
        QAction *server2Action;
        QAction *disconnectAction;
        QAction *settingsAction;
        QAction *quitAction;
        // fptn::gui::SpeedWidget *speedWidget;
        // QWidgetAction *speedWidgetAction;
        QTimer timer;
        bool connected;
    };
}
