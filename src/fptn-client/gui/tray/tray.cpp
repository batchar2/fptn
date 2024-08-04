
// #include "tray.h"


// TrayApp::TrayApp(QSystemTrayIcon *trayIcon, SpeedWidget *speedWidget) 
//     : trayIcon(trayIcon), speedWidget(speedWidget), isConnected(false) 
// {  
//     QMenu *menu = new QMenu; 
 
//     // Create actions 
//     QAction *connectAction = new QAction("Connect to", menu); 
//     QAction *disconnectAction = new QAction("Disconnect", menu); 
//     QAction *settingsAction = new QAction("Settings", menu); 
//     QAction *quitAction = new QAction("Quit", menu); 
 
//     // Submenu for server options 
//     QMenu *connectMenu = new QMenu("Connect to", menu); 
//     QAction *server1Action = new QAction("server1", connectMenu); 
//     QAction *server2Action = new QAction("server2", connectMenu); 
 
//     connectMenu->addAction(server1Action); 
//     connectMenu->addAction(server2Action); 
//     connectAction->setMenu(connectMenu); 
 
//     // Connect actions 
//     // connect(server1Action, &QAction::triggered, [this]() { 
//     //     connectedServer = "server1"; 
//     //     speedWidget->setConnectionStatus(true, connectedServer); 
//     //     isConnected = true; 
//     //     updateMenu(); 
//     // }); 
 
//     // connect(server2Action, &QAction::triggered, [this]() { 
//     //     connectedServer = "server2"; 
//     //     speedWidget->setConnectionStatus(true, connectedServer); 
//     //     isConnected = true; 
//     //     updateMenu(); 
//     // }); 
 
//     // connect(disconnectAction, &QAction::triggered, [this]() { 
//     //     if (isConnected) { 
//     //         isConnected = false; 
//     //         speedWidget->setConnectionStatus(false); 
//     //         connectedServer.clear(); 
//     //         updateMenu(); 
//     //     } else { 
//     //         QMessageBox::information(nullptr, "Disconnect", "Not connected to any server."); 
//     //     } 
//     // }); 
 
//     // connect(settingsAction, &QAction::triggered, [this]() { 
//     //     QMessageBox::information(nullptr, "Settings", "Settings dialog (dummy implementation)."); 
//     // }); 
 
//     // connect(quitAction, &QAction::triggered, qApp, &QApplication::quit); 
 
//     // // Add actions to menu 
//     // menu->addAction(connectAction); 
//     // menu->addAction(disconnectAction); 
//     // menu->addAction(settingsAction); 
//     // menu->addAction(quitAction); 
 
//     // // Update the menu initially 
//     // updateMenu(); 
 
//     // trayIcon->setContextMenu(menu); 
//     // trayIcon->show(); 
 
//     // // Simulate speed updates 
//     // QTimer *timer = new QTimer(this); 
//     // connect(timer, &QTimer::timeout, this, &TrayApp::simulateSpeedUpdates); 
//     // timer->start(1000);  // Update every second 
// } 
 
// void TrayApp::onConnectToServer() { 
//     // Placeholder for connection logic 
// } 
 
// void TrayApp::onDisconnect() { 
//     // Placeholder for disconnection logic 
// } 
 
// void TrayApp::onSettings() { 
//     // Placeholder for settings dialog 
// } 
 
// void TrayApp::onQuit() { 
//     qApp->quit(); 
// } 
 
// void TrayApp::updateMenu() { 
//     QMenu *menu = trayIcon->contextMenu(); 
//     menu->clear(); // Clear existing actions 
 
//     if (isConnected) { 
//         menu->addAction(new QAction("Disconnect", menu)); 
//         // menu->addAction(new QWidgetAction(menu)); 
//         // Add speed widget to menu 
//         // QWidgetAction *speedAction = new QWidgetAction(menu); 
//         // speedAction->setDefaultWidget(speedWidget); 
//         // menu->addAction(speedAction); 
//     } else { 
//         QMenu *connectMenu = new QMenu("Connect to", menu); 
//         QAction *server1Action = new QAction("server1", connectMenu); 
//         QAction *server2Action = new QAction("server2", connectMenu); 
//         connectMenu->addAction(server1Action); 
//         connectMenu->addAction(server2Action);

// menu->addMenu(connectMenu); 
//     } 
 
//     menu->addAction(new QAction("Settings", menu)); 
//     menu->addAction(new QAction("Quit", menu)); 
// } 
 
// void TrayApp::simulateSpeedUpdates() { 
//     // if (isConnected) { 
//     //     int upSpeed = qrand() % 100; 
//     //     int downSpeed = qrand() % 100; 
//     //     speedWidget->updateSpeeds(upSpeed, downSpeed); 
//     // } 
// } 