#include <QApplication>

#include "gui/tray/tray.h"


int main(int argc, char *argv[]) 
{
    QApplication app(argc, argv);
    fptn::gui::TrayApp trayApp;
    return app.exec();
}

#include "fptn-client-gui.moc"

