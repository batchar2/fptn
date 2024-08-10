#include <QApplication>
#include "gui/tray/tray.h"


int main(int argc, char *argv[]) 
{
    if (geteuid() != 0) {
        LOG(ERROR) << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }

    QApplication app(argc, argv);
    fptn::gui::TrayApp trayApp;
    return app.exec();
}

#include "fptn-client-gui.moc"
