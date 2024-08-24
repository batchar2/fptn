#include <iostream>
#include <QApplication>
#include <QStyleFactory>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include "gui/tray/tray.h"


int main(int argc, char *argv[]) 
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    QApplication app(argc, argv);
    fptn::gui::TrayApp trayApp;
    return app.exec();
}

