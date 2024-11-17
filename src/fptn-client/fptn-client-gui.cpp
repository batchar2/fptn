#include <memory>
#include <filesystem>

#include <QMap>
#include <QLocale>
#include <QTranslator>
#include <QApplication>
#include <QStyleFactory>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <common/logger/logger.h>

#include "gui/tray/tray.h"


int main(int argc, char *argv[]) 
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    if (fptn::logger::init("fptn-client-gui")) {
        spdlog::info("Application started successfully.");
    } else {
        std::cerr << "Logger initialization failed. Exiting application." << std::endl;
        return EXIT_FAILURE;
    }

    // init gui app
    QApplication::setDesktopSettingsAware(true);
    QApplication::setQuitOnLastWindowClosed(false);
    QApplication app(argc, argv);
    auto settings = std::make_shared<fptn::gui::SettingsModel>(
        QMap<QString, QString>{
            {"en", "English"},
            {"ru", "Русский"}
        }
    );
    fptn::gui::TrayApp trayApp(settings);

    // start gui app
    const int code = app.exec();
    spdlog::shutdown();
    return code;
}
