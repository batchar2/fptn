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


#if defined(__linux__) || defined(__APPLE__)
static void signalHandler(int)
{
    qApp->quit();
}
#elif defined(_WIN32)
static BOOL WINAPI signalHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        qApp->quit();
        return TRUE;
    }
    return FALSE;
}
#else
    #error "Unsupported platform"
#endif


int main(int argc, char *argv[]) 
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    // Initialize logger
    if (fptn::logger::init("fptn-client-gui")) {
        spdlog::info("Application started successfully.");
    } else {
        std::cerr << "Logger initialization failed. Exiting application." << std::endl;
        return EXIT_FAILURE;
    }

    // Setup signal handler
#if defined(__linux__) || defined(__APPLE__)
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
#elif defined(_WIN32)
    SetConsoleCtrlHandler(signalHandler, TRUE);
#endif

    // Initialize GUI app
    QApplication::setDesktopSettingsAware(true);
    QApplication::setQuitOnLastWindowClosed(false);
    QApplication app(argc, argv);
    auto settings = std::make_shared<fptn::gui::SettingsModel>(
        QMap<QString, QString>{
            {"en", "English"},
            {"ru", "Русский"}
        }
    );

    // Start GUI app
    fptn::gui::TrayApp trayApp(settings);

    const int code = app.exec();
    spdlog::shutdown();

    return code;
}
