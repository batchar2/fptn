#include <filesystem>

#include <QApplication>
#include <QStyleFactory>

#include <glog/logging.h>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include "gui/tray/tray.h"


inline void initLogger(char *argv[])
{
    const std::filesystem::path log_dir = "./logs";
    if (!std::filesystem::exists(log_dir)) {
        std::filesystem::create_directory(log_dir);
    }
    ::FLAGS_log_dir = "./logs/";
    ::FLAGS_logbuflevel = -1;
    ::FLAGS_alsologtostderr = 1;
    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::GLOG_INFO);
    google::SetLogDestination(google::GLOG_INFO, "");
    google::SetLogDestination(google::GLOG_INFO, "logs/fptn.log.txt");
}


int main(int argc, char *argv[]) 
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    initLogger(argv);

    QApplication::setDesktopSettingsAware(true);
    QApplication app(argc, argv);

    fptn::gui::TrayApp trayApp;

    int retcode = app.exec();
    google::ShutdownGoogleLogging();
    return retcode;
}

