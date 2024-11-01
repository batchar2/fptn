#include <filesystem>

#include <QLocale>
#include <QTranslator>
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
    ::FLAGS_alsologtostderr = true;
    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::GLOG_INFO);
    google::SetLogDestination(google::GLOG_INFO, "");
    google::SetLogDestination(google::GLOG_INFO, "logs/fptn.log.txt");
}


inline void setTranslation(QApplication& app, QTranslator& translator)
{
    // debug
    // QLocale::setDefault(QLocale("ru_RU.UTF-8"));

    const QLocale locale;
    const QString localeName = locale.name();
    LOG(INFO) << "LOCALE NAME: " << localeName.toStdString();
    if (localeName.contains('_')) {
        const QString languageCode = locale.name().split('_').first(); // Split on underscore and take the first part
        const QString translationFile = QString("fptn_%1.qm").arg(languageCode);
        if (translator.load(translationFile, ":/translations")) {
            if (app.installTranslator(&translator)) {
                LOG(INFO) << "Successfully loaded language: " << languageCode.toStdString();
            } else {
                LOG(WARNING) << "Failed to install translator for language: " << languageCode.toStdString();
            }
        } else {
            LOG(WARNING) << "Translation file not found: " << translationFile.toStdString();
        }
    } else {
        LOG(WARNING) << "No translation will be loaded.";
    }
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
    // init app
    QApplication::setDesktopSettingsAware(true);
    QApplication app(argc, argv);

    // load translations
    QTranslator translator;
    setTranslation(app, translator);

    // start gui app
    fptn::gui::TrayApp trayApp;

    const int retcode = app.exec();
    google::ShutdownGoogleLogging();
    return retcode;
}

