#include "translations.h"

#include <QTranslator>
#include <QApplication>

#include <common/logger/logger.h>

static QTranslator translator;


bool fptn::gui::setTranslation(const QString &languageCode)
{
    const QString translationFile = QString("fptn_%1.qm").arg(languageCode);
    qApp->removeTranslator(&translator);
    if (translator.load(translationFile, ":/translations")) {
        if (qApp->installTranslator(&translator)) {
            SPDLOG_INFO("Successfully loaded language: {}", languageCode.toStdString());
            return true;
        } else {
            spdlog::warn("Failed to install translator for language: {}", languageCode.toStdString());
        }
    } else {
        spdlog::warn("Translation file not found: {}", translationFile.toStdString());
    }
    return false;
}
