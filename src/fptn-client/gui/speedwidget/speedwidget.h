#pragma once

#include <QStyle>
#include <QLabel>
#include <QWidget>

#include <QVBoxLayout>
#include <QHBoxLayout>

namespace fptn::gui
{
    class SpeedWidget : public QWidget
    {
    public:
        SpeedWidget();
        ~SpeedWidget()=default;
        void updateSpeeds(const QString &uploadSpeed, const QString &downloadSpeed) noexcept;
    private:
        QLabel *uploadSpeedLabel;
        QLabel *downloadSpeedLabel;
    };

}