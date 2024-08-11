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
        Q_OBJECT
    public:
        SpeedWidget(QWidget *parent = nullptr);
    public slots:
        void updateSpeed(std::size_t uploadSpeed, std::size_t downloadSpeed);
    private:
        QLabel *uploadSpeedLabel_;
        QLabel *downloadSpeedLabel_;
    };

}