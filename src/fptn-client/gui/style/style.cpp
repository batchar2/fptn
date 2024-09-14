#include "style.h"


namespace fptn::gui
{
QString darkStyleSheet = R"(
QMenu {
    background-color: #333;
    color: #fff;
    border: 1px solid #555;
}
QMenu::item {
    background-color: #333;
    color: #fff;
    padding: 5px 5px;
}
QMenu::item:selected {
    background-color: #555;
    color: #fff;
}
QMenu::icon {
    margin-right: 10px;
}
QAction {
    color: #fff;
}
QWidgetAction {
    padding: 5px;
}
)";

QString whiteStyleSheet = R"(
QMenu {
    background-color: #f0f0f0;
    color: #000;
    border: 1px solid #ccc;
}
QMenu::item {
    background-color: #f0f0f0;
    color: #000;
    padding: 5px 5px;
}
QMenu::item:selected {
    background-color: #e0e0e0;
    color: #000;
}
QMenu::icon {
    margin-right: 10px;
}
QAction {
    color: #000;
}
QWidgetAction {
    padding: 5px;
}
)";


QString ubuntuStyleSheet = R"(
QMenu {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-radius: 8px;
    padding: 0;
}
QMenu::item {
    background-color: #ffffff;
    color: #333333;
    padding: 8px 12px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #e0e0e0;
    color: #333333;
}
QMenu::icon {
    margin-right: 8px;
}
QAction {
    color: #333333;
}
QWidgetAction {
    padding: 8px 12px;
}
QWidget {
    font-family: 'Ubuntu', 'Segoe UI', Tahoma, Verdana, Arial, sans-serif;
    font-size: 11pt;
    color: #333333;
    background-color: #f0f0f0;
}
QPushButton {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    padding: 6px 12px;
}
QPushButton:hover {
    background-color: #e0e0e0;
}
QPushButton:pressed {
    background-color: #d0d0d0;
}
QLineEdit, QTextEdit {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    padding: 4px 8px;
}
QCheckBox, QRadioButton {
    color: #333333;
}
QSlider::groove:horizontal {
    border: 1px solid #d0d0d0;
    height: 8px;
    background: #ffffff;
    border-radius: 4px;
}
QSlider::handle:horizontal {
    background: #333333;
    border: 1px solid #d0d0d0;
    width: 16px;
    border-radius: 4px;
}
QScrollBar:vertical {
    border: 1px solid #d0d0d0;
    background: #ffffff;
    width: 16px;
}
QScrollBar::handle:vertical {
    background: #c0c0c0;
    min-height: 20px;
    border-radius: 8px;
}
QTabBar::tab {
    background: #e0e0e0;
    color: #333333;
    padding: 6px 12px;
    border: 1px solid #d0d0d0;
    border-bottom: 1px solid #ffffff;
    border-radius: 4px 4px 0 0;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-bottom: 1px solid #ffffff;
    border-radius: 4px 4px 0 0;
    font-weight: bold;
}

QTabBar::tab:!selected {
    background: #f0f0f0;
}
QTabWidget::pane {
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    background: #ffffff;
}
QMenu::item:disabled {
    background-color: #ffffff;
    color: #a0a0a0;
}
QAction:disabled {
    color: #a0a0a0;
}
)";



QString windowsStyleSheet = R"(
QMenu {
    background-color: #ffffff;
    color: #000000;
    border: 1px solid #bfbfbf;
    border-radius: 4px;
    padding: 4px 8px;
}
QMenu::item {
    background-color: #ffffff;
    color: #000000;
    padding: 4px 8px;
    border-radius: 3px;
}
QMenu::item:selected {
    background-color: #e0e0e0;
    color: #000000;
}
QMenu::icon {
    margin-right: 8px;
}
QAction {
    color: #000000;
}
QMenu QWidget {
    background-color: #ffffff;
    color: #000000; 
    border: none;
    padding: 4px;
}
QMenu::item:disabled {
    background-color: #ffffff; 
    color: #a0a0a0;
}
QAction:disabled {
    color: #a0a0a0;
}
)";


}
