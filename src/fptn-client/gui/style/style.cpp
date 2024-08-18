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

}