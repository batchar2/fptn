#pragma once

#include <QLabel>
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>


namespace fptn::gui
{
    class TokenDialog final : public QDialog
    {
        Q_OBJECT
    public:
        explicit TokenDialog(QWidget* parent = nullptr);
        const QString& token() const;
    private slots:
        void onOkClicked();
    private:
        QLabel* label_;
        QLineEdit* tokenField_;
        QHBoxLayout* tokenLayout_;

        QPushButton* okButton_;
        QPushButton* cancelButton_;
        QHBoxLayout* buttonLayout_;

        QVBoxLayout* mainLayout_;

        QString token_;
    };
}


