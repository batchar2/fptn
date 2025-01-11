#include "tokendialog.h"

#include <base64.hpp>

#include <common/utils/utils.h>


using namespace fptn::gui;


TokenDialog::TokenDialog(QWidget* parent)
    : QDialog(parent)
{
    label_ = new QLabel(QObject::tr("Copy your access token") + ": ", this);
    tokenField_ = new QLineEdit(this);
    tokenField_->setPlaceholderText(QObject::tr("Token") + "...");
    tokenField_->setMinimumWidth(350);

    tokenLayout_ = new QHBoxLayout();
    tokenLayout_->addWidget(label_);
    tokenLayout_->addWidget(tokenField_);

    okButton_ = new QPushButton(QObject::tr("OK"), this);
    cancelButton_ = new QPushButton(QObject::tr("Cancel"), this);

    // Layout for buttons
    buttonLayout_ = new QHBoxLayout();
    buttonLayout_->addStretch();
    buttonLayout_->addWidget(cancelButton_);
    buttonLayout_->addWidget(okButton_);

    // Main layout
    mainLayout_ = new QVBoxLayout(this);
    mainLayout_->addLayout(tokenLayout_);
    mainLayout_->addLayout(buttonLayout_);

    setLayout(mainLayout_);

    connect(cancelButton_, &QPushButton::clicked, this, &QDialog::reject);
    connect(okButton_, &QPushButton::clicked, this, &TokenDialog::onOkClicked);

    // show on top
    setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
    setModal(true);
    show();
    activateWindow();
    raise();
}

const QString& TokenDialog::token() const
{
    return token_;
}

void TokenDialog::onOkClicked()
{
    try {
        const QString enteredToken = tokenField_->text().trimmed();
        const std::string cleanToken = fptn::common::utils::removeSubstring(
            enteredToken.toStdString(), {"fptn://", "fptn:", " ", "\n", "\r", "\t"}
        );
        const std::string decodedToken = base64::from_base64(cleanToken + "==");
        const QString t = QString::fromStdString(decodedToken);
        if (t.isEmpty()) {
            QMessageBox::warning(
                this,
                QObject::tr("Validation Error"),
                QObject::tr("Token cannot be empty") + "!"
            );
        } else {
            token_ = t;
            accept();
        }
    } catch (const std::runtime_error& err) {
        QMessageBox::warning(
            this,
            QObject::tr("Wrong token"),
            QObject::tr("Wrong token") + ": "  + err.what()
        );
    }
}
