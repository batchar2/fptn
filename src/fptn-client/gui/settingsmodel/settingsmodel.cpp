// server_model.cpp
#include "settingsmodel.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStandardPaths>

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDebug>
#include <QNetworkInterface>

#include <boost/asio.hpp>
//#include <QNetworkInterface>

using namespace fptn::gui;


SettingsModel::SettingsModel(QObject *parent) : QObject(parent) {
    load();
}

QString SettingsModel::getFilePath() const {
    QString directory = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(directory);
    if (!dir.exists()) {
        dir.mkpath(directory);
    }
    return directory + "/settings.json";
}

void SettingsModel::load() {
    QString filePath = getFilePath();
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open file for reading:" << filePath;
        return;
    }
    qDebug() << filePath;

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument document = QJsonDocument::fromJson(data);
    QJsonObject jsonObject = document.object();

    // Load servers
    servers_.clear();
    QJsonArray serversArray = jsonObject["servers"].toArray();
    for (const QJsonValue &value : serversArray) {
        QJsonObject obj = value.toObject();
        ServerConnectionInformation server;
        server.address = obj["address"].toString();
        server.port = obj["port"].toInt();
        server.username = obj["username"].toString();
        server.password = obj["password"].toString();
        servers_.append(server);
    }

    // Load network settings
    networkInterface_ = jsonObject["networkInterface"].toString();
    gatewayIp_ = jsonObject["gatewayIp"].toString();
}

bool SettingsModel::save()
{
    QString filePath = getFilePath();
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        qWarning() << "Failed to open file for writing:" << filePath;
        return false;
    }

    QJsonObject jsonObject;
    // Save servers
    QJsonArray serversArray;
    for (const ServerConnectionInformation &server : servers_) {
        QJsonObject obj;
        obj["address"] = server.address;
        obj["port"] = server.port;
        obj["username"] = server.username;
        obj["password"] = server.password;
        serversArray.append(obj);
    }
    jsonObject["servers"] = serversArray;

    // Save network settings
    jsonObject["networkInterface"] = networkInterface_;
    jsonObject["gatewayIp"] = gatewayIp_;

    QJsonDocument document(jsonObject);
    auto len = file.write(document.toJson());
    file.close();
    qDebug() << len;

    emit dataChanged();
    return len > 0;
}

QString SettingsModel::networkInterface() const {
    return networkInterface_;
}

void SettingsModel::setNetworkInterface(const QString &interface) {
    networkInterface_ = interface;
}

QString SettingsModel::gatewayIp() const {
    return gatewayIp_;
}

void SettingsModel::setGatewayIp(const QString &ip) {
    gatewayIp_ = ip;
}

const QVector<ServerConnectionInformation>& SettingsModel::servers() const {
    return servers_;
}

void SettingsModel::addServer(const ServerConnectionInformation &server) {
    servers_.append(server);
}

void SettingsModel::removeServer(int index) {
    if (index >= 0 && index < servers_.size()) {
        servers_.removeAt(index);
    }
}

void SettingsModel::clear() {
    servers_.clear();
}

QVector<QString> SettingsModel::getNetworkInterfaces() const
{
    QVector<QString> interfaces;
    QList<QNetworkInterface> networkInterfaces = QNetworkInterface::allInterfaces();

    for (const QNetworkInterface& networkInterface : networkInterfaces) {
        if (networkInterface.flags().testFlag(QNetworkInterface::IsUp) &&
            !networkInterface.flags().testFlag(QNetworkInterface::IsLoopBack) &&
            !networkInterface.flags().testFlag(QNetworkInterface::IsPointToPoint) &&
            !networkInterface.hardwareAddress().isEmpty()) {
            QList<QNetworkAddressEntry> entries = networkInterface.addressEntries();
            if (!entries.isEmpty()) {
                interfaces.append(networkInterface.humanReadableName());
            }
        }
    }
    return interfaces;
}

