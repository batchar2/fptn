#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStandardPaths>

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QNetworkInterface>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include "system/iptables.h"

#include "settingsmodel.h"


using namespace fptn::gui;


SettingsModel::SettingsModel(const QMap<QString, QString>& languages, const QString& defaultLanguage, QObject *parent)
    :
        QObject(parent),
        languages_(languages),
        defaultLanguage_(defaultLanguage),
        selectedLanguage_(defaultLanguage),
        clientAutostart_(false)
{
    load();
}

QString SettingsModel::getFilePath() const
{
    QString directory = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(directory);
    if (!dir.exists()) {
        dir.mkpath(directory);
    }
    return directory + "/fptn-settings.json";
}

void SettingsModel::load()
{
    // Load servers
    services_.clear();

    QString filePath = getFilePath();
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        spdlog::warn("Failed to open file for reading: {}", filePath.toStdString());
        return;
    }
    spdlog::info("Settings: {}", filePath.toStdString());

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument document = QJsonDocument::fromJson(data);
    QJsonObject serviceObj = document.object();

    if (serviceObj.contains("services")) {
        QJsonArray servicesArray = serviceObj["services"].toArray();
        for (const QJsonValue& serviceValue : servicesArray) {
            QJsonObject jsonServiceObj = serviceValue.toObject();
            ServiceConfig service;

            service.serviceName = jsonServiceObj["service_name"].toString();
            service.username = jsonServiceObj["username"].toString();
            service.password = jsonServiceObj["password"].toString();

            QJsonArray serversArray = jsonServiceObj["servers"].toArray();
            for (const QJsonValue& serverValue : serversArray) {
                QJsonObject serverObj = serverValue.toObject();
                ServerConfig server;
                server.name = serverObj["name"].toString();
                server.host = serverObj["host"].toString();
                server.port = serverObj["port"].toInt();
                server.isUsing = serverObj["is_using"].toBool();
                service.servers.push_back(server);
            }
            services_.push_back(service);
        }
    }
    // Load network settings
    if (serviceObj.contains("network_interface")) {
        networkInterface_ = serviceObj["network_interface"].toString();
    }
    if (networkInterface_.isEmpty()) {
        networkInterface_ = "auto";
    }

    if (serviceObj.contains("language")) {
        selectedLanguage_ = serviceObj["language"].toString();
    }
    if (serviceObj.contains("autostart")) {
        clientAutostart_ = serviceObj["autostart"].toInt();
    }

    if (serviceObj.contains("gateway_ip")) {
        gatewayIp_ = serviceObj["gateway_ip"].toString();
    }
    if (gatewayIp_.isEmpty()) {
        gatewayIp_ = "auto";
    }

    if (serviceObj.contains("sni")) {
        sni_ = serviceObj["sni"].toString();
    }
    if (sni_.isEmpty()) {
        sni_ = FPTN_DEFAULT_SNI;
    }
}

const QString SettingsModel::languageName() const
{
    for (auto it = languages_.begin(); it != languages_.end(); ++it) {
        if (it.key() == selectedLanguage_) {
            return it.value();
        }
    }
    return "English";
}

const QString& SettingsModel::languageCode() const
{
    return selectedLanguage_;
}

const QString& SettingsModel::defaultLanguageCode() const
{
    return defaultLanguage_;
}

void SettingsModel::setLanguage(const QString& languageName)
{
    for (auto it = languages_.begin(); it != languages_.end(); ++it) {
        if (languageName == it.value()) {
            selectedLanguage_ = it.key();
        }
    }
    save();
}

void SettingsModel::setLanguageCode(const QString& languageCode)
{
    for (auto it = languages_.begin(); it != languages_.end(); ++it) {
        if (languageCode == it.key()) {
            selectedLanguage_ = languageCode;
        }
    }
    save();
}

const QVector<QString> SettingsModel::getLanguages() const
{
    QVector<QString> languages;
    for (auto it = languages_.begin(); it != languages_.end(); ++it) {
        languages.push_back(it.value());
    }
    return languages;
}

bool SettingsModel::existsTranslation(const QString &languageCode) const
{
    return languages_.find(languageCode) != languages_.end();
}

bool SettingsModel::save()
{
    QString filePath = getFilePath();
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        spdlog::error("Failed to open file for writing: {}", filePath.toStdString());
        return false;
    }

    QJsonObject jsonObject;
    QJsonArray servicesArray;
    for (const ServiceConfig& service : services_) {
        QJsonObject serviceObj;
        serviceObj["service_name"] = service.serviceName;
        serviceObj["username"] = service.username;
        serviceObj["password"] = service.password;

        QJsonArray serversArray;
        for (const ServerConfig& server : service.servers) {
            QJsonObject serverObj;
            serverObj["name"] = server.name;
            serverObj["host"] = server.host;
            serverObj["port"] = server.port;
            serviceObj["is_using"] = server.isUsing;
            serversArray.append(serverObj);
        }
        serviceObj["servers"] = serversArray;
        servicesArray.append(serviceObj);
    }

    jsonObject["language"] = selectedLanguage_;
    jsonObject["services"] = servicesArray;
    jsonObject["network_interface"] = networkInterface_;
    jsonObject["gateway_ip"] = gatewayIp_;
    jsonObject["autostart"] = clientAutostart_ ? 1 : 0;
    jsonObject["sni"] = sni_;
    QJsonDocument document(jsonObject);
    auto len = file.write(document.toJson());
    file.close();

    if (len > 0) {
        spdlog::info("Success save: {}", filePath.toStdString());
    }
    // load saved data
    load();

    // send signal
    emit dataChanged();

    return len > 0;
}

ServiceConfig SettingsModel::parseToken(const QString& token)
{
    QJsonParseError parseError;
    const QByteArray tokenData = token.toUtf8();
    QJsonDocument jsonDoc = QJsonDocument::fromJson(tokenData, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        throw std::runtime_error("JSON parsing error: " + parseError.errorString().toStdString());
    }

    QJsonObject jsonObject = jsonDoc.object();
    if (!jsonObject.contains("service_name") || !jsonObject.contains("username") || !jsonObject.contains("password") || !jsonObject.contains("servers")) {
        throw std::runtime_error("Missing required fields in JSON.");
    }
    ServiceConfig service;
    service.serviceName = jsonObject["service_name"].toString();
    service.username = jsonObject["username"].toString();
    service.password = jsonObject["password"].toString();

    QJsonArray serversArray = jsonObject["servers"].toArray();
    for (const QJsonValue& serverValue : serversArray) {
        QJsonObject serverObj = serverValue.toObject();
        if (!serverObj.contains("name") || !serverObj.contains("host") || !serverObj.contains("port")) {
            throw std::runtime_error("Missing required fields in server object.");
        }

        ServerConfig server;
        server.name = serverObj["name"].toString();
        server.host = serverObj["host"].toString();
        server.port = serverObj["port"].toInt();
        server.isUsing = true;

        service.servers.push_back(server);
    }
    return service;
}

QString SettingsModel::networkInterface() const {
    return networkInterface_;
}

void SettingsModel::setNetworkInterface(const QString &interface) {
    networkInterface_ = (interface.isEmpty() ? "auto" : interface);
}

QString SettingsModel::gatewayIp() const {
    return gatewayIp_.isEmpty() ? "auto" : gatewayIp_;
}

void SettingsModel::setGatewayIp(const QString &ip) {
    gatewayIp_ = ip.isEmpty() ? "auto" : ip;
    save();
}

QString SettingsModel::SNI() const
{
    return sni_.isEmpty() ? FPTN_DEFAULT_SNI : sni_;
}

void SettingsModel::setSNI(const QString &sni)
{
    sni_ = sni;
    save();
}

bool SettingsModel::autostart() const
{
    return clientAutostart_;
}

void SettingsModel::setAutostart(bool value)
{
    clientAutostart_ = value;
    save();
}

const QVector<ServiceConfig>& SettingsModel::services() const {
    return services_;
}

void SettingsModel::addService(const ServiceConfig &server) {
    services_.append(server);
}

void SettingsModel::removeServer(int index) {
    if (index >= 0 && index < services_.size()) {
        services_.removeAt(index);
    }
}

void SettingsModel::clear() {
    services_.clear();
}

QVector<QString> SettingsModel::getNetworkInterfaces() const
{
    QVector<QString> interfaces;
    interfaces.append("auto"); // default empty

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

int SettingsModel::getExistServiceIndex(const QString& name) const
{
    for (int i = 0; i < services_.size(); i++) {
        if (services_[i].serviceName == name) {
            return i;
        }
    }
    return -1;
}

