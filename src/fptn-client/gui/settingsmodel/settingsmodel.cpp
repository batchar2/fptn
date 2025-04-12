/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/settingsmodel/settingsmodel.h"

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QDir>               // NOLINT(build/include_order)
#include <QFile>              // NOLINT(build/include_order)
#include <QJsonArray>         // NOLINT(build/include_order)
#include <QJsonDocument>      // NOLINT(build/include_order)
#include <QJsonObject>        // NOLINT(build/include_order)
#include <QNetworkInterface>  // NOLINT(build/include_order)
#include <QStandardPaths>     // NOLINT(build/include_order)

#include "routing//iptables.h"

using fptn::gui::ServiceConfig;
using fptn::gui::SettingsModel;

SettingsModel::SettingsModel(const QMap<QString, QString>& languages,
    const QString& default_language,
    QObject* parent)
    : QObject(parent),
      languages_(languages),
      default_language_(default_language),
      selected_language_(default_language),
      client_autostart_(false) {
  Load();
}

QString SettingsModel::GetFilePath() const {
  QString directory =
      QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  QDir dir(directory);
  if (!dir.exists()) {
    dir.mkpath(directory);
  }
  return directory + "/fptn-settings.json";
}

void SettingsModel::Load() {
  // Load servers
  services_.clear();

  QString file_path = GetFilePath();
  QFile file(file_path);
  if (!file.open(QIODevice::ReadOnly)) {
    spdlog::warn(
        "Failed to open file for reading: {}", file_path.toStdString());
    return;
  }
  SPDLOG_INFO("Settings: {}", file_path.toStdString());

  QByteArray data = file.readAll();
  file.close();

  QJsonDocument document = QJsonDocument::fromJson(data);
  QJsonObject service_obj = document.object();

  if (service_obj.contains("services")) {
    QJsonArray servicesArray = service_obj["services"].toArray();
    for (const QJsonValue& serviceValue : servicesArray) {
      QJsonObject jsonservice_obj = serviceValue.toObject();
      ServiceConfig service;

      service.service_name = jsonservice_obj["service_name"].toString();
      service.username = jsonservice_obj["username"].toString();
      service.password = jsonservice_obj["password"].toString();

      QJsonArray serversArray = jsonservice_obj["servers"].toArray();
      for (const QJsonValue& serverValue : serversArray) {
        QJsonObject serverObj = serverValue.toObject();
        ServerConfig server;
        server.name = serverObj["name"].toString();
        server.host = serverObj["host"].toString();
        server.port = serverObj["port"].toInt();
        server.is_using = serverObj["is_using"].toBool();
        service.servers.push_back(server);
      }
      services_.push_back(service);
    }
  }
  // Load network settings
  if (service_obj.contains("network_interface")) {
    network_interface_ = service_obj["network_interface"].toString();
  }
  if (network_interface_.isEmpty()) {
    network_interface_ = "auto";
  }

  if (service_obj.contains("language")) {
    selected_language_ = service_obj["language"].toString();
  }
  if (service_obj.contains("autostart")) {
    client_autostart_ = service_obj["autostart"].toInt();
  }

  if (service_obj.contains("gateway_ip")) {
    gatewayIp_ = service_obj["gateway_ip"].toString();
  }
  if (gatewayIp_.isEmpty()) {
    gatewayIp_ = "auto";
  }

  if (service_obj.contains("sni")) {
    sni_ = service_obj["sni"].toString();
  }
  if (sni_.isEmpty()) {
    sni_ = FPTN_DEFAULT_SNI;
  }
}

const QString SettingsModel::LanguageName() const {
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    if (it.key() == selected_language_) {
      return it.value();
    }
  }
  return "English";
}

const QString& SettingsModel::LanguageCode() const {
  return selected_language_;
}

const QString& SettingsModel::DefaultLanguageCode() const {
  return default_language_;
}

void SettingsModel::SetLanguage(const QString& language_name) {
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    if (language_name == it.value()) {
      selected_language_ = it.key();
    }
  }
  Save();
}

void SettingsModel::SetLanguageCode(const QString& language_code) {
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    if (language_code == it.key()) {
      selected_language_ = language_code;
    }
  }
  Save();
}

const QVector<QString> SettingsModel::GetLanguages() const {
  QVector<QString> languages;
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    languages.push_back(it.value());
  }
  return languages;
}

bool SettingsModel::ExistsTranslation(const QString& language_code) const {
  return languages_.find(language_code) != languages_.end();
}

bool SettingsModel::Save() {
  QString file_path = GetFilePath();
  QFile file(file_path);
  if (!file.open(QIODevice::WriteOnly)) {
    SPDLOG_ERROR(
        "Failed to open file for writing: {}", file_path.toStdString());
    return false;
  }

  QJsonObject json_object;
  QJsonArray servicesArray;
  for (const ServiceConfig& service : services_) {
    QJsonObject service_obj;
    service_obj["service_name"] = service.service_name;
    service_obj["username"] = service.username;
    service_obj["password"] = service.password;

    QJsonArray serversArray;
    for (const ServerConfig& server : service.servers) {
      QJsonObject serverObj;
      serverObj["name"] = server.name;
      serverObj["host"] = server.host;
      serverObj["port"] = server.port;
      service_obj["is_using"] = server.is_using;
      serversArray.append(serverObj);
    }
    service_obj["servers"] = serversArray;
    servicesArray.append(service_obj);
  }

  json_object["language"] = selected_language_;
  json_object["services"] = servicesArray;
  json_object["network_interface"] = network_interface_;
  json_object["gateway_ip"] = gatewayIp_;
  json_object["autostart"] = client_autostart_ ? 1 : 0;
  json_object["sni"] = sni_;
  QJsonDocument document(json_object);
  auto len = file.write(document.toJson());
  file.close();

  if (len > 0) {
    SPDLOG_INFO("Success save: {}", file_path.toStdString());
  }
  // load saved data
  Load();

  // send signal
  emit dataChanged();

  return len > 0;
}

ServiceConfig SettingsModel::ParseToken(const QString& token) {
  QJsonParseError parse_error;
  const QByteArray tokenData = token.toUtf8();
  QJsonDocument jsonDoc = QJsonDocument::fromJson(tokenData, &parse_error);

  if (parse_error.error != QJsonParseError::NoError) {
    throw std::runtime_error(
        "JSON parsing error: " + parse_error.errorString().toStdString());
  }

  QJsonObject json_object = jsonDoc.object();
  if (!json_object.contains("service_name") ||
      !json_object.contains("username") || !json_object.contains("password") ||
      !json_object.contains("servers")) {
    throw std::runtime_error("Missing required fields in JSON.");
  }
  ServiceConfig service;
  service.service_name = json_object["service_name"].toString();
  service.username = json_object["username"].toString();
  service.password = json_object["password"].toString();

  QJsonArray servers_array = json_object["servers"].toArray();
  for (const QJsonValue& serverValue : servers_array) {
    QJsonObject serverObj = serverValue.toObject();
    if (!serverObj.contains("name") || !serverObj.contains("host") ||
        !serverObj.contains("port")) {
      throw std::runtime_error("Missing required fields in server object.");
    }

    ServerConfig server;
    server.name = serverObj["name"].toString();
    server.host = serverObj["host"].toString();
    server.port = serverObj["port"].toInt();
    server.is_using = true;

    service.servers.push_back(server);
  }
  return service;
}

QString SettingsModel::UsingNetworkInterface() const {
  return network_interface_;
}

void SettingsModel::SetUsingNetworkInterface(const QString& interface) {
  network_interface_ = (interface.isEmpty() ? "auto" : interface);
}

QString SettingsModel::GatewayIp() const {
  return gatewayIp_.isEmpty() ? "auto" : gatewayIp_;
}

void SettingsModel::SetGatewayIp(const QString& ip) {
  gatewayIp_ = ip.isEmpty() ? "auto" : ip;
  Save();
}

QString SettingsModel::SNI() const {
  return sni_.isEmpty() ? FPTN_DEFAULT_SNI : sni_;
}

void SettingsModel::SetSNI(const QString& sni) {
  sni_ = sni;
  Save();
}

bool SettingsModel::Autostart() const { return client_autostart_; }

void SettingsModel::SetAutostart(bool value) {
  client_autostart_ = value;
  Save();
}

const QVector<ServiceConfig>& SettingsModel::Services() const {
  return services_;
}

void SettingsModel::AddService(const ServiceConfig& server) {
  services_.append(server);
}

void SettingsModel::RemoveServer(int index) {
  if (index >= 0 && index < services_.size()) {
    services_.removeAt(index);
  }
}

void SettingsModel::Clear() { services_.clear(); }

QVector<QString> SettingsModel::GetNetworkInterfaces() const {
  QVector<QString> interfaces;
  interfaces.append("auto");  // default empty

  QList<QNetworkInterface> network_interfaces =
      QNetworkInterface::allInterfaces();

  for (const QNetworkInterface& network_interface : network_interfaces) {
    if (network_interface.flags().testFlag(QNetworkInterface::IsUp) &&
        !network_interface.flags().testFlag(QNetworkInterface::IsLoopBack) &&
        !network_interface.flags().testFlag(
            QNetworkInterface::IsPointToPoint) &&
        !network_interface.hardwareAddress().isEmpty()) {
      QList<QNetworkAddressEntry> entries = network_interface.addressEntries();
      if (!entries.isEmpty()) {
        interfaces.append(network_interface.humanReadableName());
      }
    }
  }
  return interfaces;
}

int SettingsModel::GetExistServiceIndex(const QString& name) const {
  for (int i = 0; i < services_.size(); i++) {
    if (services_[i].service_name == name) {
      return i;
    }
  }
  return -1;
}
