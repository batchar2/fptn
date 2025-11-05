/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/settingsmodel/settingsmodel.h"

#if _WIN32
#include <Ws2tcpip.h>  // NOLINT(build/include_order)
#include <windows.h>   // NOLINT(build/include_order)
#endif

#include <utility>

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

using fptn::gui::ServerConfig;
using fptn::gui::ServiceConfig;
using fptn::gui::SettingsModel;

namespace {
QVector<ServerConfig> ParseServers(const QJsonArray& servers_array) {
  QVector<ServerConfig> servers;
  for (const auto& server_value : servers_array) {
    const QJsonObject server_obj = server_value.toObject();
    bool status = false;
    auto server = ServerConfig::parse(server_obj, status);
    if (status) {
      servers.push_back(std::move(server));
    } else {
      QString error = QObject::tr(
          "Missing required fields in configuration. Generate and apply a new "
          "token.");
      throw std::runtime_error(error.toStdString());
    }
  }
  return servers;
}
};  // namespace

SettingsModel::SettingsModel(const QMap<QString, QString>& languages,
    const QString& default_language,
    QObject* parent)
    : QObject(parent),
      languages_(languages),
      default_language_(default_language),
      selected_language_(default_language),
      client_autostart_(false) {
  Load(true);
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
QString SettingsModel::GetFilePath() const {
#ifdef __APPLE__
  const QString directory =
      QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
#else
  const QString directory =
      QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
#endif
  QDir dir(directory);
  if (!dir.exists()) {
    dir.mkpath(directory);
  }
  return directory + "/fptn-settings.json";
}

void SettingsModel::Load(bool dont_load_server) {
  // Load servers
  services_.clear();

  const QString file_path = GetFilePath();
  QFile file(file_path);
  if (!file.open(QIODevice::ReadOnly)) {
    SPDLOG_WARN("Failed to open file for reading: {}", file_path.toStdString());
    return;
  }
  SPDLOG_INFO("Settings: {}", file_path.toStdString());

  const QByteArray data = file.readAll();
  file.close();
  const QJsonDocument document = QJsonDocument::fromJson(data);
  const QJsonObject service_obj = document.object();

  if (service_obj.contains("services")) {
    QJsonArray services_array = service_obj["services"].toArray();
    for (const auto& service_value : services_array) {
      QJsonObject jsonservice_obj = service_value.toObject();
      ServiceConfig service;

      service.service_name = jsonservice_obj["service_name"].toString();
      service.username = jsonservice_obj["username"].toString();
      service.password = jsonservice_obj["password"].toString();

      // servers
      if (!dont_load_server) {
        service.servers = ParseServers(jsonservice_obj["servers"].toArray());
        if (jsonservice_obj.contains("censored_zone_servers")) {
          service.censored_zone_servers =
              ParseServers(jsonservice_obj["censored_zone_servers"].toArray());
        }
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
    client_autostart_ = service_obj["autostart"].toBool();
  }

  if (service_obj.contains("gateway_ip")) {
    gateway_ip_ = service_obj["gateway_ip"].toString();
  }
  if (gateway_ip_.isEmpty()) {
    gateway_ip_ = "auto";
  }

  if (service_obj.contains("sni")) {
    sni_ = service_obj["sni"].toString();
  }
  if (sni_.isEmpty()) {
    sni_ = FPTN_DEFAULT_SNI;
  }

  if (service_obj.contains("bypass_method")) {
    bypass_method_ = service_obj["bypass_method"].toString();
  }
  if (bypass_method_.isEmpty() ||
      (bypass_method_ != "SNI" && bypass_method_ != "OBFUSCATION")) {
    bypass_method_ = "SNI";
  }
}

QString SettingsModel::LanguageName() const {
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

QVector<QString> SettingsModel::GetLanguages() const {
  QVector<QString> languages;
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    languages.push_back(it.value());
  }
  return languages;
}

bool SettingsModel::ExistsTranslation(const QString& language_code) const {
  // NOLINTNEXTLINE(readability-container-contains)
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
  QJsonArray services_array;
  for (const auto& service : services_) {
    QJsonObject service_obj;
    service_obj["service_name"] = service.service_name;
    service_obj["username"] = service.username;
    service_obj["password"] = service.password;

    // servers
    QJsonArray servers_array;
    for (const auto& server : service.servers) {
      QJsonObject server_obj;
      server_obj["name"] = server.name;
      server_obj["host"] = server.host;
      server_obj["port"] = server.port;
      server_obj["is_using"] = server.is_using;
      server_obj["md5_fingerprint"] = server.md5_fingerprint;
      servers_array.append(server_obj);
    }
    service_obj["servers"] = servers_array;

    // censored_zone_servers
    QJsonArray censored_zone_servers;
    for (const auto& server : service.censored_zone_servers) {
      QJsonObject server_obj;
      server_obj["name"] = server.name;
      server_obj["host"] = server.host;
      server_obj["port"] = server.port;
      server_obj["is_using"] = server.is_using;
      server_obj["md5_fingerprint"] = server.md5_fingerprint;
      censored_zone_servers.append(server_obj);
    }
    service_obj["censored_zone_servers"] = censored_zone_servers;
    services_array.append(service_obj);
  }

  json_object["language"] = selected_language_;
  json_object["services"] = services_array;
  json_object["network_interface"] = network_interface_;
  json_object["gateway_ip"] = gateway_ip_;
  json_object["autostart"] = client_autostart_ ? 1 : 0;
  json_object["sni"] = sni_;
  json_object["bypass_method"] = bypass_method_;
  QJsonDocument document(json_object);
  auto len = file.write(document.toJson());
  file.close();

  if (len > 0) {
    SPDLOG_INFO("Success save: {}", file_path.toStdString());
  }
  // send signal
  emit dataChanged();

  return len > 0;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ServiceConfig SettingsModel::ParseToken(const QString& token) {
  QJsonParseError parse_error;
  const QByteArray token_data = token.toUtf8();
  QJsonDocument json_doc = QJsonDocument::fromJson(token_data, &parse_error);

  if (parse_error.error != QJsonParseError::NoError) {
    throw std::runtime_error(
        "JSON parsing error: " + parse_error.errorString().toStdString());
  }

  QJsonObject json_object = json_doc.object();
  if (!json_object.contains("service_name") ||
      !json_object.contains("username") || !json_object.contains("password") ||
      !json_object.contains("servers")) {
    throw std::runtime_error("Missing required fields in JSON.");
  }
  ServiceConfig service;
  service.service_name = json_object["service_name"].toString();
  service.username = json_object["username"].toString();
  service.password = json_object["password"].toString();

  // servers
  service.servers = ParseServers(json_object["servers"].toArray());
  if (json_object.contains("censored_zone_servers")) {
    service.censored_zone_servers =
        ParseServers(json_object["censored_zone_servers"].toArray());
  }
  return service;
}

QString SettingsModel::UsingNetworkInterface() const {
  return network_interface_;
}

void SettingsModel::SetUsingNetworkInterface(const QString& iface) {
  network_interface_ = (iface.isEmpty() ? "auto" : iface);
}

QString SettingsModel::GatewayIp() const {
  return gateway_ip_.isEmpty() ? "auto" : gateway_ip_;
}

void SettingsModel::SetGatewayIp(const QString& ip) {
  gateway_ip_ = ip.isEmpty() ? "auto" : ip;
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

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
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

QString SettingsModel::BypassMethod() const {
  return bypass_method_.isEmpty() ? "SNI" : bypass_method_;
}

void SettingsModel::SetBypassMethod(const QString& method) {
  bypass_method_ = method;
  Save();
}
