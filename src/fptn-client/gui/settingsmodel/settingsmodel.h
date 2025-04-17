/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>

#include <QFile>          // NOLINT(build/include_order)
#include <QJsonArray>     // NOLINT(build/include_order)
#include <QJsonDocument>  // NOLINT(build/include_order)
#include <QJsonObject>    // NOLINT(build/include_order)
#include <QMap>           // NOLINT(build/include_order)
#include <QObject>        // NOLINT(build/include_order)
#include <QString>        // NOLINT(build/include_order)
#include <QVector>        // NOLINT(build/include_order)

namespace fptn::gui {
/*
{
    "gateway_ip": "auto",
    "language": "en",
    "network_interface": "auto",
    "services": [
        {
            "version": 1,
            "service_name": "FPTN.ONLINE",
            "username": "test",
            "password": "test",
                "servers": [
                    {
                        "name": "pq1",
                        "host": "74.119.195.151",
                        "port": 443
                    },
                    {
                        "name": "australia.fptn.online",
                        "host": "australia.fptn.online",
                        "port": 443
                    }
                ],
                "censored_zone_servers": [
                    {
                        "name": "Server1",
                        "host": "127.0.0.1",
                        "port": 443
                    }
                ]
            }
        }
    ]
}
*/

struct ServerConfig {
  QString name;
  QString host;
  int port;
  bool is_using;

  static ServerConfig parse(const QJsonObject& server_obj, bool& status) {
    status = false;
    if (!server_obj.contains("name") || !server_obj.contains("host") ||
        !server_obj.contains("port")) {
      return {};
    }

    ServerConfig server = {};
    server.name = server_obj["name"].toString();
    server.host = server_obj["host"].toString();
    server.port = server_obj["port"].toInt();
    server.is_using = true;
    status = true;
    return server;
  }
};

struct ServiceConfig {
  QString service_name;
  QString username;
  QString password;
  QVector<ServerConfig> servers;
  QVector<ServerConfig> censored_zone_servers;
  QString language;
};

class SettingsModel : public QObject {
  Q_OBJECT

 public:
  explicit SettingsModel(const QMap<QString, QString>& languages,
      const QString& default_language = "en",
      QObject* parent = nullptr);

  void Load();
  bool Save();

  QString UsingNetworkInterface() const;

  void SetUsingNetworkInterface(const QString&);

  QString GatewayIp() const;
  void SetGatewayIp(const QString& ip);

  QString SNI() const;
  void SetSNI(const QString& sni);

  QVector<QString> GetNetworkInterfaces() const;

  const QVector<ServiceConfig>& Services() const;
  void AddService(const ServiceConfig& server);
  void RemoveServer(int index);
  int GetExistServiceIndex(const QString& name) const;
  ServiceConfig ParseToken(const QString& token);
  void Clear();

  QString LanguageName() const;
  void SetLanguage(const QString& language);
  void SetLanguageCode(const QString& language_code);

  QVector<QString> GetLanguages() const;

  const QString& DefaultLanguageCode() const;
  const QString& LanguageCode() const;

  bool ExistsTranslation(const QString& language_code) const;

  bool Autostart() const;
  void SetAutostart(bool value);

  QString GetFilePath() const;
 signals:
  void dataChanged();

 private:
  QMap<QString, QString> languages_;

  QString default_language_;

  QString selected_language_;

  QVector<ServiceConfig> services_;
  QString network_interface_;
  QString gateway_ip_;
  QString sni_;

  bool client_autostart_;
};

using SettingsModelPtr = std::shared_ptr<SettingsModel>;
}  // namespace fptn::gui
