#pragma once

#include <QMap>
#include <QFile>
#include <QObject>
#include <QVector>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>


namespace fptn::gui
{
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
                ]
            }
        }
    ]
}
*/

    struct ServerConfig
    {
        QString name;
        QString host;
        int port;
        bool isUsing;
    };

    struct ServiceConfig
    {
        QString serviceName;
        QString username;
        QString password;
        QVector<ServerConfig> servers;
        QString language;
    };

    class SettingsModel : public QObject
    {
    Q_OBJECT
    public:
        explicit SettingsModel(
            const QMap<QString, QString>& languages,
            const QString& defaultLanguage="en",
            QObject *parent = nullptr
        );

        void load();
        bool save();

        QString networkInterface() const;
        void setNetworkInterface(const QString &interface);

        QString gatewayIp() const;
        void setGatewayIp(const QString &ip);

        QVector<QString> getNetworkInterfaces() const;

        const QVector<ServiceConfig>& services() const;
        void addService(const ServiceConfig& server);
        void removeServer(int index);
        int getExistServiceIndex(const QString& name) const;
        ServiceConfig parseToken(const QString& token);
        void clear();

        const QString languageName() const;
        void setLanguage(const QString& language);
        void setLanguageCode(const QString& languageCode);

        const QVector<QString> getLanguages() const;

        const QString& defaultLanguageCode() const;
        const QString& languageCode() const;

        bool existsTranslation(const QString &languageCode) const;
    signals:
        void dataChanged();
    private:
        QMap<QString, QString> languages_;

        QString defaultLanguage_;

        QString selectedLanguage_;

        QVector<ServiceConfig> services_;
        QString networkInterface_;
        QString gatewayIp_;
        QString getFilePath() const;
    };

    using SettingsModelPtr = std::shared_ptr<SettingsModel>;
}
