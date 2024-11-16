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
     "services":
     [
         {
            "version": 1,
            "service_name": "FPTN.ONLINE",
            "username": "admin",
            "password": "skokov92",
                "servers": [
                    {
                        "name": "pq1",
                        "host": "74.119.195.150",
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
        explicit SettingsModel(QMap<QString, QString> languages, QString selectedLanguage="en", QObject *parent = nullptr);

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
        ServiceConfig parseFile(const QString& filepath);
        void clear();

        const QString languageName() const;
        void setLanguage(const QString& language);

        const QVector<QString> getLanguages() const;
    signals:
        void dataChanged();
    private:
        QMap<QString, QString> languages_;

        QString selectedLanguage_;

        QVector<ServiceConfig> services_;
        QString networkInterface_;
        QString gatewayIp_;
        QString getFilePath() const;
    };

    using SettingsModelPtr = std::shared_ptr<SettingsModel>;
}
