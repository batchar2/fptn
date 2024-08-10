#pragma once

#include <QObject>
#include <QVector>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QFile>

namespace fptn::gui {

    struct ServerConnectionInformation
    {
        QString address;
        int port;
        QString username;
        QString password;
    };


    class SettingsModel : public QObject {
    Q_OBJECT

    public:
        explicit SettingsModel(QObject *parent = nullptr);

        void load();
        void save() const;

        QString networkInterface() const;
        void setNetworkInterface(const QString &interface);

        QString gatewayIp() const;
        void setGatewayIp(const QString &ip);

        QVector<QString> getNetworkInterfaces() const;

        const QVector<ServerConnectionInformation>& servers() const;
        void addServer(const ServerConnectionInformation& server);
        void removeServer(int index);
        void clear();

    private:
        QVector<ServerConnectionInformation> servers_;
        QString networkInterface_;
        QString gatewayIp_;
        QString getFilePath() const;
    };


}