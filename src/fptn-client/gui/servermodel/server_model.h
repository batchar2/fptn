#pragma once

#include <QObject>
#include <QVector>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QFile>

namespace fptn::gui {



    struct Server {
        QString address;
        int port;
        QString username;
        QString password;
    };

    class ServerModel : public QObject {
    Q_OBJECT

    public:
        explicit ServerModel(QObject *parent = nullptr);

        void load();
        void save() const;

        const QVector<Server>& servers() const;
        void addServer(const Server &server);
        void removeServer(int index);
        void clear();
    private:
        QVector<Server> servers_;
        QString getFilePath() const;
    };


}