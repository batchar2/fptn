// server_model.cpp
#include "server_model.h"
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

using namespace fptn::gui;


ServerModel::ServerModel(QObject *parent) : QObject(parent) {
    load();
}

QString ServerModel::getFilePath() const {
    // Получаем путь к пользовательскому каталогу
    QString directory = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    // Убедитесь, что каталог существует
    QDir dir(directory);
    if (!dir.exists()) {
        dir.mkpath(directory);
    }
    return directory + "/servers.json"; // Имя файла
}

void ServerModel::load() {
    QString filePath = getFilePath();
    qDebug() << filePath;
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning("Failed to open file for reading: %s", qPrintable(filePath));
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument document = QJsonDocument::fromJson(data);
    if (document.isNull() || !document.isArray()) {
        qWarning("Failed to parse JSON or JSON is not an array.");
        return;
    }

    QJsonArray jsonArray = document.array();

    servers_.clear();
    for (const QJsonValue &value : jsonArray) {
        QJsonObject obj = value.toObject();
        Server server;
        server.address = obj["address"].toString();
        server.port = obj["port"].toInt();
        server.username = obj["username"].toString();
        server.password = obj["password"].toString();
        servers_.append(server);
    }
}

void ServerModel::clear()
{
    servers_.clear();
}

void ServerModel::save() const {
    QString filePath = getFilePath();
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        qWarning("Failed to open file for writing: %s", qPrintable(filePath));
        return;
    }

    QJsonArray jsonArray;
    for (const Server &server : servers_) {
        QJsonObject obj;
        obj["address"] = server.address;
        obj["port"] = server.port;
        obj["username"] = server.username;
        obj["password"] = server.password;
        jsonArray.append(obj);
    }

    QJsonDocument document(jsonArray);
    file.write(document.toJson());
    file.close();
}

const QVector<Server>& ServerModel::servers() const {
    return servers_;
}

void ServerModel::addServer(const Server &server) {
    servers_.append(server);
}

void ServerModel::removeServer(int index) {
    if (index >= 0 && index < servers_.size()) {
        servers_.removeAt(index);
    }
}

//
//
//ServerModel::ServerModel(QObject *parent) : QObject(parent) {}
//
//void ServerModel::load(const QString &filename) {
//    QFile file(filename);
//    if (!file.open(QIODevice::ReadOnly)) {
//        return;
//    }
//
//    QByteArray data = file.readAll();
//    file.close();
//
//    QJsonDocument document = QJsonDocument::fromJson(data);
//    QJsonArray jsonArray = document.array();
//
//    servers_.clear();
//    for (const QJsonValue &value : jsonArray) {
//        QJsonObject obj = value.toObject();
//        Server server;
//        server.address = obj["address"].toString();
//        server.port = obj["port"].toInt();
//        server.username = obj["username"].toString();
//        server.password = obj["password"].toString();
//        servers_.append(server);
//    }
//}
//
//void ServerModel::save(const QString &filename) const {
//
//    QFile file(filename);
//    if (!file.open(QIODevice::WriteOnly)) {
//        return;
//    }
//
//    QJsonArray jsonArray;
//    for (const Server &server : servers_) {
//        QJsonObject obj;
//        obj["address"] = server.address;
//        obj["port"] = server.port;
//        obj["username"] = server.username;
//        obj["password"] = server.password;
//        jsonArray.append(obj);
//    }
//
//    QJsonDocument document(jsonArray);
//    file.write(document.toJson());
//    file.close();
//}
//
//const QVector<Server>& ServerModel::servers() const {
//    return servers_;
//}
//
//void ServerModel::addServer(const Server &server) {
//    servers_.append(server);
//}
//
//void ServerModel::removeServer(int index) {
//    if (index >= 0 && index < servers_.size()) {
//        servers_.removeAt(index);
//    }
//}
//




//ServerModel::ServerModel(QObject *parent) : QObject(parent) {
//    QString filePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/servers.json";
//    load(filePath);
//}
//
//QList<Server> ServerModel::servers() const {
//    return servers_;
//}
//
//void ServerModel::addServer(const Server &server) {
//    servers_.append(server);
//    QString filePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/servers.json";
//    save(filePath);
//}
//
//void ServerModel::removeServer(int index) {
//    if (index >= 0 && index < servers_.size()) {
//        servers_.removeAt(index);
//        QString filePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/servers.json";
//        save(filePath);
//    }
//}
//
//void ServerModel::save(const QString &filePath) {
//    QString directoryPath = QFileInfo(filePath).absolutePath();
//    QDir dir(directoryPath);
//
//    // Создаем директорию, если она не существует
//    if (!dir.exists()) {
//        if (!dir.mkpath(directoryPath)) {
//            qWarning() << "Cannot create directory:";
//            return;
//        }
//    }
//
//    // Открываем файл для записи
//    QFile file(filePath);
//    if (!file.open(QIODevice::WriteOnly)) {
//        qWarning() << "Cannot open file for writing:" << file.errorString();
//        return;
//    }
//
//    // Создаем массив серверов в формате JSON
//    QJsonArray serversArray;
//    for (const Server &server : servers_) {
//        QJsonObject serverObj;
//        serverObj["name"] = server.name;
//        serverObj["address"] = server.address;
//        serverObj["port"] = server.port;
//        serverObj["username"] = server.username;
//        serverObj["password"] = server.password;
//        serversArray.append(serverObj);
//    }
//
//    // Создаем корневой JSON объект и добавляем массив серверов
//    QJsonObject jsonObj;
//    jsonObj["servers"] = serversArray;
//
//    // Сохраняем JSON документ в файл
//    QJsonDocument doc(jsonObj);
//    file.write(doc.toJson());
//    file.close();
//}
//
//void ServerModel::load(const QString &filePath) {
//    qWarning() << "directoryPath>" << filePath;
//    QFile file(filePath);
//    if (!file.open(QIODevice::ReadOnly)) {
//        qWarning() << "Cannot open file for reading:" << file.errorString();
//        return;
//    }
//
//    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
//    QJsonObject jsonObj = doc.object();
//    QJsonArray serversArray = jsonObj["servers"].toArray();
//
//    servers_.clear();
//    for (const QJsonValue &value : serversArray) {
//        QJsonObject serverObj = value.toObject();
//        Server server;
//        server.name = serverObj["name"].toString();
//        server.address = serverObj["address"].toString();
//        server.port = serverObj["port"].toInt();
//        server.username = serverObj["username"].toString();
//        server.password = serverObj["password"].toString();
//        servers_.append(server);
//    }
//}