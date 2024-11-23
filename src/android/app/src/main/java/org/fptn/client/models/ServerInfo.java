package org.fptn.client.models;

import java.io.Serializable;

public class ServerInfo implements Serializable {
    private String name;
    private String host;
    private int port;

    ServerInfo(String name, String host, int port) {
        this.name = name;
        this.host = host;
        this.port = port;
    }

    public String getName() {
        return name;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }
}
