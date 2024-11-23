package org.fptn.client.models;

import java.io.Serializable;
import java.util.List;

public class ServiceInfo implements Serializable {
    private int version;
    private String service_name;

    private String username;
    private String password;

    private List<ServerInfo> servers;

    ServiceInfo(int version, String serviceName, String username, String password, List<ServerInfo> servers) {
        this.version = version;
        this.service_name = serviceName;
        this.username = username;
        this.password = password;
        this.servers = servers;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public String getServiceName() {
        return service_name;
    }

    public int getVersion() {
        return version;
    }

    public List<ServerInfo> getServers() {
        return servers;
    }
}
