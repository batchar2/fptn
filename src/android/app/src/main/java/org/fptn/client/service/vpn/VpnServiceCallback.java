package org.fptn.client.service.vpn;

public interface VpnServiceCallback {
    void onMessageReceived(byte[] msg);
    void onError(Exception e);
}
