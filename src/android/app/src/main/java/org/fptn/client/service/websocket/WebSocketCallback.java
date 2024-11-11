package org.fptn.client.service.websocket;

import com.google.protobuf.ByteString;

public interface WebSocketCallback {
    void onMessageReceived(byte[] msg);
    void onError(Exception e);
}
