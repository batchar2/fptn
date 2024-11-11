package org.fptn.client.service.websocket;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

public class WebSocketClient implements Runnable {
    private String host;
    private Integer port;
    private String username;
    private String password;

    WebSocketCallback callback;

    private String accessToken;

    WebSocket webSocket = null;
    private static final String LOG_TAG = "FptnClient";

    public WebSocketClient(String host, Integer port, String username, String password, WebSocketCallback callback) {
        Log.i(LOG_TAG, "onStartCommand+" + host + " " + port + " " + username + " " + password);
        this.host = host; //"185.215.187.165";
        this.port = port;
        this.username = username;
        this.password = password;
        this.accessToken = "";
        this.callback = callback;
    }

    public boolean send(byte[] msg)
    {
        if (webSocket != null) {
            webSocket.send(msg.toString());
            return true;
        }
        return false;
    }

    public boolean login()
    {
        try {
            JSONObject json = new JSONObject();
            json.put("username", username);
            json.put("password", password);

            RequestBody requestBody = RequestBody.create(
                    json.toString(),
                    MediaType.get("application/json")
            );
            String url = String.format("https://%s:%d/api/v1/login", host, port);

            Request request = new Request.Builder()
                    .url(url)
                    .post(requestBody)
                    .build();

            OkHttpClient client = getUnsafeOkHttpClient();
            Response response = client.newCall(request).execute();
            if (response.code() == 200) {
                String responseBody =  response.body().string();
                JSONObject jsonResponse = new JSONObject(responseBody);
                if (jsonResponse.has("access_token")) {
                    accessToken = jsonResponse.getString("access_token");
                    System.out.println("Login successful. " + accessToken);
                    return true;
                } else {
                    System.err.println("Error: Access token not found in the response.");
                }
            }
        } catch (JSONException err) {
            Log.i(LOG_TAG, "Error1: " + err.toString());
        } catch (IOException err) {
            Log.i(LOG_TAG, "Error2: " + err.toString());
        }
        return false;
    }

    @Override
    public void run() {
        if (login()) {
            OkHttpClient client = getUnsafeOkHttpClient();
            WebSocketListener websocketListener = getWebSocketListener();
            Request request = new Request.Builder()
                    .url(String.format("wss://%s:%d/fptn", host, port))
                    .addHeader("Authorization", "Bearer " + accessToken)
                    .addHeader("ClientIP", "10.10.10.1")
                    .build();

            WebSocket webSocket = client.newWebSocket(request, websocketListener);
            try {
                Thread.sleep(100000);  // Adjust time to keep the connection open
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            // Shut down the client
            System.err.println("start");
            client.dispatcher().executorService().shutdown();
            System.err.println("stop");
        }
    }

    private WebSocketListener getWebSocketListener(){
        return new WebSocketListener() {
            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                System.out.println("WebSocket opened!" + response.code());
                // Send a message after the connection is opened
//                webSocket.send("Hello WebSocket!");
            }

            @Override
            public void onMessage(WebSocket webSocket, String text) {
                System.out.println("Message received: " + text);
                callback.onMessageReceived(text.getBytes());
            }

            @Override
            public void onMessage(WebSocket webSocket, ByteString bytes) {
                System.out.println("Message received: " + bytes.hex());
                callback.onMessageReceived(bytes.toByteArray());
            }

            @Override
            public void onClosing(WebSocket webSocket, int code, String reason) {
                System.out.println("WebSocket closing: " + reason);
            }

            @Override
            public void onClosed(WebSocket webSocket, int code, String reason) {
                System.out.println("WebSocket closed: " + reason);
            }

            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                t.printStackTrace();
                System.out.println("WebSocket failure: " + t.getMessage());
            }
        };
    }

    public static OkHttpClient getUnsafeOkHttpClient() {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // Create an SSL socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier((hostname, session) -> true);

            OkHttpClient client = builder.build();
//            client.readTimeout(0,  TimeUnit.MILLISECONDS);
            return client;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final String CHROME_CIPHERS = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
            + "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
            + "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,"
            + "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,"
            + "TLS_RSA_WITH_AES_128_GCM_SHA256,"
            + "TLS_RSA_WITH_AES_256_GCM_SHA384,"
            + "TLS_RSA_WITH_AES_128_CBC_SHA,"
            + "TLS_RSA_WITH_AES_256_CBC_SHA,"
            + "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
}
