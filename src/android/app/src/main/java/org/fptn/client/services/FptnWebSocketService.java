package org.fptn.client.services;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.fptn.client.R;
import org.fptn.protocol.Protocol;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

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
//import okio.ByteString;




public class FptnWebSocketService extends Service {
    private static final String TAG = "FptnWebSocketService";
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    Thread webSocketThread = null;

    WebSocket webSocket;

    private WebSocketListener getWebSocketListener(){
        String action = getString(R.string.action_send_to_tun_interface);
        String intentName = getString(R.string.action_send_intent_name_protobuf_data);

        return new WebSocketListener() {
            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                System.out.println("WebSocket opened!" + response.code());
                // Send a message after the connection is opened
//                webSocket.send("Hello WebSocket!");
            }

            @Override
            public void onMessage(WebSocket webSocket, String text) {
                System.out.println("Message received1: " + text);
//                callback.onMessageReceived(text.getBytes());
            }

            @Override
            public void onMessage(WebSocket webSocket, ByteString protobufPacket) {
                System.out.println("Message received2: ");

                byte[] msg = protobufPacket.toByteArray();
                Intent intent = new Intent(action);
                intent.putExtra(intentName, msg);

                LocalBroadcastManager.getInstance(FptnWebSocketService.this).sendBroadcast(intent);
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

//    public IBinder onBind(Intent intent) {
//        return new IService.Stub() {
//            @Override
//            public void sendData(String data) {
//                // Handle incoming data
//            }
//        };
//    }

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

    public String login(String host, int port, String username, String password) throws Exception
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
                    String token = jsonResponse.getString("access_token");
                    System.out.println("Login successful. " + token);
                    return token;
                } else {
                    System.err.println("Error: Access token not found in the response.");
                }
            }
        } catch (JSONException err) {
            Log.i(TAG, "Error1: " + err.toString());
        } catch (IOException err) {
            Log.i(TAG, "Error2: " + err.toString());
        }
        throw new Exception("Auth error");
    }
    void readFromWebSocket(OkHttpClient client)
    {
        Log.i(TAG, "=== readFromWebSocket.start ===");
        while (isRunning.get()) {
            try {
                Thread.sleep(1);
            } catch (Exception err) {
            }
        }
        Log.i(TAG, "=== readFromWebSocket.stop ===");
    }

    void writeToWebSocket(OkHttpClient client) {
//        Log.i(TAG, "=== writeToWebSocket.start ===");
//        String action = getString(R.string.action_send_to_websocket);
//        String intentName = getString(R.string.action_send_intent_name_protobuf_data);
//
//        BroadcastReceiver packetReceiver = new BroadcastReceiver() {
//            @Override
//            public void onReceive(Context context, Intent intent) {
//                Log.i(TAG, "onGet " + intent);
//                if (intent.getAction() != null && intent.getAction().equals(action)) {
//                    byte[] protobufData = intent.getByteArrayExtra(intentName);
//                    if (protobufData != null) {
//                        try {
//                            webSocket.send(new ByteString(protobufData));
//                            Log.i(TAG, "Send IP packet");
//                        } catch (Exception e) {
//                            Log.e(TAG, "Error parsing or writing IP packet data: " + e.getMessage());
//                        }
//                    }
//                }
//            }
//        };
//        //            IntentFilter intentFilter = new IntentFilter();
////            intentFilter.addAction("SEND_TO_WEBSOCKET");
////            registerReceiver(broadcastReceiver, intentFilter);
//
//        LocalBroadcastManager.getInstance(this).registerReceiver(packetReceiver, new IntentFilter(action));
//        try {
//            while (isRunning.get()) {
//                Thread.sleep(100); // Sleep to prevent busy-waiting
//            }
//        } catch (InterruptedException e) {
//            Log.e(TAG, "Writer thread interrupted: " + e.getMessage());
//        } finally {
//            LocalBroadcastManager.getInstance(this).unregisterReceiver(packetReceiver);
//        }
//        Log.i(TAG, "=== writeToWebSocket.stop ===");
    }

    void runWebSocketConnection(String host, int port, String username, String password) {
        Log.i(TAG, "=== runWebSocketConnection.start ===");
        isRunning.set(true);
        try {
            String token = login(host, port, username, password);
            Request request = new Request.Builder()
                    .url(String.format("wss://%s:%d/fptn", host, port))
                    .addHeader("Authorization", "Bearer " + token)
                    .addHeader("ClientIP", "10.10.10.1")
                    .build();
            OkHttpClient client = getUnsafeOkHttpClient();
            WebSocketListener websocketListener = getWebSocketListener();
            this.webSocket = client.newWebSocket(request, websocketListener);

            Thread readerThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    FptnWebSocketService.this.readFromWebSocket(client);
                }
            });
            Thread writerThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    FptnWebSocketService.this.writeToWebSocket(client);
                }
            });
            System.err.println("start");

            writerThread.start();
            readerThread.start();

            readerThread.join();
            writerThread.join();

            client.dispatcher().executorService().shutdown();
            System.err.println("stop");
            Log.i(TAG, "=== runWebSocketConnection.stop ===");
        } catch (Exception err) {
            Log.i(TAG, "AUTH error: " + err.toString());
        }
    }

    BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
        String action = "SEND_TO_WEBSOCKET"; // FIXME getString(R.string.action_send_to_websocket);
        String intentName = "protobufData";// FIXME getString(R.string.action_send_intent_name_protobuf_data);
        @Override
        public void onReceive(Context context, Intent intent) {
            String recvAction = intent.getAction();
            if (recvAction.equals(action)) {
//                Log.d(TAG, "A");
                byte[] protobufData = intent.getByteArrayExtra(intentName);
                if (protobufData != null) {
                    System.out.println("web1 >>> " + Integer.toString(protobufData.length) + " " + Arrays.toString(protobufData));
                    try {
//                        ByteString
                        //ByteString.of(protobufData);
                        ByteString bs = new ByteString(protobufData);
                        System.out.println("web2 >>> " + Integer.toString(bs.size()) + " ");// + bs.toString());

                        webSocket.send(bs);//new String(protobufData)) ;//ByteString.of(protobufData));
                        Log.i(TAG, "Send IP packet");
                    } catch (Exception e) {
                        Log.e(TAG, "Error parsing or packet data: " + e.getMessage());
                    }
                }
            } else {
                Log.i(TAG, "ACTION: " + recvAction);
            }
        }
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            Log.i(TAG, "=== WebSocket.onStartCommand ===");
            String host = intent.getStringExtra("host");
            Integer port = intent.getIntExtra("port", 443);
            String username = intent.getStringExtra("username");
            String password = intent.getStringExtra("password");

            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("SEND_TO_WEBSOCKET");

            LocalBroadcastManager.getInstance(this).registerReceiver(broadcastReceiver, new IntentFilter("SEND_TO_WEBSOCKET"));

//            registerReceiver(broadcastReceiver, intentFilter);

//            appCtx.registerReceiver

            isRunning.set(true);
            webSocketThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    FptnWebSocketService.this.runWebSocketConnection(
                            host, port, username, password
                    );
                }
            });
            webSocketThread.start();
        }
        return START_NOT_STICKY;
        //return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public void onDestroy() {
        isRunning.set(false);
        if (webSocketThread != null) {
            try {
                webSocketThread.join();
            } catch (Exception e) {
                Log.i(TAG, "=== webSocketThread:err: " + e.getMessage());
            }
        }
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
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


