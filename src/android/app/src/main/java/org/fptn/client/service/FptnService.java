package org.fptn.client.service;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import org.fptn.client.service.vpn.FptnVpnService;
import org.fptn.client.service.vpn.VpnServiceCallback;
import org.fptn.client.service.websocket.WebSocketCallback;
import org.fptn.client.service.websocket.WebSocketClient;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FptnService extends Service {
    private ExecutorService webSocketExecutor;


    private WebSocketClient webSocket = null;
    private FptnVpnService vpnService = null;

    private static final String LOG_TAG = "FptnServiceTag";

    @Override
    public void onCreate() {
        super.onCreate();
        webSocketExecutor = Executors.newFixedThreadPool(1);
        Log.i(LOG_TAG, "onCreate+");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(LOG_TAG, "onStartCommand+");
        String host = intent.getStringExtra("host");
        Integer port = intent.getIntExtra("port", 0);
        String username = intent.getStringExtra("username");
        String password = intent.getStringExtra("password");


        webSocket = new WebSocketClient(
            host, port, username, password,
            new WebSocketCallback() {
                @Override
                public void onMessageReceived(byte[] msg) {
                    messageFromServer(msg);
                }
                @Override
                public void onError(Exception e) {
                }
            }
        );
        webSocketExecutor.execute(this.webSocket);

        Intent vpnServiceIntent = new Intent(this, FptnVpnService.class);
        vpnServiceIntent.putExtra("dnsServer", "172.20.0.1"); // example DNS
        this.startService(vpnServiceIntent);
//        this.bindService(vpnServiceIntent, vpnServiceConnection, Context.BIND_AUTO_CREATE);

        return super.onStartCommand(intent, flags, startId);
    }

//    private final ServiceConnection vpnServiceConnection = new ServiceConnection() {
//        @Override
//        public void onServiceConnected(ComponentName name, IBinder service) {
//            FptnVpnService.FptnVpnServiceBinder binder = (FptnVpnService.FptnVpnServiceBinder)service;
//            vpnService = binder.getService();
//            vpnService.setCallback(new VpnServiceCallback() {
//                @Override
//                public void onMessageReceived(byte[] msg) {
//                    messageToServer(msg);
//                }
//
//                @Override
//                public void onError(Exception e) {
//                    // Handle VPN service error
//                }
//            });
//        }
//
//        @Override
//        public void onServiceDisconnected(ComponentName name) {
////            vpnServiceBound = false;
//        }
//    };

    public boolean messageFromServer(byte[] msg)
    {
        if (vpnService != null) {
//            return vpnService.send(msg);
        }
        return false;
    }

    public boolean messageToServer(byte[] msg)
    {
        if (webSocket != null) {
            return webSocket.send(msg);
        }
        return false;
    }

    @Override
    public void onDestroy() {
        Log.i(LOG_TAG, "onDestroy");
        super.onDestroy();
    }

//    @Override
//    public void onStart(Intent intent, int startId) {
//        super.onStart(intent, startId);
//    }



    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        Log.i(LOG_TAG, "onBind");
        return null;
    }
//
//    @Override
//    public boolean onUnbind(Intent intent) {
//        Log.i(TAG, "onUnbind");
//        return super.onUnbind(intent);
//    }
}














//package org.fptn.client.service;
//
//import android.app.Service;
//import android.content.Intent;
//import android.os.IBinder;
//import android.util.Log;
//
//import androidx.annotation.Nullable;
//
//import java.util.concurrent.ExecutorService;
//import java.util.concurrent.Executors;
//
//public class FptnService extends Service {
//    private ExecutorService es;
//
//    private static final String LOG_TAG = "FptnServiceTag";
//
//    @Override
//    public void onCreate() {
//        super.onCreate();
//        es = Executors.newFixedThreadPool(1);
//        Log.i(LOG_TAG, "onCreate");
//    }
//
//    @Override
//    public int onStartCommand(Intent intent, int flags, int startId) {
//        Log.i(LOG_TAG, "onStartCommand");
//
//        // get params
////        String host = intent.getStringExtra("host");
////        Integer port = intent.getIntExtra("port", 433);
////        String username = intent.getStringExtra("username");
////        String password = intent.getStringExtra("password");
//
//        // run client
////        WebSocketClient client = new WebSocketClient(); //(host, port, username, password);
////        es.execute(client);
//        return super.onStartCommand(intent, flags, startId);
//    }
//
//    @Override
//    public void onDestroy() {
//        Log.i(LOG_TAG, "onDestroy");
//        super.onDestroy();
//    }
//
////    @Override
////    public void onStart(Intent intent, int startId) {
////        super.onStart(intent, startId);
////    }
//
//
//
//    @Nullable
//    @Override
//    public IBinder onBind(Intent intent) {
//        Log.i(LOG_TAG, "onBind");
//        return null;
//    }
////
////    @Override
////    public boolean onUnbind(Intent intent) {
////        Log.i(TAG, "onUnbind");
////        return super.onUnbind(intent);
////    }
//}
