package org.fptn.client.service.vpn;

import android.app.Service;
import android.content.Intent;
import android.net.VpnService;
import android.os.Binder;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;



public class FptnVpnService extends VpnService { //implements Runnable {
//    private static FptnVpnService instance = null; // Singleton instance

    private static final String VPN_ADDRESS = "10.10.10.1"; // Only IPv4 support for now
    private static final String VPN_ROUTE = "0.0.0.0"; // Intercept everything


    private static final String LOG_TAG = "FptnVpnService";

    private VpnServiceCallback callback;
//    String dnsServer;
    private ParcelFileDescriptor vpnInterface = null;
    private Thread thread;

    private FileOutputStream out = null;

    private static final String TAG = "FptnVpnService";
    private static final int MTU_SIZE = 1500;


    private final IBinder binder = new FptnVpnServiceBinder();


    public class FptnVpnServiceBinder extends Binder {
        public FptnVpnService getService() {
            // Return this instance of LocalService so clients can call public methods.
            return FptnVpnService.this;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

//    public static FptnVpnService getInstance() {
//        return instance;
//    }

    public void setCallback(VpnServiceCallback callback) {
        this.callback = callback;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        Log.i(TAG, "onCreateFptnVpnService");
    }


    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand");
        try {
            Log.i(LOG_TAG, "onStartCommand++");
            String dnsServer = intent.getStringExtra("dnsServer");
//        if (instance == null) {
//            instance = this;
//        }
            Builder builder = new Builder();
            builder //.setSession("FptnVPN")
                    .addAddress(VPN_ADDRESS, 24)
                    .addRoute(VPN_ROUTE, 0)

                    ;
//                    .addDnsServer(dnsServer)
//                    .setMtu(MTU_SIZE);

//            builder.addAllowedApplication("org.fptn.client.service.vpn");

            vpnInterface = builder.establish();
            if (vpnInterface != null) {
                Log.i(LOG_TAG, "onStartCommand++START");
//                thread = new Thread(this);
//                thread.start();
            } else {
                Log.i(LOG_TAG, "onStartCommand++EMPTY");
            }
        } catch (Exception err) {
            Log.e(LOG_TAG, "Exception: " + err.getMessage());
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (thread != null) {
            stopVpn();
            thread.interrupt();
        }
//        instance = null;
        super.onDestroy();
    }

//    @Override
//    public void run() {
//        try {
//            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
//            out = new FileOutputStream(vpnInterface.getFileDescriptor());
//
//            ByteBuffer packetBuffer = ByteBuffer.allocate(MTU_SIZE);
//            while (!Thread.interrupted()) {
//                packetBuffer.clear();
//                int length = in.read(packetBuffer.array());
//
//                if (length > 0) {
//                    byte[] packetData = new byte[length];
//                    packetBuffer.get(packetData, 0, length);
//
//                    // Callback to send packet to client
//                    callback.onMessageReceived(packetData);
//
//                    // Echo packet back to output stream
//                    out.write(packetData, 0, length);
//                }
//            }
//        } catch (Exception e) {
//            Log.e(TAG, "Error processing VPN packets", e);
//        } finally {
//            stopVpn();
//        }
//    }

    public boolean send(byte[] msg) {
        try {
            if (out != null) {
                out.write(msg, 0, msg.length);
                return true;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error send", e);
        }
        return false;
    }

    private void stopVpn() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                Log.e(TAG, "Failed to close VPN interface", e);
            }
            vpnInterface = null;
            Log.i(TAG, "VPN stopped");
        }
    }
}
