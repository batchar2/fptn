package org.fptn.client.services;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.fptn.client.R;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

public class FptnVpnService extends VpnService {
    public static final String ACTION_VPN_CONNECTED = "org.fptn.client.services";
    private static final String TAG = "FptnVpnService";
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ParcelFileDescriptor vpnInterface;
    private String serverHost;
    private int serverPort;
    private String username;
    private String password;
    private Handler handler = new Handler(Looper.getMainLooper());
    private static FptnVpnService instance;



    Thread vpnThread = null;

    public ParcelFileDescriptor getVpnInterface() {
        return vpnInterface;
    }
    public static FptnVpnService getInstance() {
        return instance;
    }


    @Override
    public void onCreate() {
        instance = this;
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            vpnThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    FptnVpnService.this.runVpnConnection();
                }
            });
            vpnThread.start();
        }
        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public void onDestroy() {
        stopVpnConnection();
        super.onDestroy();
    }

    private void runVpnConnection() {
        try {
            if (establishedVpnConnection()) {
                Log.i(TAG, "+++++");
                readFromVpnInterface();
            } else {
                Log.i(TAG, "ERROR");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error during VPN connection: " + e.getMessage());
        } finally {
            stopVpnConnection();
        }
    }

    private boolean establishedVpnConnection() throws IOException {
        if (vpnInterface == null) {
            Builder builder = new Builder();
            builder.addAddress("10.10.0.1", 32);
            builder.addRoute("0.0.0.0", 0);

            vpnInterface = builder.setSession(getString(R.string.app_name))
                    .setConfigureIntent(null)
                    .establish();
            return vpnInterface != null;
        } else {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    onVpnConnectionSuccess();
                    Toast.makeText(FptnVpnService.this, "Vpn connection Already Establiched", Toast.LENGTH_SHORT).show();
                }
            });
        }
        return true;
    }

    private void stopVpnConnection() {
        isRunning.set(false);
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing VPN Interface: " + e.getMessage());
            }
        }
    }

    private void readFromVpnInterface() throws IOException {
        isRunning.set(true);
        ByteBuffer buffer = ByteBuffer.allocate(65536);

        while (isRunning.get()) {
            try {
                FileInputStream inputStream = new FileInputStream(vpnInterface.getFileDescriptor());
                int length = inputStream.read(buffer.array());
                if (length > 0) {
                    String receivedData = new String(buffer.array(), 0, length);
                    // broadcast to receiver
                    Intent intent = new Intent("received_data_from_vpn");
                    intent.putExtra("data", receivedData);
                    LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error reading data from VPN interface: " + e.getMessage());
            }
        }
    }

    private void writeToNetwork(ByteBuffer buffer, int length) {
        String processData = new String(buffer.array(), 0, length);
        try {
            // socket here

        } catch (Exception e) {
            Log.e(TAG, "Error sending data to VPN the server: " + e.getMessage());
        }
    }

    private void onVpnConnectionSuccess()
    {
        // notify main activity
        Intent intent = new Intent(ACTION_VPN_CONNECTED);
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }
}
