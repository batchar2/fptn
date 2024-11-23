package org.fptn.client.services;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.IpPrefix;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.google.protobuf.ByteString;

import org.fptn.client.R;
import org.fptn.protocol.Protocol;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

public class FptnVpnService extends VpnService {
    public static final String ACTION_VPN_CONNECTED = "org.fptn.client.services";
    private static final String TAG = "FptnVpnService";
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ParcelFileDescriptor vpnInterface;
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
            String vpnHost = intent.getStringExtra("host");
            vpnThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    FptnVpnService.this.runVpnConnection(vpnHost);
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

    private boolean establishedVpnConnection(String vpnHost) throws IOException {
        isRunning.set(true);
        if (vpnInterface == null) {
            Builder builder = new Builder();
//            builder.excludeRoute(vpnHost)
//            builder.excludeRoute(new IpPrefix(vpnHost));
            builder.addAddress("10.10.0.1", 32);
            builder.addRoute("0.0.0.0", 0);

            vpnInterface = builder.setSession(getString(R.string.app_name))
                    .setConfigureIntent(null)
                    .establish();
//            builder.excludeAddress();
            builder.setHttpProxy(ProxyInfo.buildDirectProxy(vpnHost, 443));
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

    private byte[] ipPacketToProtobuf(ByteBuffer data) {
        Protocol.IPPacket packet = Protocol.IPPacket.newBuilder()
                .setPayload(ByteString.copyFrom(data))
                //.setPaddingData(ByteString.copyFromUtf8("Random padding"))
                .build();
        Protocol.Message msg = Protocol.Message.newBuilder()
                .setProtocolVersion(1)
                .setMsgType(Protocol.MessageType.MSG_IP_PACKET)
                .setPacket(packet)
                .build();
        return msg.toByteArray();
    }

    private void readFromVpnInterface(FileInputStream inputStream) { //throws IOException {
        Log.i(TAG, "=== readFromVpnInterface:start ===");
        String action = getString(R.string.action_send_to_websocket);
        String intentName = getString(R.string.action_send_intent_name_protobuf_data);
        ByteBuffer buffer = ByteBuffer.allocate(65536);
        while (isRunning.get()) {
            try {
                int length = inputStream.read(buffer.array());
                if (length > 0) {
//                    Log.i(TAG, "READ PACKET");
                    // send to websocket service
                    Intent intent = new Intent(action);

                    byte[] rawData = ipPacketToProtobuf(buffer);
                    Log.i(TAG, "from tun> " + Integer.toString(length) + "  " +  Integer.toString(rawData.length) + "  " +  Arrays.toString(rawData));

                    intent.putExtra(intentName, rawData);
                    LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
//                    Log.w(TAG, "Read IP packet");
                }
            } catch (Exception e) {
                Log.e(TAG, "Error reading data from VPN interface: " + e.getMessage());
            }
        }
        Log.i(TAG, "=== readFromVpnInterface:stop ===");
    }
    private void writeToVpnInterface(FileOutputStream outputStream) {
        //recv data from websocket
        Log.i(TAG, "=== writeToVpnInterface:start ===");
        String action = getString(R.string.action_send_to_tun_interface);
        String intentName = getString(R.string.action_send_intent_name_protobuf_data);

        BroadcastReceiver packetReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent.getAction() != null && intent.getAction().equals(action)) {
                    byte[] protobufData = intent.getByteArrayExtra(intentName);
                    if (protobufData != null) {
                        try {
                            // Parse the protobuf data back into an IP packet
                            Protocol.Message message = Protocol.Message.parseFrom(protobufData);
                            if (message.getMsgType() == Protocol.MessageType.MSG_IP_PACKET) {
                                Log.w(TAG, "Write IP packet");
                                byte[] rawData = message.getPacket().getPayload().toByteArray();
                                outputStream.write(rawData);
                            } else {
                                Log.w(TAG, "Received a non-IP packet message type.");
                            }
                        } catch (IOException e) {
                            Log.e(TAG, "Error parsing or writing IP packet data: " + e.getMessage());
                        }
                    }
                }
            }
        };
        LocalBroadcastManager.getInstance(this).registerReceiver(packetReceiver, new IntentFilter(action));
        try {
            while (isRunning.get()) {
                Thread.sleep(100); // Sleep to prevent busy-waiting
            }
        } catch (InterruptedException e) {
            Log.e(TAG, "Writer thread interrupted: " + e.getMessage());
        } finally {
            // Cleanup: Unregister the broadcast receiver
            LocalBroadcastManager.getInstance(this).unregisterReceiver(packetReceiver);
            try {
                outputStream.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing output stream: " + e.getMessage());
            }
        }
        Log.i(TAG, "=== writeToVpnInterface:stop ===");
    }

    private void onVpnConnectionSuccess() {
        // notify main activity
        Intent intent = new Intent(ACTION_VPN_CONNECTED);
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }


    private void runVpnConnection(String vpnHost) {
        try {
            if (establishedVpnConnection(vpnHost)) {
                Log.i(TAG, "=== runTunInterface ===");
                FileInputStream inputTunInterfaceStream = new FileInputStream(vpnInterface.getFileDescriptor());
                FileOutputStream outputTunInterfaceStream = new FileOutputStream(vpnInterface.getFileDescriptor());

                Thread readerThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        FptnVpnService.this.readFromVpnInterface(inputTunInterfaceStream);
                    }
                });
                Thread writerThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        FptnVpnService.this.writeToVpnInterface(outputTunInterfaceStream);
                    }
                });
                writerThread.start();
                readerThread.start();

                readerThread.join();
                writerThread.join();
            } else {
                Log.i(TAG, "ERROR");
            }
        } catch (IOException e) {
            Log.e(TAG, "IOException during VPN connection: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "Error during VPN connection: " + e.getMessage());
        } finally {
            stopVpnConnection();
        }
    }
}

