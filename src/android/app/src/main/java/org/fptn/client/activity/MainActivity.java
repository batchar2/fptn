package org.fptn.client.activity;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.google.protobuf.ByteString;

import org.fptn.client.R;

import org.fptn.client.models.ServiceInfo;
import org.fptn.client.services.FptnVpnService;
import org.fptn.client.services.FptnWebSocketService;
import org.fptn.protocol.Protocol;
import org.fptn.protocol.Protocol.IPPacket;
import org.fptn.protocol.Protocol.Message;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private static final int VPN_REQUEST_CODE = 1;

    private EditText editTextAddress;
    private EditText editTextUsername;
    private EditText editTextPassword;

    private ServiceInfo serviceInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        // PROTOCOL EXAMPLE
//        IPPacket packet = IPPacket.newBuilder()
//                .setPayload(ByteString.copyFromUtf8("IP-packet"))
//                .setPaddingData(ByteString.copyFromUtf8("Random padding"))
//                .build();
//        Message msg = Message.newBuilder()
//                .setProtocolVersion(1)
//                .setMsgType(Protocol.MessageType.MSG_IP_PACKET)
//                .setPacket(packet)
//                .build();

        LocalBroadcastManager.getInstance(this).registerReceiver(vpnConnectedReceiver, new IntentFilter(FptnVpnService.ACTION_VPN_CONNECTED));
    }

    public void startService(View view) {

        EditText editTextAddress = findViewById(R.id.editTextAddress);
        EditText editTextUsername = findViewById(R.id.editTextUsername);
        EditText editTextPassword = findViewById(R.id.editTextPassword);

        String host = editTextAddress.getText().toString();
        String username = editTextUsername.getText().toString();
        String password = editTextPassword.getText().toString();

        establishedVpnConnection(host, username, password);
    }

    private void establishedVpnConnection(String host, String username, String password) {
        Intent vpnIntent = VpnService.prepare(MainActivity.this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            startVpnServiceWithIp(host, username, password);
        }
    }

    private void startVpnServiceWithIp(String host, String username, String password) {
        Intent vpnIntent = new Intent(MainActivity.this, FptnVpnService.class);
        vpnIntent.putExtra("host", host);
        startService(vpnIntent);

        Intent webSocketIntent = new Intent(MainActivity.this, FptnWebSocketService.class);
        webSocketIntent.putExtra("host", host);
        webSocketIntent.putExtra("port", 443);
        webSocketIntent.putExtra("username", username);
        webSocketIntent.putExtra("password", password);
        startService(webSocketIntent);
    }

    public void stopService(View view) {
        Intent serviceIntent = new Intent(this, FptnVpnService.class);
        stopService(serviceIntent);
    }

    private BroadcastReceiver vpnConnectedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
        // succerss message
        Log.i(TAG, "RECV YES!!!!");
        }
    };

    private ServiceInfo parseJson()
    {
        return null;
    }
}