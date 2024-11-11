package org.fptn.client.activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

import com.google.protobuf.ByteString;

import org.fptn.client.R;

import org.fptn.client.service.FptnService;
import org.fptn.protocol.Protocol;
import org.fptn.protocol.Protocol.IPPacket;
import org.fptn.protocol.Protocol.Message;

public class MainActivity extends AppCompatActivity {

    private EditText editTextAddress;
    private EditText editTextUsername;
    private EditText editTextPassword;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        // PROTOCOL EXAMPLE
        IPPacket packet = IPPacket.newBuilder()
                .setPayload(ByteString.copyFromUtf8("IP-packet"))
                .setPaddingData(ByteString.copyFromUtf8("Random padding"))
                .build();
        Message msg = Message.newBuilder()
                .setProtocolVersion(1)
                .setMsgType(Protocol.MessageType.MSG_IP_PACKET)
                .setPacket(packet)
                .build();
    }

    public void startService(View view) {

        EditText editTextAddress = findViewById(R.id.editTextAddress);
        EditText editTextUsername = findViewById(R.id.editTextUsername);
        EditText editTextPassword = findViewById(R.id.editTextPassword);

        String host = editTextAddress.getText().toString();
        String username = editTextUsername.getText().toString();
        String password = editTextPassword.getText().toString();

        Intent serviceIntent = new Intent(this, FptnService.class);
        serviceIntent.putExtra("host", host);
        serviceIntent.putExtra("username", username);
        serviceIntent.putExtra("password", password);
        serviceIntent.putExtra("port", 443);

        startService(serviceIntent);
    }

    public void stopService(View view) {
        Intent serviceIntent = new Intent(this, FptnService.class);
        stopService(serviceIntent);
    }
}