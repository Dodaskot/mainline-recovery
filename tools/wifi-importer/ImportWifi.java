package org.a22x.wifi;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.wifi.WifiNetworkSuggestion;
import android.os.Bundle;
import android.provider.Settings;
import android.util.AtomicFile;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Locale;

public final class ImportWifi extends Activity {
    private static final int SAVE_NETWORKS = 1;
    private String digest;
    private int count;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        digest = getIntent().getStringExtra("sha256");
        if (digest == null || !digest.matches("[0-9a-f]{64}")) {
            finish();
            return;
        }
        TextView message = new TextView(this);
        message.setText("Review the networks in Android Settings.");
        setContentView(message);
        if (state != null) {
            count = state.getInt("count");
            return;
        }
        try {
            File request = new File(getFilesDir(), "wifi.json");
            if (request.length() > 16384) throw new IllegalArgumentException();
            byte[] bytes = Files.readAllBytes(request.toPath());
            deleteFile("wifi.json");
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder actual = new StringBuilder(64);
            for (byte value : hash) actual.append(String.format(Locale.ROOT, "%02x", value & 255));
            if (!digest.contentEquals(actual)) throw new SecurityException();
            JSONArray rows = new JSONObject(new String(bytes, StandardCharsets.UTF_8)).getJSONArray("networks");
            count = rows.length();
            if (count < 1 || count > 5) throw new IllegalArgumentException();
            ArrayList<WifiNetworkSuggestion> networks = new ArrayList<>();
            for (int i = 0; i < count; ++i) {
                JSONObject row = rows.getJSONObject(i);
                WifiNetworkSuggestion.Builder network = new WifiNetworkSuggestion.Builder()
                    .setSsid(row.getString("ssid")).setIsHiddenSsid(row.getBoolean("hidden"));
                switch (row.getString("security")) {
                    case "nopass": break;
                    case "WPA": network.setWpa2Passphrase(row.getString("password")); break;
                    case "SAE": network.setWpa3Passphrase(row.getString("password")); break;
                    default: throw new IllegalArgumentException();
                }
                networks.add(network.build());
            }
            Intent intent = new Intent(Settings.ACTION_WIFI_ADD_NETWORKS);
            ResolveInfo settings = getPackageManager().resolveActivity(intent, PackageManager.MATCH_SYSTEM_ONLY);
            if (settings == null || settings.activityInfo == null || !settings.activityInfo.exported) {
                result("unsupported", null);
                return;
            }
            intent.setComponent(new ComponentName(settings.activityInfo.packageName, settings.activityInfo.name));
            intent.putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, networks);
            startActivityForResult(intent, SAVE_NETWORKS);
        } catch (Exception error) {
            result("error", null);
        }
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        state.putInt("count", count);
        super.onSaveInstanceState(state);
    }

    @Override protected void onActivityResult(int request, int outcome, Intent data) {
        super.onActivityResult(request, outcome, data);
        if (request != SAVE_NETWORKS) return;
        if (outcome == RESULT_CANCELED) {
            result("cancelled", null);
            return;
        }
        ArrayList<Integer> codes = data == null ? null : data.getIntegerArrayListExtra(Settings.EXTRA_WIFI_NETWORK_RESULT_LIST);
        if (outcome != RESULT_OK || codes == null || codes.size() != count) {
            result("unverified", null);
            return;
        }
        result("processed", codes);
    }

    private void result(String state, ArrayList<Integer> codes) {
        FileOutputStream output = null;
        AtomicFile destination = new AtomicFile(new File(getFilesDir(), "result-" + digest + ".json"));
        try {
            JSONObject row = new JSONObject().put("status", state).put("sha256", digest);
            if (codes != null) row.put("codes", new JSONArray(codes));
            output = destination.startWrite();
            output.write(row.toString().getBytes(StandardCharsets.UTF_8));
            destination.finishWrite(output);
        } catch (Exception error) {
            destination.failWrite(output);
        }
        finish();
    }
}
