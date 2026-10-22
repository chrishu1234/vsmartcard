/*
 * Copyright (C) 2015 Frank Morgner
 *
 * This file is part of ACardEmulator.
 *
 * ACardEmulator is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * ACardEmulator is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ACardEmulator.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.vsmartcard.acardemulator;

import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.cardemulation.CardEmulation;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.ImageView;
import android.widget.Spinner;
import android.widget.CheckBox;
import android.widget.ArrayAdapter;
import android.widget.AdapterView;
import android.view.WindowManager;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.vsmartcard.acardemulator.emulators.EmulatorSingleton;

import ACardEmulator.BuildConfig;
import ACardEmulator.R;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.util.Objects;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {

    private TextView textViewVPCDStatus;
    private TextView cardStatus;
    private CardEmulation foregroundCardEmulation;
    private final BroadcastReceiver bReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (Objects.requireNonNull(intent.getAction()).equals(EmulatorSingleton.TAG)) {
                String capdu = intent.getStringExtra(EmulatorSingleton.EXTRA_CAPDU);
                String rapdu = intent.getStringExtra(EmulatorSingleton.EXTRA_RAPDU);
                String error = intent.getStringExtra(EmulatorSingleton.EXTRA_ERROR);
                String deselect = intent.getStringExtra(EmulatorSingleton.EXTRA_DESELECT);
                String install = intent.getStringExtra(EmulatorSingleton.EXTRA_INSTALL);
                String status = intent.getStringExtra(EmulatorSingleton.EXTRA_STATUS);
                if (status != null && !status.isEmpty()) cardStatus.setText(status);
                textViewVPCDStatus.append(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "\n");
                if (textViewVPCDStatus.length() > 24000) textViewVPCDStatus.setText(textViewVPCDStatus.getText().subSequence(textViewVPCDStatus.length() - 16000, textViewVPCDStatus.length()));
                if (install != null)
                    textViewVPCDStatus.append(getResources().getString(R.string.status_install) + ":" + install + "\n");
                if (capdu != null)
                    textViewVPCDStatus.append(getResources().getString(R.string.status_capdu) + ": " + capdu + "\n");
                if (error != null)
                    textViewVPCDStatus.append(getResources().getString(R.string.status_error) + ": " + error + "\n");
                if (rapdu != null) {
                    textViewVPCDStatus.append(getResources().getString(R.string.status_rapdu) + ": " + rapdu + "\n");
                }
                if (deselect != null) {
                    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
                    boolean local = preferences.getString("emulator", getString(R.string.local_mrtd)).equals(getString(R.string.local_mrtd));
                    cardStatus.setText(local ? "Ready · " + preferences.getString("mrtd_auth", "PACE") : "Ready");
                }
                if (deselect != null)
                    textViewVPCDStatus.append(getResources().getString(R.string.status_disconnected) + ": " + deselect + "\n");
            }
        }
    };
    private AlertDialog dialog;
    final String PREFS = "ACardEmulatorPrefs";
    final String PREF_LASTVERSION = "last version";
    private static final String SAVED_STATUS = "textViewVPCDStatus";

    private void showStartupMessage() {
        if (dialog == null)
            dialog = new AlertDialog.Builder(this)
                    .setMessage(R.string.local_help)
                    .setTitle(R.string.startup_title)
                    .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                        }
                    }).create();
        dialog.show();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        PreferenceManager.setDefaultValues(this, R.xml.settings, false);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        assert fab != null;
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                EmulatorSingleton.destroyEmulator();
                EmulatorSingleton.createEmulator(MainActivity.this);
                refreshCardControls();
            }
        });

        textViewVPCDStatus = findViewById(R.id.textViewLog);
        cardStatus = findViewById(R.id.textViewCardStatus);
        setupSelector(R.id.documentFormat, "mrtd_format", new String[] {"TD1", "TD2", "TD3"}, "TD1");
        setupSelector(R.id.authenticationMode, "mrtd_auth", com.vsmartcard.acardemulator.emulators.mrtd.PACECardProfile.CHOICES, "PACE");
        setupSelector(R.id.paScenario, "mrtd_pa", new String[] {"Valid", "Altered DG1", "Bad signature", "Untrusted CSCA", "CMS RSA (SHA-384)", "CMS PSS (SHA-256)", "CMS ECDSA (SHA-512)", "ISO 39794 base", "ISO 39794 ICAO"}, "Valid");
        setupSelector(R.id.chipScenario, "mrtd_chip", new String[] {"Valid", "Bad AA signature", "Wrong CA key"}, "Valid");
        String mfFallback = PreferenceManager.getDefaultSharedPreferences(this).getBoolean("mrtd_reject_mf", false)
                ? "Reject (6A81)" : "Normal (9000)";
        setupSelector(R.id.selectMFResponse, "mrtd_mf_response",
                new String[] {"Normal (9000)", "Reject (6A81)", "Wrong length (6700)"}, mfFallback);
        CheckBox displayed = findViewById(R.id.displayedImages);
        CheckBox biometric = findViewById(R.id.biometricFiles);
        CheckBox terminalAuth = findViewById(R.id.terminalAuth);
        terminalAuth.setChecked(PreferenceManager.getDefaultSharedPreferences(this).getBoolean("mrtd_ta", false));
        terminalAuth.setOnCheckedChangeListener((button, checked) -> {
            PreferenceManager.getDefaultSharedPreferences(this).edit().putBoolean("mrtd_ta", checked).apply();
            EmulatorSingleton.destroyEmulator(); textViewVPCDStatus.setText(""); refreshCardControls();
        });
        biometric.setChecked(PreferenceManager.getDefaultSharedPreferences(this).getBoolean("mrtd_biometric", false));
        biometric.setOnCheckedChangeListener((button, checked) -> {
            PreferenceManager.getDefaultSharedPreferences(this).edit().putBoolean("mrtd_biometric", checked).apply();
            EmulatorSingleton.destroyEmulator(); textViewVPCDStatus.setText(""); refreshCardControls();
        });
        displayed.setChecked(PreferenceManager.getDefaultSharedPreferences(this).getBoolean("mrtd_displayed", false));
        displayed.setOnCheckedChangeListener((button, checked) -> {
            PreferenceManager.getDefaultSharedPreferences(this).edit().putBoolean("mrtd_displayed", checked).apply();
            EmulatorSingleton.destroyEmulator(); textViewVPCDStatus.setText(""); refreshCardControls();
        });
        CheckBox additionalDetails = findViewById(R.id.additionalDetails);
        additionalDetails.setChecked(PreferenceManager.getDefaultSharedPreferences(this).getBoolean("mrtd_details", false));
        additionalDetails.setOnCheckedChangeListener((button, checked) -> {
            PreferenceManager.getDefaultSharedPreferences(this).edit().putBoolean("mrtd_details", checked).apply();
            EmulatorSingleton.destroyEmulator(); textViewVPCDStatus.setText(""); refreshCardControls();
        });
        CheckBox securityFiles = findViewById(R.id.securityFiles);
        securityFiles.setChecked(PreferenceManager.getDefaultSharedPreferences(this).getBoolean("mrtd_security", false));
        securityFiles.setOnCheckedChangeListener((button, checked) -> {
            PreferenceManager.getDefaultSharedPreferences(this).edit().putBoolean("mrtd_security", checked).apply();
            EmulatorSingleton.destroyEmulator(); textViewVPCDStatus.setText(""); refreshCardControls();
        });
        SharedPreferences settings = getSharedPreferences(PREFS, 0);
        if (settings.getInt(PREF_LASTVERSION, 0) != BuildConfig.VERSION_CODE) {
            settings.edit().putInt(PREF_LASTVERSION, BuildConfig.VERSION_CODE).apply();
        }

        LocalBroadcastManager bManager = LocalBroadcastManager.getInstance(this);
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(EmulatorSingleton.TAG);
        bManager.registerReceiver(bReceiver, intentFilter);

        Intent serviceIntent = new Intent(this.getApplicationContext(), SmartcardProviderService.class);
        startService(serviceIntent);
    }

    private void setupSelector(int id, final String key, final String[] values, final String fallback) {
        Spinner spinner = findViewById(id);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, values);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        String current = PreferenceManager.getDefaultSharedPreferences(this).getString(key, fallback);
        for (int i = 0; i < values.length; i++) if (values[i].equals(current)) spinner.setSelection(i);
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long row) {
                SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                if (!values[position].equals(preferences.getString(key, fallback))) {
                    preferences.edit().putString(key, values[position]).apply();
                    EmulatorSingleton.destroyEmulator();
                    EmulatorSingleton.createEmulator(MainActivity.this);
                    textViewVPCDStatus.setText("");
                    refreshCardControls();
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
    }

    private void refreshCardControls() {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        String emulator = preferences.getString("emulator", getString(R.string.local_mrtd));
        boolean local = emulator.equals(getString(R.string.local_mrtd));
        findViewById(R.id.localCardControls).setVisibility(local ? View.VISIBLE : View.GONE);
        findViewById(R.id.dg2Preview).setVisibility(local ? View.VISIBLE : View.GONE);
        findViewById(R.id.paControls).setVisibility(local ? View.VISIBLE : View.GONE);
        findViewById(R.id.displayedImages).setVisibility(local ? View.VISIBLE : View.GONE);
        findViewById(R.id.biometricFiles).setVisibility(local ? View.VISIBLE : View.GONE);
        boolean biometrics = local && preferences.getBoolean("mrtd_biometric", false);
        findViewById(R.id.biometricPreviews).setVisibility(biometrics ? View.VISIBLE : View.GONE);
        findViewById(R.id.additionalDetails).setVisibility(local ? View.VISIBLE : View.GONE);
        findViewById(R.id.securityFiles).setVisibility(local ? View.VISIBLE : View.GONE);
        boolean displayed = preferences.getBoolean("mrtd_displayed", false);
        findViewById(R.id.displayedPreviews).setVisibility(local && displayed ? View.VISIBLE : View.GONE);
        String format = preferences.getString("mrtd_format", "TD1");
        boolean td1 = format.equals("TD1");
        boolean pace = !preferences.getString("mrtd_auth", "PACE").equals("BAC");
        String fixture = format.toLowerCase(java.util.Locale.ROOT) + "-" + (pace ? "pace" : "bac");
        String resource = fixture.replace('-', '_');
        setFixturePreview(R.id.fingerRightPreview, "dg3_" + resource + "_0");
        setFixturePreview(R.id.fingerLeftPreview, "dg3_" + resource + "_1");
        setFixturePreview(R.id.irisRightPreview, "dg4_" + resource + "_0");
        setFixturePreview(R.id.irisLeftPreview, "dg4_" + resource + "_1");
        ((TextView) findViewById(R.id.biometricPreviewInfo)).setText(biometrics ? loadDetailPreview("biometric", fixture) : "");
        findViewById(R.id.selectMFControls).setVisibility(local && !pace ? View.VISIBLE : View.GONE);
        TextView detailPreview = findViewById(R.id.additionalDetailsPreview);
        boolean showDetails = local && preferences.getBoolean("mrtd_details", false);
        detailPreview.setVisibility(showDetails ? View.VISIBLE : View.GONE);
        detailPreview.setText(showDetails ? loadDetailPreview("details", fixture) : "");
        TextView securityPreview = findViewById(R.id.securityFilesPreview);
        boolean showSecurity = local && preferences.getBoolean("mrtd_security", false);
        findViewById(R.id.terminalAuth).setVisibility(showSecurity && biometrics ? View.VISIBLE : View.GONE);
        securityPreview.setVisibility(showSecurity ? View.VISIBLE : View.GONE);
        findViewById(R.id.chipControls).setVisibility(showSecurity ? View.VISIBLE : View.GONE);
        securityPreview.setText(showSecurity ? loadDetailPreview("security", fixture).replace("AA: NOT_CHECKED", td1 ? "AA: RSA signing" : "AA: ECDSA signing").replace("CA: NOT_CHECKED", td1 ? "CA: DH / AES-128" : "CA: ECDH / AES-128") : "");
        setFixturePreview(R.id.dg2Preview, "dg2_" + resource);
        setFixturePreview(R.id.dg5Preview, "dg5_" + resource);
        setFixturePreview(R.id.dg7Preview, "dg7_" + resource);
        TextView details = findViewById(R.id.textViewCardDetails);
        details.setText(local ? getString(R.string.fixture_details, format.equals("TD3") ? "L898902C3" : "D23145890") : emulator);
        cardStatus.setText(local ? EmulatorSingleton.getStatus() : "Ready");
    }

    private void setFixturePreview(int viewId, String resourceName) {
        int resourceId = getResources().getIdentifier(resourceName, "drawable", getPackageName());
        if (resourceId == 0) throw new IllegalStateException("Missing test preview: " + resourceName);
        ((ImageView) findViewById(viewId)).setImageResource(resourceId);
    }

    private String loadDetailPreview(String kind, String fixture) {
        try (InputStream input = getClass().getResourceAsStream("/mrtd/" + kind + "-preview-" + fixture + ".txt")) {
            if (input == null) throw new IOException("Missing additional details preview: " + fixture);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024]; int count;
            while ((count = input.read(buffer)) != -1) {
                if (bytes.size() + count > 16384) throw new IOException("Additional details preview too large");
                bytes.write(buffer, 0, count);
            }
            return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException error) {
            Log.w("ACardEmulator", "Could not load additional details preview", error);
            return "Preview unavailable";
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle presses on the action bar items
        if (item.getItemId() == R.id.action_copy) {
            // Code to Copy the content of Text View to the Clip board.
            ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("simple text", textViewVPCDStatus.getText());
            clipboard.setPrimaryClip(clip);
            Toast.makeText(getApplicationContext(), "Log copied to clipboard.",
                    Toast.LENGTH_LONG).show();
            return true;
        } else if (item.getItemId() == R.id.action_delete) {
                textViewVPCDStatus.setText("");
            return true;
        } else if (item.getItemId() == R.id.action_help) {
            showStartupMessage();
            return true;
        } else if (item.getItemId() == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        } else {
            return super.onOptionsItemSelected(item);
        }
    }

    @Override
    public void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        textViewVPCDStatus.setText(savedInstanceState.getCharSequence(SAVED_STATUS));
    }
    @Override
    public void onSaveInstanceState(Bundle savedInstanceState) {
        savedInstanceState.putCharSequence(SAVED_STATUS, textViewVPCDStatus.getText());
        super.onSaveInstanceState(savedInstanceState);
    }

    @Override
    protected void onResume() {
        super.onResume();
        EmulatorSingleton.createEmulator(this);
        refreshCardControls();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null) {
            return;
        }
        try {
            CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
            ComponentName service = new ComponentName(this, EmulatorHostApduService.class);
            if (cardEmulation.setPreferredService(this, service)) {
                foregroundCardEmulation = cardEmulation;
                Log.i("ACardEmulator", "Foreground NFC service preference registered");
            } else {
                textViewVPCDStatus.append("Error: Could not enable foreground NFC routing.\n");
                Log.w("ACardEmulator", "Foreground NFC service preference was rejected");
            }
        } catch (RuntimeException error) {
            textViewVPCDStatus.append("Error: Could not enable foreground NFC routing.\n");
            Log.w("ACardEmulator", "Could not register foreground NFC service preference", error);
        }
    }

    @Override
    protected void onPause() {
        if (foregroundCardEmulation != null) {
            try {
                foregroundCardEmulation.unsetPreferredService(this);
                Log.i("ACardEmulator", "Foreground NFC service preference released");
            } catch (RuntimeException error) {
                Log.w("ACardEmulator", "Could not release foreground NFC service preference", error);
            } finally {
                foregroundCardEmulation = null;
            }
        }
        if (dialog != null)
            dialog.dismiss();
        super.onPause();
    }

    @Override protected void onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(bReceiver);
        super.onDestroy();
    }
}
