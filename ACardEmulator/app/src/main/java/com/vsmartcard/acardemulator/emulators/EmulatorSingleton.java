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

package com.vsmartcard.acardemulator.emulators;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.XmlResourceParser;
import android.preference.PreferenceManager;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import android.util.Log;

import ACardEmulator.R;
import com.vsmartcard.acardemulator.Util;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import com.vsmartcard.acardemulator.emulators.mrtd.TravelDocumentEmulator;

public class EmulatorSingleton {
    public static final String TAG = "com.vsmartcard.acardemulator.EmulatorService";
    public static final String EXTRA_CAPDU = "MSG_CAPDU";
    public static final String EXTRA_RAPDU = "MSG_RAPDU";
    public static final String EXTRA_ERROR = "MSG_ERROR";
    public static final String EXTRA_DESELECT = "MSG_DESELECT";
    public static final String EXTRA_INSTALL = "MSG_INSTALL";
    public static final String EXTRA_STATUS = "MSG_STATUS";

    private static Emulator emulator = null;
    private static boolean do_destroy = false;
    private static Map<String, ?> activePreferences;

    private static void destroyEmulatorIfRequested(Context context) {
        if (do_destroy) {
            if (emulator != null) emulator.destroy();
            emulator = null;
            activePreferences = null;
            do_destroy = false;
            Intent i = new Intent(TAG);
            i.putExtra(EXTRA_DESELECT, "Uninstalled all applets.");
            LocalBroadcastManager.getInstance(context).sendBroadcast(i);
        }
    }

    public static synchronized void destroyEmulator() {
        do_destroy = true;
    }

    public static synchronized void createEmulator(Context context) {
        SharedPreferences SP = PreferenceManager.getDefaultSharedPreferences(context);
        Map<String, ?> preferences = new HashMap<>(SP.getAll());
        if (emulator != null && !preferences.equals(activePreferences)) do_destroy = true;
        // force reloading applets if requested
        destroyEmulatorIfRequested(context);

        if (emulator == null) {
            Log.d("", "Begin transaction");
            String str_emulator = SP.getString("emulator", context.getString(R.string.local_mrtd));
            if (str_emulator.equals(context.getString(R.string.local_mrtd))) {
                emulator = new TravelDocumentEmulator(SP.getString("mrtd_format", "TD1"), SP.getString("mrtd_auth", "PACE"), SP.getString("mrtd_pa", "Valid"), SP.getBoolean("mrtd_displayed", false), SP.getBoolean("mrtd_details", false), SP.getBoolean("mrtd_security", false));
            } else if (str_emulator.equals(context.getString(R.string.vicc))) {
                final Context applicationContext = context.getApplicationContext();
                emulator = new VICCEmulator(
                        SP.getString("hostname", VICCEmulator.DEFAULT_HOSTNAME),
                        Integer.parseInt(SP.getString("port", Integer.toString(VICCEmulator.DEFAULT_PORT))),
                        new VICCEmulator.ErrorListener() {
                            @Override
                            public void onError(String message) {
                                Intent intent = new Intent(TAG);
                                intent.putExtra(EXTRA_ERROR, message);
                                LocalBroadcastManager.getInstance(applicationContext)
                                        .sendBroadcast(intent);
                            }
                        });
            } else {
                emulator = new JCEmulator(context,
                        SP.getBoolean("activate_openpgp", false),
                        SP.getBoolean("activate_oath", false),
                        SP.getBoolean("activate_isoapplet", false),
                        SP.getBoolean("activate_pivapplet", false),
                        SP.getBoolean("activate_gidsapplet", false));
            }
            activePreferences = preferences;
        }
    }

    public static synchronized byte[] process(Context context, byte[] capdu) {
        createEmulator(context);
        byte[] rapdu = emulator.process(capdu);

        Intent i = new Intent(TAG);
        i.putExtra(EXTRA_CAPDU, Util.byteArrayToHexString(capdu));
        i.putExtra(EXTRA_STATUS, getStatus());
        if (rapdu != null)
            i.putExtra(EXTRA_RAPDU, Util.byteArrayToHexString(rapdu));
        LocalBroadcastManager.getInstance(context).sendBroadcast(i);

        return rapdu;
    }

    public static String[] getRegisteredAids(Context context) {
        List<String> aidList = new ArrayList<>();
        XmlResourceParser aidXmlParser = context.getResources().getXml(R.xml.aid_list);

        try {
            while (aidXmlParser.getEventType() != XmlPullParser.END_DOCUMENT) {
                if (aidXmlParser.getEventType() == XmlPullParser.START_TAG) {
                    if (aidXmlParser.getName().equals("aid-filter")) {
                        int aid = aidXmlParser.getAttributeResourceValue(0, -1);
                        if (aid != -1) {
                            aidList.add(context.getResources().getString(aid));
                        }
                    }
                }

                aidXmlParser.next();
            }

            aidXmlParser.close();
        } catch (XmlPullParserException | IOException e) {
            Log.e(TAG.substring(0, 23), "Couldn't parse aid xml list.");
        }

        return aidList.toArray(new String[0]);
    }

    public static synchronized String getStatus() {
        return emulator instanceof TravelDocumentEmulator ? ((TravelDocumentEmulator) emulator).getStatus() : "";
    }

    public static synchronized void deactivate() {
        if (emulator != null) emulator.deactivate();
    }
}
