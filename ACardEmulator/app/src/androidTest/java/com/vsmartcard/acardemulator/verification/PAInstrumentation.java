/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.verification;

import android.app.Instrumentation;
import android.app.Activity;
import android.os.Bundle;
import java.io.*;
import java.util.Date;
import com.vsmartcard.acardemulator.emulators.mrtd.TravelDocumentEmulator;

/** Headless only: no activities, NFC, settings, taps or real identity data. */
public final class PAInstrumentation extends Instrumentation {
    private byte[] asset(String name) throws Exception { return bytes(getContext().getAssets().open(name)); }
    private byte[] resource(String name) throws Exception { return bytes(TravelDocumentEmulator.class.getResourceAsStream("/mrtd/" + name)); }
    private byte[] bytes(InputStream input) throws Exception {
        if (input == null) throw new IOException("Missing test resource");
        try (InputStream stream = input; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] b = new byte[4096]; int n; while ((n = stream.read(b)) != -1) out.write(b, 0, n); return out.toByteArray();
        }
    }
    private void require(boolean value, String name) { if (!value) throw new AssertionError(name); }
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }
    @Override public void onStart() {
        Bundle result = new Bundle(); int count = 0;
        try {
            byte[] root = resource("test-csca.der");
            for (String format : new String[]{"td1", "td3"}) for (String mode : new String[]{"bac", "pace"}) {
                String id = format + "-" + mode;
                byte[] dg1 = asset("dg1-" + id + ".bin"), dg2 = asset("dg2-" + id + ".bin"), sod = resource("sod-" + id + ".bin");
                PAOracle.Result valid = PAOracle.verify(sod, dg1, dg2, root, new Date());
                require(valid.passed(), id + " valid SOD/hash/native PKIX"); count++;
                byte[] altered = dg1.clone(); altered[altered.length - 1] ^= 1;
                PAOracle.Result badDG = PAOracle.verify(sod, altered, dg2, root, new Date());
                require(!badDG.dg1 && badDG.dg2 && badDG.signature && badDG.trust, id + " altered DG1"); count++;
                PAOracle.Result badSig = PAOracle.verify(resource("sod-bad-signature-" + id + ".bin"), dg1, dg2, root, new Date());
                require(badSig.dg1 && badSig.dg2 && !badSig.signature && badSig.trust, id + " bad signature"); count++;
                PAOracle.Result untrusted = PAOracle.verify(resource("sod-untrusted-" + id + ".bin"), dg1, dg2, root, new Date());
                require(untrusted.dg1 && untrusted.dg2 && untrusted.signature && !untrusted.trust, id + " untrusted CSCA"); count++;
                require(!PAOracle.verify(sod, dg1, dg2, null, new Date()).trust, id + " no implicit trust"); count++;
                require(!PAOracle.verify(sod, dg1, dg2, root, new Date(2240611200000L)).trust, id + " expired certificate"); count++;
                Bundle progress = new Bundle(); progress.putString("stream", "PASS " + id + " native RSA / PKIX and negative cases\n"); sendStatus(0, progress);
            }
            result.putString("stream", "PASS " + count + " Android headless PA checks; no UI or NFC used.\n");
            result.putInt("passed", count); finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("stream", "FAIL after " + count + " checks: " + android.util.Log.getStackTraceString(error)); finish(Activity.RESULT_CANCELED, result);
        }
    }
}
