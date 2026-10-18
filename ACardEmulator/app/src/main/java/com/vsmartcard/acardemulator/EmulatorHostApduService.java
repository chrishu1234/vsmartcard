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

import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import android.util.Log;

import com.vsmartcard.acardemulator.emulators.EmulatorSingleton;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

public class EmulatorHostApduService extends HostApduService {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Object transactionLock = new Object();
    private int generation;
    private boolean destroyed;

    @Override
    public void onCreate() {
        super.onCreate();
        EmulatorSingleton.createEmulator(this);
    }

    @Override
    public byte[] processCommandApdu(byte[] capdu, Bundle extras) {
        final int requestGeneration;
        synchronized (transactionLock) {
            if (destroyed) {
                return new byte[] {0x6F, 0x00};
            }
            requestGeneration = generation;
        }
        final byte[] command = capdu.clone();
        try {
            worker.execute(new Runnable() {
                @Override
                public void run() {
                    synchronized (transactionLock) {
                        if (destroyed || requestGeneration != generation) {
                            return;
                        }
                    }
                    byte[] response;
                    try {
                        response = EmulatorSingleton.process(EmulatorHostApduService.this, command);
                    } catch (RuntimeException error) {
                        Log.e("ACardEmulator", "Could not process remote card APDU", error);
                        response = new byte[] {0x6F, 0x00};
                    }
                    synchronized (transactionLock) {
                        if (!destroyed && requestGeneration == generation && response != null) {
                            sendResponseApdu(response);
                        }
                    }
                }
            });
        } catch (RejectedExecutionException ignored) {
            return new byte[] {0x6F, 0x00};
        }
        // Network exchange must not block HostApduService's main-thread callback.
        return null;
    }

    @Override
    public void onDeactivated(int reason) {
        synchronized (transactionLock) {
            generation++;
        }
        Intent i = new Intent(EmulatorSingleton.TAG);

        Log.d("", "End transaction");
        switch (reason) {
            case DEACTIVATION_LINK_LOSS:
                i.putExtra(EmulatorSingleton.EXTRA_DESELECT, "link lost");
                break;
            case DEACTIVATION_DESELECTED:
                break;
        }

        if (reason == DEACTIVATION_LINK_LOSS || reason == DEACTIVATION_DESELECTED) {
            try {
                // Keep power-off ordered after an exchange that is already running,
                // and before commands from the next NFC transaction.
                worker.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            EmulatorSingleton.deactivate();
                        } catch (RuntimeException error) {
                            Log.e("ACardEmulator", "Could not deactivate card", error);
                        }
                    }
                });
            } catch (RejectedExecutionException ignored) {
                // The service is already being destroyed.
            }
        }

        LocalBroadcastManager.getInstance(this).sendBroadcast(i);
    }

    @Override
    public void onDestroy() {
        synchronized (transactionLock) {
            destroyed = true;
            generation++;
        }
        worker.shutdownNow();
        super.onDestroy();
    }
}
