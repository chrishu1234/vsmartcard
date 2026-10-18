package com.vsmartcard.acardemulator.emulators;

import android.util.Log;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class VICCEmulator implements Emulator {
    public static final int DEFAULT_PORT = 35963;
    public static final String DEFAULT_HOSTNAME = "10.0.2.2";

    private static final String TAG = "VICCEmulator";
    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int RESPONSE_TIMEOUT_MS = 5000;
    private static final int REQUEST_TIMEOUT_MS = 12000;

    public interface ErrorListener {
        void onError(String message);
    }

    private final String hostname;
    private final int port;
    private final ErrorListener errorListener;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "VICC-connection");
            thread.setDaemon(true);
            return thread;
        }
    });
    private volatile Socket socket;
    private volatile boolean destroyed;
    // Only the connection worker accesses the streams and power state.
    private DataInputStream inputStream;
    private OutputStream outputStream;
    private boolean poweredOn;

    public VICCEmulator(String hostname, int port) {
        this(hostname, port, null);
    }

    public VICCEmulator(String hostname, int port, ErrorListener errorListener) {
        this.hostname = hostname;
        this.port = port;
        this.errorListener = errorListener;
        // Services are created on Android's main thread. Never connect there.
        worker.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    ensureConnected();
                } catch (IOException | RuntimeException error) {
                    connectionFailed(error);
                }
            }
        });
    }

    @Override
    public void deactivate() {
        if (destroyed) {
            return;
        }
        try {
            worker.execute(new Runnable() {
                @Override
                public void run() {
                    if (socket == null || !poweredOn) {
                        return;
                    }
                    try {
                        sendToVPCD(new byte[] {0x00});
                        poweredOn = false;
                    } catch (IOException | RuntimeException error) {
                        connectionFailed(error);
                    }
                }
            });
        } catch (RejectedExecutionException ignored) {
            // The emulator was destroyed while this operation was being queued.
        }
    }

    @Override
    public void destroy() {
        destroyed = true;
        // Closing the socket also interrupts a pending connect/read without waiting
        // for the worker from the UI or NFC lifecycle callback.
        closeSocket();
        worker.shutdownNow();
    }

    @Override
    public byte[] process(final byte[] commandAPDU) {
        if (destroyed || commandAPDU == null) {
            return failureResponse();
        }
        Future<byte[]> result = null;
        try {
            result = worker.submit(new java.util.concurrent.Callable<byte[]>() {
                @Override
                public byte[] call() {
                    try {
                        ensureConnected();
                        sendToVPCD(commandAPDU);
                        return receiveFromVPCD();
                    } catch (IOException | RuntimeException error) {
                        connectionFailed(error);
                        return failureResponse();
                    }
                }
            });
            return result.get(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            if (result != null) {
                result.cancel(true);
            }
            closeSocket();
        } catch (ExecutionException | TimeoutException | RejectedExecutionException error) {
            if (result != null) {
                result.cancel(true);
            }
            closeSocket();
            reportError(error);
        }
        return failureResponse();
    }

    private static byte[] failureResponse() {
        return new byte[] {0x6F, 0x00};
    }

    private byte[] receiveFromVPCD() throws IOException {
        int length = inputStream.readUnsignedShort();
        if (length < 2) {
            throw new IOException("Remote card returned an incomplete response APDU");
        }
        byte[] data = new byte[length];
        inputStream.readFully(data);
        return data;
    }

    private void sendToVPCD(byte[] data) throws IOException {
        if (outputStream == null || data.length > 0xFFFF) {
            throw new IOException("Remote card connection is unavailable");
        }
        byte[] frame = new byte[data.length + 2];
        frame[0] = (byte) (data.length >> 8);
        frame[1] = (byte) (data.length & 0xFF);
        System.arraycopy(data, 0, frame, 2, data.length);
        outputStream.write(frame);
        outputStream.flush();
    }

    private void ensureConnected() throws IOException {
        if (destroyed) {
            throw new IOException("Remote card emulator has been closed");
        }
        if (socket == null || socket.isClosed()) {
            disconnect();
            Log.d(TAG, "Connecting to " + hostname + ":" + port);
            Socket connection = new Socket();
            socket = connection;
            if (destroyed) {
                connection.close();
                throw new IOException("Remote card emulator has been closed");
            }
            connection.connect(new InetSocketAddress(hostname, port), CONNECT_TIMEOUT_MS);
            connection.setSoTimeout(RESPONSE_TIMEOUT_MS);
            connection.setTcpNoDelay(true);
            outputStream = connection.getOutputStream();
            inputStream = new DataInputStream(connection.getInputStream());
        }
        if (!poweredOn) {
            sendToVPCD(new byte[] {0x01});
            poweredOn = true;
        }
    }

    private void connectionFailed(Exception error) {
        disconnect();
        reportError(error);
    }

    private void reportError(Exception error) {
        if (destroyed) {
            return;
        }
        String detail = error.getMessage();
        if (detail == null || detail.isEmpty()) {
            detail = error.getClass().getSimpleName();
        }
        Log.e(TAG, "Remote card connection failed: " + detail, error);
        if (errorListener != null) {
            errorListener.onError("Remote card connection failed: " + detail
                    + ". Check the Windows backend and network, then try again.");
        }
    }

    private void disconnect() {
        closeSocket();
        socket = null;
        inputStream = null;
        outputStream = null;
        poweredOn = false;
    }

    private void closeSocket() {
        Socket connection = socket;
        if (connection != null) {
            try {
                connection.close();
            } catch (IOException ignored) {
                // The connection is already unusable.
            }
        }
    }
}
