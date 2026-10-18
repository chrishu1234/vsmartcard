package com.vsmartcard.acardemulator.emulators;

import org.junit.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

public class VICCEmulatorTest {
    private static final byte[] COMMAND = {0x00, (byte) 0xA4, 0x04, 0x0C};
    private static final byte[] OK = {(byte) 0x90, 0x00};
    private static final byte[] FAILURE = {0x6F, 0x00};

    private interface Scenario {
        void run(Socket socket) throws Exception;
    }

    private static class Backend implements AutoCloseable {
        final ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        final ExecutorService worker = Executors.newSingleThreadExecutor();
        final Future<?> result;
        volatile Socket connection;

        Backend(final Scenario scenario) throws Exception {
            result = worker.submit(() -> {
                try (Socket socket = listener.accept()) {
                    connection = socket;
                    socket.setSoTimeout(8000);
                    scenario.run(socket);
                } catch (Exception error) {
                    throw new RuntimeException(error);
                }
            });
        }

        VICCEmulator connect() {
            return new VICCEmulator("127.0.0.1", listener.getLocalPort());
        }

        void verify() throws Exception {
            result.get(10, TimeUnit.SECONDS);
        }

        @Override
        public void close() throws Exception {
            listener.close();
            if (connection != null) {
                connection.close();
            }
            worker.shutdownNow();
        }
    }

    private static byte[] readFrame(Socket socket) throws Exception {
        DataInputStream input = new DataInputStream(socket.getInputStream());
        byte[] frame = new byte[input.readUnsignedShort()];
        input.readFully(frame);
        return frame;
    }

    private static void respond(Socket socket, byte[] response) throws Exception {
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());
        output.writeShort(response.length);
        output.write(response);
        output.flush();
    }

    private static void readCommand(Socket socket) throws Exception {
        assertArrayEquals(new byte[] {0x01}, readFrame(socket));
        assertArrayEquals(COMMAND, readFrame(socket));
    }

    @Test(timeout = 4000)
    public void unavailableBackendReportsErrorOutsideCallingThread() throws Exception {
        int closedPort;
        try (ServerSocket listener = new ServerSocket(0)) {
            closedPort = listener.getLocalPort();
        }
        CountDownLatch reported = new CountDownLatch(1);
        AtomicReference<Thread> reportingThread = new AtomicReference<>();
        Thread caller = Thread.currentThread();
        VICCEmulator emulator = new VICCEmulator("127.0.0.1", closedPort, message -> {
            reportingThread.set(Thread.currentThread());
            reported.countDown();
        });
        try {
            assertTrue(reported.await(2, TimeUnit.SECONDS));
            assertNotSame(caller, reportingThread.get());
            assertArrayEquals(FAILURE, emulator.process(COMMAND));
        } finally {
            emulator.destroy();
        }
    }

    @Test(timeout = 4000)
    public void receivesFragmentedResponseWithTwoByteLength() throws Exception {
        byte[] response = new byte[302];
        for (int index = 0; index < 300; index++) {
            response[index] = (byte) index;
        }
        response[300] = (byte) 0x90;
        try (Backend backend = new Backend(socket -> {
            readCommand(socket);
            socket.getOutputStream().write(response.length >> 8);
            socket.getOutputStream().flush();
            Thread.sleep(20);
            socket.getOutputStream().write(response.length & 0xFF);
            socket.getOutputStream().write(response, 0, 3);
            socket.getOutputStream().flush();
            Thread.sleep(20);
            socket.getOutputStream().write(response, 3, response.length - 3);
            socket.getOutputStream().flush();
        })) {
            VICCEmulator emulator = backend.connect();
            try {
                assertArrayEquals(response, emulator.process(COMMAND));
                backend.verify();
            } finally {
                emulator.destroy();
            }
        }
    }

    @Test(timeout = 4000)
    public void truncatedResponseReturnsFailureInsteadOfNull() throws Exception {
        try (Backend backend = new Backend(socket -> {
            readCommand(socket);
            socket.getOutputStream().write(new byte[] {0x00, 0x04, (byte) 0x90});
            socket.getOutputStream().flush();
        })) {
            VICCEmulator emulator = backend.connect();
            try {
                assertArrayEquals(FAILURE, emulator.process(COMMAND));
                backend.verify();
            } finally {
                emulator.destroy();
            }
        }
    }

    @Test(timeout = 9000)
    public void stalledBackendHasBoundedResponseTimeout() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        try (Backend backend = new Backend(socket -> {
            readCommand(socket);
            assertTrue(release.await(7, TimeUnit.SECONDS));
        })) {
            VICCEmulator emulator = backend.connect();
            try {
                long started = System.nanoTime();
                assertArrayEquals(FAILURE, emulator.process(COMMAND));
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                assertTrue("Response timed out too soon: " + elapsedMs, elapsedMs >= 4500);
                assertTrue("Response did not time out: " + elapsedMs, elapsedMs < 7500);
                release.countDown();
                backend.verify();
            } finally {
                release.countDown();
                emulator.destroy();
            }
        }
    }

    @Test(timeout = 4000)
    public void deactivationDoesNotWaitForExchangeAndNextTapPowersOnAgain() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try (Backend backend = new Backend(socket -> {
            readCommand(socket);
            received.countDown();
            assertTrue(release.await(2, TimeUnit.SECONDS));
            respond(socket, OK);
            assertArrayEquals(new byte[] {0x00}, readFrame(socket));
            readCommand(socket);
            respond(socket, OK);
        })) {
            VICCEmulator emulator = backend.connect();
            try {
                Future<byte[]> first = caller.submit(() -> emulator.process(COMMAND));
                assertTrue(received.await(2, TimeUnit.SECONDS));
                long started = System.nanoTime();
                emulator.deactivate();
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 250);
                release.countDown();
                assertArrayEquals(OK, first.get(2, TimeUnit.SECONDS));
                assertArrayEquals(OK, emulator.process(COMMAND));
                backend.verify();
            } finally {
                release.countDown();
                emulator.destroy();
            }
        } finally {
            caller.shutdownNow();
        }
    }

    @Test(timeout = 4000)
    public void destroyingEmulatorInterruptsPendingRead() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try (Backend backend = new Backend(socket -> {
            readCommand(socket);
            received.countDown();
            assertEquals(-1, socket.getInputStream().read());
        })) {
            VICCEmulator emulator = backend.connect();
            try {
                Future<byte[]> pending = caller.submit(() -> emulator.process(COMMAND));
                assertTrue(received.await(2, TimeUnit.SECONDS));
                emulator.destroy();
                assertArrayEquals(FAILURE, pending.get(2, TimeUnit.SECONDS));
                assertArrayEquals(FAILURE, emulator.process(COMMAND));
                backend.verify();
            } finally {
                emulator.destroy();
            }
        } finally {
            caller.shutdownNow();
        }
    }
}
