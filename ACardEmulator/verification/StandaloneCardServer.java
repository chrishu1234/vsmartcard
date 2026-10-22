/* SPDX-License-Identifier: GPL-3.0-or-later */
import com.vsmartcard.acardemulator.emulators.mrtd.TravelDocumentEmulator;
import java.io.*;
import java.net.*;

/** Runs the APK's exact card implementation with its pinned BC 1.46 dependency. */
public final class StandaloneCardServer {
    public static void main(String[] args) throws Exception {
        TravelDocumentEmulator card = new TravelDocumentEmulator(args[0], args[1], args.length > 2 ? args[2] : "Valid", args.length > 3 && args[3].equals("displayed"), args.length > 4 && args[4].equals("details"), args.length > 5 && args[5].equals("security"), args.length > 9 && args[9].equals("biometric"));
        if(args.length>6)card.setChipScenario(args[6]);
        if(args.length>7)card.setRejectSelectMF(Boolean.parseBoolean(args[7]));
        if(args.length>8)card.setSelectMFResponse(Integer.parseInt(args[8],16));
        if(args.length>10)card.setRequireTerminalAuthentication(Boolean.parseBoolean(args[10]));
        if(args.length>11)card.setTerminalCertificateType(args[11]);
        if(args.length>13)card.setPACEProfile(args[12],Integer.parseInt(args[13]));
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            server.setSoTimeout(20000);
            System.out.println(server.getLocalPort()); System.out.flush();
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(20000);
                DataInputStream input = new DataInputStream(socket.getInputStream());
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                while (true) {
                    int length;
                    try { length = input.readUnsignedShort(); } catch (EOFException done) { break; }
                    byte[] command = new byte[length]; input.readFully(command);
                    byte[] response;
                    if (length == 1 && command[0] == 0) { card.deactivate(); response = new byte[] {(byte) 0x90, 0}; }
                    else response = card.process(command);
                    output.writeShort(response.length); output.write(response); output.flush();
                }
            }
        } finally { card.destroy(); }
    }
}
