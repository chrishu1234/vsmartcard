/* SPDX-License-Identifier: GPL-3.0-or-later
 * Independent reader uses the unmodified JMRTD 0.8.9 + BC 1.79 artifacts.
 */
import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.security.Security;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import java.util.Arrays;
import net.sf.scuba.smartcards.*;
import net.sf.scuba.util.Hex;
import org.jmrtd.*;
import org.jmrtd.protocol.*;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import java.nio.file.*;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;

public final class StandaloneReaderOracle {
    static byte[] h(String s) { return Hex.hexStringToBytes(s); }
    static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    static class Remote extends CardService {
        final Socket socket;
        final DataInputStream input;
        final DataOutputStream output;
        Remote(int port) throws Exception { socket = new Socket("127.0.0.1", port); socket.setSoTimeout(10000); input = new DataInputStream(socket.getInputStream()); output = new DataOutputStream(socket.getOutputStream()); }
        public void open() { }
        public boolean isOpen() { return !socket.isClosed(); }
        public byte[] getATR() { return new byte[0]; }
        public void close() { try { socket.close(); } catch (Exception ignored) { } }
        public boolean isConnectionLost(Exception e) { return socket.isClosed(); }
        ResponseAPDU raw(byte[] c) throws Exception { output.writeShort(c.length); output.write(c); output.flush(); byte[] response = new byte[input.readUnsignedShort()]; input.readFully(response); return new ResponseAPDU(response); }
        public ResponseAPDU transmit(CommandAPDU c) throws CardServiceException {
            try { return raw(c.getBytes()); }
            catch (Exception e) { throw new CardServiceException("Local card test exchange failed", e); }
        }
    }
    static ResponseAPDU plain(Remote card, String command) throws Exception { return card.transmit(new CommandAPDU(h(command))); }
    static ResponseAPDU secure(Remote card, SecureMessagingWrapper wrapper, CommandAPDU command) throws Exception {
        CommandAPDU protectedCommand = wrapper.wrap(command);
        ResponseAPDU response = card.transmit(protectedCommand);
        check(response.getData().length <= protectedCommand.getNe(), "Protected response exceeds outer Le");
        return wrapper.unwrap(response);
    }
    static void bootstrap(Remote card) throws Exception { check(plain(card, "00A4040C07A0000002471001").getSW() == 0x9000, "SELECT AID"); }
    static SecureMessagingWrapper authenticate(Remote card, String mode, String document, boolean can, boolean wrong) throws Exception {
        bootstrap(card);
        BACKey key = new BACKey(document, "740812", wrong ? "120416" : "120415");
        if (mode.equals("BAC")) return new BACProtocol(new BACAPDUSender(card), 256, true).doBAC(key).getWrapper();
        check(plain(card, "00A4000C").getSW() == 0x9000, "SELECT MF (JMRTD public sender encoding)");
        check(plain(card, "00A4020C02011C").getSW() == 0x9000, "SELECT EF.CardAccess");
        CardAccessFile access = new CardAccessFile(new ByteArrayInputStream(plain(card, "00B0000000").getData()));
        check(access.getSecurityInfos().size() == 1, "PACEInfo discovery");
        AccessKeySpec password = can ? PACEKeySpec.createCANKey(wrong ? "654321" : "123456") : key;
        return new PACEProtocol(new PACEAPDUSender(card), null, 256, true).doPACE(password, "0.4.0.127.0.7.2.2.4.2.2", PACEInfo.toParameterSpec(BigInteger.valueOf(13)), BigInteger.valueOf(13)).getWrapper();
    }
    static byte[] file(Remote card, SecureMessagingWrapper wrapper, int fid) throws Exception {
        check(secure(card, wrapper, new CommandAPDU(0, 0xA4, 2, 12, new byte[] {(byte) (fid >> 8), (byte) fid})).getSW() == 0x9000, "Protected SELECT");
        ResponseAPDU header = secure(card, wrapper, new CommandAPDU(0, 0xB0, 0, 0, 4));
        check(header.getSW() == 0x9000, "Protected header");
        byte[] prefix = header.getData();
        int length = prefix[1] & 255, headerSize = 2;
        if (length >= 128) {
            int count = length & 127;
            check(count > 0 && count <= 2 && prefix.length >= 2 + count, "Invalid fixture BER length");
            length = 0; headerSize += count;
            for (int i = 0; i < count; i++) length = length * 256 + (prefix[2 + i] & 255);
        }
        int size = headerSize + length;
        check(size >= 4 && size <= 8192, "Unexpected fixture size");
        ByteArrayOutputStream data = new ByteArrayOutputStream(); data.write(header.getData());
        while (data.size() < size) {
            int requested = Math.min(fid == 0x0102 ? 224 : 17, size - data.size());
            ResponseAPDU r = secure(card, wrapper, new CommandAPDU(0, 0xB0, data.size() >> 8, data.size() & 255, requested));
            if (r.getSW1() == 0x6C) {
                check(r.getSW2() == 223, "Short APDU length correction");
                r = secure(card, wrapper, new CommandAPDU(0, 0xB0, data.size() >> 8, data.size() & 255, r.getSW2()));
            }
            check(r.getSW() == 0x9000 && r.getData().length > 0 && r.getData().length <= requested, "Protected file chunk"); data.write(r.getData());
        }
        return data.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        Security.addProvider(Util.getBouncyCastleProvider());
        Remote card = new Remote(Integer.parseInt(args[0]));
        String format = args[1], mode = args[2], scenario = args[3], paScenario = args.length > 5 ? args[5] : "Valid";
        boolean can = scenario.equals("CAN");
        boolean displayed = args.length > 7 && args[7].equals("displayed");
        String document = format.equals("TD1") ? "D23145890" : "L898902C3";
        try {
            // A wrong MRZ/CAN must be rejected, and a subsequent valid attempt must recover.
            boolean refused = false;
            try { authenticate(card, mode, document, can, true); }
            catch (CardServiceException expected) { refused = true; }
            check(refused, "Incorrect access key accepted");
            SecureMessagingWrapper wrapper = authenticate(card, mode, document, can, false);
            check(secure(card, wrapper, new CommandAPDU(h("00A4040C07A0000002471001"))).getSW() == 0x9000, "Protected application SELECT");
            COMFile com = new COMFile(new ByteArrayInputStream(file(card, wrapper, 0x011E)));
            check(Arrays.equals(com.getTagList(), displayed ? new int[] {0x61, 0x75, 0x65, 0x67} : new int[] {0x61, 0x75}), "COM must declare the configured groups");
            byte[] dg1Bytes = file(card, wrapper, 0x0101);
            MRZInfo mrz = new DG1File(new ByteArrayInputStream(dg1Bytes)).getMRZInfo();
            check(mrz.getDocumentNumber().equals(document) && mrz.getDateOfBirth().equals("740812") && mrz.getDateOfExpiry().equals("120415"), "MRZ mismatch");
            check(mrz.getPrimaryIdentifier().equals(paScenario.equals("Altered DG1") ? "XRIKSSON" : "ERIKSSON") && mrz.getDocumentCode().startsWith(format.equals("TD1") ? "I" : "P"), "Wrong document format");
            byte[] dg2Bytes = file(card, wrapper, 0x0102);
            DG2File dg2 = new DG2File(new ByteArrayInputStream(dg2Bytes));
            check(dg2.getFaceInfos().size() == 1 && dg2.getFaceInfos().get(0).getFaceImageInfos().size() == 1, "DG2 image count");
            FaceImageInfo photo = dg2.getFaceInfos().get(0).getFaceImageInfos().get(0);
            byte[] jpeg = photo.getImageInputStream().readAllBytes();
            check(photo.getWidth() == 160 && photo.getHeight() == 120 && photo.getImageDataType() == FaceImageInfo.IMAGE_DATA_TYPE_JPEG, "DG2 photo metadata");
            check(Arrays.equals(jpeg, Files.readAllBytes(Paths.get(args[4]))), "DG2 JPEG payload differs from the fixture");
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(jpeg));
            check(image != null && image.getWidth() == 160 && image.getHeight() == 120, "DG2 JPEG decode");
            byte[] sodBytes = file(card, wrapper, 0x011D);
            SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
            MessageDigest hash = MessageDigest.getInstance(sod.getDigestAlgorithm());
            if (displayed) for (int number : new int[]{5,7}) {
                byte[] encoded = file(card, wrapper, 0x0100 + number);
                DisplayedImageDataGroup group = number == 5 ? new DG5File(new ByteArrayInputStream(encoded)) : new DG7File(new ByteArrayInputStream(encoded));
                check(group.getImages().size() == 1, "Displayed image count");
                byte[] picture = group.getImages().get(0).getImageInputStream().readAllBytes();
                Path expected = Paths.get(args[4]).getParent().resolve("dg"+number+"-"+format.toLowerCase()+"-"+mode.toLowerCase()+".jpg");
                check(Arrays.equals(picture, Files.readAllBytes(expected)), "DG"+number+" picture payload");
                BufferedImage decoded = ImageIO.read(new ByteArrayInputStream(picture));
                check(decoded != null && decoded.getWidth() == (number == 5 ? 160 : 240) && decoded.getHeight() == (number == 5 ? 120 : 80), "Displayed JPEG decode");
                check(Arrays.equals(hash.digest(encoded), sod.getDataGroupHashes().get(number)), "DG"+number+" hash outcome");
            }
            check(Arrays.equals(hash.digest(dg1Bytes), sod.getDataGroupHashes().get(1)) != paScenario.equals("Altered DG1"), "DG1 hash outcome");
            check(Arrays.equals(hash.digest(dg2Bytes), sod.getDataGroupHashes().get(2)), "DG2 hash outcome");
            int sodHeader = 2 + ((sodBytes[1] & 128) == 0 ? 0 : sodBytes[1] & 127);
            CMSSignedData cms = new CMSSignedData(Arrays.copyOfRange(sodBytes, sodHeader, sodBytes.length));
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            boolean signatureOK = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(sod.getDocSigningCertificate()));
            check(signatureOK != paScenario.equals("Bad signature"), "SOD signature outcome");
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate root = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Paths.get(args[6]))));
            PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
            parameters.setRevocationEnabled(false); parameters.setDate(new Date());
            boolean trustOK = true;
            try { CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(Collections.singletonList(sod.getDocSigningCertificate())), parameters); }
            catch (CertPathValidatorException expected) { trustOK = false; }
            check(trustOK != paScenario.equals("Untrusted CSCA"), "Certificate trust outcome");
            check(plain(card, "00B0000004").getSW() == 0x6982, "Plaintext session bypass");
            check(secure(card, wrapper, new CommandAPDU(h("0022C1A412800A04007F0007020204020283010184010D"))).getSW() == 0x6985, "Protected reauthentication must preserve the active channel");
            check(secure(card, wrapper, new CommandAPDU(h("00A4020C020103"))).getSW() == 0x6A82, "Missing DG3 status");
            byte[] protectedCommand = wrapper.wrap(new CommandAPDU(h("00B0000004"))).getBytes();
            protectedCommand[protectedCommand.length - 2] ^= 1;
            check(card.transmit(new CommandAPDU(protectedCommand)).getSW() == 0x6988, "MAC tampering accepted");
            check(card.transmit(wrapper.wrap(new CommandAPDU(h("00B0000004")))).getSW() != 0x9000, "Rejected session survived");
            wrapper = authenticate(card, mode, document, can, false);
            check(secure(card, wrapper, new CommandAPDU(h("00A4040C07A0000002471001"))).getSW() == 0x9000, "Recovery after MAC failure");
            file(card, wrapper, 0x0101);
            CommandAPDU once = wrapper.wrap(new CommandAPDU(h("00B0000004")));
            check(wrapper.unwrap(card.transmit(once)).getSW() == 0x9000, "First protected command");
            check(card.transmit(once).getSW() == 0x6988, "Replay accepted");
            wrapper = authenticate(card, mode, document, can, false);
            check(secure(card, wrapper, new CommandAPDU(h("00A4040C07A0000002471001"))).getSW() == 0x9000, "Recovery after replay");
            file(card, wrapper, 0x0101);
            check(card.raw(new byte[] {0}).getSW() == 0x9000, "Link reset");
            check(card.transmit(wrapper.wrap(new CommandAPDU(h("00B0000004")))).getSW() != 0x9000, "Session survived link loss");
            System.out.println("PASS " + format + " " + mode + " " + scenario + " / " + paScenario + ": DG1 + DG2 + SOD/hash/CMS/native PKIX; access, MAC/replay and recovery checks");
        } finally { card.close(); }
    }
}
