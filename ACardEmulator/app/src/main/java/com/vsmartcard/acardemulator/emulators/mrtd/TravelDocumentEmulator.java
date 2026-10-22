/* SPDX-License-Identifier: GPL-3.0-or-later
 * Public ICAO examples, synthetic JPEG and development-only signed SOD.
 */
package com.vsmartcard.acardemulator.emulators.mrtd;

import com.vsmartcard.acardemulator.emulators.Emulator;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.math.ec.ECPoint;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardCrypto.*;

/** Card-side BAC/PACE and secure DG1/DG2 fixture; independent of Android/TCP. */
public final class TravelDocumentEmulator implements Emulator {
    private static final byte[] AID = hex("A0000002471001");
    private PACECardProfile paceProfile = PACECardProfile.preset("PACE");
    private PACECardSession paceSession;
    private static final byte[] COM = tlv(0x60, concat(tlv(0x5F01, ascii("0107")), tlv(0x5F36, ascii("040000")), tlv(0x5C, hex("6175"))));
    private final boolean pace;
    private final byte[] dg1, dg2, dg3, dg4, dg5, dg7, dg11, dg12, dg14, dg15, com, sod, mrzInformation;
    private final boolean displayedImages, additionalDetails, securityFiles, biometricFiles;
    private byte[] challenge;
    private int phase = -1, selectedFile;
    private boolean applicationSelected, destroyed;
    private SecureChannel channel, pendingChannel;
    private final byte[] aaPrivateBytes;
    private final PrivateKey caPrivate;
    private boolean caReady;
    private int caCipher = 2;
    private final ByteArrayOutputStream caSegments = new ByteArrayOutputStream();
    private String chipScenario = "Valid";
    private int selectMFResponse = 0x9000;
    private boolean requireTA;
    private TerminalAuthorization terminal = new TerminalAuthorization(loadFixture("ta-ec-root.cvc", 0x7F));
    private byte[] paceIdentifier;
    public synchronized void setPACEProfile(String oid, int parameterId) { if (!pace) throw new IllegalArgumentException("PACE profile requires PACE mode"); reset(); paceProfile = new PACECardProfile(oid, parameterId); }
    public synchronized void setPACEPreset(String preset) { if (!pace) throw new IllegalArgumentException("PACE preset requires PACE mode"); reset(); paceProfile = PACECardProfile.preset(preset); }

    public synchronized void setRequireTerminalAuthentication(boolean required) {
        if(required && (!securityFiles || !biometricFiles)) throw new IllegalArgumentException("TA requires security and biometric fixtures");
        reset();requireTA=required;
    }
    /** Select a synthetic trust anchor for interoperability tests; resets all sessions. */
    public synchronized void setTerminalCertificateType(String type) {
        if(!type.equals("ec")&&!type.equals("rsa"))throw new IllegalArgumentException("Unknown test CVC algorithm");
        reset();terminal=new TerminalAuthorization(loadFixture("ta-"+type+"-root.cvc",0x7F));
    }

    public TravelDocumentEmulator(String format, String authentication) {
        this(format, authentication, "Valid");
    }
    public TravelDocumentEmulator(String format, String authentication, String paScenario) {
        this(format, authentication, paScenario, false);
    }
    public TravelDocumentEmulator(String format, String authentication, String paScenario, boolean displayedImages) {
        this(format, authentication, paScenario, displayedImages, false);
    }
    public TravelDocumentEmulator(String format, String authentication, String paScenario, boolean displayedImages, boolean additionalDetails) {
        this(format, authentication, paScenario, displayedImages, additionalDetails, false);
    }
    public TravelDocumentEmulator(String format, String authentication, String paScenario, boolean displayedImages, boolean additionalDetails, boolean securityFiles) {
        this(format, authentication, paScenario, displayedImages, additionalDetails, securityFiles, false);
    }
    public TravelDocumentEmulator(String format, String authentication, String paScenario, boolean displayedImages, boolean additionalDetails, boolean securityFiles, boolean biometricFiles) {
        if (!(format.equals("TD1") || format.equals("TD2") || format.equals("TD3")) || !(authentication.equals("BAC") || authentication.equals("PACE"))) throw new IllegalArgumentException("Unsupported fixture");
        if (!(paScenario.equals("Valid") || paScenario.equals("Altered DG1") || paScenario.equals("Bad signature") || paScenario.equals("Untrusted CSCA") || paScenario.equals("CMS RSA (SHA-384)") || paScenario.equals("CMS PSS (SHA-256)") || paScenario.equals("CMS ECDSA (SHA-512)") || paScenario.equals("ISO 39794 base") || paScenario.equals("ISO 39794 ICAO"))) throw new IllegalArgumentException("Unsupported PA scenario");
        pace = authentication.equals("PACE");
        this.displayedImages = displayedImages;
        this.additionalDetails = additionalDetails;
        this.securityFiles = securityFiles;
        this.biometricFiles = biometricFiles;
        String fixture = format.toLowerCase(java.util.Locale.ROOT) + "-" + authentication.toLowerCase(java.util.Locale.ROOT);
        String encodingPrefix = paScenario.startsWith("ISO 39794") ? "iso39794-" + (paScenario.endsWith("ICAO") ? "icao-" : "base-") : "";
        dg2 = loadFixture("dg2-" + encodingPrefix + fixture, 0x75);
        dg3 = biometricFiles ? loadFixture("dg3-" + encodingPrefix + fixture, 0x63) : null;
        dg4 = biometricFiles ? loadFixture("dg4-" + encodingPrefix + fixture, 0x76) : null;
        dg5 = displayedImages ? loadFixture("dg5-" + fixture, 0x65) : null;
        dg7 = displayedImages ? loadFixture("dg7-" + fixture, 0x67) : null;
        dg11 = additionalDetails ? loadFixture("dg11-" + fixture, 0x6B) : null;
        dg12 = additionalDetails ? loadFixture("dg12-" + fixture, 0x6C) : null;
        dg14 = securityFiles ? loadFixture("dg14-" + fixture, 0x6E) : null;
        dg15 = securityFiles ? loadFixture("dg15-" + fixture, 0x6F) : null;
        aaPrivateBytes = securityFiles ? loadFixture("aa-private-" + fixture, 0x30) : null;
        try { caPrivate = securityFiles ? KeyFactory.getInstance(format.equals("TD1") ? "DH" : "EC", new BouncyCastleProvider()).generatePrivate(new PKCS8EncodedKeySpec(loadFixture("ca-private-" + fixture, 0x30))) : null; }
        catch (GeneralSecurityException error) { throw new IllegalStateException("Could not load synthetic CA key", error); }
        com = tlv(0x60, concat(tlv(0x5F01, ascii("0107")), tlv(0x5F36, ascii("040000")),
                tlv(0x5C, hex("6175" + (biometricFiles ? "6376" : "") + (displayedImages ? "6567" : "") + (additionalDetails ? "6B6C" : "") + (securityFiles ? "6E6F" : "")))));
        String sodPrefix = "sod-" + (displayedImages ? "displayed-" : "") + (additionalDetails ? "details-" : "") + (securityFiles ? "security-" : "") + (biometricFiles ? "biometric-" : "");
        if (!encodingPrefix.isEmpty()) sodPrefix = sodPrefix.replace("sod-", "sod-" + encodingPrefix);
        if (paScenario.startsWith("CMS ")) sodPrefix = sodPrefix.replace("sod-", "sod-cms-" + (paScenario.contains("PSS") ? "pss256" : paScenario.contains("ECDSA") ? "ec512" : "rsa384") + "-");
        sod = loadFixture(sodPrefix + (paScenario.equals("Bad signature") ? "bad-signature-" : paScenario.equals("Untrusted CSCA") ? "untrusted-" : "") + fixture, 0x77);
        dg1 = loadFixture("dg1-" + fixture, 0x61);
        if (paScenario.equals("Altered DG1")) {
            byte[] name = ascii("ERIKSSON");
            for (int i=0;i<=dg1.length-name.length;i++) {
                if (equal(slice(dg1,i,i+name.length),name)) { dg1[i]='X'; break; }
            }
        }
        mrzInformation = ascii((format.equals("TD3") ? "L898902C36" : "D231458907") + "7408122" + "1204159");
    }
    /** Optional synthetic negative cases, independent from PA scenarios. */
    public synchronized void setChipScenario(String scenario) {
        if (!(scenario.equals("Valid") || scenario.equals("Bad AA signature") || scenario.equals("Wrong CA key"))) throw new IllegalArgumentException("Unknown chip scenario");
        reset(); chipScenario = scenario;
    }
    /** Temporary BAC compatibility fixture; PACE cards retain normal MF access. */
    public synchronized void setRejectSelectMF(boolean reject) {
        setSelectMFResponse(reject ? 0x6A81 : 0x9000);
    }
    /** Reject only SELECT MF, before changing file selection or authentication state. */
    public synchronized void setSelectMFResponse(int status) {
        if (status != 0x9000 && status != 0x6A81 && status != 0x6700) throw new IllegalArgumentException("Unsupported SELECT MF response");
        reset(); selectMFResponse = pace ? 0x9000 : status;
    }
    private static byte[] ascii(String text) { return text.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] loadFixture(String fixture, int tag) {
        try (InputStream input = TravelDocumentEmulator.class.getResourceAsStream("/mrtd/" + fixture + (fixture.endsWith(".cvc") ? "" : ".bin"))) {
            if (input == null) throw new IOException("Bundled fixture missing: " + fixture);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024]; int count;
            while ((count = input.read(buffer)) != -1) {
                if (bytes.size() + count > 65536) throw new IOException("Fixture too large");
                bytes.write(buffer, 0, count);
            }
            byte[] encoded = bytes.toByteArray();
            require(encoded.length > 4 && encoded[0] == tag, 0x6F00);
            return encoded;
        } catch (IOException error) { throw new IllegalStateException("Could not load test fixture", error); }
    }
    public synchronized String getStatus() {
        if (destroyed) return "Stopped";
        if (channel != null) return (pace ? "PACE" : "BAC") + " authenticated" + (requireTA ? terminal.authenticated() ? " · TA passed · DG3" + (terminal.allows(4) ? " / DG4" : " only") : " · DG3 / DG4 locked" : "") + (selectedFile == 0x0101 ? " · DG1 selected" : selectedFile == 0x0102 ? " · DG2 selected" : selectedFile == 0x011D ? " · SOD selected" : "");
        if (phase >= 0) return "PACE · step " + (phase + 1);
        return "Ready · " + (pace ? paceProfile.toString() : "BAC");
    }
    @Override public synchronized byte[] process(byte[] raw) {
        if (destroyed) return hex("6F00");
        boolean protectedCommand = false;
        try {
            Command c = Command.parse(raw);
            protectedCommand = (c.cla & 12) == 12;
            SecureChannel active = channel;
            if (protectedCommand) {
                require(active != null, 0x6982);
                c = active.unwrap(c);
            } else if (channel != null) {
                // A new reader can explicitly start a fresh session with SELECT AID.
                if (c.ins == 0xA4 && c.p1 == 4 && equal(c.data, AID)) reset();
                else throw new Status(0x6982);
            }
            byte[] result;
            int sw = 0x9000;
            try { result = execute(c); }
            catch (Status status) { result = new byte[0]; sw = status.sw; }
            byte[] response = protectedCommand ? active.wrap(result, sw) : concat(result, new byte[] {(byte) (sw >> 8), (byte) sw});
            // The CA response still belongs to the old channel. Install new keys only afterwards.
            if (pendingChannel != null) { if (channel != null) channel.destroy(); channel = pendingChannel; pendingChannel = null; }
            return response;
        } catch (Status status) {
            if (protectedCommand) { reset(); return hex("6988"); }
            return new byte[] {(byte) (status.sw >> 8), (byte) status.sw};
        } catch (GeneralSecurityException | RuntimeException error) {
            reset();
            return protectedCommand ? hex("6988") : hex("6F00");
        }
    }
    private byte[] execute(Command c) throws GeneralSecurityException {
        require(c.cla == 0 || (c.cla == 0x10 && c.ins == 0x86), 0x6E00);
        if (channel != null && ((c.ins == 0x22 && c.p1 == 0x81) || c.ins == 0x2A || c.ins == 0x84 || c.ins == 0x82)) {
            return terminal.execute(c.ins,c.p1,c.p2,c.data,c.le);
        }
        if (channel != null && c.ins == 0x88) return activeAuthenticate(c);
        if (channel != null && (c.ins == 0x22 || c.ins == 0x86)) return chipAuthenticate(c);
        if (c.ins == 0x22 || c.ins == 0x82 || c.ins == 0x84 || c.ins == 0x86) require(channel == null, 0x6985);
        switch (c.ins) {
            case 0xA4: return select(c);
            case 0xB0: return read(c);
            case 0x84:
                require(c.p1 == 0 && c.p2 == 0 && c.data.length == 0 && c.le == 8, 0x6A86);
                require(!pace && applicationSelected, 0x6982);
                wipe(challenge); challenge = random(8); return challenge.clone();
            case 0x82: return bac(c);
            case 0x22: return mse(c);
            case 0x86:
                try { return generalAuthenticate(c); }
                catch (Status | GeneralSecurityException | IllegalArgumentException error) { resetSecurity(); throw new Status(0x6300); }
            default: throw new Status(0x6D00);
        }
    }
    private byte[] activeAuthenticate(Command c) throws GeneralSecurityException {
        require(securityFiles && applicationSelected, 0x6985);
        require(c.p1 == 0 && c.p2 == 0 && c.data.length == 8, 0x6A86);
        byte[] response;
        if (caPrivate instanceof DHPrivateKey) {
            // ICAO RSA AA uses ISO 9796-2 partial message recovery: random M1 || challenge.
            ISO9796d2Signer signer = new ISO9796d2Signer(new RSAEngine(), new SHA1Digest(), true);
            try { signer.init(true, PrivateKeyFactory.createKey(aaPrivateBytes)); }
            catch (IOException error) { throw new GeneralSecurityException(error); }
            byte[] message = concat(random(234),c.data);
            signer.update(message,0,message.length); try { response = signer.generateSignature(); } catch (org.bouncycastle.crypto.CryptoException error) { throw new GeneralSecurityException(error); } finally { wipe(message); }
        } else {
            Signature signer = Signature.getInstance("SHA256withECDSA",new BouncyCastleProvider());
            signer.initSign(KeyFactory.getInstance("EC",new BouncyCastleProvider()).generatePrivate(new PKCS8EncodedKeySpec(aaPrivateBytes)));
            signer.update(c.data); byte[] der = signer.sign();
            try {
                ASN1Sequence seq = (ASN1Sequence)new ASN1InputStream(der).readObject();
                response = concat(fixed(DERInteger.getInstance(seq.getObjectAt(0)).getPositiveValue(),32),fixed(DERInteger.getInstance(seq.getObjectAt(1)).getPositiveValue(),32));
            } catch(IOException error){throw new GeneralSecurityException(error);}
        }
        if(chipScenario.equals("Bad AA signature")) response[response.length-1] ^= 1;
        return response;
    }
    private static byte[] fixed(BigInteger value,int size) {
        byte[] encoded=value.toByteArray(); if(encoded.length>size && encoded[0]==0)encoded=slice(encoded,1,encoded.length);
        require(encoded.length<=size,0x6A80);byte[] out=new byte[size];System.arraycopy(encoded,0,out,size-encoded.length,encoded.length);return out;
    }
    private byte[] chipAuthenticate(Command c) throws GeneralSecurityException {
        require(securityFiles && applicationSelected,0x6985);
        if(c.ins==0x22){
            require(c.p1==0x41,0x6985);require(c.p2==0xA4 || c.p2==0xA6,0x6A86);
            caReady=false;caSegments.reset(); List<TLV> fields=objects(c.data);
            require(fields.size()==1 || fields.size()==2,0x6A80);
            if(fields.size()==2)require(fields.get(1).tag==0x84 && equal(fields.get(1).value,hex("01")),0x6A88);
            if(c.p2==0xA6){ require(fields.get(0).tag==0x91,0x6A80);caCipher=1;establishCA(fields.get(0).value);return new byte[0]; }
            byte[] oid=fields.get(0).value;require(fields.get(0).tag==0x80 && oid.length==10,0x6A80);
            require(equal(slice(oid,0,8),hex("04007F0007020203")),0x6A80);
            require(oid[8]==(caPrivate instanceof DHPrivateKey?1:2) && oid[9]>=2 && oid[9]<=4,0x6A80);
            caCipher=oid[9];caReady=true;return new byte[0];
        }
        require(c.ins==0x86 && c.p1==0 && c.p2==0 && caReady,0x6985);
        List<TLV> outer=objects(c.data);require(outer.size()==1 && outer.get(0).tag==0x7C,0x6A80);
        byte[] segment=outer.get(0).value;require(caSegments.size()+segment.length<=4096,0x6700);caSegments.write(segment,0,segment.length);
        if(c.cla==0x10)return tlv(0x7C,new byte[0]);
        require(c.cla==0,0x6E00); List<TLV> fields=objects(caSegments.toByteArray());caSegments.reset();
        require(fields.size()==1 && fields.get(0).tag==0x80,0x6A80);caReady=false;establishCA(fields.get(0).value);return tlv(0x7C,new byte[0]);
    }
    private void establishCA(byte[] peerBytes) throws GeneralSecurityException {
        byte[] secret;
        if(caPrivate instanceof DHPrivateKey){
            DHPrivateKey key=(DHPrivateKey)caPrivate;BigInteger y=new BigInteger(1,peerBytes),p=key.getParams().getP();
            require(y.compareTo(BigInteger.ONE)>0 && y.compareTo(p.subtract(BigInteger.ONE))<0,0x6A80);
            secret=fixed(y.modPow(key.getX(),p),(p.bitLength()+7)/8);
        }else{
            ECPrivateKey key=(ECPrivateKey)caPrivate;
            ECPoint shared=point(peerBytes).multiply(key.getD());require(!shared.isInfinity(),0x6A80);secret=fixed(shared.getX().toBigInteger(),32);
        }
        if(chipScenario.equals("Wrong CA key"))secret[0]^=1;
        int size=caCipher<=2?16:caCipher==3?24:32;
        byte[] enc=caKdf(secret,1,size),macKey=caKdf(secret,2,size);wipe(secret);
        pendingChannel=new SecureChannel(caCipher!=1,enc,macKey,new byte[caCipher==1?8:16]);wipe(enc);wipe(macKey);selectedFile=0;
        byte[] keyHash=caPrivate instanceof DHPrivateKey?sha1(peerBytes):slice(peerBytes,1,33);
        terminal.afterCA(pace ? paceIdentifier : slice(mrzInformation,0,10),keyHash);wipe(keyHash);
    }
    private byte[] caKdf(byte[] secret,int counter,int size)throws GeneralSecurityException {
        return java.util.Arrays.copyOf(java.security.MessageDigest.getInstance(size==16?"SHA-1":"SHA-256").digest(concat(secret,new byte[]{0,0,0,(byte)counter})),size);
    }
    private byte[] select(Command c) {
        require(c.p2 == 0 || c.p2 == 0x0C, 0x6A86);
        if (selectMFResponse != 0x9000 && c.p1 == 0 && (c.data.length == 0
                || (c.data.length == 2 && c.data[0] == 0x3F && c.data[1] == 0))) {
            throw new Status(selectMFResponse);
        }
        if (c.p1 == 4) {
            require(equal(c.data, AID), 0x6A82);
            applicationSelected = true; selectedFile = 0;
        } else if (c.p1 == 0 && c.data.length == 0) {
            // ISO 7816 SELECT MF, as emitted by JMRTD ReadBinaryAPDUSender.
            applicationSelected = false; selectedFile = 0;
        } else {
            require((c.p1 == 0 || c.p1 == 2) && c.data.length == 2, 0x6A86);
            int fid = (c.data[0] & 255) * 256 + (c.data[1] & 255);
            if (fid == 0x3F00) { applicationSelected = false; selectedFile = 0; }
            else if (!applicationSelected && pace && (fid == 0x011C || fid == 0x011D && paceProfile.cam)) selectedFile = fid;
            else if (applicationSelected && (fid == 0x0101 || fid == 0x0102 || fid == 0x011D || fid == 0x011E || biometricFiles && (fid == 0x0103 || fid == 0x0104) || displayedImages && (fid == 0x0105 || fid == 0x0107) || additionalDetails && (fid == 0x010B || fid == 0x010C) || securityFiles && (fid == 0x010E || fid == 0x010F))) selectedFile = fid;
            else throw new Status(0x6A82);
        }
        checkBiometricPermission();
        return new byte[0];
    }
    private void checkBiometricPermission(){if(requireTA && (selectedFile==0x0103||selectedFile==0x0104))require(terminal.allows(selectedFile-0x0100),0x6982);}
    private byte[] read(Command c) {
        require(c.data.length == 0 && c.le > 0, 0x6700);
        int offset = c.p1 * 256 + c.p2;
        if ((c.p1 & 128) != 0) {
            int sfi = c.p1 & 31;
            require((c.p1 & 0x60) == 0, 0x6A86);
            if (applicationSelected && sfi == 1) selectedFile = 0x0101;
            else if (applicationSelected && sfi == 2) selectedFile = 0x0102;
            else if (applicationSelected && biometricFiles && sfi == 3) selectedFile = 0x0103;
            else if (applicationSelected && biometricFiles && sfi == 4) selectedFile = 0x0104;
            else if (applicationSelected && displayedImages && sfi == 5) selectedFile = 0x0105;
            else if (applicationSelected && displayedImages && sfi == 7) selectedFile = 0x0107;
            else if (applicationSelected && additionalDetails && sfi == 11) selectedFile = 0x010B;
            else if (applicationSelected && additionalDetails && sfi == 12) selectedFile = 0x010C;
            else if (applicationSelected && securityFiles && sfi == 14) selectedFile = 0x010E;
            else if (applicationSelected && securityFiles && sfi == 15) selectedFile = 0x010F;
            else if (applicationSelected && sfi == 29) selectedFile = 0x011D;
            else if (applicationSelected && sfi == 30) selectedFile = 0x011E;
            else if (!applicationSelected && sfi == 28 && pace) selectedFile = 0x011C;
            else throw new Status(0x6A82);
            offset = c.p2;
        }
        require(selectedFile != 0, 0x6986);
        require(selectedFile == 0x011C || !applicationSelected && selectedFile == 0x011D && paceProfile.cam || channel != null, 0x6982);
        checkBiometricPermission();
        byte[] file = selectedFile == 0x011C ? paceProfile.cardAccess() : !applicationSelected && selectedFile == 0x011D && paceProfile.cam ? paceProfile.cardSecurity() : selectedFile == 0x0101 ? dg1 : selectedFile == 0x0102 ? dg2 : selectedFile == 0x0103 ? dg3 : selectedFile == 0x0104 ? dg4 : selectedFile == 0x0105 ? dg5 : selectedFile == 0x0107 ? dg7 : selectedFile == 0x010B ? dg11 : selectedFile == 0x010C ? dg12 : selectedFile == 0x010E ? dg14 : selectedFile == 0x010F ? dg15 : selectedFile == 0x011D ? sod : com;
        require(offset < file.length, 0x6B00);
        // With AES padding, 224 plaintext bytes would produce 258 protected data
        // bytes, beyond short Le=256. Announce the supported read length; the
        // reader can retry with 223, keeping the existing authenticated channel.
        if (channel != null && Math.min(c.le, file.length - offset) > 223) throw new Status(0x6CDF);
        return slice(file, offset, Math.min(file.length, offset + c.le));
    }
    private byte[] bac(Command c) throws GeneralSecurityException {
        require(!pace && applicationSelected && challenge != null, 0x6982);
        require(c.p1 == 0 && c.p2 == 0 && c.data.length == 40, 0x6700);
        byte[] rndICC = challenge; challenge = null;
        byte[] seed = slice(sha1(mrzInformation), 0, 16), enc = kdf(seed, 1, true), macKey = kdf(seed, 2, true);
        byte[] request = null, keyICC = null;
        try {
            byte[] encrypted = slice(c.data, 0, 32);
            require(equal(mac(false, macKey, pad(encrypted, 8)), slice(c.data, 32, 40)), 0x6300);
            request = crypt(false, false, enc, new byte[8], encrypted);
            require(equal(slice(request, 8, 16), rndICC), 0x6300);
            keyICC = random(16);
            byte[] response = crypt(true, false, enc, new byte[8], concat(rndICC, slice(request, 0, 8), keyICC));
            for (int i = 0; i < 16; i++) seed[i] = (byte) (keyICC[i] ^ request[16 + i]);
            byte[] ksEnc = kdf(seed, 1, true), ksMac = kdf(seed, 2, true);
            channel = new SecureChannel(false, ksEnc, ksMac, concat(slice(rndICC, 4, 8), slice(request, 4, 8)));
            wipe(ksEnc); wipe(ksMac);
            return concat(response, mac(false, macKey, pad(response, 8)));
        } finally { wipe(rndICC); wipe(seed); wipe(enc); wipe(macKey); wipe(request); wipe(keyICC); }
    }
    private byte[] mse(Command c) throws GeneralSecurityException {
        require(pace, 0x6D00);
        resetSecurity();
        require(c.p1 == 0xC1 && c.p2 == 0xA4, 0x6A86);
        List<TLV> fields = objects(c.data);
        require(fields.size() == 2 || fields.size() == 3, 0x6A80);
        require(fields.get(0).tag == 0x80 && equal(fields.get(0).value, paceProfile.oid) && fields.get(1).tag == 0x83 && fields.get(1).value.length == 1, 0x6A80);
        if (fields.size() == 3) require(fields.get(2).tag == 0x84 && new BigInteger(1, fields.get(2).value).intValue() == paceProfile.parameterId, 0x6A80);
        int reference = fields.get(1).value[0];
        require(reference >= 1 && reference <= 4, 0x6A88);
        byte[] seed = reference == 1 ? sha1(mrzInformation) : ascii(reference == 4 ? "12345678" : "123456");
        paceSession = new PACECardSession(paceProfile, seed); wipe(seed); phase = 0;
        return new byte[0];
    }
    private byte[] generalAuthenticate(Command c) throws GeneralSecurityException {
        require(pace && paceSession != null, 0x6985);
        byte[] response = paceSession.exchange(c); phase = paceSession.phase();
        if (phase == 4) { channel = paceSession.channel(); wipe(paceIdentifier); paceIdentifier = paceSession.identifier(); paceSession.clear(); paceSession = null; }
        return response;
    }
    private void resetSecurity() {
        if (paceSession != null) { paceSession.clear(); paceSession = null; }
        terminal.clear();wipe(paceIdentifier);paceIdentifier=null;
        caReady=false;caSegments.reset();if(pendingChannel!=null){pendingChannel.destroy();pendingChannel=null;}
        if (channel != null) channel.destroy(); channel = null;
        wipe(challenge); challenge = null;
        phase = -1;
    }
    private void reset() { resetSecurity(); applicationSelected = false; selectedFile = 0; }
    @Override public synchronized void deactivate() { reset(); }
    @Override public synchronized void destroy() { reset(); wipe(aaPrivateBytes); destroyed = true; }
}
