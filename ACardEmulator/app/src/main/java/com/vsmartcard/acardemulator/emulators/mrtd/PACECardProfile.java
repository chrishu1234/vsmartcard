/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;

/** Card-side profiles; deliberately independent from the reader implementation. */
public final class PACECardProfile {
    public static final String[] CHOICES = {"BAC", "PACE", "PACE AES-192", "PACE AES-256", "PACE 3DES", "PACE NIST P-256", "PACE NIST P-384", "PACE DH-1024", "PACE DH-2048 AES-256", "PACE IM", "PACE IM AES-256", "PACE IM 3DES", "PACE IM DH-1024", "PACE CAM", "PACE CAM AES-256", "PACE CAM NIST P-384"};
    final boolean dh, aes, im, cam;
    final int parameterId, keyBits, width;
    final byte[] oid;
    final X9ECParameters curve;
    final BigInteger p, g, q;
    private final String description;
    private byte[] security;
    public PACECardProfile(String identifier, int parameterId) {
        String[] parts = identifier.split("\\.");
        if (!identifier.startsWith("0.4.0.127.0.7.2.2.4.") || parts.length != 11) throw new IllegalArgumentException("Unknown PACE OID");
        int family = Integer.parseInt(parts[9]), algorithm = Integer.parseInt(parts[10]);
        if (!((family>=1&&family<=4)||(family==6&&algorithm>=2)) || algorithm < 1 || algorithm > 4) throw new IllegalArgumentException("Unknown PACE mapping/cipher");
        this.dh = family == 1 || family == 3; this.im = family == 3 || family == 4; this.cam = family == 6; this.aes = algorithm != 1; this.keyBits = algorithm <= 2 ? 128 : algorithm == 3 ? 192 : 256;
        this.parameterId = parameterId; this.oid = concat(hex("04007F0007020204"), new byte[]{(byte) family, (byte) algorithm});
        if (dh) {
            BigInteger[] values = PACEDHGroups.values(parameterId); p = values[0]; g = values[1]; q = values[2]; curve = null;
            width = (p.bitLength() + 7) / 8; description = "DH-"+(im?"IM":"GM")+" / " + (aes ? "AES-" + keyBits : "3DES") + " / " + p.bitLength() + " bits";
        } else {
            String[] names = {"secp192r1","brainpoolP192r1","secp224r1","brainpoolP224r1","secp256r1","brainpoolP256r1","brainpoolP320r1","secp384r1","brainpoolP384r1","brainpoolP512r1","secp521r1"};
            if (parameterId < 8 || parameterId > 18) throw new IllegalArgumentException("Unknown EC parameter identifier");
            String name = names[parameterId - 8]; curve = name.startsWith("brainpool") ? TeleTrusTNamedCurves.getByName(name) : SECNamedCurves.getByName(name);
            if (curve == null) throw new IllegalArgumentException("Curve unavailable: " + name);
            p = ((ECCurve.Fp) curve.getCurve()).getQ(); g = null; q = curve.getN(); width = (p.bitLength() + 7) / 8;
            description = "ECDH-"+(im?"IM":cam?"CAM":"GM")+" / " + (aes ? "AES-" + keyBits : "3DES") + " / " + name;
        }
    }
    public static PACECardProfile preset(String choice) {
        switch (choice) {
            case "PACE IM": return new PACECardProfile("0.4.0.127.0.7.2.2.4.4.2", 13);
            case "PACE IM AES-256": return new PACECardProfile("0.4.0.127.0.7.2.2.4.4.4", 13);
            case "PACE IM 3DES": return new PACECardProfile("0.4.0.127.0.7.2.2.4.4.1", 13);
            case "PACE IM DH-1024": return new PACECardProfile("0.4.0.127.0.7.2.2.4.3.2", 0);
            case "PACE CAM": return new PACECardProfile("0.4.0.127.0.7.2.2.4.6.2", 13);
            case "PACE CAM AES-256": return new PACECardProfile("0.4.0.127.0.7.2.2.4.6.4", 13);
            case "PACE CAM NIST P-384": return new PACECardProfile("0.4.0.127.0.7.2.2.4.6.2", 15);
            case "PACE AES-192": return new PACECardProfile("0.4.0.127.0.7.2.2.4.2.3", 13);
            case "PACE AES-256": return new PACECardProfile("0.4.0.127.0.7.2.2.4.2.4", 13);
            case "PACE 3DES": return new PACECardProfile("0.4.0.127.0.7.2.2.4.2.1", 13);
            case "PACE NIST P-256": return new PACECardProfile("0.4.0.127.0.7.2.2.4.2.2", 12);
            case "PACE NIST P-384": return new PACECardProfile("0.4.0.127.0.7.2.2.4.2.2", 15);
            case "PACE DH-1024": return new PACECardProfile("0.4.0.127.0.7.2.2.4.1.2", 0);
            case "PACE DH-2048 AES-256": return new PACECardProfile("0.4.0.127.0.7.2.2.4.1.4", 2);
            case "PACE": return new PACECardProfile("0.4.0.127.0.7.2.2.4.2.2", 13);
            default: throw new IllegalArgumentException("Unknown PACE preset: " + choice);
        }
    }
    byte[] cardAccess() { return tlv(0x31, tlv(0x30, concat(tlv(6, oid), tlv(2, new byte[]{2}), tlv(2, new byte[]{(byte) parameterId})))); }
    byte[] cardSecurity() {
        if(!cam)throw new IllegalStateException("EF.CardSecurity is only present in CAM fixtures");
        if(security==null){try(java.io.InputStream input=PACECardProfile.class.getResourceAsStream("/mrtd/cardsecurity-cam-"+parameterId+"-"+oid[oid.length-1]+".bin")){if(input==null)throw new java.io.IOException("Missing CAM security fixture");java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();byte[] buffer=new byte[2048];int n;while((n=input.read(buffer))>=0){if(n>0)bytes.write(buffer,0,n);}security=bytes.toByteArray();}catch(java.io.IOException error){throw new IllegalStateException(error);}}
        return security;
    }
    BigInteger scalar() {
        BigInteger limit = dh ? p.subtract(BigInteger.ONE) : q, n;
        do { n = new BigInteger(limit.bitLength(), CardCrypto.RANDOM); } while (n.compareTo(dh ? BigInteger.valueOf(2) : BigInteger.ONE) < 0 || n.compareTo(limit) >= 0);
        return n;
    }
    BigInteger publicValue(byte[] bytes) {
        BigInteger y = new BigInteger(1, bytes); require(y.compareTo(BigInteger.valueOf(2)) >= 0 && y.compareTo(p.subtract(BigInteger.ONE)) < 0 && y.modPow(q, p).equals(BigInteger.ONE), 0x6A80); return y;
    }
    ECPoint point(byte[] bytes) {
        require(bytes.length == 1 + 2 * width && bytes[0] == 4, 0x6A80);
        BigInteger x = new BigInteger(1, slice(bytes, 1, 1 + width)), y = new BigInteger(1, slice(bytes, 1 + width, bytes.length));
        require(x.compareTo(p) < 0 && y.compareTo(p) < 0 && y.multiply(y).mod(p).equals(x.pow(3).add(curve.getCurve().getA().toBigInteger().multiply(x)).add(curve.getCurve().getB().toBigInteger()).mod(p)), 0x6A80);
        ECPoint point = curve.getCurve().decodePoint(bytes); require(!point.isInfinity() && point.multiply(q).isInfinity(), 0x6A80); return point;
    }
    byte[] encode(ECPoint point) { require(!point.isInfinity(), 0x6A80); return concat(new byte[]{4}, fixed(point.getX().toBigInteger(), width), fixed(point.getY().toBigInteger(), width)); }
    static byte[] minimal(BigInteger value) { byte[] b = value.toByteArray(); return b.length > 1 && b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b; }
    static byte[] fixed(BigInteger value, int width) { byte[] data = minimal(value); if (data.length > width) throw new IllegalArgumentException("Value exceeds field"); byte[] out = new byte[width]; System.arraycopy(data, 0, out, width - data.length, data.length); return out; }
    public String toString() { return description; }
}
