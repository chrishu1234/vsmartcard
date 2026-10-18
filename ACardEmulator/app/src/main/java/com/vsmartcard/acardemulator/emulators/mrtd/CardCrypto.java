/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;

final class CardCrypto {
    static final SecureRandom RANDOM = new SecureRandom();
    static final X9ECParameters CURVE = TeleTrusTNamedCurves.getByName("brainpoolP256r1");
    private CardCrypto() { }
    static byte[] random(int size) { byte[] out = new byte[size]; RANDOM.nextBytes(out); return out; }
    static byte[] sha1(byte[] bytes) throws GeneralSecurityException { return MessageDigest.getInstance("SHA-1").digest(bytes); }
    static byte[] kdf(byte[] seed, int counter, boolean des) throws GeneralSecurityException {
        byte[] key = Arrays.copyOf(sha1(concat(seed, new byte[] {0, 0, 0, (byte) counter})), 16);
        if (des) for (int i = 0; i < key.length; i++) {
            int value = key[i] & 254;
            key[i] = (byte) (value | ((Integer.bitCount(value) & 1) ^ 1));
        }
        return key;
    }
    static byte[] crypt(boolean encrypt, boolean aes, byte[] key, byte[] iv, byte[] data) throws GeneralSecurityException {
        String algorithm = aes ? "AES" : "DESede";
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");
        byte[] material = aes ? key : concat(key, slice(key, 0, 8));
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(material, algorithm), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
    static byte[] aesIV(byte[] key, byte[] counter) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(counter);
    }
    static byte[] mac(boolean aes, byte[] key, byte[] input) {
        org.bouncycastle.crypto.Mac mac = aes ? new CMac(new AESEngine()) : new ISO9797Alg3Mac(new DESEngine());
        mac.init(new KeyParameter(key)); mac.update(input, 0, input.length);
        byte[] result = new byte[mac.getMacSize()]; mac.doFinal(result, 0);
        return Arrays.copyOf(result, 8);
    }
    static BigInteger scalar() {
        BigInteger value;
        do { value = new BigInteger(CURVE.getN().bitLength(), RANDOM); } while (value.signum() == 0 || value.compareTo(CURVE.getN()) >= 0);
        return value;
    }
    static ECPoint point(byte[] encoded) {
        require(encoded.length == 65 && encoded[0] == 4, 0x6A80);
        BigInteger x = new BigInteger(1, slice(encoded, 1, 33)), y = new BigInteger(1, slice(encoded, 33, 65));
        BigInteger prime = new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16);
        require(x.compareTo(prime) < 0 && y.compareTo(prime) < 0
                && y.multiply(y).mod(prime).equals(x.pow(3).add(CURVE.getCurve().getA().toBigInteger().multiply(x)).add(CURVE.getCurve().getB().toBigInteger()).mod(prime)), 0x6A80);
        return CURVE.getCurve().decodePoint(encoded);
    }
    static byte[] encode(ECPoint point) {
        require(!point.isInfinity(), 0x6A80);
        byte[] encoded = point.getEncoded();
        require(encoded.length == 65 && encoded[0] == 4, 0x6A80);
        return encoded;
    }
    static boolean equal(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); }
    static void wipe(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
}
