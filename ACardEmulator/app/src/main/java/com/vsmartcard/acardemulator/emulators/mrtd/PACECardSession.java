/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.math.ec.ECPoint;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardCrypto.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.PACECardProfile.fixed;

final class PACECardSession {
    private final PACECardProfile profile;
    private byte[] passwordKey, enc, macKey, publicBytes, peerBytes, piccNonce, camData;
    private BigInteger nonce, dhGenerator;
    private ECPoint ecGenerator;
    private int phase;
    PACECardSession(PACECardProfile profile, byte[] passwordSeed) throws GeneralSecurityException { this.profile = profile; passwordKey = derive(passwordSeed, 3); }
    private byte[] derive(byte[] seed, int counter) throws GeneralSecurityException {
        byte[] hash = MessageDigest.getInstance(profile.keyBits > 128 ? "SHA-256" : "SHA-1").digest(concat(seed, new byte[]{0,0,0,(byte)counter}));
        return profile.aes ? Arrays.copyOf(hash, profile.keyBits / 8) : concat(Arrays.copyOf(hash, 16), Arrays.copyOf(hash, 8));
    }
    int phase() { return phase; }
    byte[] exchange(Command c) throws GeneralSecurityException {
        require(c.p1 == 0 && c.p2 == 0 && phase < 4 && c.cla == (phase == 3 ? 0 : 0x10), 0x6985);
        List<TLV> outer = objects(c.data); require(outer.size() == 1 && outer.get(0).tag == 0x7C, 0x6A80);
        List<TLV> inner = objects(outer.get(0).value); require(phase == 0 ? inner.isEmpty() : inner.size() == 1 && inner.get(0).tag == new int[]{0,0x81,0x83,0x85}[phase], 0x6A80);
        byte[] data = inner.isEmpty() ? new byte[0] : inner.get(0).value, response, additional = new byte[0];
        if (phase == 0) {
            byte[] clear = random(profile.aes || profile.im ? 16 : 8); nonce = new BigInteger(1, clear); if(profile.im)piccNonce=clear.clone();
            response = crypt(true, profile.aes, passwordKey, new byte[profile.aes ? 16 : 8], clear); wipe(clear);
        } else if (phase == 1) {
            if(profile.im){require(data.length==piccNonce.length,0x6A80);BigInteger x=CardIntegratedMapping.prf(profile,piccNonce,data);if(profile.dh)dhGenerator=x.modPow(profile.p.subtract(BigInteger.ONE).divide(profile.q),profile.p);else ecGenerator=CardIntegratedMapping.icart(profile,x);response=new byte[0];wipe(piccNonce);piccNonce=null;}
            else{BigInteger secret = profile.scalar();
                if (profile.dh) { BigInteger peer = profile.publicValue(data); BigInteger value = profile.g.modPow(secret, profile.p); dhGenerator = profile.g.modPow(nonce, profile.p).multiply(peer.modPow(secret, profile.p)).mod(profile.p); response = PACECardProfile.minimal(value); }
                else { ECPoint peer = profile.point(data); ECPoint pub = profile.curve.getG().multiply(secret); ecGenerator = profile.curve.getG().multiply(nonce).add(peer.multiply(secret)); response = profile.encode(pub); profile.encode(ecGenerator);if(profile.cam)camData=fixed(secret.multiply(BigInteger.valueOf(5).modInverse(profile.q)).mod(profile.q),profile.width); }
            }
            nonce = null;
        } else if (phase == 2) {
            BigInteger secret = profile.scalar(); byte[] shared;
            if (profile.dh) { BigInteger peer = profile.publicValue(data); publicBytes = PACECardProfile.minimal(dhGenerator.modPow(secret, profile.p)); peerBytes = PACECardProfile.minimal(peer); shared = fixed(peer.modPow(secret, profile.p), profile.width); }
            else { ECPoint peer = profile.point(data); publicBytes = profile.encode(ecGenerator.multiply(secret)); peerBytes = profile.encode(peer); shared = fixed(peer.multiply(secret).getX().toBigInteger(), profile.width); }
            require(!equal(peerBytes, publicBytes), 0x6A80); enc = derive(shared, 1); macKey = derive(shared, 2); wipe(shared); response = publicBytes.clone();
        } else {
            require(equal(data, token(publicBytes)), 0x6300); response = token(peerBytes);
            if(profile.cam){byte[] minusOne=new byte[16];Arrays.fill(minusOne,(byte)255);byte[] iv=crypt(true,true,enc,new byte[16],minusOne);additional=tlv(0x8A,crypt(true,true,enc,iv,pad(camData,16)));wipe(iv);}
        }
        return tlv(0x7C, concat(tlv(new int[]{0x80,0x82,0x84,0x86}[phase++], response),additional));
    }
    private byte[] token(byte[] key) { byte[] data = tlv(0x7F49, concat(tlv(6, profile.oid), tlv(profile.dh ? 0x84 : 0x86, key))); return mac(profile.aes, macKey, profile.aes ? data : pad(data, 8)); }
    SecureChannel channel() { require(phase == 4, 0x6985); return new SecureChannel(profile.aes, enc, macKey, new byte[profile.aes ? 16 : 8]); }
    byte[] identifier() throws GeneralSecurityException { require(phase == 4, 0x6985); return profile.dh ? sha1(publicBytes) : slice(publicBytes, 1, 1 + profile.width); }
    void clear() { wipe(passwordKey); wipe(enc); wipe(macKey); wipe(publicBytes); wipe(peerBytes); wipe(piccNonce);wipe(camData);passwordKey = enc = macKey = publicBytes = peerBytes = piccNonce = camData = null; nonce = dhGenerator = null; ecGenerator = null; }
}
