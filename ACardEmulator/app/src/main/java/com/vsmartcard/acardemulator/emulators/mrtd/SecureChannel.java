/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;

import java.security.GeneralSecurityException;
import java.util.List;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardCrypto.*;

final class SecureChannel {
    private final boolean aes;
    private final int block;
    private final byte[] enc, macKey, ssc;
    SecureChannel(boolean aes, byte[] enc, byte[] macKey, byte[] ssc) {
        this.aes = aes; this.block = aes ? 16 : 8;
        this.enc = enc.clone(); this.macKey = macKey.clone(); this.ssc = ssc.clone();
    }
    private void increment() {
        for (int i = ssc.length - 1; i >= 0; i--) if (++ssc[i] != 0) return;
        throw new Status(0x6988);
    }
    private byte[] iv() throws GeneralSecurityException { return aes ? aesIV(enc, ssc) : new byte[8]; }
    Command unwrap(Command c) throws GeneralSecurityException {
        increment();
        List<TLV> entries = objects(c.data);
        require(!entries.isEmpty(), 0x6988);
        TLV checksum = entries.remove(entries.size() - 1);
        require(checksum.tag == 0x8E && checksum.value.length == 8, 0x6988);
        byte[] payload = new byte[0], encrypted = null;
        int le = 0;
        for (TLV object : entries) {
            if (object.tag == 0x87 || object.tag == 0x85) {
                require(encrypted == null && le == 0, 0x6988);
                if (object.tag == 0x87) {
                    require(object.value.length > 1 && object.value[0] == 1, 0x6988);
                    encrypted = slice(object.value, 1, object.value.length);
                } else encrypted = object.value;
                require(encrypted.length > 0 && encrypted.length % block == 0, 0x6988);
            } else if (object.tag == 0x97) {
                require(le == 0 && (object.value.length == 1 || object.value.length == 2), 0x6988);
                for (byte value : object.value) le = le * 256 + (value & 255);
                if (le == 0) le = object.value.length == 1 ? 256 : 65536;
            } else throw new Status(0x6988);
            payload = concat(payload, object.encoded);
        }
        byte[] header = {(byte) c.cla, (byte) c.ins, (byte) c.p1, (byte) c.p2};
        require(equal(mac(aes, macKey, pad(concat(ssc, pad(header, block), payload), block)), checksum.value), 0x6988);
        byte[] data = encrypted == null ? new byte[0] : unpad(crypt(false, aes, enc, iv(), encrypted), block);
        return new Command(c.cla & ~12, c.ins, c.p1, c.p2, data, le);
    }
    byte[] wrap(byte[] data, int sw) throws GeneralSecurityException {
        increment();
        byte[] body = data.length == 0 ? new byte[0] : tlv(0x87, concat(new byte[] {1}, crypt(true, aes, enc, iv(), pad(data, block))));
        body = concat(body, tlv(0x99, new byte[] {(byte) (sw >> 8), (byte) sw}));
        return concat(body, tlv(0x8E, mac(aes, macKey, pad(concat(ssc, body), block))), hex("9000"));
    }
    void destroy() { wipe(enc); wipe(macKey); wipe(ssc); }
}
