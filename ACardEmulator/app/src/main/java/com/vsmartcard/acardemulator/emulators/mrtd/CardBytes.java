/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class CardBytes {
    private CardBytes() { }
    static byte[] hex(String text) {
        byte[] result = new byte[text.length() / 2];
        for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return result;
    }
    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part, 0, part.length);
        return out.toByteArray();
    }
    static byte[] slice(byte[] value, int start, int end) { return Arrays.copyOfRange(value, start, end); }
    static byte[] pad(byte[] value, int block) {
        byte[] result = Arrays.copyOf(value, (value.length / block + 1) * block);
        result[value.length] = (byte) 0x80;
        return result;
    }
    static byte[] unpad(byte[] value, int block) {
        int end = value.length - 1;
        while (end >= 0 && value[end] == 0) end--;
        require(end >= 0 && value[end] == (byte) 0x80 && value.length - end <= block, 0x6988);
        return slice(value, 0, end);
    }
    static byte[] tlv(int tag, byte[] value) {
        byte[] t = tag > 255 ? new byte[] {(byte) (tag >> 8), (byte) tag} : new byte[] {(byte) tag};
        byte[] l = value.length < 128 ? new byte[] {(byte) value.length}
                : value.length < 256 ? new byte[] {(byte) 0x81, (byte) value.length}
                : new byte[] {(byte) 0x82, (byte) (value.length >> 8), (byte) value.length};
        return concat(t, l, value);
    }
    static List<TLV> objects(byte[] data) {
        List<TLV> result = new ArrayList<>();
        for (int offset = 0; offset < data.length;) {
            int start = offset, tag = data[offset++] & 255;
            if ((tag & 31) == 31) {
                require(offset < data.length && (data[offset] & 128) == 0, 0x6A80);
                tag = tag * 256 + (data[offset++] & 255);
            }
            require(offset < data.length, 0x6A80);
            int length = data[offset++] & 255;
            if (length >= 128) {
                int count = length & 127;
                require(count > 0 && count <= 2 && offset + count <= data.length, 0x6A80);
                length = 0;
                for (int i = 0; i < count; i++) length = length * 256 + (data[offset++] & 255);
                require(length >= 128 && (count != 2 || length > 255), 0x6A80);
            }
            require(offset + length <= data.length, 0x6A80);
            result.add(new TLV(tag, slice(data, offset, offset + length), slice(data, start, offset + length)));
            offset += length;
        }
        return result;
    }
    static void require(boolean condition, int sw) { if (!condition) throw new Status(sw); }
    static final class Status extends RuntimeException {
        final int sw;
        Status(int sw) { this.sw = sw; }
    }
    static final class TLV {
        final int tag;
        final byte[] value, encoded;
        TLV(int tag, byte[] value, byte[] encoded) { this.tag = tag; this.value = value; this.encoded = encoded; }
    }
    static final class Command {
        final int cla, ins, p1, p2, le;
        final byte[] data;
        Command(int cla, int ins, int p1, int p2, byte[] data, int le) {
            this.cla = cla; this.ins = ins; this.p1 = p1; this.p2 = p2; this.data = data; this.le = le;
        }
        static Command parse(byte[] raw) {
            require(raw != null && raw.length >= 4, 0x6700);
            int le = 0;
            byte[] data = new byte[0];
            if (raw.length == 5) le = (raw[4] & 255) == 0 ? 256 : raw[4] & 255;
            else if (raw.length > 5) {
                int offset = 5, length = raw[4] & 255, leBytes = 1;
                if (length == 0) {
                    require(raw.length >= 7, 0x6700);
                    offset = 7; leBytes = 2;
                    length = (raw[5] & 255) * 256 + (raw[6] & 255);
                    if (raw.length == 7) return new Command(raw[0] & 255, raw[1] & 255, raw[2] & 255, raw[3] & 255, data, length == 0 ? 65536 : length);
                }
                require(length > 0 && (raw.length == offset + length || raw.length == offset + length + leBytes), 0x6700);
                data = slice(raw, offset, offset + length);
                if (raw.length > offset + length) {
                    for (int i = offset + length; i < raw.length; i++) le = le * 256 + (raw[i] & 255);
                    if (le == 0) le = leBytes == 1 ? 256 : 65536;
                }
            }
            return new Command(raw[0] & 255, raw[1] & 255, raw[2] & 255, raw[3] & 255, data, le);
        }
    }
}
