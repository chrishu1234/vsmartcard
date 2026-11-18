/* SPDX-License-Identifier: GPL-3.0-or-later
 * Synthetic image-codec interoperability fixtures. No real biometric data.
 */
package com.vsmartcard.acardemulator.emulators.mrtd;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class ImageCodecFixtures {
    public static final String JPEG = "JPEG";
    public static final String JPEG2000 = "JPEG 2000 (DG2)";
    public static final String WSQ = "WSQ (DG3)";
    public static final String[] CHOICES = { JPEG, JPEG2000, WSQ };
    private static final int MAX_FILE_BYTES = 65536;

    private ImageCodecFixtures() { }

    public static void validate(String codec) {
        if (!JPEG.equals(codec) && !JPEG2000.equals(codec) && !WSQ.equals(codec)) {
            throw new IllegalArgumentException("Unknown image encoding: " + codec);
        }
    }

    static byte[] load(String codec, String fixture, int expectedTag) {
        validate(codec);
        String folder = JPEG2000.equals(codec) ? "jpeg2000" : WSQ.equals(codec) ? "wsq" : "";
        if (folder.isEmpty()) throw new IllegalArgumentException("JPEG uses baseline fixtures");
        byte[] result = readEntry(folder + "/" + fixture + ".bin");
        if (result.length < 4 || (result[0] & 255) != expectedTag) {
            throw new IllegalStateException("Invalid image-codec fixture: " + fixture);
        }
        return result;
    }

    public static String wsqPreview(String fixture) {
        return new String(readEntry("wsq/biometric-preview-" + fixture + ".txt"), StandardCharsets.UTF_8);
    }

    private static byte[] readEntry(String name) {
        InputStream resource = ImageCodecFixtures.class.getResourceAsStream("/mrtd/image-codecs.zip");
        if (resource == null) throw new IllegalStateException("Image-codec fixture archive missing");
        try (ZipInputStream input = new ZipInputStream(resource)) {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                if (!entry.getName().equals(name)) continue;
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (bytes.size() + count > MAX_FILE_BYTES) throw new IOException("Fixture exceeds size limit");
                    bytes.write(buffer, 0, count);
                }
                return bytes.toByteArray();
            }
            throw new IOException("Fixture missing: " + name);
        } catch (IOException error) {
            throw new IllegalStateException("Could not load image-codec fixture: " + name, error);
        }
    }
}
