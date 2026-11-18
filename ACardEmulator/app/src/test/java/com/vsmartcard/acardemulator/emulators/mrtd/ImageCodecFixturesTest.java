/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;

import org.junit.Test;
import java.lang.reflect.Field;
import static org.junit.Assert.*;

public class ImageCodecFixturesTest {
    private static byte[] field(TravelDocumentEmulator card, String name) throws Exception {
        Field field = TravelDocumentEmulator.class.getDeclaredField(name);
        field.setAccessible(true);
        return (byte[]) field.get(card);
    }

    @Test public void defaultEncodingPreservesAllBaselineFiles() throws Exception {
        for (String format : new String[]{"TD1", "TD2", "TD3"}) for (String auth : new String[]{"BAC", "PACE"}) {
            TravelDocumentEmulator before = new TravelDocumentEmulator(format, auth, "Valid", true, true, true, true);
            TravelDocumentEmulator explicit = new TravelDocumentEmulator(format, auth, "Valid", true, true, true, true, ImageCodecFixtures.JPEG);
            for (String file : new String[]{"dg1", "dg2", "dg3", "dg4", "com", "sod"}) {
                assertArrayEquals(file, field(before, file), field(explicit, file));
            }
        }
    }

    @Test public void codecVariantsChangeOnlyTheSelectedImageGroupAndSOD() throws Exception {
        for (String codec : new String[]{ImageCodecFixtures.JPEG2000, ImageCodecFixtures.WSQ}) {
            TravelDocumentEmulator baseline = new TravelDocumentEmulator("TD3", "BAC", "Valid", true, true, true, true);
            TravelDocumentEmulator variant = new TravelDocumentEmulator("TD3", "BAC", "Valid", true, true, true, true, codec);
            for (String file : new String[]{"dg1", "dg4", "dg5", "dg7", "dg11", "dg12", "dg14", "dg15", "com"}) {
                assertArrayEquals(file, field(baseline, file), field(variant, file));
            }
            assertFalse(java.util.Arrays.equals(field(baseline, "sod"), field(variant, "sod")));
            assertArrayEquals(field(baseline, codec.equals(ImageCodecFixtures.WSQ) ? "dg2" : "dg3"),
                    field(variant, codec.equals(ImageCodecFixtures.WSQ) ? "dg2" : "dg3"));
        }
    }

    @Test public void allDocumentAndPAScenariosCanLoadBothCodecProfiles() {
        for (String format : new String[]{"TD1", "TD2", "TD3"}) for (String auth : new String[]{"BAC", "PACE"}) {
            for (String scenario : new String[]{"Valid", "Altered DG1", "Bad signature", "Untrusted CSCA",
                    "CMS RSA (SHA-384)", "CMS PSS (SHA-256)", "CMS ECDSA (SHA-512)", "ISO 39794 base", "ISO 39794 ICAO"}) {
                for (String codec : new String[]{ImageCodecFixtures.JPEG2000, ImageCodecFixtures.WSQ}) {
                    TravelDocumentEmulator card = new TravelDocumentEmulator(format, auth, scenario, true, true, true, true, codec);
                    byte[] response = card.process(CardBytes.hex("00A4040C07A0000002471001"));
                    assertArrayEquals(CardBytes.hex("9000"), response);
                    card.destroy();
                }
            }
        }
    }

    @Test public void wsqWithoutBiometricsKeepsTheOriginalCard() throws Exception {
        TravelDocumentEmulator original = new TravelDocumentEmulator("TD3", "PACE");
        TravelDocumentEmulator selected = new TravelDocumentEmulator("TD3", "PACE", "Valid", false, false, false, false, ImageCodecFixtures.WSQ);
        assertNull(field(selected, "dg3"));
        assertArrayEquals(field(original, "dg2"), field(selected, "dg2"));
        assertArrayEquals(field(original, "sod"), field(selected, "sod"));
    }

    @Test(expected = IllegalArgumentException.class) public void unsupportedCodecRejected() {
        new TravelDocumentEmulator("TD3", "BAC", "Valid", false, false, false, false, "Unknown");
    }
}
