/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;

import org.junit.Test;
import java.util.Arrays;
import static org.junit.Assert.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardCrypto.*;

public class TravelDocumentEmulatorTest {
    private void sw(TravelDocumentEmulator card, String command, String status) {
        byte[] response = card.process(hex(command));
        assertArrayEquals(hex(status), slice(response, response.length - 2, response.length));
    }
    @Test public void nistAESCMACKnownAnswer() {
        assertArrayEquals(hex("070A16B46B4D4144"), mac(true, hex("2B7E151628AED2A6ABF7158809CF4F3C"), hex("6BC1BEE22E409F96E93D7E117393172A")));
    }
    @Test public void originalJMRTDPasswordKeyKnownAnswer() throws Exception {
        byte[] seed = sha1("T22000129364081251010318".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        // The public JMRTD PACE oracle uses this MRZ information.
        assertArrayEquals(hex("89DED1B26624EC1E634C1989302849DD"), kdf(seed, 3, false));
    }
    @Test public void cardAccessOnlyAdvertisedForPACE() {
        for (String format : new String[] {"TD1", "TD3"}) for (String mode : new String[] {"BAC", "PACE"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, mode);
            sw(card, "00A4000C023F00", "9000");
            sw(card, "00A4020C02011C", mode.equals("PACE") ? "9000" : "6A82");
            if (mode.equals("PACE")) assertArrayEquals(hex("31143012060A04007F0007020204020202010202010D9000"), card.process(hex("00B0000000")));
        }
    }
    @Test public void rejectedMasterFileSelectionIsOptionalAndDoesNotChangeOtherSelections() {
        for (String format : new String[] {"TD1", "TD3"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, "BAC");
            sw(card, "00A4000C", "9000");
            sw(card, "00A4000C023F00", "9000");
            card.setRejectSelectMF(true);
            sw(card, "00A4040C07A0000002471001", "9000");
            sw(card, "00A4000C023F00", "6A81");
            sw(card, "00A4000C", "6A81");
            sw(card, "00A4020C020101", "9000");
            sw(card, "00B0000004", "6982");
            sw(card, "0084000008", "9000");
            card.deactivate();
            sw(card, "00A4000C023F00", "6A81");
            card.setRejectSelectMF(false);
            sw(card, "00A4000C023F00", "9000");
            sw(card, "00A4000C", "9000");
        }
    }
    @Test public void rejectedMasterFileFixtureDoesNotAffectPACE() {
        for (String format : new String[] {"TD1", "TD3"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, "PACE");
            card.setRejectSelectMF(true);
            sw(card, "00A4000C", "9000");
            sw(card, "00A4000C023F00", "9000");
            sw(card, "00A4020C02011C", "9000");
            assertArrayEquals(hex("31143012060A04007F0007020204020202010202010D9000"), card.process(hex("00B0000000")));
        }
    }
    @Test public void wrongLengthMasterFileReproducesTheCapturedDiscoverySequence() {
        for (String format : new String[] {"TD1", "TD3"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, "BAC");
            card.setSelectMFResponse(0x6700);
            sw(card, "00A4040C07A0000002471001", "9000");
            sw(card, "00A4020C02011C", "6A82");
            sw(card, "00A4000C", "6700");
            // MF rejection leaves the previously selected application usable.
            sw(card, "00A4020C020101", "9000");
            sw(card, "00B0000004", "6982");
            sw(card, "00A4000C023F00", "6700");
            sw(card, "00A4040C07A0000002471002", "6A82");
        }
    }
    @Test public void wrongLengthMasterFilePersistsAcrossLinkLossAndCanBeRestored() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD3", "BAC");
        card.setSelectMFResponse(0x6700);
        card.deactivate();
        sw(card, "00A4000C", "6700");
        card.setSelectMFResponse(0x6A81);
        sw(card, "00A4000C", "6A81");
        card.setSelectMFResponse(0x9000);
        sw(card, "00A4000C", "9000");
        sw(card, "00A4000C023F00", "9000");
    }
    @Test public void wrongLengthMasterFileDoesNotAffectPACE() {
        for (String format : new String[] {"TD1", "TD3"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, "PACE");
            card.setSelectMFResponse(0x6700);
            sw(card, "00A4000C", "9000");
            sw(card, "00A4000C023F00", "9000");
            sw(card, "00A4020C02011C", "9000");
            assertArrayEquals(hex("31143012060A04007F0007020204020202010202010D9000"), card.process(hex("00B0000000")));
        }
    }
    @Test public void invalidMasterFileResponseDoesNotChangeTheActiveScenario() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD3", "BAC");
        card.setSelectMFResponse(0x6700);
        try { card.setSelectMFResponse(0x6988); fail("Unsupported fixture status accepted"); }
        catch (IllegalArgumentException expected) { }
        sw(card, "00A4000C", "6700");
    }
    @Test public void bacAuthenticationStillWorksAfterRejectedMasterFileSelection() throws Exception {
        for (int rejection : new int[] {0x6A81, 0x6700}) for (String format : new String[] {"TD1", "TD3"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, "BAC");
            card.setSelectMFResponse(rejection);
            sw(card, "00A4040C07A0000002471001", "9000");
            sw(card, "00A4000C023F00", Integer.toHexString(rejection));
            sw(card, "00A4000C", Integer.toHexString(rejection));
            String mrz = (format.equals("TD1") ? "D231458907" : "L898902C36") + "7408122" + "1204159";
            byte[] seed = slice(sha1(mrz.getBytes(java.nio.charset.StandardCharsets.US_ASCII)), 0, 16);
            byte[] enc = kdf(seed, 1, true), macKey = kdf(seed, 2, true);
            byte[] challenge = card.process(hex("0084000008"));
            assertEquals(10, challenge.length);
            assertArrayEquals(hex("9000"), slice(challenge, 8, 10));
            byte[] rndICC = slice(challenge, 0, 8), rndIFD = hex("0102030405060708");
            byte[] keyIFD = hex("000102030405060708090A0B0C0D0E0F");
            byte[] encrypted = crypt(true, false, enc, new byte[8], concat(rndIFD, rndICC, keyIFD));
            byte[] response = card.process(concat(hex("0082000028"), encrypted, mac(false, macKey, pad(encrypted, 8)), hex("28")));
            assertEquals(42, response.length);
            assertArrayEquals(hex("9000"), slice(response, 40, 42));
            assertArrayEquals(mac(false, macKey, pad(slice(response, 0, 32), 8)), slice(response, 32, 40));
            byte[] plain = crypt(false, false, enc, new byte[8], slice(response, 0, 32));
            assertArrayEquals(concat(rndICC, rndIFD), slice(plain, 0, 16));
            assertEquals("BAC authenticated", card.getStatus());
        }
    }
    @Test public void fixtureFilesCannotBeReadBeforeAuthentication() {
        for (String mode : new String[] {"BAC", "PACE"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator("TD1", mode);
            sw(card, "00A4040C07A0000002471001", "9000");
            for (String fid : new String[] {"0101", "0102", "011D", "011E"}) {
                sw(card, "00A4020C02" + fid, "9000");
                sw(card, "00B0000004", "6982");
            }
            sw(card, "00B0810004", "6982");
            sw(card, "00B0820004", "6982");
            sw(card, "00B09D0004", "6982");
        }
    }
    @Test public void optionalBiometricFilesRequireAuthenticationInEveryFixture() {
        for (String format : new String[] {"TD1", "TD3"}) for (String mode : new String[] {"BAC", "PACE"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator(format, mode, "Valid", false, false, false, true);
            sw(card, "00A4040C07A0000002471001", "9000");
            for (String fid : new String[] {"0103", "0104"}) { sw(card, "00A4020C02" + fid, "9000"); sw(card, "00B0000004", "6982"); }
            sw(card, "00B0830004", "6982"); sw(card, "00B0840004", "6982");
        }
    }
    @Test public void biometricFilesAreAbsentWhenTheirOptionIsOff() {
        for (String mode : new String[] {"BAC", "PACE"}) {
            TravelDocumentEmulator card = new TravelDocumentEmulator("TD3", mode);
            sw(card, "00A4040C07A0000002471001", "9000"); sw(card, "00A4020C020103", "6A82"); sw(card, "00A4020C020104", "6A82");
            sw(card, "00B0830004", "6A82"); sw(card, "00B0840004", "6A82");
        }
    }
    @Test public void noBACDowngradeOnPACECard() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD1", "PACE");
        sw(card, "00A4040C07A0000002471001", "9000");
        sw(card, "0084000008", "6982");
        sw(card, "0082000028" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000", "6982");
    }
    @Test public void wrongAIDAndUnavailableFilesReturnNotFound() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD3", "BAC");
        sw(card, "00A4040C07A0000002471002", "6A82");
        sw(card, "00A4040C07A0000002471001", "9000");
        sw(card, "00A4020C020103", "6A82");
        sw(card, "00A4020C02011D", "9000");
    }
    @Test public void challengeConsumedOnFailureAndClearedOnLinkLoss() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD3", "BAC");
        sw(card, "00A4040C07A0000002471001", "9000");
        sw(card, "0084000008", "9000");
        byte[] command = new byte[45]; command[1] = (byte) 0x82; command[4] = 40;
        assertArrayEquals(hex("6300"), card.process(command));
        assertArrayEquals(hex("6982"), card.process(command));
        sw(card, "0084000008", "9000");
        card.deactivate(); assertArrayEquals(hex("6982"), card.process(command));
    }
    @Test public void malformedCommandAndLengthRejected() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD1", "PACE");
        for (String command : new String[] {"", "00", "00A400", "00A4000C023F", "00A4000C003F"}) sw(card, command, "6700");
        sw(card, "00A4000C023F00", "9000");
        sw(card, "00B0000004", "6986");
    }
    @Test public void malformedPACEAndOutOfSequenceStepsResetState() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD1", "PACE");
        sw(card, "10860000027C00", "6300");
        sw(card, "0022C1A412800A04007F0007020204020283010184010D", "9000");
        sw(card, "10860000037C0100", "6300");
        sw(card, "10860000027C00", "6300");
        sw(card, "0022C1A412800A04007F0007020204020283010184010D", "9000");
        sw(card, "10860000027C00", "9000");
    }
    @Test public void invalidAndCompressedPointsRejected() {
        for (byte[] value : new byte[][] {new byte[65], concat(new byte[] {4}, new byte[64]), new byte[33]}) {
            try { point(value); fail("Invalid point accepted"); } catch (Status expected) { assertEquals(0x6A80, expected.sw); }
        }
        assertEquals(65, encode(point(encode(CURVE.getG()))).length);
    }
    @Test public void secureMessagingSequenceOverflowRejected() {
        byte[] counter = new byte[16]; Arrays.fill(counter, (byte) 0xFF);
        SecureChannel channel = new SecureChannel(true, new byte[16], new byte[16], counter);
        try { channel.wrap(new byte[0], 0x9000); fail("Overflow accepted"); } catch (Status expected) { assertEquals(0x6988, expected.sw); } catch (Exception error) { throw new AssertionError(error); }
    }
    @Test public void destroyedCardCannotReopen() {
        TravelDocumentEmulator card = new TravelDocumentEmulator("TD1", "BAC");
        card.destroy(); card.deactivate(); sw(card, "00A4040C07A0000002471001", "6F00");
    }
}
