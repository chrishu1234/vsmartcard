/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import javax.imageio.ImageIO;

/** Deterministic labeled test patterns; no external images or identity data. */
public final class GenerateDG2Fixtures {
    private static String digest(Path file) throws Exception {
        StringBuilder hex = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file))) hex.append(String.format("%02x", b & 255));
        return hex.toString();
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: GenerateDG2Fixtures ACardEmulator-directory");
        Path root = Paths.get(args[0]);
        String[] formats = {"TD1", "TD1", "TD3", "TD3", "TD2", "TD2"};
        String[] methods = {"BAC", "PACE", "BAC", "PACE", "BAC", "PACE"};
        String[] colors = {"#2563EB", "#059669", "#D97706", "#7C3AED", "#BE185D", "#0E7490"};
        StringBuilder manifest = new StringBuilder("{\n  \"description\": \"Synthetic labeled JPEG test cards; no personal or biometric image.\",\n  \"generator\": \"GenerateDG2Fixtures.java + GenerateDG2Fixture.java with JMRTD 0.8.9\",\n  \"width\": 160,\n  \"height\": 120,\n  \"fixtures\": [\n");
        for (int i = 0; i < formats.length; i++) {
            String name = formats[i].toLowerCase(java.util.Locale.ROOT) + "-" + methods[i].toLowerCase(java.util.Locale.ROOT);
            BufferedImage image = new BufferedImage(160, 120, BufferedImage.TYPE_INT_RGB);
            Graphics2D g = image.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            Color base = Color.decode(colors[i]);
            g.setColor(base); g.fillRect(0, 0, 160, 120);
            g.setColor(base.brighter()); g.fillPolygon(new int[] {90, 160, 160}, new int[] {0, 0, 90}, 3);
            g.setColor(Color.WHITE);
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 28)); g.drawString(formats[i], 13, 39);
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 24)); g.drawString(methods[i], 13, 70);
            g.drawLine(13, 82, 146, 82);
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12)); g.drawString("DG2 TEST " + (i + 1), 13, 103);
            g.dispose();
            Path jpeg = root.resolve("verification/fixtures/photo-" + name + ".jpg");
            Files.createDirectories(jpeg.getParent());
            if (!ImageIO.write(image, "JPEG", jpeg.toFile())) throw new IOException("JPEG writer unavailable");
            Path dg2 = root.resolve("app/src/main/resources/mrtd/dg2-" + name + ".bin");
            Path preview = root.resolve("app/src/main/res/drawable-nodpi/dg2_" + name.replace('-', '_') + ".jpg");
            GenerateDG2Fixture.main(new String[] {jpeg.toString(), dg2.toString(), preview.toString()});
            if (Files.size(dg2) > 8192) throw new IOException("Fixture exceeds card resource bound");
            manifest.append(String.format(java.util.Locale.ROOT,
                "    {\"id\":\"%s\",\"format\":\"%s\",\"authentication\":\"%s\",\"color\":\"%s\",\"jpegBytes\":%d,\"dg2Bytes\":%d,\"jpegSHA256\":\"%s\",\"dg2SHA256\":\"%s\"}%s\n",
                name, formats[i], methods[i], colors[i], Files.size(jpeg), Files.size(dg2), digest(jpeg), digest(dg2), i == formats.length - 1 ? "" : ","));
            System.out.println(name + " " + colors[i] + " " + digest(jpeg));
        }
        manifest.append("  ]\n}\n");
        Files.write(root.resolve("verification/fixtures/photo.json"), manifest.toString().getBytes(StandardCharsets.UTF_8));
    }
}
