/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.io.*;
import java.nio.file.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.util.Collections;
import net.sf.scuba.data.Gender;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;

/** Generate the APK fixture with unmodified JMRTD 0.8.9, not a custom encoder. */
public final class GenerateDG2Fixture {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Usage: GenerateDG2Fixture input.jpg output-dg2.bin preview.jpg");
        byte[] jpeg = Files.readAllBytes(Paths.get(args[0]));
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(jpeg));
        if (image == null) throw new IOException("Invalid test JPEG");
        FaceImageInfo face = new FaceImageInfo(Gender.UNSPECIFIED, FaceImageInfo.EyeColor.UNSPECIFIED,
                0, 0, 0, new int[3], new int[3], 0, 0, 0, 0, 0, new FaceImageInfo.FeaturePoint[0],
                image.getWidth(), image.getHeight(), new ByteArrayInputStream(jpeg), jpeg.length,
                FaceImageInfo.IMAGE_DATA_TYPE_JPEG);
        byte[] encoded = new DG2File(Collections.singletonList(new FaceInfo(Collections.singletonList(face)))).getEncoded();
        Path output = Paths.get(args[1]); Files.createDirectories(output.getParent()); Files.write(output, encoded);
        Path preview = Paths.get(args[2]); Files.createDirectories(preview.getParent()); Files.write(preview, jpeg);
        System.out.println("DG2: " + encoded.length + " bytes; JPEG: " + jpeg.length + " bytes; " + image.getWidth() + "x" + image.getHeight());
    }
}
