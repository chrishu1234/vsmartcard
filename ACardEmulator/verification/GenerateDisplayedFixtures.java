/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.Collections;
import javax.imageio.ImageIO;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
/** Synthetic display patterns encoded by the unmodified JMRTD 0.8.9 writer. */
public final class GenerateDisplayedFixtures {
  public static void main(String[] args)throws Exception {
    Path root=Paths.get(args[0]);
    for(String format:new String[]{"td1","td3","td2"})for(String auth:new String[]{"bac","pace"})for(int number:new int[]{5,7}){
      String id=format+"-"+auth; BufferedImage image=new BufferedImage(number==5?160:240,number==5?120:80,BufferedImage.TYPE_INT_RGB);
      Graphics2D g=image.createGraphics();g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
      g.setColor(number==5?new Color(0x31546D):Color.WHITE);g.fillRect(0,0,image.getWidth(),image.getHeight());
      g.setColor(number==5?Color.WHITE:new Color(0x31546D));g.setFont(new Font(Font.SANS_SERIF,Font.BOLD,18));
      g.drawString("DG"+number+" TEST",12,25);g.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,14));g.drawString(format.toUpperCase()+" / "+auth.toUpperCase(),12,46);
      if(number==7){g.setStroke(new BasicStroke(3));g.drawPolyline(new int[]{130,145,140,164,177,188,218},new int[]{60,38,65,49,59,43,54},7);}
      else{g.drawRect(12,60,134,43);g.drawString("DISPLAYED IMAGE",16,87);}g.dispose();
      ByteArrayOutputStream bytes=new ByteArrayOutputStream();if(!ImageIO.write(image,"JPEG",bytes))throw new IOException("JPEG unavailable");
      DisplayedImageInfo info=new DisplayedImageInfo(number==5?ImageInfo.TYPE_PORTRAIT:ImageInfo.TYPE_SIGNATURE_OR_MARK,bytes.toByteArray());
      byte[] encoded=(number==5?new DG5File(Collections.singletonList(info)):new DG7File(Collections.singletonList(info))).getEncoded();
      if(encoded.length>8192)throw new IOException("Fixture limit");
      Files.write(root.resolve("app/src/main/resources/mrtd/dg"+number+"-"+id+".bin"),encoded);
      Files.write(root.resolve("verification/fixtures/dg"+number+"-"+id+".jpg"),bytes.toByteArray());
      Files.write(root.resolve("app/src/main/res/drawable-nodpi/dg"+number+"_"+id.replace('-','_')+".jpg"),bytes.toByteArray());
    }
    System.out.println("Generated eight synthetic DG5/DG7 files with original JMRTD 0.8.9.");
  }
}
