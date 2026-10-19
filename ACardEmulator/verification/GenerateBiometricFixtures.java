/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.*;
/** Deterministic geometric test patterns, encoded and parsed by unmodified JMRTD 0.8.9. */
public final class GenerateBiometricFixtures {
  static String hex(byte[] b) { StringBuilder s=new StringBuilder(); for(byte v:b)s.append(String.format("%02X",v&255)); return s.toString(); }
  static byte[] jpeg(String id,int number,int side)throws Exception {
    BufferedImage image=new BufferedImage(96,96,BufferedImage.TYPE_BYTE_GRAY);
    Graphics2D g=image.createGraphics();g.setColor(Color.WHITE);g.fillRect(0,0,96,96);g.setColor(Color.DARK_GRAY);
    g.setStroke(new BasicStroke(1.2f));
    if(number==3){for(int i=0;i<14;i++)g.drawOval(5+i*3,9+i*2,85-i*6,78-i*4);}
    else{g.fillOval(14,14,68,68);g.setColor(Color.LIGHT_GRAY);for(int i=0;i<40;i++){double a=i*Math.PI/20;g.drawLine(48+(int)(14*Math.cos(a)),48+(int)(14*Math.sin(a)),48+(int)(32*Math.cos(a)),48+(int)(32*Math.sin(a)));}g.setColor(Color.BLACK);g.fillOval(35,35,26,26);}
    g.setColor(Color.WHITE);g.fillRect(0,0,96,12);g.setColor(Color.BLACK);g.setFont(new Font(Font.MONOSPACED,Font.PLAIN,9));g.drawString("TEST "+id.toUpperCase(),0,9);g.drawString(side==0?"RIGHT":"LEFT",2,94);g.dispose();
    ByteArrayOutputStream out=new ByteArrayOutputStream();ImageWriter writer=ImageIO.getImageWritersByFormatName("JPEG").next();
    ImageWriteParam parameters=writer.getDefaultWriteParam();parameters.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);parameters.setCompressionQuality(0.4f);
    try(javax.imageio.stream.ImageOutputStream output=ImageIO.createImageOutputStream(out)){writer.setOutput(output);writer.write(null,new IIOImage(image,null,null),parameters);}finally{writer.dispose();}return out.toByteArray();
  }
  static void put(Path p,byte[] bytes)throws Exception{Files.createDirectories(p.getParent());Files.write(p,bytes);}
  static void value(Map<String,String> v,String key,Object value){v.put(key,String.valueOf(value));}
  public static void main(String[] args)throws Exception {
    Path root=Paths.get(args[0]),out=root.resolve("app/src/main/resources/mrtd"),preview=root.resolve("app/src/main/res/drawable-nodpi");
    for(Class<?> type:new Class<?>[]{FingerInfo.class,FingerImageInfo.class,IrisInfo.class,IrisBiometricSubtypeInfo.class,IrisImageInfo.class})for(java.lang.reflect.Field field:type.getDeclaredFields())if(java.lang.reflect.Modifier.isPublic(field.getModifiers())&&java.lang.reflect.Modifier.isStatic(field.getModifiers())&&field.getType()==int.class)System.out.println("constant|"+type.getSimpleName()+"|"+field.getName()+"|"+field.getInt(null));
    for(String format:new String[]{"td1","td3"})for(String auth:new String[]{"bac","pace"}){
      String id=format+"-"+auth;java.util.List<FingerImageInfo> fingers=new ArrayList<>();java.util.List<IrisBiometricSubtypeInfo> eyes=new ArrayList<>();Map<String,String> v=new LinkedHashMap<>();v.put("id",id);
      for(int side=0;side<2;side++){
        byte[] finger=jpeg(id,3,side),iris=jpeg(id,4,side);v.put("fingerImage"+side,hex(finger));v.put("irisImage"+side,hex(iris));
        fingers.add(new FingerImageInfo(side==0?2:7,1,1,80+side*10,0,96,96,new ByteArrayInputStream(finger),finger.length,FingerInfo.COMPRESSION_JPEG));
        IrisImageInfo image=new IrisImageInfo(1,254,0,65535,96,96,new ByteArrayInputStream(iris),iris.length,IrisInfo.IMAGEFORMAT_MONO_JPEG);
        eyes.add(new IrisBiometricSubtypeInfo(side==0?1:2,IrisInfo.IMAGEFORMAT_MONO_JPEG,Collections.singletonList(image)));
        put(preview.resolve("dg3_"+id.replace('-','_')+"_"+side+".jpg"),finger);put(preview.resolve("dg4_"+id.replace('-','_')+"_"+side+".jpg"),iris);
      }
      FingerInfo finger=new FingerInfo(291,31,1,500,500,500,500,8,3,fingers);
      IrisInfo iris=new IrisInfo(291,1,1,1,0,0,1,64,6,96,96,8,0,new byte[16],eyes);
      byte[] dg3=DG3File.createISO19794DG3File(Collections.singletonList(finger)).getEncoded(),dg4=DG4File.createISO19794DG4File(Collections.singletonList(iris)).getEncoded();
      if(dg3.length>8192||dg4.length>8192)throw new IOException("Biometric fixture exceeds current card limit");
      put(out.resolve("dg3-"+id+".bin"),dg3);put(out.resolve("dg4-"+id+".bin"),dg4);
      v.put("dg3",hex(dg3));v.put("dg4",hex(dg4));
      DG3File read3=new DG3File(new ByteArrayInputStream(dg3));DG4File read4=new DG4File(new ByteArrayInputStream(dg4));
      FingerInfo f=read3.getFingerInfos().get(0);IrisInfo i=read4.getIrisInfos().get(0);
      // Header map hashes contain Java byte-array identity hashes and are not portable.
      v.put("finger",hex(f.getEncoded()));v.put("iris",hex(i.getEncoded()));
      value(v,"fingerImageHash",f.getFingerImageInfos().get(0).hashCode());value(v,"irisImageHash",i.getIrisBiometricSubtypeInfos().get(0).getIrisImageInfos().get(0).hashCode());value(v,"irisSubtypeHash",i.getIrisBiometricSubtypeInfos().get(0).hashCode());
      value(v,"fingerImageString",f.getFingerImageInfos().get(0).toString());value(v,"irisImageString",i.getIrisBiometricSubtypeInfos().get(0).getIrisImageInfos().get(0).toString());value(v,"irisSubtypeString",i.getIrisBiometricSubtypeInfos().get(0).toString());
      StringBuilder line=new StringBuilder("{");for(Map.Entry<String,String> e:v.entrySet()){if(line.length()>1)line.append(',');line.append('"').append(e.getKey()).append("\":\"").append(e.getValue().replace("\\","\\\\").replace("\"","\\\"")).append('"');}System.out.println(line.append('}'));
      put(out.resolve("biometric-preview-"+id+".txt"),("DG3 / DG4 - SYNTHETIC TEST IMAGES\n"+id.toUpperCase()+"\nDG3: Right index / Left index, quality 80 / 90\n96 x 96, JPEG, 500 ppi, 8-bit\nDG4: Right eye / Left eye, quality undefined\n96 x 96, JPEG, 8-bit\nDG3 bytes: "+dg3.length+"; DG4 bytes: "+dg4.length).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
  }
}
