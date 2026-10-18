/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.math.BigInteger;
import java.util.*;
import org.jmrtd.*;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
/** Real JMRTD writers/readers. Synthetic AA/CA private keys are bundled only for card emulation. */
public final class GenerateSecurityFixtures {
  static String x(byte[] b){return HexFormat.of().withUpperCase().formatHex(b);}
  public static void main(String[] args)throws Exception {
    Security.addProvider(Util.getBouncyCastleProvider()); Path out=Paths.get(args[0]).resolve("app/src/main/resources/mrtd");
    for(String format:new String[]{"td1","td3"})for(String auth:new String[]{"bac","pace"}){
      String id=format+"-"+auth;boolean rsa=format.equals("td1");
      SecureRandom random=SecureRandom.getInstance("SHA1PRNG");random.setSeed(("JMRTD-0.8.9-public-fixture-"+id).getBytes(StandardCharsets.US_ASCII));
      KeyPairGenerator aa=KeyPairGenerator.getInstance(rsa?"RSA":"EC",Util.getBouncyCastleProvider());
      if(rsa)aa.initialize(2048,random);else aa.initialize(PACEInfo.toParameterSpec(BigInteger.valueOf(12)),random);
      KeyPair aaPair=aa.generateKeyPair(); PublicKey aaKey=aaPair.getPublic();
      Files.write(out.resolve("aa-private-"+id+".bin"),aaPair.getPrivate().getEncoded());
      KeyPairGenerator ca=KeyPairGenerator.getInstance(rsa?"DH":"EC",Util.getBouncyCastleProvider());
      ca.initialize(PACEInfo.toParameterSpec(BigInteger.valueOf(rsa?0:13)),random);
      KeyPair caPair=ca.generateKeyPair(); PublicKey caKey=caPair.getPublic();
      Files.write(out.resolve("ca-private-"+id+".bin"),caPair.getPrivate().getEncoded());
      List<SecurityInfo> infos=new ArrayList<>();
      if(!rsa)infos.add(new ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID));
      infos.add(new ChipAuthenticationInfo(rsa?SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128:SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128,2,BigInteger.ONE));
      infos.add(new ChipAuthenticationPublicKeyInfo(caKey,BigInteger.ONE));
      infos.add(new TerminalAuthenticationInfo((short)0x011C,(byte)0x1C));
      if(auth.equals("pace"))infos.add(new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,2,13));
      Files.write(out.resolve("dg14-"+id+".bin"),new DG14File(infos).getEncoded());
      Files.write(out.resolve("dg15-"+id+".bin"),new DG15File(aaKey).getEncoded());
      DG14File dg14=new DG14File(new ByteArrayInputStream(Files.readAllBytes(out.resolve("dg14-"+id+".bin"))));
      DG15File dg15=new DG15File(new ByteArrayInputStream(Files.readAllBytes(out.resolve("dg15-"+id+".bin"))));
      StringBuilder preview=new StringBuilder("DG14\n");
      List<SecurityInfo> sorted=new ArrayList<>(dg14.getSecurityInfos());sorted.sort(Comparator.comparing(SecurityInfo::getObjectIdentifier));
      for(SecurityInfo info:sorted){
        preview.append(info.getProtocolOIDString());
        if(info instanceof ActiveAuthenticationInfo){ActiveAuthenticationInfo v=(ActiveAuthenticationInfo)info;preview.append(" · v").append(v.getVersion()).append(" · ").append(ActiveAuthenticationInfo.toSignatureAlgorithmOIDString(v.getSignatureAlgorithmOID()));}
        if(info instanceof ChipAuthenticationInfo){ChipAuthenticationInfo v=(ChipAuthenticationInfo)info;preview.append(" · v").append(v.getVersion()).append(" · Key ID ").append(v.getKeyId());}
        if(info instanceof ChipAuthenticationPublicKeyInfo){ChipAuthenticationPublicKeyInfo v=(ChipAuthenticationPublicKeyInfo)info;preview.append(" · Key ID ").append(v.getKeyId()).append(" · ").append(Util.getDetailedPublicKeyAlgorithm(v.getSubjectPublicKey()));}
        if(info instanceof TerminalAuthenticationInfo){TerminalAuthenticationInfo v=(TerminalAuthenticationInfo)info;preview.append(" · CVCA FID ").append(String.format(Locale.ROOT,"%04X",v.getFileId()&0xFFFF)).append(" · SFI ").append(v.getShortFileId());}
        if(info instanceof PACEInfo){PACEInfo v=(PACEInfo)info;preview.append(" · v").append(v.getVersion()).append(" · Parameter ID ").append(v.getParameterId());}
        preview.append('\n');
      }
      PublicKey key=dg15.getPublicKey();byte[] encoded=key.getEncoded();
      preview.append("\nDG15\nPublic key: ").append(Util.getDetailedPublicKeyAlgorithm(key)).append("\nEncoding: ").append(key.getFormat()).append("\nSPKI: ").append(encoded.length).append(" bytes\nSHA-256: ").append(x(MessageDigest.getInstance("SHA-256").digest(encoded))).append("\nAA: NOT_CHECKED\nCA: NOT_CHECKED");
      Files.write(out.resolve("security-preview-"+id+".txt"),preview.toString().getBytes(StandardCharsets.UTF_8));
    }
    System.out.println("Generated DG14/DG15 and synthetic AA/CA test keys. These keys are public test fixtures, never document-signing keys.");
  }
}
