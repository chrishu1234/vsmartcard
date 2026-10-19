/* Development-only EAC v1 PKI, produced by unmodified JMRTD 0.8.9 / EJBCA. */
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.jmrtd.cert.*;
import org.jmrtd.lds.CVCAFile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public final class GenerateTAFixtures {
  static Path card, reader;
  static KeyPair key(String algorithm) throws Exception {
    KeyPairGenerator g=KeyPairGenerator.getInstance(algorithm,"BC");
    if(algorithm.equals("EC"))g.initialize(new ECGenParameterSpec("secp256r1"));else g.initialize(2048);
    return g.generateKeyPair();
  }
  static Date date(String s){return Date.from(java.time.Instant.parse(s+"T00:00:00Z"));}
  static void save(String n,byte[] b)throws Exception{Files.write(card.resolve(n),b);Files.write(reader.resolve(n),b);}
  static CardVerifiableCertificate cert(KeyPair subject, KeyPair issuer,String alg,String car,String chr,CVCAuthorizationTemplate.Role role,CVCAuthorizationTemplate.Permission permission,String end)throws Exception{
    return CVCertificateBuilder.createCertificate(subject.getPublic(),issuer.getPrivate(),alg,new CVCPrincipal(car),new CVCPrincipal(chr),new CVCAuthorizationTemplate(role,permission),date("2020-01-01"),date(end),"BC");
  }
  public static void main(String[] args)throws Exception{
    Security.addProvider(new BouncyCastleProvider());card=Paths.get(args[0]);reader=Paths.get(args[1]);Files.createDirectories(card);Files.createDirectories(reader);
    for(String type:new String[]{"ec","rsa"}){
      KeyPair root=key(type.equals("ec")?"EC":"RSA"),dv=key(type.equals("ec")?"EC":"RSA"),terminal=key(type.equals("ec")?"EC":"RSA"),wrong=key(type.equals("ec")?"EC":"RSA"),alien=key(type.equals("ec")?"EC":"RSA");
      String alg=type.equals("ec")?"SHA256withECDSA":"SHA256withRSA",prefix="ta-"+type+"-";
      CVCAuthorizationTemplate.Permission both=CVCAuthorizationTemplate.Permission.READ_ACCESS_DG3_AND_DG4;
      CardVerifiableCertificate ca=cert(root,root,alg,"UTTESTCVCA00001","UTTESTCVCA00001",CVCAuthorizationTemplate.Role.CVCA,both,"2099-12-31");
      CardVerifiableCertificate d=cert(dv,root,alg,"UTTESTCVCA00001","UTTESTDV00001",CVCAuthorizationTemplate.Role.DV_D,both,"2049-12-31");
      CardVerifiableCertificate t=cert(terminal,dv,alg,"UTTESTDV00001","UTTESTIS00001",CVCAuthorizationTemplate.Role.IS,both,"2049-12-31");
      ca.verify(root.getPublic(),"BC");d.verify(root.getPublic(),"BC");t.verify(dv.getPublic(),"BC");
      save(prefix+"root.cvc",ca.getEncoded());save(prefix+"dv.cvc",d.getEncoded());save(prefix+"valid.cvc",t.getEncoded());
      save(prefix+"dg3.cvc",cert(terminal,dv,alg,"UTTESTDV00001","UTTESTIS00001",CVCAuthorizationTemplate.Role.IS,CVCAuthorizationTemplate.Permission.READ_ACCESS_DG3,"2049-12-31").getEncoded());
      save(prefix+"expired.cvc",cert(terminal,dv,alg,"UTTESTDV00001","UTTESTIS00001",CVCAuthorizationTemplate.Role.IS,both,"2021-01-01").getEncoded());
      save(prefix+"untrusted.cvc",cert(dv,alien,alg,"UTTESTCVCA00001","UTTESTDV00001",CVCAuthorizationTemplate.Role.DV_D,both,"2049-12-31").getEncoded());
      byte[] bad=t.getEncoded();bad[bad.length-1]^=1;save(prefix+"bad-cert.cvc",bad);
      save(prefix+"terminal.pk8",terminal.getPrivate().getEncoded());save(prefix+"wrong.pk8",wrong.getPrivate().getEncoded());
      save(prefix+"root.spki",root.getPublic().getEncoded());save(prefix+"dv.spki",dv.getPublic().getEncoded());save(prefix+"terminal.spki",terminal.getPublic().getEncoded());
      System.out.println("Generated synthetic "+type+" CVCA -> DV -> IS; valid / DG3-only / expired / untrusted / bad signature");
    }
    save("ta-cvca.bin",new CVCAFile("UTTESTCVCA00001",null).getEncoded());
  }
}
