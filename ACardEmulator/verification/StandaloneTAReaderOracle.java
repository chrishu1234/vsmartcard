/* EAC v1 interoperability with unmodified JMRTD 0.8.9 and EJBCA CVC. */
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import org.jmrtd.*;
import org.jmrtd.cert.*;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.protocol.*;
import net.sf.scuba.smartcards.*;
import static java.util.Arrays.asList;
public final class StandaloneTAReaderOracle {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 static CardVerifiableCertificate cert(Path folder,String type,String name)throws Exception{return (CardVerifiableCertificate)new CVCertificateFactorySpi().engineGenerateCertificate(Files.newInputStream(folder.resolve("ta-"+type+"-"+name+".cvc")));}
 static void denied(StandaloneReaderOracle.Remote card,SecureMessagingWrapper wrapper,int dg)throws Exception{ResponseAPDU response=StandaloneReaderOracle.secure(card,wrapper,new CommandAPDU(0,0xA4,2,12,new byte[]{1,(byte)dg}));check(response.getSW()==0x6982,"DG"+dg+" must be denied");}
 public static void main(String[] args)throws Exception{
  Security.addProvider(Util.getBouncyCastleProvider());
  String format=args[1],mode=args[2],type=args[3],profile=args[4],document=format.equals("TD3")?"L898902C3":"D23145890";Path folder=Paths.get(args[5]);
  StandaloneReaderOracle.Remote card=new StandaloneReaderOracle.Remote(Integer.parseInt(args[0]));
  try{
   StandaloneReaderOracle.bootstrap(card);BACKey key=new BACKey(document,"740812","120415");PACEResult pace=null;SecureMessagingWrapper wrapper;
   if(mode.equals("BAC")){wrapper=new BACProtocol(new BACAPDUSender(card),256,true).doBAC(key).getWrapper();}
   else{StandaloneReaderOracle.plain(card,"00A4000C");pace=new PACEProtocol(new PACEAPDUSender(card),null,256,true).doPACE(PACEKeySpec.createCANKey("123456"),"0.4.0.127.0.7.2.2.4.2.2",PACEInfo.toParameterSpec(BigInteger.valueOf(13)),BigInteger.valueOf(13));wrapper=pace.getWrapper();}
   check(StandaloneReaderOracle.secure(card,wrapper,new CommandAPDU(StandaloneReaderOracle.h("00A4040C07A0000002471001"))).getSW()==0x9000,"SELECT applet");denied(card,wrapper,3);denied(card,wrapper,4);
   DG14File dg14=new DG14File(new ByteArrayInputStream(StandaloneReaderOracle.file(card,wrapper,0x10E)));ChipAuthenticationPublicKeyInfo pub=null;ChipAuthenticationInfo protocol=null;
   for(SecurityInfo info:dg14.getSecurityInfos()){if(info instanceof ChipAuthenticationPublicKeyInfo)pub=(ChipAuthenticationPublicKeyInfo)info;if(info instanceof ChipAuthenticationInfo)protocol=(ChipAuthenticationInfo)info;}
   EACCAResult ca=new EACCAProtocol(new EACCAAPDUSender(card),wrapper,256,true).doCA(pub.getKeyId(),protocol.getObjectIdentifier(),pub.getObjectIdentifier(),pub.getSubjectPublicKey());wrapper=ca.getWrapper();
   StandaloneReaderOracle.file(card,wrapper,0x101);denied(card,wrapper,3);denied(card,wrapper,4);
   CardVerifiableCertificate root=cert(folder,type,"root"),dv=cert(folder,type,profile.equals("untrusted")?"untrusted":"dv"),terminal=cert(folder,type,asList("dg3","expired","bad-cert").contains(profile)?profile:"valid");
   PrivateKey privateKey=KeyFactory.getInstance(type.equals("ec")?"EC":"RSA","BC").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(folder.resolve("ta-"+type+"-"+(profile.equals("wrong-key")?"wrong":"terminal")+".pk8"))));
   boolean success=asList("valid","dg3").contains(profile),accepted=false;
   try{EACTAProtocol ta=new EACTAProtocol(new EACTAAPDUSender(card),wrapper);EACTAResult result=pace==null?ta.doEACTA(null,asList(root,dv,terminal),privateKey,null,ca,document):ta.doTA(null,asList(root,dv,terminal),privateKey,null,ca,pace);check(result.getCVCertificates().size()==2,"Root marker omitted");accepted=true;}
   catch(CardServiceException expected){if(success)throw expected;}
   check(accepted==success,"Unexpected TA verdict");
   if(success){new DG3File(new ByteArrayInputStream(StandaloneReaderOracle.file(card,wrapper,0x103)));if(profile.equals("valid"))new DG4File(new ByteArrayInputStream(StandaloneReaderOracle.file(card,wrapper,0x104)));else denied(card,wrapper,4);}
   else{denied(card,wrapper,3);denied(card,wrapper,4);}
   StandaloneReaderOracle.file(card,wrapper,0x101);System.out.println("PASS original JMRTD TA "+type+" "+format+" "+mode+" "+profile);
  }finally{card.close();}
 }
}
