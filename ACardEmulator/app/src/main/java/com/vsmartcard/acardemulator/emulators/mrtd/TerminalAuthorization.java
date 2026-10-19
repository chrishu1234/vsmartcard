/* SPDX-License-Identifier: GPL-3.0-or-later
 * Synthetic EAC v1 chip policy. Never authorizes a real travel document.
 */
package com.vsmartcard.acardemulator.emulators.mrtd;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.asn1.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardCrypto.*;

final class TerminalAuthorization {
  private final Certificate root;
  private Certificate issuer;
  private String destination;
  private byte[] id, hash, challenge;
  private int rights;
  private boolean selected;
  TerminalAuthorization(byte[] encoded){try{List<TLV> outer=objects(encoded);require(outer.size()==1&&outer.get(0).tag==0x7F21,0x6A80);root=new Certificate(outer.get(0).value,null);require(root.role==0xC0&&root.car.equals(root.chr),0x6A80);root.verify(root.key);clear();}catch(GeneralSecurityException e){throw new IllegalStateException("Invalid development CVCA",e);}}
  void clear(){issuer=root;destination=null;selected=false;rights=0;wipe(id);wipe(hash);wipe(challenge);id=hash=challenge=null;}
  void afterCA(byte[] identifier,byte[] keyHash){clear();id=identifier.clone();hash=keyHash.clone();}
  boolean allows(int dg){return (rights&(dg==3?1:2))!=0;}
  boolean authenticated(){return selected&&rights!=0;}
  int permissions(){return rights;}
  byte[] execute(int ins,int p1,int p2,byte[] data,int le)throws GeneralSecurityException {
    require(hash!=null&&id!=null,0x6985);
    try{
      if(ins==0x22&&p1==0x81&&p2==0xB6){
        rights=0;selected=false;wipe(challenge);challenge=null;String car=reference(data);
        if(car.equals(root.chr)){issuer=root;}require(car.equals(issuer.chr),0x6A88);destination=car;return new byte[0];
      }
      if(ins==0x2A){
        require(p1==0&&p2==0xBE&&destination!=null,0x6985);
        Certificate cert=new Certificate(data,issuer.key);require(cert.car.equals(destination)&&cert.car.equals(issuer.chr),0x6A88);
        require(issuer.role==0xC0?(cert.role==0x80||cert.role==0x40):((issuer.role==0x80||issuer.role==0x40)&&cert.role==0),0x6982);
        cert.verify(issuer.key);cert.checkDate();require((cert.rights&issuer.rights)==cert.rights,0x6982);
        issuer=cert;destination=null;return new byte[0];
      }
      if(ins==0x22&&p1==0x81&&p2==0xA4){require(issuer.role==0&&reference(data).equals(issuer.chr),0x6985);rights=0;selected=true;wipe(challenge);challenge=null;return new byte[0];}
      if(ins==0x84){require(selected&&p1==0&&p2==0&&data.length==0&&le==8,0x6985);rights=0;wipe(challenge);challenge=random(8);return challenge.clone();}
      if(ins==0x82){require(selected&&challenge!=null&&p1==0&&p2==0,0x6985);byte[] message=concat(id,challenge,hash);wipe(challenge);challenge=null;rights=0;
        require(verify(issuer.algorithm,issuer.key,message,data),0x6300);rights=issuer.rights;return new byte[0];}
      throw new Status(0x6D00);
    }catch(GeneralSecurityException|RuntimeException e){rights=0;selected=false;destination=null;wipe(challenge);challenge=null;issuer=root;if(e instanceof Status)throw (Status)e;if(e instanceof GeneralSecurityException)throw new Status(0x6300);throw new Status(0x6A80);}
  }
  private static String reference(byte[] data){List<TLV> f=objects(data);require(f.size()==1&&f.get(0).tag==0x83,0x6A80);return text(f.get(0).value);}
  private static String text(byte[] b){return new String(b,java.nio.charset.StandardCharsets.ISO_8859_1);}
  private static byte[] field(List<TLV> f,int tag){byte[] result=null;for(TLV v:f)if(v.tag==tag){require(result==null,0x6A80);result=v.value;}require(result!=null,0x6A80);return result;}
  private static BigInteger number(List<TLV> f,int tag){return new BigInteger(1,field(f,tag));}
  private static String algorithm(byte[] oid){String s=toHex(oid);require(s.startsWith("04007F0007020202"),0x6A80);String tail=s.substring(16);if(tail.equals("0102"))return "SHA256withRSA";if(tail.equals("0203"))return "SHA256withECDSA";throw new Status(0x6A80);}
  private static String toHex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format(java.util.Locale.ROOT,"%02X",v&255));return s.toString();}
  private static boolean verify(String algorithm,PublicKey key,byte[] body,byte[] raw)throws GeneralSecurityException{
    byte[] signature=raw;
    if(algorithm.contains("ECDSA")){int size=(((ECPublicKey)key).getParameters().getCurve().getFieldSize()+7)/8;require(raw.length==2*size,0x6300);ASN1EncodableVector v=new ASN1EncodableVector();v.add(new DERInteger(new BigInteger(1,slice(raw,0,size))));v.add(new DERInteger(new BigInteger(1,slice(raw,size,raw.length))));signature=new DERSequence(v).getDEREncoded();}
    Signature verifier=Signature.getInstance(algorithm,new BouncyCastleProvider());verifier.initVerify(key);verifier.update(body);return verifier.verify(signature);
  }
  private static final class Certificate {
    final byte[] body,signature;final String car,chr,algorithm;final int role,rights;final PublicKey key;final int before,after;
    Certificate(byte[] data,PublicKey issuer)throws GeneralSecurityException{
      List<TLV> parts=objects(data);require(parts.size()==2,0x6A80);byte[] b=field(parts,0x7F4E);body=tlv(0x7F4E,b);signature=field(parts,0x5F37);List<TLV> f=objects(b);require(f.size()==7&&equal(field(f,0x5F29),new byte[]{0}),0x6A80);
      car=text(field(f,0x42));chr=text(field(f,0x5F20));require(car.length()>=7&&car.length()<=16&&chr.length()>=7&&chr.length()<=16,0x6A80);before=date(field(f,0x5F25));after=date(field(f,0x5F24));require(before<=after,0x6A80);
      List<TLV> chat=objects(field(f,0x7F4C));require(chat.size()==2&&equal(field(chat,6),hex("04007F000703010201")),0x6A80);byte[] a=field(chat,0x53);require(a.length==1&&(a[0]&0x3C)==0,0x6A80);role=a[0]&0xC0;rights=a[0]&3;
      List<TLV> k=objects(field(f,0x7F49));algorithm=algorithm(field(k,6));
      if(algorithm.contains("RSA")){require(k.size()==3,0x6A80);key=KeyFactory.getInstance("RSA",new BouncyCastleProvider()).generatePublic(new RSAPublicKeySpec(number(k,0x81),number(k,0x82)));}
      else{ECParameterSpec params;if(k.size()==8){ECCurve curve=new ECCurve.Fp(number(k,0x81),number(k,0x82),number(k,0x83));params=new ECParameterSpec(curve,curve.decodePoint(field(k,0x84)),number(k,0x85),number(k,0x87));}
        else{require(k.size()==2&&issuer instanceof ECPublicKey,0x6A80);params=((ECPublicKey)issuer).getParameters();}
        org.bouncycastle.math.ec.ECPoint q=params.getCurve().decodePoint(field(k,0x86));require(!q.isInfinity()&&q.multiply(params.getN()).isInfinity(),0x6A80);key=KeyFactory.getInstance("EC",new BouncyCastleProvider()).generatePublic(new ECPublicKeySpec(q,params));}
    }
    void verify(PublicKey issuer)throws GeneralSecurityException{require(TerminalAuthorization.verify(algorithm,issuer,body,signature),0x6300);}
    void checkDate(){java.util.Calendar today=java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));int n=today.get(java.util.Calendar.YEAR)*10000+(today.get(java.util.Calendar.MONTH)+1)*100+today.get(java.util.Calendar.DAY_OF_MONTH);require(before<=n&&n<=after,0x6982);}
    static int date(byte[] b){require(b.length==6,0x6A80);int n=0;for(byte v:b){require(v>=0&&v<=9,0x6A80);n=n*10+v;}int year=2000+n/10000,month=n/100%100,day=n%100;java.util.GregorianCalendar c=new java.util.GregorianCalendar(java.util.TimeZone.getTimeZone("UTC"));c.setLenient(false);c.clear();c.set(year,month-1,day);try{c.getTimeInMillis();}catch(IllegalArgumentException e){throw new Status(0x6A80);}return 20000000+n;}
  }
}
