/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.emulators.mrtd;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardBytes.*;
import static com.vsmartcard.acardemulator.emulators.mrtd.CardCrypto.*;

/** Independent card-side Integrated Mapping implementation. */
final class CardIntegratedMapping {
    private static final byte[] C0_128=hex("A668892A7C41E3CA739F40B057D85904"),C1_128=hex("A4E136AC725F738B01C1F60217C188AD");
    private static final byte[] C0_256=hex("D463D65234124EF7897054986DCA0A174E28DF758CBAA03F240616414D5A1676"),C1_256=hex("54BD7255F0AAF831BEC3423FCF39D69B6CBF066677D0FAAE5AADD99DF8E53517");
    static BigInteger prf(PACECardProfile profile,byte[] s,byte[] t)throws GeneralSecurityException{
        if(s.length!=16&&s.length!=24&&s.length!=32)throw new GeneralSecurityException("Invalid IM nonce length");
        byte[] c0=s.length==16?C0_128:C0_256,c1=s.length==16?C1_128:C1_256,zero=new byte[profile.aes?16:8];
        byte[] key=crypt(true,profile.aes,t,zero,s);ByteArrayOutputStream output=new ByteArrayOutputStream();
        for(int n=0;n*s.length*8<profile.p.bitLength()+64;n++){
            if(key.length<t.length)break;byte[] k=Arrays.copyOf(key,t.length);key=crypt(true,profile.aes,k,zero,c0);byte[] piece=crypt(true,profile.aes,k,zero,c1);output.write(piece,0,piece.length);wipe(k);wipe(piece);
        }
        wipe(key);return new BigInteger(1,output.toByteArray()).mod(profile.p);
    }
    static ECPoint icart(PACECardProfile profile,BigInteger t){
        BigInteger p=profile.p,a=profile.curve.getCurve().getA().toBigInteger(),b=profile.curve.getCurve().getB().toBigInteger(),one=BigInteger.ONE;
        if(!p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)))throw new IllegalArgumentException("Icart requires p=3 mod 4");
        BigInteger alpha=t.modPow(BigInteger.valueOf(2),p).negate().mod(p),sum=alpha.add(alpha.modPow(BigInteger.valueOf(2),p)).mod(p);
        BigInteger x2=b.negate().multiply(one.add(sum)).multiply(a.multiply(sum).modPow(p.subtract(BigInteger.valueOf(2)),p)).mod(p),x3=alpha.multiply(x2).mod(p);
        BigInteger h2=x2.modPow(BigInteger.valueOf(3),p).add(a.multiply(x2)).add(b).mod(p),u=t.modPow(BigInteger.valueOf(3),p).multiply(h2).mod(p);
        BigInteger aa=h2.modPow(p.subtract(one).subtract(p.add(one).divide(BigInteger.valueOf(4))),p);
        boolean square=aa.multiply(aa).multiply(h2).mod(p).equals(one);BigInteger x=square?x2:x3,y=aa.multiply(square?h2:u).mod(p);
        return profile.curve.getCurve().createPoint(x,y,false);
    }
}
