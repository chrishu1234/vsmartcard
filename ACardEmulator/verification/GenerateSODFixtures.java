/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.io.*;
import java.nio.file.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.*;

/** Offline, public development fixtures. Private keys are never put in the APK. */
public final class GenerateSODFixtures {
    static final Date START = Date.from(java.time.Instant.parse("2020-01-01T00:00:00Z"));
    static final Date END = Date.from(java.time.Instant.parse("2040-01-01T00:00:00Z"));
    static X509Certificate certificate(KeyPair subject, X500Name name, X509Certificate issuer,
            PrivateKey issuerKey, boolean ca, int serial) throws Exception {
        X500Name issuerName = issuer == null ? name : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName, BigInteger.valueOf(serial), START, END, name, subject.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subject.getPublic()));
        b.addExtension(Extension.authorityKeyIdentifier, false, issuer == null ? ext.createAuthorityKeyIdentifier(subject.getPublic()) : ext.createAuthorityKeyIdentifier(issuer));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey)));
    }
    static void put(Path p, byte[] bytes) throws Exception { Files.createDirectories(p.getParent()); Files.write(p, bytes); }
    static byte[] badSignature(byte[] sod) throws Exception {
        int n = sod[1] & 255, head = 2;
        if (n >= 128) head += n & 127;
        CMSSignedData cms = new CMSSignedData(Arrays.copyOfRange(sod, head, sod.length));
        byte[] signature = cms.getSignerInfos().getSigners().iterator().next().getSignature();
        byte[] out = sod.clone();
        for (int i = head; i <= out.length - signature.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(out, i, i + signature.length), signature)) { out[i] ^= 1; return out; }
        }
        throw new IllegalStateException("Signature missing");
    }
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path root = Paths.get(args[0]), out = root.resolve("app/src/main/resources/mrtd"), vectors = root.resolve("verification/fixtures/pa");
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); gen.initialize(2048);
        KeyPair ca = gen.generateKeyPair(), ds = gen.generateKeyPair(), otherCA = gen.generateKeyPair(), otherDS = gen.generateKeyPair();
        X509Certificate csca = certificate(ca, new X500Name("C=ZZ,O=Passport Development Test,CN=TEST CSCA - NOT GOVERNMENT"), null, ca.getPrivate(), true, 1);
        X509Certificate dsc = certificate(ds, new X500Name("C=ZZ,O=Passport Development Test,CN=TEST Document Signer"), csca, ca.getPrivate(), false, 2);
        X509Certificate alienRoot = certificate(otherCA, new X500Name("C=ZZ,O=Passport Development Test,CN=UNTRUSTED TEST CSCA"), null, otherCA.getPrivate(), true, 3);
        X509Certificate alienDSC = certificate(otherDS, new X500Name("C=ZZ,O=Passport Development Test,CN=UNTRUSTED Document Signer"), alienRoot, otherCA.getPrivate(), false, 4);
        put(out.resolve("test-csca.der"), csca.getEncoded());
        put(vectors.resolve("test-csca.der"), csca.getEncoded());
        put(vectors.resolve("untrusted-csca.der"), alienRoot.getEncoded());
        for (String format : new String[]{"td1", "td3"}) for (String auth : new String[]{"bac", "pace"}) {
            String id = format + "-" + auth;
            String mrz = format.equals("td1") ? "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<" : "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
            byte[] dg1 = new DG1File(new MRZInfo(mrz)).getEncoded(), dg2 = Files.readAllBytes(out.resolve("dg2-" + id + ".bin"));
            Map<Integer,byte[]> hashes = new TreeMap<>();
            hashes.put(1, MessageDigest.getInstance("SHA-256").digest(dg1)); hashes.put(2, MessageDigest.getInstance("SHA-256").digest(dg2));
            byte[] sod = new SODFile("SHA-256", "SHA256withRSA", hashes, ds.getPrivate(), dsc).getEncoded();
            byte[] alien = new SODFile("SHA-256", "SHA256withRSA", hashes, otherDS.getPrivate(), alienDSC).getEncoded();
            put(out.resolve("sod-" + id + ".bin"), sod);
            put(out.resolve("sod-bad-signature-" + id + ".bin"), badSignature(sod));
            put(out.resolve("sod-untrusted-" + id + ".bin"), alien);
            put(vectors.resolve("dg1-" + id + ".bin"), dg1); put(vectors.resolve("dg2-" + id + ".bin"), dg2);
            for (String prefix : new String[]{"sod-", "sod-bad-signature-", "sod-untrusted-"}) put(vectors.resolve(prefix + id + ".bin"), Files.readAllBytes(out.resolve(prefix + id + ".bin")));
            for (int number : new int[]{5, 7}) {
                byte[] encoded = Files.readAllBytes(out.resolve("dg" + number + "-" + id + ".bin"));
                hashes.put(number, MessageDigest.getInstance("SHA-256").digest(encoded));
                put(vectors.resolve("dg" + number + "-" + id + ".bin"), encoded);
            }
            byte[] displayed = new SODFile("SHA-256", "SHA256withRSA", hashes, ds.getPrivate(), dsc).getEncoded();
            byte[] displayedAlien = new SODFile("SHA-256", "SHA256withRSA", hashes, otherDS.getPrivate(), alienDSC).getEncoded();
            put(out.resolve("sod-displayed-" + id + ".bin"), displayed);
            put(out.resolve("sod-displayed-bad-signature-" + id + ".bin"), badSignature(displayed));
            put(out.resolve("sod-displayed-untrusted-" + id + ".bin"), displayedAlien);
            for (String prefix : new String[]{"sod-displayed-", "sod-displayed-bad-signature-", "sod-displayed-untrusted-"}) put(vectors.resolve(prefix + id + ".bin"), Files.readAllBytes(out.resolve(prefix + id + ".bin")));
        }
        System.out.println("Generated four SOD fixtures, invalid-signature/untrusted variants and public test CSCA. No private keys saved.");
    }
}
