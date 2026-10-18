/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.vsmartcard.acardemulator.verification;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.icao.*;

/** Test-only independent BC ASN.1 parser + platform RSA/PKIX oracle, never part of main APK. */
public final class PAOracle {
    public static final class Result {
        public boolean dg1, dg2, signature, trust;
        public boolean passed() { return dg1 && dg2 && signature && trust; }
    }
    public static Result verify(byte[] encoded, byte[] dg1, byte[] dg2, byte[] root, Date date) throws Exception {
        int header = 2; if ((encoded[1] & 128) != 0) header += encoded[1] & 127;
        ContentInfo ci = ContentInfo.getInstance(new ASN1InputStream(Arrays.copyOfRange(encoded, header, encoded.length)).readObject());
        if (!ci.getContentType().getId().equals("1.2.840.113549.1.7.2")) throw new GeneralSecurityException("Not SignedData");
        SignedData sd = SignedData.getInstance(ci.getContent());
        if (!sd.getEncapContentInfo().getContentType().getId().equals("2.23.136.1.1.1")) throw new GeneralSecurityException("Not LDS");
        byte[] content = ASN1OctetString.getInstance(sd.getEncapContentInfo().getContent()).getOctets();
        LDSSecurityObject lds = LDSSecurityObject.getInstance(new ASN1InputStream(content).readObject());
        if (!lds.getDigestAlgorithmIdentifier().getAlgorithm().getId().equals("2.16.840.1.101.3.4.2.1")) throw new GeneralSecurityException("Unsupported hash");
        Result r = new Result(); MessageDigest hash = MessageDigest.getInstance("SHA-256");
        for (DataGroupHash h : lds.getDatagroupHash()) {
            if (h.getDataGroupNumber() == 1) r.dg1 = MessageDigest.isEqual(h.getDataGroupHashValue().getOctets(), hash.digest(dg1));
            if (h.getDataGroupNumber() == 2) r.dg2 = MessageDigest.isEqual(h.getDataGroupHashValue().getOctets(), hash.digest(dg2));
        }
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        IssuerAndSerialNumber sid = IssuerAndSerialNumber.getInstance(si.getSID().getId());
        CertificateFactory factory = CertificateFactory.getInstance("X.509"); X509Certificate dsc = null;
        for (int i = 0; i < sd.getCertificates().size(); i++) {
            byte[] der = sd.getCertificates().getObjectAt(i).getDERObject().getEncoded("DER");
            X509Certificate candidate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
            if (candidate.getSerialNumber().equals(sid.getSerialNumber().getValue()) && candidate.getIssuerX500Principal().equals(new X500Principal(sid.getName().getEncoded("DER")))) dsc = candidate;
        }
        if (dsc == null) throw new GeneralSecurityException("Signer certificate missing");
        ASN1Set attrs = si.getAuthenticatedAttributes(); boolean contentType = false, contentHash = false;
        for (int i = 0; i < attrs.size(); i++) {
            Attribute a = Attribute.getInstance(attrs.getObjectAt(i));
            if (a.getAttrType().getId().equals("1.2.840.113549.1.9.3")) contentType = DERObjectIdentifier.getInstance(a.getAttrValues().getObjectAt(0)).getId().equals("2.23.136.1.1.1");
            if (a.getAttrType().getId().equals("1.2.840.113549.1.9.4")) contentHash = MessageDigest.isEqual(hash.digest(content), ASN1OctetString.getInstance(a.getAttrValues().getObjectAt(0)).getOctets());
        }
        Signature verifier = Signature.getInstance("SHA256withRSA"); verifier.initVerify(dsc.getPublicKey()); verifier.update(attrs.getEncoded("DER"));
        r.signature = contentType && contentHash && verifier.verify(si.getEncryptedDigest().getOctets());
        if (root != null) {
            try {
                X509Certificate ca = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(root));
                ca.checkValidity(date); dsc.checkValidity(date);
                if (ca.getBasicConstraints() < 0 || dsc.getBasicConstraints() >= 0 || !ca.getKeyUsage()[5] || !dsc.getKeyUsage()[0]) throw new GeneralSecurityException("Invalid certificate constraints");
                PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(ca, null)));
                parameters.setRevocationEnabled(false); parameters.setDate(date);
                CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(Collections.singletonList(dsc)), parameters);
                r.trust = true;
            } catch (GeneralSecurityException expected) { r.trust = false; }
        }
        return r;
    }
}
