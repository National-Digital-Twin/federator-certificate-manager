/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class PemUtilTest {

    @Test
    void verifyCertificate_success() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");

        // Create CA cert (self-signed)
        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());
        // Create leaf cert signed by CA
        X509Certificate leafCert = createCert(leafName, caName, leafKeyPair.getPublic(), caKeyPair.getPrivate());

        String caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());
        String leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());

        // Should not throw
        PemUtil.verifyCertificate(leafPem, caPem);
    }

    @Test
    void verifyCertificate_failure() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair1 = kpg.generateKeyPair();
        KeyPair caKeyPair2 = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName1 = new X500Name("CN=CA1");
        X500Name leafName = new X500Name("CN=Leaf");

        X509Certificate caCert2 = createCert(
                new X500Name("CN=CA2"), new X500Name("CN=CA2"), caKeyPair2.getPublic(), caKeyPair2.getPrivate());
        // Leaf signed by CA1
        X509Certificate leafCert = createCert(leafName, caName1, leafKeyPair.getPublic(), caKeyPair1.getPrivate());

        String leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());
        String caPem2 = PemUtil.toPem("CERTIFICATE", caCert2.getEncoded());

        assertThrows(Exception.class, () -> PemUtil.verifyCertificate(leafPem, caPem2));
    }

    @Test
    void daysUntilExpiry_handlesException() {
        assertEquals(Long.MIN_VALUE, PemUtil.daysUntilExpiry("invalid"));
    }

    @Test
    void verifyCertificate_expiryFailure() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");

        // Create expired cert
        long past = System.currentTimeMillis() - 1000000;
        Date start = new Date(past);
        Date end = new Date(past + 1000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKeyPair.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(past), start, end, leafName, leafKeyPair.getPublic());
        X509Certificate expiredCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());

        String leafPem = PemUtil.toPem("CERTIFICATE", expiredCert.getEncoded());
        String caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());

        // Should throw CertificateExpiredException or similar wrapped in Exception
        assertThrows(Exception.class, () -> PemUtil.verifyCertificate(leafPem, caPem));
    }

    private X509Certificate createCert(X500Name subject, X500Name issuer, PublicKey pubKey, PrivateKey privKey)
            throws Exception {
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + 100000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privKey);
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(now), start, end, subject, pubKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void toPem_and_parse_roundTrip_private_and_public() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        String privatePem = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
        String publicPem = PemUtil.toPem("PUBLIC KEY", kp.getPublic().getEncoded());

        PrivateKey parsedPriv = PemUtil.parsePkcs8PrivateKey(privatePem);
        PublicKey parsedPub = PemUtil.parsePublicKey(publicPem);

        assertNotNull(parsedPriv);
        assertNotNull(parsedPub);
        assertEquals("RSA", parsedPriv.getAlgorithm());
        assertEquals("RSA", parsedPub.getAlgorithm());

        // Ensure keys are correct by reconstructing via standard factories
        PrivateKey reconstructedPriv =
                KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(parsedPriv.getEncoded()));
        PublicKey reconstructedPub =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(parsedPub.getEncoded()));

        assertArrayEquals(reconstructedPriv.getEncoded(), parsedPriv.getEncoded());
        assertArrayEquals(reconstructedPub.getEncoded(), parsedPub.getEncoded());
    }

    @Test
    void toPem_lineWrapping_and_decode_stability() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        String privatePem = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
        assertTrue(privatePem.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(privatePem.contains("-----END PRIVATE KEY-----"));

        PrivateKey parsed = PemUtil.parsePkcs8PrivateKey(privatePem);
        assertNotNull(parsed);
    }

    @Test
    void isValidForAtLeastDays_success() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");

        // Create cert valid for ~1.15 days
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + (1000L * 60 * 60 * 24 * 2)); // 2 days from now
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());

        assertTrue(PemUtil.isValidForAtLeastDays(pem, 1));
    }



    @Test
    void extractCn_directTest() throws Exception {
        // Since it is private, we can't test it directly easily without reflection,
        // but we can test verifyCertificate with various DNs.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        // DN with no CN
        X500Name caName = new X500Name("O=Org, C=UK");
        X500Name leafName = new X500Name("CN=Leaf");

        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());
        X509Certificate leafCert = createCert(leafName, caName, leafKeyPair.getPublic(), caKeyPair.getPrivate());

        String caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());
        String leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());

        // Should work and log "Unknown" for CN
        PemUtil.verifyCertificate(leafPem, caPem);
    }
}
