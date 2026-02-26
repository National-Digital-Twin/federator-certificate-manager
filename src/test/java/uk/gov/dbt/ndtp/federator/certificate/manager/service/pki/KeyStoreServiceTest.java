/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.KeyStoreCreationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

class KeyStoreServiceTest {

    private KeyStoreService keyStoreService;
    private KeyPair caKeyPair;
    private KeyPair leafKeyPair;
    private String caPem;
    private String leafPem;
    private String privateKeyPem;

    @BeforeEach
    void setUp() throws Exception {
        keyStoreService = new KeyStoreService();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        caKeyPair = kpg.generateKeyPair();
        leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");

        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());
        X509Certificate leafCert = createCert(leafName, caName, leafKeyPair.getPublic(), caKeyPair.getPrivate());

        caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());
        leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());
        privateKeyPem = PemUtil.toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());
    }

    @Test
    void createKeyStore_success() throws Exception {
        String password = "test-password";
        String alias = "test-alias";
        byte[] ksBytes = keyStoreService.createKeyStore(privateKeyPem, leafPem, List.of(caPem), password, alias);

        assertNotNull(ksBytes);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(ksBytes), password.toCharArray());

        assertTrue(ks.containsAlias(alias));
        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, password.toCharArray()));
        assertNotNull(ks.getCertificateChain(alias));
        assertEquals(2, ks.getCertificateChain(alias).length);
    }

    @Test
    void createKeyStore_failure_invalidKeyStoreType() {
        String password = "test-password";

        // We can't easily mock KeyStore.getInstance("PKCS12") without a lot of ceremony
        // But we can trigger an exception in ks.setKeyEntry if the certificate chain is empty or has nulls
        // Or if we pass a null alias.
        
        assertThrows(
                KeyStoreCreationException.class,
                () -> keyStoreService.createKeyStore(privateKeyPem, leafPem, List.of(caPem), password, null));
    }

    @Test
    void createTrustStore_success() throws Exception {
        String password = "trust-password";
        byte[] tsBytes = keyStoreService.createTrustStore(List.of(caPem), password);

        assertNotNull(tsBytes);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(tsBytes), password.toCharArray());

        assertTrue(ks.containsAlias("ca-0"));
        assertNotNull(ks.getCertificate("ca-0"));
    }

    private X509Certificate createCert(X500Name subject, X500Name issuer, PublicKey pubKey, PrivateKey privKey)
            throws Exception {
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + 1000000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privKey);
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(now), start, end, subject, pubKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
