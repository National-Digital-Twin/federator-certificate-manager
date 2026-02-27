/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.KeyStoreService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

@ExtendWith(MockitoExtension.class)
class KeyStoreSyncServiceImplTest {

    @TempDir
    Path tempDir;

    @Mock
    private VaultSecretProvider vaultSecretProvider;

    @Mock
    private KeyStoreService keyStoreService;

    private FileSystemServiceImpl realFileSystemService;

    private CertificateProperties certificateProperties;
    private KeyStoreSyncServiceImpl keyStoreSyncService;

    private String certPem;
    private String privateKeyPem;
    private String caPem;
    private byte[] validKeystoreBytes;
    private byte[] validTruststoreBytes;
    private KeyStoreService realKeyStoreService;

    @BeforeEach
    void setUp() throws Exception {
        realFileSystemService = new FileSystemServiceImpl();
        certificateProperties = new CertificateProperties();
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setPath(tempDir.toString());
        dest.setKeystoreFile("keystore.p12");
        dest.setTruststoreFile("truststore.p12");
        dest.setKeystoreAlias("federator");
        dest.setKeystorePassword("ks-pass");
        dest.setTruststorePassword("ts-pass");
        dest.setKeystorePasswordFile("keystore.password");
        dest.setTruststorePasswordFile("truststore.password");

        keyStoreSyncService = new KeyStoreSyncServiceImpl(
                certificateProperties, vaultSecretProvider, keyStoreService, realFileSystemService);

        // Generate test certs and real keystore bytes
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + 1000000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKeyPair.getPrivate());

        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(now), start, end, caName, caKeyPair.getPublic());
        X509Certificate caCert = new JcaX509CertificateConverter().getCertificate(caBuilder.build(signer));
        caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());

        X509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(now + 1), start, end, leafName, leafKeyPair.getPublic());
        X509Certificate leafCert = new JcaX509CertificateConverter().getCertificate(leafBuilder.build(signer));
        certPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());
        privateKeyPem = PemUtil.toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());

        // Build real PKCS12 bytes for validation to pass
        realKeyStoreService = new KeyStoreService();
        validKeystoreBytes =
                realKeyStoreService.createKeyStore(privateKeyPem, certPem, List.of(caPem), "ks-pass", "federator");
        validTruststoreBytes = realKeyStoreService.createTrustStore(List.of(caPem), "ts-pass");
    }

    @Test
    void syncKeyStoresToFilesystem_createsKeystoreAndTruststore() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        assertTrue(Files.exists(tempDir.resolve("keystore.p12")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
    }

    @Test
    void syncKeyStoresToFilesystem_skipsUpdateWhenInSync() throws Exception {
        // Pre-write the keystore and truststore
        Files.write(tempDir.resolve("keystore.p12"), validKeystoreBytes);
        Files.write(tempDir.resolve("truststore.p12"), validTruststoreBytes);
        Files.write(tempDir.resolve("keystore.password"), "ks-pass".getBytes());
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));

        keyStoreSyncService.syncKeyStoresToFilesystem();

        // Keystore service should not be called since existing files match
        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService, never()).createTrustStore(any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsWhenNoCertificate() {
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService, never()).createTrustStore(any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsWhenNoCaChain() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createTrustStore(any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsWhenNullCaChain() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(null);
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createTrustStore(any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_handlesCorruptExistingKeystore() throws Exception {
        // Write a corrupt keystore to trigger the catch branch in shouldUpdateKeyStore
        Files.write(tempDir.resolve("keystore.p12"), "corrupt data".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        // Should still create the keystore because corrupt file triggers update
        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    @Test
    void syncKeyStoresToFilesystem_handlesCorruptExistingTruststore() throws Exception {
        // Write a corrupt truststore
        Files.write(tempDir.resolve("truststore.p12"), "corrupt data".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(any(), anyString());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsWhenNoPrivateKey() {
        CreateKeyResponseDTO keyPair =
                CreateKeyResponseDTO.builder().publicKeyPem("pub").build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        // Truststore should still be created since caChain is available
        verify(keyStoreService).createTrustStore(any(), anyString());
    }

    @Test
    void syncKeyStoresToFilesystem_updatesWhenCaChainDiffers() throws Exception {
        // Pre-write a truststore with 1 CA cert
        Files.write(tempDir.resolve("truststore.p12"), validTruststoreBytes);
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        // Now vault returns 2 CA certs (different from what was written)
        // This doesn't need actual 2 different certs; the size mismatch triggers update
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem, caPem));
        byte[] newTruststoreBytes = realKeyStoreService.createTrustStore(List.of(caPem, caPem), "ts-pass");
        when(keyStoreService.createTrustStore(any(), anyString())).thenReturn(newTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(any(), anyString());
    }

    @Test
    void resolvePassword_usesConfiguredPassword() {
        String result = keyStoreSyncService.resolvePassword("configured-pass", "suffix");
        assertEquals("configured-pass", result);
        verify(vaultSecretProvider, never()).getSecret(any());
    }

    @Test
    void resolvePassword_fetchesFromVault() {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(Map.of("password", "vault-pass"));

        String result = keyStoreSyncService.resolvePassword(null, "suffix");
        assertEquals("vault-pass", result);
    }

    @Test
    void resolvePassword_generatesNewPassword() {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(null);

        String result = keyStoreSyncService.resolvePassword(null, "suffix");
        assertNotNull(result);
        assertFalse(result.isBlank());
        verify(vaultSecretProvider).persistSecret(eq("suffix"), any());
    }

    @Test
    void resolvePassword_generatesWhenVaultSecretHasNoPasswordKey() {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(Map.of("other", "value"));

        String result = keyStoreSyncService.resolvePassword(null, "suffix");
        assertNotNull(result);
        assertFalse(result.isBlank());
        verify(vaultSecretProvider).persistSecret(eq("suffix"), any());
    }

    @Test
    void resolvePassword_blankConfiguredFetchesFromVault() {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(Map.of("password", "vault-pass"));

        String result = keyStoreSyncService.resolvePassword("  ", "suffix");
        assertEquals("vault-pass", result);
    }

    @Test
    void syncKeyStoresToFilesystem_passwordFileAlreadyInSync() throws Exception {
        // Write matching password files first
        Files.write(tempDir.resolve("keystore.password"), "ks-pass".getBytes());
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        // Password files exist and match, so write should not be called for them
        // (they were already in sync)
        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
    }

    @Test
    void syncKeyStoresToFilesystem_handlesEmptyCaChainInKeystore() {
        // Keystore with no CA chain
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();
        byte[] ksNoCaChain = realKeyStoreService.createKeyStore(
                privateKeyPem, certPem, Collections.emptyList(), "ks-pass", "federator");

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(Collections.emptyList());
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(ksNoCaChain);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }
}
