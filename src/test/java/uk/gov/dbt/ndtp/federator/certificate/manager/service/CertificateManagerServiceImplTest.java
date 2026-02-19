/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 */
package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponse;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.idp.TokenCacheService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.PkiService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertificateManagerServiceImplTest {

    @Mock
    private TokenCacheService tokenCacheService;

    @Mock
    private ManagementNodeService managementNodeService;

    @Mock
    private PkiService pkiService;

    @Mock
    private VaultSecretProvider vaultSecretProvider;

    @Spy
    private CertificateProperties certificateProperties = new CertificateProperties();

    @InjectMocks
    private CertificateManagerServiceImpl certificateManagerService;

    @BeforeEach
    void setUp() {
        certificateProperties.setRenewalThresholdPercentage(10.0);
        certificateProperties.setKeySize(2048);
        certificateProperties.getSubject().setCommonName("api.acme-digital.co.uk");
        certificateProperties.getSubject().setCountry("UK");
    }

    @Test
    void run_checksIntermediateCaAndRenews() {
        when(managementNodeService.getIntermediateCertificate()).thenReturn(CertificateResponse.builder().build());

        certificateManagerService.run();

        verify(vaultSecretProvider, times(1)).getIntermediateCa();
        verify(managementNodeService, times(1)).getIntermediateCertificate();
        verify(pkiService, times(1)).createKeyPair(null, 2048);
    }

    @Test
    void run_handlesExceptionGracefully() {
        when(vaultSecretProvider.getIntermediateCa()).thenThrow(new RuntimeException("vault failure"));

        // Method should catch and log the exception without throwing it
        certificateManagerService.run();

        verify(vaultSecretProvider, times(1)).getIntermediateCa();
    }

    @Test
    void renewCertificate_success() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub").privateKeyPem("priv").build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed = SignCertResponseDTO.builder()
                .certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null); // skip verification

        certificateManagerService.renewCertificate();

        verify(pkiService, times(1)).createKeyPair(null, 2048);
        verify(vaultSecretProvider, times(1)).persistKeyPair(keyPair);
        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
    }

    @Test
    void renewCertificate_skipsPersistenceOnVerificationFailure() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub").privateKeyPem("priv").build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed = SignCertResponseDTO.builder()
                .certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn("intermediate-pem");

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, never()).persistCertificate(any());
    }

    @Test
    void persistSignedArtifacts_skipsVerificationIfIntermediateMissing() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub").privateKeyPem("priv").build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed = SignCertResponseDTO.builder()
                .certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
    }

    @Test
    void persistSignedArtifacts_guardsAgainstNulls() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub").privateKeyPem("priv").build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed = SignCertResponseDTO.builder()
                .certificate("cert-pem")
                .caChain(null)
                .issuingCa(null)
                .build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
        verify(vaultSecretProvider, never()).persistCaChain(any());
        verify(vaultSecretProvider, never()).persistIntermediateCa(any());
    }

    @Test
    void renewCertificate_throwsExceptionOnPkiFailure() {
        when(pkiService.createKeyPair(null, 2048)).thenThrow(new PkiException("PKI failure"));

        assertThrows(PkiException.class, () -> certificateManagerService.renewCertificate());

        verify(pkiService, times(1)).createKeyPair(null, 2048);
        verify(vaultSecretProvider, never()).persistKeyPair(any());
    }

    @Test
    void checkAndRefreshIntermediateCa_persistsNewIfMissing() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        when(managementNodeService.getIntermediateCertificate()).thenReturn(
                CertificateResponse.builder().certificate("new-cert").build()
        );

        certificateManagerService.run();

        verify(vaultSecretProvider).persistIntermediateCa("new-cert");
    }

    @Test
    void checkAndRefreshIntermediateCa_guardsAgainstNullResponse() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        when(managementNodeService.getIntermediateCertificate()).thenReturn(null);

        certificateManagerService.run();

        verify(vaultSecretProvider, never()).persistIntermediateCa(any());
    }

    @Test
    void checkAndRefreshIntermediateCa_refreshesIfExpiringSoon() throws Exception {
        // Create a cert that is already "expired" or expires very soon
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Old");
        long now = System.currentTimeMillis();
        Date start = new Date(now - 100000);
        Date end = new Date(now + 1000); // Expires in 1 second
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate oldCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String oldPem = PemUtil.toPem("CERTIFICATE", oldCert.getEncoded());

        // Set threshold to 14 days so that 1 second remaining is definitely "expiring soon"
        certificateProperties.setIntermediateMinValidDays(14);

        when(vaultSecretProvider.getIntermediateCa()).thenReturn(oldPem);
        when(managementNodeService.getIntermediateCertificate()).thenReturn(
                CertificateResponse.builder().certificate("fresh-cert").build()
        );

        certificateManagerService.run();

        verify(vaultSecretProvider).persistIntermediateCa("fresh-cert");
    }

    @Test
    void run_skipsRenewalIfCertificateIsValid() throws Exception {
        // Create a cert that is valid for a long time
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Valid");
        long now = System.currentTimeMillis();
        // Total duration: 60 days. Passed: 1 day. Remaining: 59 days (~98% remaining).
        Date start = new Date(now - 3600000 * 24); 
        Date end = new Date(now + 3600000 * 24 * 59);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate validCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String validPem = PemUtil.toPem("CERTIFICATE", validCert.getEncoded());

        // Also create a valid intermediate cert to avoid its refresh
        X509Certificate intermediateCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String intermediatePem = PemUtil.toPem("CERTIFICATE", intermediateCert.getEncoded());

        when(vaultSecretProvider.getIntermediateCa()).thenReturn(intermediatePem);
        when(vaultSecretProvider.getCertificate()).thenReturn(validPem);

        certificateManagerService.run();

        verify(pkiService, never()).createKeyPair(any(), any());
    }

    @Test
    void run_renewsIfCertificateIsMissing() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn("some-intermediate");
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(pkiService.createKeyPair(null, 2048)).thenReturn(CreateKeyResponseDTO.builder().build());

        certificateManagerService.run();

        verify(pkiService, times(1)).createKeyPair(any(), any());
    }

    @Test
    void run_renewsIfCertificateIsBelowThreshold() throws Exception {
        // Create a cert that is almost expired (validity threshold is 10%)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=ExpiringSoon");
        long now = System.currentTimeMillis();
        // Total duration: 100 units. Passed: 95 units. Remaining: 5 units (5% remaining).
        Date start = new Date(now - 95000);
        Date end = new Date(now + 5000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate expiringCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String expiringPem = PemUtil.toPem("CERTIFICATE", expiringCert.getEncoded());

        when(vaultSecretProvider.getIntermediateCa()).thenReturn("some-intermediate");
        when(vaultSecretProvider.getCertificate()).thenReturn(expiringPem);
        when(pkiService.createKeyPair(null, 2048)).thenReturn(CreateKeyResponseDTO.builder().build());

        certificateManagerService.run();

        verify(pkiService, times(1)).createKeyPair(any(), any());
    }
}
