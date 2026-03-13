/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties.Destination;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;

@ExtendWith(MockitoExtension.class)
public class MtlsHttpClientBuilderTest {

    @InjectMocks
    MtlsHttpClientBuilder builder;

    @Mock
    VaultSecretProvider vaultSecretProvider;

    @Mock
    CertificateProperties certificateProperties;

    private Path keyStoreFile;
    private Path trustStoreFile;

    private static final String PASSWORD = "password";
    private static final String TYPE = "JKS";

    @BeforeEach
    void setUp() throws Exception {
        keyStoreFile = createTempKeyStore();
        trustStoreFile = createTempKeyStore();
        ReflectionTestUtils.setField(builder, "keyStorePath", keyStoreFile.toString());
        ReflectionTestUtils.setField(builder, "trustStorePath", trustStoreFile.toString());
        ReflectionTestUtils.setField(builder, "keyStorePassword", PASSWORD);
        ReflectionTestUtils.setField(builder, "trustStorePassword", PASSWORD);
        ReflectionTestUtils.setField(builder, "keyStoreType", "JKS");
    }

    @Test
    void buildConnectionManager() {
        Destination mockConfig = mock(CertificateProperties.Destination.class);
        when(mockConfig.getKeystorePassword()).thenReturn(PASSWORD);
        when(certificateProperties.getDestination()).thenReturn(mockConfig);
        PoolingHttpClientConnectionManager connectionManager = builder.buildConnectionManager();
    
        assertNotNull(connectionManager);
    }

    @Test
    void buildConnectionManager_WithPassword() {
        PoolingHttpClientConnectionManager connectionManager = builder.buildConnectionManager(PASSWORD, PASSWORD);
    
        assertNotNull(connectionManager);
    }

    @Test
    void buildHttpClient() {
        PoolingHttpClientConnectionManager connectionManager = mock(PoolingHttpClientConnectionManager.class);
        CloseableHttpClient httpClient = builder.buildHttpClient(connectionManager);
        
        assertNotNull(httpClient);
    }

    @Test
    void buildRestClient() {
        Destination mockConfig = mock(CertificateProperties.Destination.class);
        when(mockConfig.getKeystorePassword()).thenReturn(PASSWORD);
        when(certificateProperties.getDestination()).thenReturn(mockConfig);
        RestClient restClient = builder.buildRestClient();

        assertNotNull(restClient);
    }
    
    private Path createTempKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(TYPE);
        ks.load(null, PASSWORD.toCharArray());

        Path file = Files.createTempFile("test-keystore", ".jks");

        try (FileOutputStream fos = new FileOutputStream(file.toFile())) {
            ks.store(fos, PASSWORD.toCharArray());
        }

        return file;
    }
}
