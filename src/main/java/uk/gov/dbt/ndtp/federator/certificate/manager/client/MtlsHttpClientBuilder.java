/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.client;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.LoggingKeyManager;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.RestClientConfigurationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;

/**
 * Service that builds a HTTP connection manager, client and REST client from a local keystore and truststore.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MtlsHttpClientBuilder {
    @Value("${application.client.key-store}")
    private String keyStorePath;

    @Value("${application.client.key-store-password}")
    private String keyStorePassword;

    @Value("${application.client.trust-store}")
    private String trustStorePath;

    @Value("${application.client.trust-store-password}")
    private String trustStorePassword;

    @Value("${application.client.key-store-type:JKS}")
    private String keyStoreType;

    private final VaultSecretProvider vaultSecretProvider;
    private final CertificateProperties certificateProperties;
    private static final String PASSWORD = "password";

    /**
     * Builds a connection manager from a known keystore and truststore.
     */
    public PoolingHttpClientConnectionManager buildConnectionManager() {
        String keyStorePassword = getKeyStorePassword();
        String trustStorePassword = getTrustStorePassword();
        return buildConnectionManager(keyStorePassword, trustStorePassword);
    }


    /**
     * Builds a connection manager from a known keystore and truststore.
     * @param keyStorePassword credentials to access the keystore
     * @param trustStorePassword credentials to access the truststore
     * @return
     */
    public PoolingHttpClientConnectionManager buildConnectionManager(String keyStorePassword, String trustStorePassword) {
        try {
            KeyStore keyStore = loadKeyStore(keyStorePath, keyStorePassword, keyStoreType);
            KeyStore trustStore = loadKeyStore(trustStorePath, trustStorePassword, keyStoreType);
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = trustStore.getCertificate(alias);
                if (cert instanceof X509Certificate x509) {
                    log.info("Truststore entry: {} -> {}", alias, x509.getSubjectX500Principal());
                }
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyStorePassword.toCharArray());
            
            X509ExtendedKeyManager originalKeyManager = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];
            KeyManager loggingKeyManager = new LoggingKeyManager(originalKeyManager);
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(
                     new KeyManager[]{loggingKeyManager},
                     tmf.getTrustManagers(),
                     null
             );

            ConnectionConfig connectionConfig = ConnectionConfig.custom()
                    .setConnectTimeout(Timeout.of(10, TimeUnit.SECONDS))
                    .setSocketTimeout(Timeout.of(30, TimeUnit.SECONDS))
                    .setTimeToLive(TimeValue.ofHours(1))
                    .build();

            return PoolingHttpClientConnectionManagerBuilder.create()
                    .setTlsSocketStrategy(new DefaultClientTlsStrategy(sslContext))
                    .setDefaultConnectionConfig(connectionConfig)
                    .build();
        } catch (Exception e) {
            throw new RestClientConfigurationException("Failed to configure mTLS HttpClient", e);
        }
    }

    /**
     * Builds an HTTP client configured with connection manager.
     * @param connectionManager an instance of {@link HttpClientConnectionManager}
     * @return an instance of {@link CloseableHttpClient}
     */
    public CloseableHttpClient buildHttpClient(HttpClientConnectionManager connectionManager) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.of(30, TimeUnit.SECONDS))
                .build();

        return HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .evictExpiredConnections()
                .build();
    }

    /**
     * Builds an instance of {@link RestClient} with a new connection manager and http client. 
     * @return an instance of {@link RestClient}
     */
    public RestClient buildRestClient() {
        PoolingHttpClientConnectionManager connectionManager = buildConnectionManager();
        CloseableHttpClient httpClient = buildHttpClient(connectionManager);
        return RestClient.builder()
                .requestFactory(new HttpComponentsClientHttpRequestFactory(httpClient))
                .build();
    }

    private String getKeyStorePassword() {
        CertificateProperties.Destination config = certificateProperties.getDestination();
        String configKeyStorePassword = config.getKeystorePassword();
        if (configKeyStorePassword != null && !configKeyStorePassword.isBlank()) return configKeyStorePassword;

        Optional<String> vaultKeyStorePassword = getSecretFromVault("keystore-password");
        if (vaultKeyStorePassword.isPresent()) return vaultKeyStorePassword.get();

        return keyStorePassword;

    }

    private String getTrustStorePassword() {
        CertificateProperties.Destination config = certificateProperties.getDestination();
        String configTrustStorePassword = config.getTruststorePassword();
        if (configTrustStorePassword != null && !configTrustStorePassword.isBlank()) {
            return configTrustStorePassword;
        }

        Optional<String> vaultTrustStorePassword = getSecretFromVault("truststore-password");
        if (vaultTrustStorePassword.isPresent()) return vaultTrustStorePassword.get();
        
        return trustStorePassword;
    }

    private Optional<String> getSecretFromVault(String secretName) {
        Map<String, Object> secret = vaultSecretProvider.getSecret(secretName);
        if (secret.containsKey(PASSWORD)) {
            return Optional.of((String) secret.get(PASSWORD));
        }
        return Optional.empty();
    }

    private KeyStore loadKeyStore(String path, String password, String type) {
        try {
            KeyStore ks = KeyStore.getInstance(type);
            try (FileInputStream fis = new FileInputStream(path)) {
                ks.load(fis, password.toCharArray());
            }
            log.info("Fetched key store.");
            return ks;
        } catch (Exception e) {
            throw new RestClientConfigurationException("Failed to load keystore from " + path, e);
        }
    }
}
