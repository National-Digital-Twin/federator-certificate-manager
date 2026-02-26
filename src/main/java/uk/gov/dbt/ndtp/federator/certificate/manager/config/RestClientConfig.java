/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import java.io.FileInputStream;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.RestClientConfigurationException;

/**
 * Configuration class for the Spring RestClient.
 * Sets up a RestClient with mTLS support using Apache HttpClient 5.
 */
@Configuration
public class RestClientConfig {

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

    /**
     * Creates a RestClient bean configured for mTLS communication.
     * Loads the keystore and truststore from the configured paths and passwords.
     *
     * @return a configured RestClient instance
     */
    @Bean
    public RestClient mtlsRestClient() {
        try {
            KeyStore keyStore = loadKeyStore(keyStorePath, keyStorePassword, keyStoreType);
            KeyStore trustStore = loadKeyStore(trustStorePath, trustStorePassword, keyStoreType);

            SSLContext sslContext = SSLContextBuilder.create()
                    .loadKeyMaterial(keyStore, keyStorePassword.toCharArray())
                    .loadTrustMaterial(trustStore, null)
                    .build();

            HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                    .setTlsSocketStrategy(new DefaultClientTlsStrategy(sslContext))
                    .build();

            CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(cm)
                    .evictExpiredConnections()
                    .build();

            return RestClient.builder()
                    .requestFactory(new HttpComponentsClientHttpRequestFactory(httpClient))
                    .build();
        } catch (Exception e) {
            throw new RestClientConfigurationException("Failed to configure mTLS RestClient", e);
        }
    }

    private KeyStore loadKeyStore(String path, String password, String type) {
        try {
            KeyStore ks = KeyStore.getInstance(type);
            try (FileInputStream fis = new FileInputStream(path)) {
                ks.load(fis, password.toCharArray());
            }
            return ks;
        } catch (Exception e) {
            throw new RestClientConfigurationException("Failed to load keystore from " + path, e);
        }
    }
}
