/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
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
     * Creates a PoolingHttpClientConnectionManager bean configured for mTLS communication with timeouts.
     *
     * @return a configured PoolingHttpClientConnectionManager instance
     */
    @Bean
    public PoolingHttpClientConnectionManager connectionManager() {
        try {
            KeyStore keyStore = loadKeyStore(keyStorePath, keyStorePassword, keyStoreType);
            KeyStore trustStore = loadKeyStore(trustStorePath, trustStorePassword, keyStoreType);

            SSLContext sslContext = SSLContextBuilder.create()
                    .loadKeyMaterial(keyStore, keyStorePassword.toCharArray())
                    .loadTrustMaterial(trustStore, null)
                    .build();

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
     * Creates a CloseableHttpClient bean configured for mTLS communication with timeouts.
     *
     * @return a configured CloseableHttpClient instance
     */
    @Bean
    public CloseableHttpClient httpClient(HttpClientConnectionManager connectionManager) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.of(30, TimeUnit.SECONDS))
                .build();

        return HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setConnectionReuseStrategy((request, response, context) -> false)
                .setDefaultRequestConfig(requestConfig)
                .evictExpiredConnections()
                .build();
    }

    /**
     * Creates a RestClient bean configured for mTLS communication.
     *
     * @param httpClient the mTLS-enabled HttpClient
     * @return a configured RestClient instance
     */
    @Bean
    public RestClient mtlsRestClient(CloseableHttpClient httpClient) {
        return RestClient.builder()
                .requestFactory(new HttpComponentsClientHttpRequestFactory(httpClient))
                .build();
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
