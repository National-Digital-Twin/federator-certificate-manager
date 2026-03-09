package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

import uk.gov.dbt.ndtp.federator.certificate.manager.exception.RestClientConfigurationException;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class RestClientConfigTest {

    private RestClientConfig config;

    private Path keyStoreFile;
    private Path trustStoreFile;

    private static final String PASSWORD = "password";
    private static final String TYPE = "JKS";

    @BeforeEach
    void setUp() throws Exception {
        config = new RestClientConfig();

        keyStoreFile = createTempKeyStore();
        trustStoreFile = createTempKeyStore();
        ReflectionTestUtils.setField(config, "keyStorePath", keyStoreFile.toString());
        ReflectionTestUtils.setField(config, "trustStorePath", trustStoreFile.toString());
        ReflectionTestUtils.setField(config, "keyStorePassword", "password");
        ReflectionTestUtils.setField(config, "trustStorePassword", "password");
        ReflectionTestUtils.setField(config, "keyStoreType", "JKS");
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

    @Test
    void connectionManager_shouldCreateManager() {
        PoolingHttpClientConnectionManager manager = config.connectionManager();

        assertNotNull(manager);
    }

    @Test
    void connectionManager_shouldThrowException_whenKeystoreInvalid() {
        ReflectionTestUtils.setField(config, "keyStorePath", "invalid-path.jks");

        assertThrows(
                RestClientConfigurationException.class,
                () -> config.connectionManager()
        );
    }

    @Test
    void httpClient_shouldCreateClient() {
        HttpClientConnectionManager manager = mock(HttpClientConnectionManager.class);

        CloseableHttpClient client = config.httpClient(manager);

        assertNotNull(client);
    }

    @Test
    void mtlsRestClient_shouldCreateRestClient() {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);

        RestClient restClient = config.mtlsRestClient(httpClient);

        assertNotNull(restClient);
    }
}