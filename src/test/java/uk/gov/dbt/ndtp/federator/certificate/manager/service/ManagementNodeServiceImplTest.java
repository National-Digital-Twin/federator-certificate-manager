/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.idp.TokenCacheService;

@ExtendWith(MockitoExtension.class)
class ManagementNodeServiceImplTest {

    @Mock
    private RestClient restClient;

    @Mock
    private TokenCacheService tokenCacheService;

    private ManagementNodeServiceImpl managementNodeService;

    private final String baseUrl = "https://localhost:8090";

    @BeforeEach
    void setUp() {
        managementNodeService = new ManagementNodeServiceImpl(restClient, tokenCacheService, baseUrl);
    }

    @Test
    void getIntermediateCertificate_returnsResponseOnSuccess() {
        String token = "test-token";
        CertificateResponseDTO expectedResponse =
                CertificateResponseDTO.builder().certificate("cert-data").build();

        when(tokenCacheService.getToken()).thenReturn(token);

        RestClient.RequestHeadersUriSpec requestHeadersUriSpec = mock(RestClient.RequestHeadersUriSpec.class);
        RestClient.RequestHeadersSpec requestHeadersSpec = mock(RestClient.RequestHeadersSpec.class);
        RestClient.ResponseSpec responseSpec = mock(RestClient.ResponseSpec.class);

        when(restClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(baseUrl + ManagementNodeServiceImpl.INTERMEDIATE_CERT_PATH))
                .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(
                        eq(HttpHeaders.AUTHORIZATION), eq(ManagementNodeServiceImpl.BEARER_PREFIX + token)))
                .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(CertificateResponseDTO.class)).thenReturn(expectedResponse);

        CertificateResponseDTO actualResponse = managementNodeService.getIntermediateCertificate();

        assertEquals(expectedResponse, actualResponse);
    }

    @Test
    void getIntermediateCertificate_throwsExceptionOnFailure() {
        when(tokenCacheService.getToken()).thenReturn("token");
        when(restClient.get()).thenThrow(new RuntimeException("API error"));

        assertThrows(ManagementNodeException.class, () -> managementNodeService.getIntermediateCertificate());
    }
}
