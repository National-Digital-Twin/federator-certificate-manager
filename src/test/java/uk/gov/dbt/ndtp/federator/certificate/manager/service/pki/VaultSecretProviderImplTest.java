/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.vault.core.VaultSysOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.VaultMount;
import org.springframework.vault.support.Versioned;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.VaultException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VaultSecretProviderImplTest {

    @Mock
    private VaultTemplate vaultTemplate;

    @Mock
    private VaultSysOperations sysOps;

    @Mock
    private VaultVersionedKeyValueOperations kvOps;

    private VaultSecretProviderImpl vaultSecretProvider;

    private static final String BASE_PATH = "node-net/client";

    @BeforeEach
    void setUp() {
        vaultSecretProvider = new VaultSecretProviderImpl(vaultTemplate, BASE_PATH);
        when(vaultTemplate.opsForSys()).thenReturn(sysOps);
        when(sysOps.getMounts()).thenReturn(Collections.emptyMap());
        when(vaultTemplate.opsForVersionedKeyValue("node-net")).thenReturn(kvOps);
    }

    @Test
    void persistKeyPair_success() {
        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        vaultSecretProvider.persistKeyPair(dto);

        // Verify mount is attempted and KV put is executed on relative path
        verify(sysOps, times(1)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/keypair"), anyMap());
    }

    @Test
    void persistKeyPair_mountAlreadyExists() {
        when(sysOps.getMounts()).thenReturn(java.util.Map.of("node-net/", VaultMount.builder().type("kv").build()));

        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        vaultSecretProvider.persistKeyPair(dto);

        // Verify mount is NOT attempted if it already exists
        verify(sysOps, times(0)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/keypair"), anyMap());
    }

    @Test
    void constructor_edgeCases() {
        // Test split logic in constructor
        VaultSecretProviderImpl provider1 = new VaultSecretProviderImpl(vaultTemplate, "simplemount");
        // baseRelative is empty, relativeSecretPath should be "keypair"
        // Need to use reflection or check behavior to verify, but here we just ensure no crash
        
        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();
                
        when(vaultTemplate.opsForVersionedKeyValue("simplemount")).thenReturn(kvOps);
        provider1.persistKeyPair(dto);
        verify(kvOps, times(1)).put(eq("keypair"), anyMap());
    }

    @Test
    void persistKeyPair_failure() {
        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        doThrow(new VaultException("Vault down")).when(kvOps).put(eq("client/keypair"), anyMap());

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistKeyPair(dto));

        verify(sysOps, times(1)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/keypair"), anyMap());
    }

    @Test
    void ensureKvMountExists_failure() {
        // Force opsForSys to throw, triggering catch in ensureKvMountExists
        when(vaultTemplate.opsForSys()).thenThrow(new RuntimeException("sys unavailable"));

        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistKeyPair(dto));
        // Since mount step failed early, no KV ops should be attempted
        verify(kvOps, times(0)).put(any(), anyMap());
    }

    @Test
    void persistCertificate_success() {
        vaultSecretProvider.persistCertificate("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n");
        verify(sysOps, times(1)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/certificate"), anyMap());
    }

    @Test
    void persistCaChain_success() {
        java.util.List<String> chain = java.util.List.of("cert1", "cert2");
        vaultSecretProvider.persistCaChain(chain);
        verify(sysOps, times(1)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/ca-chain"), anyMap());
    }

    @Test
    void persistIntermediateCa_success() {
        vaultSecretProvider.persistIntermediateCa("-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n");
        verify(sysOps, times(1)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/intermediate-ca"), anyMap());
    }

    @Test
    void getIntermediateCa_success() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("certificate", "cert-content"));
        when(kvOps.get("client/intermediate-ca")).thenReturn(versioned);

        String result = vaultSecretProvider.getIntermediateCa();

        assertEquals("cert-content", result);
        verify(kvOps).get("client/intermediate-ca");
    }

    @Test
    void getIntermediateCa_notFound() {
        when(kvOps.get("client/intermediate-ca")).thenReturn(null);

        String result = vaultSecretProvider.getIntermediateCa();

        assertNull(result);
    }

    @Test
    void getIntermediateCa_failure() {
        when(kvOps.get("client/intermediate-ca")).thenThrow(new RuntimeException("read failed"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getIntermediateCa());
    }
}
