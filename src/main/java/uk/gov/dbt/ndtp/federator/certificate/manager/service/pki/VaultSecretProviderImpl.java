/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultSysOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.VaultMount;
import org.springframework.vault.support.Versioned;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.VaultException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;

/**
 * Implementation of {@link VaultSecretProvider} for persisting key pairs to HashiCorp Vault.
 * Ensures the KV secrets engine mount exists and uses KV v2 for storing secrets.
 */
@Slf4j
@Service
public class VaultSecretProviderImpl implements VaultSecretProvider {

    private static final String KV_ENGINE_TYPE = "kv";
    private static final String KV_VERSION = "2";

    private final VaultTemplate vaultTemplate;
    private final String mountPath;        // e.g. "node-net"
    private final String baseRelativePath; // e.g. "client"

    /**
     * Constructs the VaultSecretProviderImpl.
     *
     * @param vaultTemplate the Spring Vault template
     * @param secretBasePath the base path for secrets from configuration (e.g., "node-net/client")
     */
    public VaultSecretProviderImpl(
            VaultTemplate vaultTemplate,
            @Value("${application.vault.secret-path}") String secretBasePath) {
        this.vaultTemplate = vaultTemplate;
        String[] parts = secretBasePath.split("/", 2);
        this.mountPath = parts[0];
        this.baseRelativePath = parts.length > 1 ? parts[1] : "";
    }

    /**
     * Persists the provided key pair to the configured Vault secret path.
     * Ensures that the KV engine is mounted at the given mount path (KV v2). If not, it mounts it.
     *
     * @param keyPairDto the DTO containing the public and private keys in PEM format
     */
    @Override
    public void persistKeyPair(CreateKeyResponseDTO keyPairDto) {
        ensureKvMountExists();

        String relativePath = getRelativePath("keypair");
        String logPath = mountPath + "/" + relativePath;
        log.info("Persisting key pair to Vault path: {} (KV v2)", logPath);

        Map<String, String> keyPairMap = new HashMap<>();
        keyPairMap.put("publicKey", keyPairDto.getPublicKeyPem());
        keyPairMap.put("privateKey", keyPairDto.getPrivateKeyPem());

        persist(relativePath, keyPairMap, "key pair");
    }

    /**
     * Persists the provided certificate to the configured Vault secret path.
     *
     * @param certificate the certificate in PEM format
     */
    @Override
    public void persistCertificate(String certificate) {
        ensureKvMountExists();

        String relativePath = getRelativePath("certificate");
        log.info("Persisting certificate to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        Map<String, String> data = new HashMap<>();
        data.put("certificate", certificate);

        persist(relativePath, data, "certificate");
    }

    /**
     * Persists the provided CA chain to the configured Vault secret path.
     *
     * @param caChain the list of certificates in the chain in PEM format
     */
    @Override
    public void persistCaChain(java.util.List<String> caChain) {
        ensureKvMountExists();

        String relativePath = getRelativePath("ca-chain");
        log.info("Persisting CA chain to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        String chain = String.join("\n", caChain);
        Map<String, String> data = new HashMap<>();
        data.put("chain", chain);

        persist(relativePath, data, "CA chain");
    }

    /**
     * Persists the provided Intermediate CA certificate to the configured Vault secret path.
     *
     * @param intermediateCa the Intermediate CA certificate in PEM format
     */
    @Override
    public void persistIntermediateCa(String intermediateCa) {
        ensureKvMountExists();

        String relativePath = getRelativePath("intermediate-ca");
        log.info("Persisting Intermediate CA to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        Map<String, String> data = new HashMap<>();
        data.put("certificate", intermediateCa);

        persist(relativePath, data, "Intermediate CA");
    }

    private String getRelativePath(String suffix) {
        return baseRelativePath.isEmpty() ? suffix : baseRelativePath + "/" + suffix;
    }

    @Override
    public String getCertificate() {
        ensureKvMountExists();
        String relativePath = getRelativePath("certificate");
        log.info("Retrieving certificate from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No certificate found at {}/{}", mountPath, relativePath);
                return null;
            }
            Object cert = versioned.getData().get("certificate");
            return cert instanceof String ? (String) cert : null;
        } catch (Exception e) {
            log.error("Failed to retrieve certificate from Vault at path {}/{}: {}", mountPath, relativePath, e.getMessage());
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    @Override
    public String getIntermediateCa() {
        ensureKvMountExists();
        String relativePath = getRelativePath("intermediate-ca");
        log.info("Retrieving Intermediate CA from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No Intermediate CA found at {}/{}", mountPath, relativePath);
                return null;
            }
            Object cert = versioned.getData().get("certificate");
            return cert instanceof String ? (String) cert : null;
        } catch (Exception e) {
            log.error("Failed to retrieve Intermediate CA from Vault at path {}/{}: {}", mountPath, relativePath, e.getMessage());
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    private void persist(String relativePath, Map<String, String> data, String type) {
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            kv.put(relativePath, data);
            log.info("Successfully persisted {} to Vault.", type);
        } catch (Exception e) {
            log.error("Failed to persist {} to Vault at path {}/{}: {}", type, mountPath, relativePath, e.getMessage());
            throw new VaultException("Vault persistence failed", e);
        }
    }

    /**
     * Ensures the KV (v2) engine is mounted at the configured mountPath.
     * If the mount does not exist, it will be created with version=2.
     */
    private void ensureKvMountExists() {
        try {
            VaultSysOperations sys = vaultTemplate.opsForSys();
            Map<String, VaultMount> mounts = sys.getMounts();
            String key = mountPath.endsWith("/") ? mountPath : mountPath + "/";
            if (!mounts.containsKey(key)) {
                log.warn("Vault mount '{}' not found. Creating KV v2 mount...", key);
                VaultMount mount = VaultMount.builder()
                        .type(KV_ENGINE_TYPE)
                        .options(java.util.Map.of("version", KV_VERSION))
                        .build();
                sys.mount(mountPath, mount);
                log.info("Mounted KV v2 at '{}'.", key);
            }
        } catch (Exception e) {
            log.error("Failed to ensure KV mount exists at '{}': {}", mountPath, e.getMessage());
            throw new VaultException("Failed to ensure KV mount exists", e);
        }
    }
}
