/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

/**
 * Contract for periodic certificate management activities.
 */
public interface CertificateManagerService {

    /**
     * Periodically executed task to check certificate status and initiate renewal if necessary.
     * Also ensures the intermediate CA is refreshed.
     */
    void run();

    /**
     * Periodically executed task to synchronize on-disk keystores and truststores with Vault.
     */
    void sync();

    /**
     * Generates a new key pair and persists it to the configured Vault secret path.
     * This involves calling PkiService to create the keys and VaultSecretProvider to store them.
     */
    void renewCertificate();
}
