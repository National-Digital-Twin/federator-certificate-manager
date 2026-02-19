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
     * Executes the scheduled task to check the current token and perform management activities.
     */
    void run();

    /**
     * Generates a new key pair and persists it to the configured Vault secret path.
     * This involves calling PkiService to create the keys and VaultSecretProvider to store them.
     */
    void renewCertificate();
}
