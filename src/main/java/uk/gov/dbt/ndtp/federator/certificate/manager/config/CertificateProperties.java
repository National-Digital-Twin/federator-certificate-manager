/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for certificate management.
 * These properties are bound from 'application.certificate' in application.yml.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "application.certificate")
public class CertificateProperties {

    /**
     * The minimum number of days the intermediate certificate must be valid for.
     */
    private long intermediateMinValidDays = 14;

    /**
     * The threshold percentage of validity remaining below which a certificate should be renewed.
     */
    private double renewalThresholdPercentage = 10.0;

    /**
     * The key size for generated key pairs (e.g., 2048 or 4096).
     */
    private Integer keySize = 2048;

    /**
     * The subject details for the certificate.
     */
    private Subject subject = new Subject();

    /**
     * Nested class for certificate subject fields.
     */
    @Getter
    @Setter
    public static class Subject {
        private String country;
        private String state;
        private String locality;
        private String organization;
        private String organizationalUnit;
        private String commonName;
        /**
         * Comma-separated list of alternative names (DNS).
         */
        private String altNames;
    }
}
