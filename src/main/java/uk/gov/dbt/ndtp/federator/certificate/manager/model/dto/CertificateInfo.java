/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object representing the metadata information of a certificate.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateInfo {
    private String subject;
    private String issuer;
    private String serialNumber;
    private String notBefore;
    private String notAfter;
    private String signatureAlgorithm;
    private Integer version;
}
