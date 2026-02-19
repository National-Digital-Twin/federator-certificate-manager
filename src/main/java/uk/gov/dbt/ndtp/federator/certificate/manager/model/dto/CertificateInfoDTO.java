/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.model.dto;

import lombok.*;

import java.time.Instant;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertificateInfoDTO {
    private String subject;
    private String issuer;
    private String serialNumber;
    private Instant notBefore;
    private Instant notAfter;
    private String signatureAlgorithm;
    private Integer version;
}
