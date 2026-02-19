/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import lombok.extern.slf4j.Slf4j;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;


@Slf4j
public class PemUtil {

    private static final String KEY_ALG = "RSA";

    public static PrivateKey parsePkcs8PrivateKey(String pem) throws Exception {
        byte[] der = decodePem(pem);
        return KeyFactory.getInstance(KEY_ALG).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    public static PublicKey parsePublicKey(String pem) throws Exception {
        byte[] der = decodePem(pem);
        return KeyFactory.getInstance(KEY_ALG).generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] decodePem(String pem) {
        String cleaned = pem
                .replaceAll("-----BEGIN ([A-Z ]+)-----", "")
                .replaceAll("-----END ([A-Z ]+)-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(cleaned);
    }

    public static String toPem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    public static X509Certificate parseCertificate(String pem) throws Exception {
        byte[] der = decodePem(pem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    public static long daysUntilExpiry(String pem) {
        try {
            X509Certificate cert = parseCertificate(pem);
            Instant now = Instant.now();
            Instant notAfter = cert.getNotAfter().toInstant();
            return now.until(notAfter, ChronoUnit.DAYS);
        } catch (Exception e) {
            return Long.MIN_VALUE; // indicates invalid/unparseable certificate
        }
    }

    public static boolean isValidForAtLeastDays(String pem, long minDays) {
        long days = daysUntilExpiry(pem);
        return days >= minDays;
    }

    public static void verifyCertificate(String certificatePem, String issuerPem) throws Exception {
        X509Certificate cert = parseCertificate(certificatePem);
        X509Certificate issuer = parseCertificate(issuerPem);

        String certSubject = cert.getSubjectX500Principal().getName();
        String issuerSubject = issuer.getSubjectX500Principal().getName();
        String issuerCn = extractCn(issuerSubject);

        log.info("Certificate for {} is validated against Intermediate Cert CN {}", certSubject, issuerCn);
        log.info("Certificate Issue Date: {}", cert.getNotBefore());
        log.info("Certificate Expiry Date: {}", cert.getNotAfter());
        log.info("Verified against Issuer Subject: {}", issuerSubject);

        // Check both validity and expiry against time
        cert.checkValidity();

        // Signature verification
        cert.verify(issuer.getPublicKey());
    }

    public static boolean isValidityBelowThreshold(String pem, double thresholdPercentage) {
        try {
            X509Certificate cert = parseCertificate(pem);
            long now = Instant.now().toEpochMilli();
            long notBefore = cert.getNotBefore().getTime();
            long notAfter = cert.getNotAfter().getTime();

            long totalDuration = notAfter - notBefore;
            long remainingDuration = notAfter - now;

            if (totalDuration <= 0) {
                return true;
            }

            double percentageRemaining = (double) remainingDuration / totalDuration * 100;
            return percentageRemaining <= thresholdPercentage;
        } catch (Exception e) {
            return true; // If unparseable, assume it needs renewal
        }
    }

    private static String extractCn(String dn) {
        if (dn == null || dn.isBlank()) {
            return "Unknown";
        }
        try {
            javax.naming.ldap.LdapName ldapName = new javax.naming.ldap.LdapName(dn);
            for (javax.naming.ldap.Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract CN from DN: {}. Error: {}", dn, e.getMessage());
        }
        return "Unknown";
    }
}
