/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class for the Federator Certificate Management service.
 * This class initializes the Spring Boot application and enables scheduling.
 */
@Slf4j
@EnableScheduling
@SpringBootApplication
public class ApplicationRunner {
    public static final String STARTING_MSG = "Starting federator Certificate Management service";

    /**
     * The main entry point for the application.
     *
     * @param args command line arguments
     */
    public static void main(final String[] args) {
        log.info(STARTING_MSG);
        SpringApplication.run(ApplicationRunner.class, args);
    }
}
