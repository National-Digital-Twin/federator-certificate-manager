/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(classes = ApplicationRunner.class)
@ActiveProfiles("test")
class ApplicationRunnerTest {

    @Test
    void contextLoads() {
        // Basic smoke test to ensure spring context starts
    }

    @Test
    void mainMethodRuns() {
        assertDoesNotThrow(() -> ApplicationRunner.main(new String[] {"--spring.main.web-application-type=none"}));
    }
}
