/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import org.slf4j.LoggerFactory;

class LoggingKeyManagerTest {

    private X509ExtendedKeyManager delegate;
    private LoggingKeyManager keyManager;

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setup() {

        delegate = mock(X509ExtendedKeyManager.class);
        keyManager = new LoggingKeyManager(delegate);

        Logger logger = (Logger) LoggerFactory.getLogger(LoggingKeyManager.class);

        logAppender = new ListAppender<>();
        logAppender.start();
        logger.addAppender(logAppender);
    }

    @Test
    void shouldLogCertificateDetailsWhenAliasSelected() throws Exception {

        String alias = "client-cert";

        X509Certificate cert = mock(X509Certificate.class);

        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=test"));
        when(cert.getNotAfter()).thenReturn(new java.util.Date());

        when(delegate.chooseClientAlias(any(), any(), any()))
                .thenReturn(alias);

        when(delegate.getCertificateChain(alias))
                .thenReturn(new X509Certificate[]{cert});

        String result = keyManager.chooseClientAlias(new String[]{"RSA"}, new Principal[0], new Socket());

        assertEquals(alias, result);

        List<ILoggingEvent> logs = logAppender.list;

        assertEquals(1, logs.size());
        assertTrue(logs.get(0).getFormattedMessage().contains("TLS client certificate selected"));
    }

    @Test
    void shouldNotLogWhenAliasIsNull() {

        when(delegate.chooseClientAlias(any(), any(), any())).thenReturn(null);

        String result = keyManager.chooseClientAlias(new String[]{"RSA"}, null, new Socket());

        assertNull(result);
        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void shouldNotLogWhenCertificateChainIsEmpty() {

        String alias = "client-cert";

        when(delegate.chooseClientAlias(any(), any(), any()))
                .thenReturn(alias);

        when(delegate.getCertificateChain(alias))
                .thenReturn(new X509Certificate[0]);

        keyManager.chooseClientAlias(new String[]{"RSA"}, null, new Socket());

        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void shouldDelegateGetPrivateKey() {

        PrivateKey key = mock(PrivateKey.class);

        when(delegate.getPrivateKey("alias")).thenReturn(key);

        assertEquals(key, keyManager.getPrivateKey("alias"));
    }

    @Test
    void shouldDelegateGetCertificateChain() {

        X509Certificate cert = mock(X509Certificate.class);

        when(delegate.getCertificateChain("alias"))
                .thenReturn(new X509Certificate[]{cert});

        assertEquals(cert, keyManager.getCertificateChain("alias")[0]);
    }

}
