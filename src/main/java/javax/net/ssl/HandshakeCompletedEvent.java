/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package javax.net.ssl;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.EventObject;

public class HandshakeCompletedEvent extends EventObject {

    private static final long serialVersionUID = 7914963744257769778L;

    private transient SSLSession session;

    public HandshakeCompletedEvent(final SSLSocket sock, final SSLSession s) {
        super(sock);
        session = s;
    }

    public SSLSession getSession() {
        return session;
    }

    public String getCipherSuite() {
        return session.getCipherSuite();
    }

    public Certificate[] getLocalCertificates() {
        return session.getLocalCertificates();
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return session.getPeerCertificates();
    }

    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return session.getPeerCertificateChain();
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        try {
            return session.getPeerPrincipal();
        } catch (AbstractMethodError ignored) {
            return ((java.security.cert.X509Certificate) getPeerCertificates()[0]).getSubjectX500Principal();
        }
    }

    public Principal getLocalPrincipal() {
        try {
            return session.getLocalPrincipal();
        } catch (AbstractMethodError ignored) {
            Certificate[] certs = getLocalCertificates();
            return certs == null || certs.length < 1 ? null : ((java.security.cert.X509Certificate) certs[0]).getSubjectX500Principal();
        }
    }

    public SSLSocket getSocket() {
        return (SSLSocket) source;
    }
}
