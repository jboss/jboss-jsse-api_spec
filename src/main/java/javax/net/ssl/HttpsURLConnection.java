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

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

public abstract class HttpsURLConnection extends HttpURLConnection {

    private static final SSLPermission SET_HOSTNAME_VERIFIER_PERMISSION = new SSLPermission("setHostnameVerifier");

    private static volatile HostnameVerifier defaultHostnameVerifier = new HostnameVerifier() {
        public boolean verify(final String hostname, final SSLSession session) {
            return false;
        }
    };
    private static final AtomicReference<SSLSocketFactory> defaultSSLSocketFactoryRef = new AtomicReference<>();

    public static HostnameVerifier getDefaultHostnameVerifier() {
        return defaultHostnameVerifier;
    }
    public static void setDefaultHostnameVerifier(final HostnameVerifier defaultHostnameVerifier) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SET_HOSTNAME_VERIFIER_PERMISSION);
        }
        HttpsURLConnection.defaultHostnameVerifier = defaultHostnameVerifier;
    }
    public static SSLSocketFactory getDefaultSSLSocketFactory() {
        SSLSocketFactory socketFactory = defaultSSLSocketFactoryRef.get();
        while (socketFactory == null) {
            if (! defaultSSLSocketFactoryRef.compareAndSet(null, socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault())) {
                socketFactory = defaultSSLSocketFactoryRef.get();
            }
        }
        return socketFactory;
    }
    public static void setDefaultSSLSocketFactory(final SSLSocketFactory defaultSSLSocketFactory) {
        if (defaultSSLSocketFactory == null) throw new IllegalArgumentException();
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkSetFactory();
        }
        defaultSSLSocketFactoryRef.set(defaultSSLSocketFactory);
    }

    protected HostnameVerifier hostnameVerifier;
    private SSLSocketFactory sslSocketFactory;

    protected HttpsURLConnection(final URL url) {
        super(url);
        hostnameVerifier = defaultHostnameVerifier;
        sslSocketFactory = defaultSSLSocketFactoryRef.get();
    }

    public abstract String getCipherSuite() throws IllegalStateException;
    public abstract Certificate[] getLocalCertificates() throws IllegalStateException;
    public abstract Certificate[] getServerCertificates() throws SSLPeerUnverifiedException, IllegalStateException;
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException, IllegalStateException {
        return ((X509Certificate) getServerCertificates()[0]).getSubjectX500Principal();
    }
    public Principal getLocalPrincipal() throws IllegalStateException {
        Certificate[] certs = getLocalCertificates();
        return certs == null ? null : ((X509Certificate) certs[0]).getSubjectX500Principal();
    }
    public void setHostnameVerifier(final HostnameVerifier hostnameVerifier) {
        this.hostnameVerifier = hostnameVerifier;
    }
    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }
    public void setSslSocketFactory(final SSLSocketFactory sslSocketFactory) {
        if (sslSocketFactory == null) throw new IllegalArgumentException();
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkSetFactory();
        }
        this.sslSocketFactory = sslSocketFactory;
    }
    public SSLSocketFactory getSslSocketFactory() {
        return sslSocketFactory;
    }
}
