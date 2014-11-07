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

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

public class SSLContext {

    private static final SSLPermission SET_DEFAULT_SSL_CONTEXT_PERMISSION = new SSLPermission("setDefaultSSLContext");

    private final SSLContextSpi contextSpi;
    private final Provider provider;
    private final String protocol;

    protected SSLContext(final SSLContextSpi contextSpi, final Provider provider, final String protocol) {
        this.contextSpi = contextSpi;
        this.provider = provider;
        this.protocol = protocol;
    }

    private static volatile SSLContext defaultContext;

    public static SSLContext getDefault() throws NoSuchAlgorithmException {
        SSLContext context = defaultContext;
        if (context != null) {
            return context;
        }
        synchronized (SSLContext.class) {
            context = defaultContext;
            if (context != null) {
                return context;
            }
            return defaultContext = getInstance("Default");
        }
    }

    public static void setDefault(SSLContext context) throws NullPointerException, SecurityException {
        if (context == null) throw new NullPointerException();
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SET_DEFAULT_SSL_CONTEXT_PERMISSION);
        }
        defaultContext = context;
    }

    public static SSLContext getInstance(String algorithm) throws NoSuchAlgorithmException, NullPointerException {
        if (algorithm == null) throw new NullPointerException();
        final Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            final Provider.Service service = provider.getService("SSLContext", algorithm);
            if (service != null) {
                return new SSLContext((SSLContextSpi) service.newInstance(null), provider, algorithm);
            }
        }
        throw new NoSuchAlgorithmException();
    }

    public static SSLContext getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException, NullPointerException, IllegalArgumentException {
        if (algorithm == null || providerName == null) throw new NullPointerException();
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException();
        final Provider.Service service = provider.getService("SSLContext", algorithm);
        if (service != null) {
            return new SSLContext((SSLContextSpi) service.newInstance(null), provider, algorithm);
        }
        throw new NoSuchAlgorithmException();
    }

    public static SSLContext getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException, NullPointerException, IllegalArgumentException {
        if (algorithm == null) throw new NullPointerException();
        if (provider == null) throw new IllegalArgumentException();
        final Provider.Service service = provider.getService("SSLContext", algorithm);
        if (service != null) {
            return new SSLContext((SSLContextSpi) service.newInstance(null), provider, algorithm);
        }
        throw new NoSuchAlgorithmException();
    }

    public String getProtocol() {
        return protocol;
    }

    public Provider getProvider() {
        return provider;
    }

    public final void init(KeyManager[] km, TrustManager[] tm, SecureRandom random) throws KeyManagementException {
        contextSpi.engineInit(km, tm, random);
    }

    public SSLSocketFactory getSocketFactory() {
        return contextSpi.engineGetSocketFactory();
    }

    public SSLServerSocketFactory getServerSocketFactory() {
        return contextSpi.engineGetServerSocketFactory();
    }

    public SSLEngine createSSLEngine() {
        return contextSpi.engineCreateSSLEngine();
    }

    public SSLEngine createSSLEngine(final String host, final int port) {
        return contextSpi.engineCreateSSLEngine(host, port);
    }

    public SSLSessionContext getServerSessionContext() {
        return contextSpi.engineGetServerSessionContext();
    }

    public SSLSessionContext getClientSessionContext() {
        return contextSpi.engineGetClientSessionContext();
    }

    public SSLParameters getDefaultSSLParameters() {
        return contextSpi.engineGetDefaultSSLParameters();
    }

    public SSLParameters getSupportedSSLParameters() {
        return contextSpi.engineGetSupportedSSLParameters();
    }
}
