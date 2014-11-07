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
import java.security.SecureRandom;

public abstract class SSLContextSpi {

    public SSLContextSpi() {
    }

    protected abstract void engineInit(final KeyManager[] km, final TrustManager[] tm, final SecureRandom random) throws KeyManagementException;

    protected abstract SSLSocketFactory engineGetSocketFactory();

    protected abstract SSLServerSocketFactory engineGetServerSocketFactory();

    protected abstract SSLEngine engineCreateSSLEngine();

    protected abstract SSLEngine engineCreateSSLEngine(final String host, final int port);

    protected abstract SSLSessionContext engineGetServerSessionContext();

    protected abstract SSLSessionContext engineGetClientSessionContext();

    protected abstract SSLParameters engineGetDefaultSSLParameters();

    protected abstract SSLParameters engineGetSupportedSSLParameters();
}
