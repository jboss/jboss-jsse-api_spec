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

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public abstract class X509ExtendedTrustManager implements X509TrustManager {

    public X509ExtendedTrustManager() {
    }

    public abstract void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException;
    public abstract void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException;
    public abstract void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException;
    public abstract void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException;
}
