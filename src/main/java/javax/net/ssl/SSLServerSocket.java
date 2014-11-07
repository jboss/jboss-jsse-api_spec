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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public abstract class SSLServerSocket extends ServerSocket {

    protected SSLServerSocket() throws IOException {
    }

    protected SSLServerSocket(final int port) throws IOException {
        super(port);
    }

    protected SSLServerSocket(final int port, final int backlog) throws IOException {
        super(port, backlog);
    }

    protected SSLServerSocket(final int port, final int backlog, final InetAddress bindAddr) throws IOException {
        super(port, backlog, bindAddr);
    }

    public abstract String[] getEnabledCipherSuites();
    public abstract void setEnabledCipherSuites(String[] names) throws IllegalArgumentException;
    public abstract String[] getSupportedCipherSuites();
    public abstract String[] getSupportedProtocols();
    public abstract String[] getEnabledProtocols();
    public abstract void setEnabledProtocols(String[] names) throws IllegalArgumentException;
    public abstract void setNeedClientAuth(boolean need);
    public abstract boolean getNeedClientAuth();
    public abstract void setWantClientAuth(boolean want);
    public abstract boolean getWantClientAuth();
    public abstract void setUseClientMode(boolean clientMode);
    public abstract boolean getUseClientMode();
    public abstract void setEnableSessionCreation(boolean enabled);
    public abstract boolean getEnableSessionCreation();

    public SSLParameters getSSLParameters() {
        SSLParameters parameters = new SSLParameters();
        parameters.setCipherSuites(getEnabledCipherSuites());
        parameters.setProtocols(getEnabledProtocols());
        if (getNeedClientAuth()) {
            parameters.setNeedClientAuth(true);
        } else if (getWantClientAuth()) {
            parameters.setWantClientAuth(true);
        }
        return parameters;
    }

    public void setSSLParameters(SSLParameters parameters) {
        final String[] cipherSuites = parameters.getCipherSuites();
        if (cipherSuites != null) setEnabledCipherSuites(cipherSuites);
        final String[] protocols = parameters.getProtocols();
        if (protocols != null) setEnabledProtocols(protocols);
        if (parameters.getNeedClientAuth()) {
            setNeedClientAuth(true);
        } else if (parameters.getWantClientAuth()) {
            setWantClientAuth(true);
        } else {
            setWantClientAuth(false);
        }
    }
}
