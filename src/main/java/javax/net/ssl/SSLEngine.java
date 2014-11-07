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

import java.nio.ByteBuffer;

public abstract class SSLEngine {
    private String peerHost;
    private int peerPort = -1;

    protected SSLEngine() {
    }

    protected SSLEngine(final String peerHost, final int peerPort) {
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }

    public String getPeerHost() {
        return peerHost;
    }

    public int getPeerPort() {
        return peerPort;
    }

    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return wrap(new ByteBuffer[] { src }, 0, 1, dst);
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
        return wrap(srcs, 0, srcs.length, dst);
    }

    public abstract SSLEngineResult wrap(final ByteBuffer[] srcs, final int offs, final int length, final ByteBuffer dst) throws SSLException;

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return unwrap(src, new ByteBuffer[] { dst }, 0, 1);
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        return unwrap(src, dsts, 0, dsts.length);
    }

    public abstract SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] byteBuffers, final int offs, final int length) throws SSLException;

    public abstract Runnable getDelegatedTask();

    public abstract void closeInbound() throws SSLException;

    public abstract boolean isInboundDone();

    public abstract void closeOutbound();

    public abstract boolean isOutboundDone();

    public abstract String[] getSupportedCipherSuites();

    public abstract String[] getEnabledCipherSuites();

    public abstract void setEnabledCipherSuites(String[] suites) throws IllegalArgumentException;

    public abstract String[] getSupportedProtocols();

    public abstract String[] getEnabledProtocols();

    public abstract void setEnabledProtocols(String[] protocols) throws IllegalArgumentException;

    public abstract SSLSession getSession();

    public abstract SSLSession getHandshakeSession();

    public abstract void beginHandshake() throws SSLException, IllegalStateException;

    public abstract SSLEngineResult.HandshakeStatus getHandshakeStatus();

    public abstract void setUseClientMode(boolean mode) throws IllegalArgumentException;

    public abstract boolean getUseClientMode();

    public abstract void setNeedClientAuth(boolean need);

    public abstract boolean getNeedClientAuth();

    public abstract void setWantClientAuth(boolean want);

    public abstract boolean getWantClientAuth();

    public abstract void setEnableSessionCreation(boolean flag);

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
        if (cipherSuites != null) {
            setEnabledCipherSuites(cipherSuites);
        }
        final String[] protocols = parameters.getProtocols();
        if (protocols != null) {
            setEnabledProtocols(protocols);
        }
        if (parameters.getNeedClientAuth()) {
            setNeedClientAuth(true);
        } else if (parameters.getWantClientAuth()) {
            setWantClientAuth(true);
        } else {
            setWantClientAuth(false);
        }
    }
}
