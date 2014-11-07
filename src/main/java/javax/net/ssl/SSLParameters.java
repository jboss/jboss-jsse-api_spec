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

import java.security.AlgorithmConstraints;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

public class SSLParameters {
    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth;
    private boolean needClientAuth;
    private String endpointIdentificationAlgorithm;
    private AlgorithmConstraints algorithmConstraints;
    private List<SNIServerName> serverNames = null;
    private List<SNIMatcher> sniMatchers = null;
    private boolean useCipherSuitesOrder;

    public SSLParameters() {
    }

    public SSLParameters(final String[] cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public SSLParameters(final String[] cipherSuites, final String[] protocols) {
        this.cipherSuites = cipherSuites;
        this.protocols = protocols;
    }

    private static String[] copyOf(String[] orig) {
        return orig == null || orig.length == 0 ? orig : orig.clone();
    }

    public String[] getCipherSuites() {
        return copyOf(cipherSuites);
    }

    public String[] getProtocols() {
        return copyOf(protocols);
    }

    public void setCipherSuites(final String[] cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setProtocols(final String[] protocols) {
        this.protocols = protocols;
    }

    public String getEndpointIdentificationAlgorithm() {
        return endpointIdentificationAlgorithm;
    }

    public void setEndpointIdentificationAlgorithm(final String algorithm) {
        endpointIdentificationAlgorithm = algorithm;
    }

    public AlgorithmConstraints getAlgorithmConstraints() {
        return algorithmConstraints;
    }

    public void setAlgorithmConstraints(final AlgorithmConstraints algorithmConstraints) {
        this.algorithmConstraints = algorithmConstraints;
    }

    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    public void setWantClientAuth(final boolean wantClientAuth) {
        this.wantClientAuth = wantClientAuth;
    }

    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    public void setNeedClientAuth(final boolean needClientAuth) {
        this.needClientAuth = needClientAuth;
    }

    public final void setServerNames(List<SNIServerName> serverNames) throws NullPointerException, IllegalArgumentException {
        if (serverNames == null) {
            this.serverNames = null;
        } else if (serverNames.isEmpty()) {
            this.serverNames = Collections.emptyList();
        } else if (serverNames.size() == 1) {
            final SNIServerName serverName = serverNames.get(0);
            if (serverName == null) throw new NullPointerException();
            this.serverNames = Collections.singletonList(serverName);
        } else {
            final HashSet<SNIServerName> set = new HashSet<>(serverNames.size());
            final List<SNIServerName> list = Arrays.asList(serverNames.toArray(new SNIServerName[serverNames.size()]));
            for (SNIServerName serverName : list) {
                if (serverName == null) throw new NullPointerException();
                if (! set.add(serverName)) throw new IllegalArgumentException();
            }
            this.serverNames = Collections.unmodifiableList(list);
        }
    }

    public final List<SNIServerName> getServerNames() {
        return serverNames;
    }

    public final void setSNIMatchers(final Collection<SNIMatcher> matchers) {
        if (matchers == null) {
            this.sniMatchers = null;
        } else if (matchers.isEmpty()) {
            this.sniMatchers = Collections.emptyList();
        } else if (matchers.size() == 1) {
            final SNIMatcher matcher = matchers.iterator().next();
            if (matcher == null) throw new NullPointerException();
            this.sniMatchers  = Collections.singletonList(matcher);
        } else {
            final HashSet<SNIMatcher> set = new HashSet<>(matchers.size());
            final List<SNIMatcher> list = Arrays.asList(matchers.toArray(new SNIMatcher[matchers.size()]));
            for (SNIMatcher matcher : list) {
                if (matcher == null) throw new NullPointerException();
                if (! set.add(matcher)) throw new IllegalArgumentException();
            }
            this.sniMatchers = Collections.unmodifiableList(list);
        }
    }

    public final Collection<SNIMatcher> getSNIMatchers() {
        return sniMatchers;
    }

    public final boolean getUseCipherSuitesOrder() {
        return useCipherSuitesOrder;
    }

    public final void setUseCipherSuitesOrder(final boolean useCipherSuitesOrder) {
        this.useCipherSuitesOrder = useCipherSuitesOrder;
    }
}
