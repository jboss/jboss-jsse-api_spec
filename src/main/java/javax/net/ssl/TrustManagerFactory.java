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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

public class TrustManagerFactory {
    private final TrustManagerFactorySpi factorySpi;
    private final Provider provider;
    private final String algorithm;

    protected TrustManagerFactory(final TrustManagerFactorySpi factorySpi, final Provider provider, final String algorithm) {
        this.factorySpi = factorySpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    public static String getDefaultAlgorithm() {
        String defaultAlgName = Security.getProperty("ssl.TrustManagerFactory.algorithm");
        if (defaultAlgName == null) {
            defaultAlgName = "SunX509"; // just guess
        }
        return defaultAlgName;
    }

    public static TrustManagerFactory getInstance(String algorithm) throws NoSuchAlgorithmException, NullPointerException {
        if (algorithm == null) throw new NullPointerException();
        final Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            final Provider.Service service = provider.getService("TrustManagerFactory", algorithm);
            if (service != null) {
                return new TrustManagerFactory((TrustManagerFactorySpi) service.newInstance(null), provider, algorithm);
            }
        }
        throw new NoSuchAlgorithmException();
    }
    public static TrustManagerFactory getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException, NullPointerException, IllegalArgumentException {
        if (algorithm == null || providerName == null) throw new NullPointerException();
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException();
        final Provider.Service service = provider.getService("TrustManagerFactory", algorithm);
        if (service != null) {
            return new TrustManagerFactory((TrustManagerFactorySpi) service.newInstance(null), provider, algorithm);
        }
        throw new NoSuchAlgorithmException();
    }
    public static TrustManagerFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException, NullPointerException, IllegalArgumentException {
        if (algorithm == null) throw new NullPointerException();
        if (provider == null) throw new IllegalArgumentException();
        final Provider.Service service = provider.getService("TrustManagerFactory", algorithm);
        if (service != null) {
            return new TrustManagerFactory((TrustManagerFactorySpi) service.newInstance(null), provider, algorithm);
        }
        throw new NoSuchAlgorithmException();
    }

    public final String getAlgorithm() {
        return algorithm;
    }

    public final Provider getProvider() {
        return provider;
    }

    public final void init(KeyStore keyStore) throws KeyStoreException {
        factorySpi.engineInit(keyStore);
    }

    public final void init(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        factorySpi.engineInit(spec);
    }

    public final TrustManager[] getTrustManagers() throws IllegalStateException {
        return factorySpi.engineGetTrustManagers();
    }
}
