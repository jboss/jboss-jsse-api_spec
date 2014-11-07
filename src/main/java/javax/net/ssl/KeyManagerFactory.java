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

import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;

public class KeyManagerFactory {
    private final KeyManagerFactorySpi factorySpi;
    private final Provider provider;
    private final String algorithm;

    public static String getDefaultAlgorithm() {
        final String type = AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                return Security.getProperty("ssl.KeyManagerFactory.algorithm");
            }
        });
        // this is what OpenJDK returns, it probably won't work but it doesn't really have to
        return type == null ? "SunX509" : type;
    }

    public static KeyManagerFactory getInstance(String algorithm) throws NoSuchAlgorithmException, NullPointerException {
        if (algorithm == null) throw new NullPointerException();
        final Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            final Provider.Service service = provider.getService("KeyManagerFactory", algorithm);
            if (service != null) {
                return new KeyManagerFactory((KeyManagerFactorySpi) service.newInstance(null), provider, algorithm);
            }
        }
        throw new NoSuchAlgorithmException();
    }
    public static KeyManagerFactory getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException, NullPointerException, IllegalArgumentException {
        if (algorithm == null || providerName == null) throw new NullPointerException();
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) throw new NoSuchProviderException();
        final Provider.Service service = provider.getService("KeyManagerFactory", algorithm);
        if (service != null) {
            return new KeyManagerFactory((KeyManagerFactorySpi) service.newInstance(null), provider, algorithm);
        }
        throw new NoSuchAlgorithmException();
    }
    public static KeyManagerFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException, NullPointerException, IllegalArgumentException {
        if (algorithm == null) throw new NullPointerException();
        if (provider == null) throw new IllegalArgumentException();
        final Provider.Service service = provider.getService("KeyManagerFactory", algorithm);
        if (service != null) {
            return new KeyManagerFactory((KeyManagerFactorySpi) service.newInstance(null), provider, algorithm);
        }
        throw new NoSuchAlgorithmException();
    }

    protected KeyManagerFactory(final KeyManagerFactorySpi factorySpi, final Provider provider, final String algorithm) {
        this.factorySpi = factorySpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    public Provider getProvider() {
        return provider;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public KeyManager[] getKeyManagers() {
        return factorySpi.engineGetKeyManagers();
    }

    public void init(KeyStore ks, char[] password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        factorySpi.engineInit(ks, password);
    }

    public void init(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        factorySpi.engineInit(spec);
    }
}
