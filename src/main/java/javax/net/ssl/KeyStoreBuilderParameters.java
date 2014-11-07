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

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class KeyStoreBuilderParameters implements ManagerFactoryParameters {
    private final List<KeyStore.Builder> parameters;

    public KeyStoreBuilderParameters(final List<KeyStore.Builder> parameters) throws IllegalArgumentException, NullPointerException {
        if (parameters == null) throw new NullPointerException();
        if (parameters.isEmpty()) throw new IllegalArgumentException();
        this.parameters = Collections.unmodifiableList(new ArrayList<>(parameters));
    }

    public KeyStoreBuilderParameters(KeyStore.Builder builder) throws NullPointerException {
        if (builder == null) throw new NullPointerException();
        parameters = Collections.singletonList(builder);
    }

    public List<KeyStore.Builder> getParameters() {
        return parameters;
    }
}
