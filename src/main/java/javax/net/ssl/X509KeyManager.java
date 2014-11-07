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
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface X509KeyManager extends KeyManager {
    String[] getClientAliases(String keyType, Principal[] issuers);
    String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket);
    String[] getServerAliases(String keyType, Principal[] issuers);
    String chooseServerAlias(String keyType, Principal[] issuers, Socket socket);
    X509Certificate[] getCertificateChain(String alias);
    PrivateKey getPrivateKey(String alias);
}
