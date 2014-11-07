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

import static javax.net.ssl.StandardConstants.SNI_HOST_NAME;

import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

public final class SNIHostName extends SNIServerName {

    private final String hostName;

    public SNIHostName(final byte[] encoded) {
        this(IDN.toASCII(new String(encoded, StandardCharsets.UTF_8)), encoded);
    }

    public SNIHostName(final String hostName) {
        this(IDN.toASCII(hostName, IDN.USE_STD3_ASCII_RULES), 0);
    }

    private SNIHostName(final String hostName, int unused) {
        this(hostName, hostName.getBytes(StandardCharsets.US_ASCII));
    }

    private SNIHostName(final String hostName, final byte[] encoded) {
        super(SNI_HOST_NAME, encoded);
        if (hostName.isEmpty() || hostName.endsWith(".")) throw new IllegalArgumentException();
        this.hostName = hostName;
    }

    public String getAsciiName() {
        return hostName;
    }

    public boolean equals(final Object obj) {
        return obj instanceof SNIHostName && equals((SNIHostName) obj);
    }

    private boolean equals(final SNIHostName obj) {
        return obj.hostName.equalsIgnoreCase(hostName);
    }

    public int hashCode() {
        return 527 + hostName.toUpperCase(Locale.ENGLISH).hashCode();
    }

    public String toString() {
        return "type=host_name (0), value=" + hostName;
    }

    public static SNIMatcher createSNIMatcher(final String regex) {
        final Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        return new SNIMatcher(SNI_HOST_NAME) {
            public boolean matches(final SNIServerName serverName) {
                if (serverName == null) throw new NullPointerException();
                final String asciiName;
                if (serverName instanceof SNIHostName) {
                    asciiName = ((SNIHostName) serverName).getAsciiName();
                } else {
                    try {
                        asciiName = IDN.toASCII(new String(serverName.getEncoded(), StandardCharsets.UTF_8));
                    } catch (RuntimeException ignored) {
                        return false;
                    }
                }
                return pattern.matcher(asciiName).matches() || pattern.matcher(IDN.toUnicode(asciiName)).matches();
            }
        };
    }
}
