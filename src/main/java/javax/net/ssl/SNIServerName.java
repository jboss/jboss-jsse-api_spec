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

import java.util.Arrays;

public abstract class SNIServerName {
    private final int type;
    private final byte[] encoded;

    protected SNIServerName(final int type, final byte[] encoded) {
        if (type < 0 || type > 255) throw new IllegalArgumentException();
        if (encoded == null) throw new NullPointerException();
        this.type = type;
        this.encoded = encoded.clone();
    }

    public boolean equals(final Object obj) {
        return obj instanceof SNIServerName && equals((SNIServerName) obj);
    }

    private boolean equals(final SNIServerName other) {
        return type == other.type && Arrays.equals(encoded, other.encoded);
    }

    public int getType() {
        return type;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public int hashCode() {
        int hc = 17;
        hc = 31 * hc + type;
        hc = 31 * hc + Arrays.hashCode(encoded);
        return hc;
    }

    public String toString() {
        final int length = encoded.length;
        StringBuilder b = new StringBuilder(33 + length * 3);
        // exactly specified string
        if (type == StandardConstants.SNI_HOST_NAME) {
            b.append("type=host_name (0), value=");
        } else {
            b.append("type=(").append(type).append("), value=");
        }
        if (length > 0) {
            int i = 0;
            for (;;) {
                final byte bb = encoded[i];
                b.append(digit(bb >> 4)).append(digit(bb));
                if (++i == length) break;
                b.append(':');
            }
        }
        return b.toString();
    }

    private static char digit(int b) {
        b &= 0x0f;
        return (char) (b < 10 ? '0' + b : 'A' + b);
    }
}
