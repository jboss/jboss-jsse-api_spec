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

public class SSLEngineResult {
    private final Status status;
    private final HandshakeStatus handshakeStatus;
    private final int bytesConsumed;
    private final int bytesProduced;

    public SSLEngineResult(final Status status, final HandshakeStatus handshakeStatus, final int bytesConsumed, final int bytesProduced) {
        if (status == null || handshakeStatus == null || bytesConsumed < 0 || bytesProduced < 0) throw new IllegalArgumentException();
        this.status = status;
        this.handshakeStatus = handshakeStatus;
        this.bytesConsumed = bytesConsumed;
        this.bytesProduced = bytesProduced;
    }

    public Status getStatus() {
        return status;
    }

    public HandshakeStatus getHandshakeStatus() {
        return handshakeStatus;
    }

    public int bytesConsumed() {
        return bytesConsumed;
    }

    public int bytesProduced() {
        return bytesProduced;
    }

    public String toString() {
        return String.format("Status = %s HandshakeStatus = %s%n" + "bytesConsumed = %d bytesProduced = %d",
            status, handshakeStatus, Integer.valueOf(bytesConsumed), Integer.valueOf(bytesProduced));
    }

    public enum HandshakeStatus {
        FINISHED,
        NEED_TASK,
        NEED_UNWRAP,
        NEED_WRAP,
        NOT_HANDSHAKING,
    }

    public enum Status {
        BUFFER_OVERFLOW,
        BUFFER_UNDERFLOW,
        CLOSED,
        OK,
    }
}
