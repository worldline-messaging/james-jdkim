package org.apache.james.jdkim.exceptions;

public class RevokedKeyException extends RuntimeException {
    public RevokedKeyException() {
    }

    public RevokedKeyException(String s) {
        super(s);
    }

    public RevokedKeyException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public RevokedKeyException(Throwable throwable) {
        super(throwable);
    }

    public RevokedKeyException(String s, Throwable throwable, boolean b, boolean b1) {
        super(s, throwable, b, b1);
    }
}
