package org.apache.james.jdkim.exceptions;

public class RevokedKeyPermFailException extends PermFailException {

    public RevokedKeyPermFailException(String error) {
        super(error);
    }

    public RevokedKeyPermFailException(String string, Exception e) {
        super(string, e);
    }

    public RevokedKeyPermFailException(String string, String signatureIdentity) {
        super(string, signatureIdentity);
    }
}
