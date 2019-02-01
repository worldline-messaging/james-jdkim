package org.apache.james.jdkim.exceptions;

public class SignaturePermFailException extends PermFailException {
    public SignaturePermFailException(String error) {
        super(error);
    }

    public SignaturePermFailException(String string, Exception e) {
        super(string, e);
    }

    public SignaturePermFailException(String string, String signatureIdentity) {
        super(string, signatureIdentity);
    }
}
