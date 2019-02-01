package org.apache.james.jdkim.exceptions;

public class BodyHashException extends PermFailException {
    private byte[] canonicalizedBody = null;

    private byte[] canonicalizedHeader = null;

    public BodyHashException(String error) {
        super(error);
    }

    public BodyHashException(String string, Exception e) {
        super(string, e);
    }

    public BodyHashException(String string, String signatureIdentity) {
        super(string, signatureIdentity);
    }

    public byte[] getCanonicalizedBody() {
        return canonicalizedBody;
    }

    public void setCanonicalizedBody(byte[] canonicalizedBody) {
        this.canonicalizedBody = canonicalizedBody;
    }

    public byte[] getCanonicalizedHeader() {
        return canonicalizedHeader;
    }

    public void setCanonicalizedHeader(byte[] canonicalizedHeader) {
        this.canonicalizedHeader = canonicalizedHeader;
    }
}
