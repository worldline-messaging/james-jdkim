package org.apache.james.jdkim.exceptions;

public class DnsPermFailException extends PermFailException {
    public DnsPermFailException(String error) {
        super(error);
    }

    public DnsPermFailException(String string, Exception e) {
        super(string, e);
    }

    public DnsPermFailException(String string, String signatureIdentity) {
        super(string, signatureIdentity);
    }
}
