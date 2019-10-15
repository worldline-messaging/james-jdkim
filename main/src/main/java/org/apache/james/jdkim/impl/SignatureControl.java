package org.apache.james.jdkim.impl;

import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;

public class SignatureControl {

    private String header;

    private SignatureRecord signatureRecord;

    private PublicKeyRecord publicKeyRecord;

    private FailException exception;

    public SignatureControl(String header) {
        this.header = header;
    }

    public String getHeader() {
        return header;
    }

    public SignatureRecord getSignatureRecord() {
        return signatureRecord;
    }

    public void setSignatureRecord(SignatureRecord signatureRecord) {
        this.signatureRecord = signatureRecord;
    }

    public PublicKeyRecord getPublicKeyRecord() {
        return publicKeyRecord;
    }

    public void setPublicKeyRecord(PublicKeyRecord publicKeyRecord) {
        this.publicKeyRecord = publicKeyRecord;
    }

    public FailException getException() {
        return exception;
    }

    public void setException(FailException exception) {
        this.exception = exception;
    }

    public String getSDID() {
        if ((signatureRecord == null) || (signatureRecord.getDToken() == null)) return null;
        return signatureRecord.getDToken().toString();
    }

    public String getSelector() {
        if ((signatureRecord == null) || (signatureRecord.getSelector() == null)) return null;
        return signatureRecord.getSelector().toString();
    }

}
