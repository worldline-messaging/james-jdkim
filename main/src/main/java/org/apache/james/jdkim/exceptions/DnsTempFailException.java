package org.apache.james.jdkim.exceptions;

public class DnsTempFailException extends TempFailException {
    public DnsTempFailException(String error) {
        super(error);
    }
}
