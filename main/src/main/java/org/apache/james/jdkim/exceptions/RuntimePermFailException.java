package org.apache.james.jdkim.exceptions;

// Simple 'wrapper' for a FailException.
// Used where original API does not expect a FailException, only runtime errors
// like IllegalStateException (often explcitly handled by caller).
public class RuntimePermFailException extends RuntimeException {

    public RuntimePermFailException(PermFailException cause) {
        super(cause.getMessage(), cause);
    }

    @Override
    public synchronized PermFailException getCause() {
        return (PermFailException)super.getCause();
    }

}
