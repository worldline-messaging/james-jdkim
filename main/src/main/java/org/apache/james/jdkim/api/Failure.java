package org.apache.james.jdkim.api;

public class Failure {

    public enum Reason {
        // signature (header) is invalid: required parameters are missing, there
        // is a syntax error, or parameters values are invalid.
        INVALID_SIGNATURE,
        // headers canonicalization method is not supported
        UNSUPPORTED_HEADER_CANONICALIZATION_METHOD,
        // body canonicalization method is not supported
        UNSUPPORTED_BODY_CANONICALIZATION_METHOD,
        // signature algorithm is not supported
        UNSUPPORTED_SIGNATURE_ALGORITHM,
        // DNS query method is not supported
        UNSUPPORTED_DNS_QUERY_METHOD,
        // DNS lookup error
        DNS_LOOKUP_ERROR,
        // DNS record for signature key is missing
        MISSING_SIGNATURE_KEY_RECORD,
        // DNS record for signature key is invalid
        INVALID_SIGNATURE_KEY_RECORD,
        // signature key has been revoked: DNS record valid but key is blank(=revoked)
        REVOKED_SIGNATURE_KEY,
        // signature key is invalid
        INVALID_SIGNATURE_KEY,
        // signature is valid but does not match
        BAD_SIGNATURE,
        // (internal error) error while computing signature
        SIGNATURE_ERROR,
        // (internal error) error while parsing MIME message
        MIME_PARSING_ERROR,
        // (internal error) implementation error: unexpected cases, ...
        IMPLEMENTATION_ERROR
    }

    public static String getReasonText(Reason reason) {
        switch(reason) {
            case INVALID_SIGNATURE:                          return "invalid signature";
            case UNSUPPORTED_HEADER_CANONICALIZATION_METHOD: return "unsupported header canonicalization method";
            case UNSUPPORTED_BODY_CANONICALIZATION_METHOD:   return "unsupported body canonicalization method";
            case UNSUPPORTED_SIGNATURE_ALGORITHM:            return "unsupported signature algorithm";
            case UNSUPPORTED_DNS_QUERY_METHOD:               return "unsupported DNS query method";
            case DNS_LOOKUP_ERROR:                           return "DNS lookup error";
            case MISSING_SIGNATURE_KEY_RECORD:               return "missing signature record";
            case INVALID_SIGNATURE_KEY_RECORD:               return "invalid signature record";
            case REVOKED_SIGNATURE_KEY:                      return "revoked signature key";
            case INVALID_SIGNATURE_KEY:                      return "invalid signature key";
            case BAD_SIGNATURE:                              return "bad signature";
            case SIGNATURE_ERROR:                            return "signature error";
            case MIME_PARSING_ERROR:                         return "MIME parsing error";
            case IMPLEMENTATION_ERROR:                       return "implementation error";
            default:                                         return "unspecified reason";
        }
    }

}
