package org.apache.james.jdkim;

import org.xbill.DNS.*;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class MockResolver implements Resolver {

    private static final String _DOMAINKEY = "._domainkey.";

    private final Map<String, TXTRecord> records = new HashMap<String, TXTRecord>();

    // When building a TXTRecord from a (list of) string, the code expects the
    // escaped value.
    private String escapeString(String s) {
        // Get given string as bytes, and escape where needed to build back an
        // escaped version of the original value.
        // Do as dnsjava which uses the default charset.
        // The nominal code that does escape codepoints above 0x7F will prevent any
        // issue with UTF-8 characters if it is ever used.
        byte[] bytes = s.getBytes();
        StringBuilder builder = new StringBuilder();
        for (byte b: bytes) {
            if ((b < 0x20) || (b >= 0x7F)) {
                builder.append(String.format("\\%03d", b));
            } else {
                if ((b == '"') || (b == '\\')) {
                    builder.append('\\');
                }
                builder.append((char) b);
            }
        }
        return builder.toString();
    }

    public MockResolver addRecord(String selector, String token, String... record) throws TextParseException {
        // Note: absolute name (ending with '.') is required for DNS entries
        // and queries.
        String key = selector + _DOMAINKEY + token + ".";
        List<String> value = new LinkedList<String>();
        for (String s: record) {
            value.add(escapeString(s));
        }
        TXTRecord txt = new TXTRecord(new Name(key), DClass.IN, 3600, value);
        records.put(key, txt);
        return this;
    }

    public MockResolver clear() {
        // Clear our entries.
        records.clear();
        // Clear Lookup cache.
        Lookup.getDefaultCache(DClass.IN).clearCache();
        return this;
    }

    @Override
    public Message send(Message query) {
        Record q = query.getQuestion();
        Message m = new Message();
        // Original question must be present for the response to be correct.
        m.addRecord(q, Section.QUESTION);
        if (q.getType() == Type.TXT) {
            TXTRecord record = records.get(q.getName().toString());
            if (record != null) m.addRecord(record, Section.ANSWER);
        }
        return m;
    }

    @Override
    public Object sendAsync(Message query, ResolverListener listener) {
        // Do the same than in 'send', except we need to notify the listener by
        // passing the object we return (use the actual answer since it's easier).
        Message m = send(query);
        listener.receiveMessage(m, m);
        return m;
    }

    // Do nothing for methods we don't care about.

    @Override
    public void setPort(int i) {
    }

    @Override
    public void setTCP(boolean b) {
    }

    @Override
    public void setIgnoreTruncation(boolean b) {
    }

    @Override
    public void setEDNS(int i) {
    }

    @Override
    public void setEDNS(int i, int i1, int i2, List list) {
    }

    @Override
    public void setTSIGKey(TSIG tsig) {
    }

    @Override
    public void setTimeout(int i, int i1) {
    }

    @Override
    public void setTimeout(int i) {
    }

}
