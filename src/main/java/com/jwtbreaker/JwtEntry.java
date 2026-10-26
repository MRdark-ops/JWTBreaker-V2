package com.jwtbreaker;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * One detected JWT and the request it came from.
 */
public class JwtEntry {

    private final String token;
    private final String host;
    private final String method;
    private final String path;
    private final String source; // "Authorization" or "Cookie: session"
    private final HttpRequest request;

    public JwtEntry(String token, String host, String method, String path,
                    String source, HttpRequest request) {
        this.token = token;
        this.host = host;
        this.method = method;
        this.path = path;
        this.source = source;
        this.request = request;
    }

    public String token() {
        return token;
    }

    public String host() {
        return host;
    }

    public String method() {
        return method;
    }

    public String path() {
        return path;
    }

    public String source() {
        return source;
    }

    public HttpRequest request() {
        return request;
    }
}
