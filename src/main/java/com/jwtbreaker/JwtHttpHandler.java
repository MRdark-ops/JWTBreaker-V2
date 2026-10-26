package com.jwtbreaker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;

/**
 * Inspects every outgoing request, extracts JWTs from the Authorization header
 * or a "session=" cookie, and feeds them to the UI panel.
 */
public class JwtHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final JwtBreakerPanel panel;

    public JwtHttpHandler(MontoyaApi api, JwtBreakerPanel panel) {
        this.api = api;
        this.panel = panel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            inspect(request);
        } catch (Exception e) {
            api.logging().logToError("JWTBreaker inspection error: " + e.getMessage());
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }

    private void inspect(HttpRequestToBeSent request) {
        String host = request.httpService() != null ? request.httpService().host() : "";
        String method = request.method();
        String path = request.path();

        for (HttpHeader header : request.headers()) {
            String name = header.name();
            String value = header.value();

            if ("Authorization".equalsIgnoreCase(name)) {
                String token = JwtUtils.extractJwt(value);
                if (token != null) {
                    panel.addEntry(new JwtEntry(token, host, method, path, "Authorization", request));
                }
            } else if ("Cookie".equalsIgnoreCase(name)) {
                String token = extractSessionCookieJwt(value);
                if (token != null) {
                    panel.addEntry(new JwtEntry(token, host, method, path, "Cookie: session", request));
                }
            }
        }
    }

    /** Looks for session=<jwt> inside a Cookie header value. */
    private String extractSessionCookieJwt(String cookieValue) {
        for (String part : cookieValue.split(";")) {
            String trimmed = part.trim();
            if (trimmed.regionMatches(true, 0, "session=", 0, "session=".length())) {
                String candidate = trimmed.substring("session=".length());
                if (JwtUtils.isJwt(candidate)) {
                    return candidate;
                }
            }
        }
        return null;
    }
}
