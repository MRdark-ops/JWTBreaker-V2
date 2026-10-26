package com.jwtbreaker;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * JWTBreaker - Burp Suite extension for inspecting and attacking JSON Web Tokens.
 *
 * Auto-detects JWTs in outgoing requests (Authorization header / session cookie),
 * decodes them, and exposes attack tooling in a dedicated suite tab.
 */
public class JwtBreakerExtension implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("JWTBreaker");
        api.extension().registerUnloadingHandler(this);

        JwtBreakerPanel panel = new JwtBreakerPanel(api);
        api.userInterface().registerSuiteTab("JWTBreaker", panel);

        api.http().registerHttpHandler(new JwtHttpHandler(api, panel));

        api.logging().logToOutput("JWTBreaker Loaded");
    }

    @Override
    public void extensionUnloaded() {
        if (api != null) {
            api.logging().logToOutput("JWTBreaker unloaded");
        }
    }
}
