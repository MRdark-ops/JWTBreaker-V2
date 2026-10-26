# JWTBreaker - Burp Suite Security Extension

A Burp Suite extension that auto-detects JSON Web Tokens in traffic, decodes them,
and runs common JWT attack checks from a dedicated tab.

## Stack

- Java 17 (compiled with `--release 17`)
- Burp Suite Montoya API (`net.portswigger.burp.extensions:montoya-api`)
- JWT / crypto: `javax.crypto` (HMAC-SHA256), `io.jsonwebtoken` (jjwt), Jackson
- Build: Gradle (with the GradleUp Shadow plugin for the fat jar)

## What it does

- Auto-detects JWTs in every request (Authorization header or `session=` cookie),
  decodes the header and payload, and lists them in the JWTBreaker tab.
- Runs three attack checks on the selected token: `alg:none` token generation,
  weak-secret brute-force (HMAC-SHA256 against a 140-entry wordlist), and expiry
  inspection. Results are colored red (vulnerable) or green (secure).
- One-click workflow: generate an `alg:none` token and send the modified request
  straight to Burp Repeater, or copy the token to the clipboard.

## Build

```bash
./gradlew shadowJar
```

Output: `build/libs/JWTBreaker-all.jar` (self-contained fat jar).

## How to install

1. Open Burp Suite (Community or Pro).
2. Go to **Extensions > Installed > Add**.
3. Extension type: **Java**.
4. Select the jar: `build/libs/JWTBreaker-all.jar`.
5. Confirm the Output log shows `JWTBreaker Loaded`. A **JWTBreaker** tab appears.

## How to use

1. Proxy some traffic that carries a JWT (Authorization header or `session=` cookie).
2. Open the **JWTBreaker** tab. Detected tokens appear in the top table.
3. Select a row to see the decoded header, payload, and signature.
4. Click any of the three buttons:
   - **Test alg:none** - builds an unsigned `alg:none` variant of the token.
   - **Brute-force Weak Secret** - tries the bundled wordlist to crack the HMAC key.
   - **Check Expiry** - reports whether the token is expired, valid, or never expires.
5. After generating an `alg:none` token, click **Send to Repeater** to replay the
   request with the forged token, or **Copy Token** to grab it.

## How to test on PortSwigger Labs

- **JWT authentication bypass via weak signing key** - capture the session JWT,
  run **Brute-force Weak Secret** to recover the key, then forge an admin token.
- **JWT authentication bypass via flawed signature verification (alg: none)** -
  capture the JWT, run **Test alg:none**, then **Send to Repeater** and change the
  user claim to `administrator`.

(Lab: Web Security Academy > JWT attacks.)

## Legal disclaimer

For educational use only, on systems and labs you are explicitly authorized to
test. Do not use this extension against any system without permission. The authors
accept no liability for misuse.
