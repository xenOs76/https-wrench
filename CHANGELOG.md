## 0.9.0 (2026-03-21)

### Feat

    Added a jwtinfo CLI command to request, decode, optionally validate, and display JWT details.

### Tests

    Added comprehensive JWT test suite, in-process HTTPS test server, and test data/assets.

### Chores / CI

    Added dev/test scripts and dev env updates; CI jobs reduced and coverage check relaxed on non-main branches.

### Dependencies

    Bumped multiple dependencies and added JWT/JWK libraries.

## 0.8.6 (2025-11-21)

## 0.8.5 (2025-11-17)

### Fix

- **certinfo**: cert and ca file paths display (#6)

## 0.8.4 (2025-11-15)

### Refactor

- HandleRequests function and create processHTTPRequestsByHost (#4)

## 0.8.3 (2025-11-08)

## 0.8.2 (2025-10-17)

### Refactor

- GetKeyFromFile

## 0.8.1 (2025-10-17)

### Refactor

- lint certinfo
- lint cmd
- update rel path to Json schema for test-configs files
- move Certinfo and Requests to internal, move code from src to upper level

## 0.8.0 (2025-10-07)

### Feat

- improve details in Certificate view
- exclude system CA pool when using custom CA Bundle

### Refactor

- remove time globals
- unexport structs
- error format, error variable shadowing
- multiplication of durations
- var naming, unused var
- line length
- deep exit
- unexport error vars
- deep exit
- deep exit
- unecessary conversion
- var naming

## 0.7.0 (2025-09-27)

### Feat

- **certinfo**: read encrypted private keys

## 0.6.0 (2025-09-25)

### Feat

- **certinfo**: add labels to PrintData function
- **requests**: add syntax highlight to response body display

### Fix

- error strings

### Refactor

- **certinfo**: CertsToTable improve readability and add color coded warning on
  cert expiration

## 0.5.0 (2025-09-21)

### Feat

- add certinfo command

## 0.4.0 (2025-09-13)

### Feat

- add responseBodyMatchRegexp option

## 0.3.0 (2025-09-08)

### Feat

- add insecure option

### Fix

- typo in proxyProtoHeaderFromRequest

## 0.2.0 (2025-09-07)

### Feat

- add enableProxyProtocolV2 to request options

## 0.1.0 (2025-09-06)

### Feat

- **json-schema**: add caBundle option to Json schema
- add caBundle option to Yaml configuration

## 0.0.4 (2025-08-29)

## 0.0.3 (2025-08-28)

## 0.0.2 (2025-08-26)

## 0.0.1 (2025-08-16)
