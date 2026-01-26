# Security Report

**Status:** 300

**Risk Score:** 300

## Reasons for decision

- Hardcoded secret detected

## Findings

### [SECRET] JWT
 - **Source:** trufflehog
- **Severity:** critical
- **Confidence:** high
- **Message:** secret found
- **File:** test/api/userApiSpec.ts
- **Lines:** 302

### [SECRET] JWT
 - **Source:** trufflehog
- **Severity:** critical
- **Confidence:** high
- **Message:** secret found
- **File:** test/server/currentUserSpec.ts
- **Lines:** 33

### [SECRET] PrivateKey
 - **Source:** trufflehog
- **Severity:** critical
- **Confidence:** high
- **Message:** secret found
- **File:** lib/insecurity.ts
- **Lines:** 23
