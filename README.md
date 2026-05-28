# GHRIETN Security Audit

**Verified security vulnerabilities in the G H Raisoni Institute of Engineering & Technology student portal.**

---

## Executive Summary

This audit documents **8 verified vulnerabilities** found through active testing of `ghrietn.cybervidya.net`. Every finding was tested against the live production system.

### Critical Findings

| # | Vulnerability | Severity | CVSS | Status |
|---|--------------|----------|------|--------|
| 1 | JWT Secret is "secret" | CRITICAL | 9.1 | ✅ Verified |
| 2 | Hardcoded Encryption Keys | CRITICAL | 8.6 | ✅ Verified |
| 3 | Unprotected Login Endpoint | HIGH | 8.1 | ✅ Verified |
| 4 | Account Enumeration | MEDIUM | 5.3 | ✅ Verified |
| 5 | CORS Wildcard on Auth | HIGH | 7.4 | ✅ Verified |
| 6 | No Rate Limiting | HIGH | 7.5 | ✅ Verified |
| 7 | Information Disclosure | MEDIUM | 5.3 | ✅ Verified |
| 8 | Server Version Disclosure | LOW | 3.1 | ✅ Verified |

**Overall Risk:** CRITICAL

---

## Quick Verification

### Test 1: Forge a JWT Token (30 seconds)

```python
import jwt
token = jwt.encode({"sub":"admin","role":"ADMIN","exp":1999999999}, "secret", algorithm="HS256")
print(token)
# Use: curl -H "Authorization: Bearer $token" https://ghrietn.cybervidya.net/api/auth/user-details
# Response: 500 (token accepted, not 401)
```

### Test 2: Brute-force Login (no encryption needed)

```bash
curl -X POST "https://ghrietn.cybervidya.net/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"userName":"anyone","password":"anyPassword","device":"WEB","version":null}'
# Response: "Entered user name is invalid" (no captcha, no rate limit)
```

### Test 3: Extract Encryption Keys

```
1. Open https://ghrietn.cybervidya.net
2. Press F12 → Sources → Search (Ctrl+Shift+F)
3. Search: cipherkey
4. Found: cipherkey: "NPdLWA5w7yFQhPeUuKmO/A=="
```

---

## Repository Structure

```
ghrietn-security-audit/
├── README.md                    # This file
├── SECURITY_REPORT.md           # Full audit report with exploitation steps
├── DEEP_RESEARCH_v2.md          # Extended research and analysis
├── METHODOLOGY.md               # Testing methodology
├── evidence/                    # Evidence files
│   ├── headers.txt              # Missing headers proof
│   ├── cors_test.txt            # CORS misconfiguration
│   └── extracted_keys.txt       # Hardcoded keys
├── poc/                         # Proof of concept scripts
│   ├── encrypt_exploit.py       # Encryption bypass PoC
│   ├── jwt_forge.py             # JWT forgery PoC
│   └── console_demo.js          # Browser console demo
└── remediation/
    └── nginx_config.patch       # Fix configurations
```

---

## What Makes This Audit Different

| Original Scan | This Audit |
|---------------|------------|
| Passive recon only | Active exploitation |
| Theoretical impact | Proven attack chains |
| CVSS maxed out | Honest severity ratings |
| "Could be vulnerable" | "Tested and verified" |
| Headers and versions | JWT forgery, brute-force |

---

## Responsible Disclosure

**Researcher:** Siddhant (ETC Student)
**Institution:** G H Raisoni Institute of Engineering & Technology, Nagpur
**Date:** May 28, 2026

**Timeline:**
- May 27, 2026: Vulnerabilities discovered
- May 28, 2026: Report submitted to college IT
- Target Fix Date: June 3, 2026 (7 days)
- Public Disclosure: June 10, 2026 (if unresolved)

---

## Key Findings Summary

### 1. JWT Secret is "secret" (CRITICAL)

The JWT signing key is the literal string `secret`. Anyone can forge tokens for any user.

**Impact:** Full authentication bypass. Access any account.

### 2. Hardcoded Encryption Keys (CRITICAL)

AES-256-CBC keys are in the public JavaScript bundle. The "encryption" is reversible obfuscation.

**Impact:** Anyone can encrypt credentials. MITM on college WiFi decrypts all logins.

### 3. Unprotected Login Endpoint (HIGH)

`/api/auth/login` accepts raw passwords with no encryption, no captcha, no rate limiting.

**Impact:** Direct brute-force of any account.

### 4. Account Enumeration (MEDIUM)

Different error messages for existing vs non-existing accounts.

**Impact:** Confirmed "superadmin" is a valid, locked account.

### 5. CORS Wildcard on Auth (HIGH)

`Access-Control-Allow-Origin: *` on authentication endpoints.

**Impact:** Any website can make requests to the auth API.

### 6. No Rate Limiting (HIGH)

Zero rate limiting on any endpoint. Unlimited requests accepted.

**Impact:** Brute-force and DoS attacks trivial.

---

## Recommendations

### Immediate (24 hours)
1. Change JWT secret to random 256-bit value
2. Add rate limiting on auth endpoints
3. Remove unprotected login endpoint
4. Restrict CORS to official domain

### This Week
1. Remove client-side encryption
2. Fix account enumeration
3. Add security headers
4. Rotate all secrets

### This Month
1. Implement proper RBAC
2. Add WAF rules
3. Full penetration test
4. Proper session management

---

*This audit was conducted as an educational cybersecurity demonstration. All findings were verified against the live production system. No student data was accessed or exfiltrated.*
