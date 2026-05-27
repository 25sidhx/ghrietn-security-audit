# 🔐 GHRIETN Security Audit

**Critical vulnerabilities found in the G H Raisoni Institute of Engineering & Technology student portal.**

---

## ⚠️ Executive Summary

The GHRIETN student portal (`ghrietn.cybervidya.net`) contains **multiple critical security vulnerabilities**:

1. **Hardcoded encryption keys** - AES-256-CBC keys exposed in public JS bundle
2. **Missing security headers** - F grade on SecurityHeaders.com
3. **CORS misconfiguration** - `Access-Control-Allow-Origin: *` on auth endpoints
4. **Information disclosure** - Internal IPs, emails hardcoded in frontend

**Overall Risk:** 🔴 **CRITICAL**

---

## 📁 Repository Structure

```
ghrietn-security-audit/
├── README.md                    # This file
├── SECURITY_REPORT.md           # Full audit report (456 lines)
├── poc/
│   ├── encrypt_exploit.py       # Encryption PoC
│   └── console_demo.js          # Browser console demo
├── evidence/
│   ├── headers.txt              # Missing headers proof
│   ├── cors_test.txt            # CORS misconfiguration
│   └── extracted_keys.txt       # Hardcoded keys evidence
└── remediation/
    └── nginx_config.patch       # Fix configurations
```

---

## 🚀 Quick Start

### Run the Encryption PoC

```bash
cd poc
python3 encrypt_exploit.py
```

This demonstrates how anyone can encrypt credentials using the exposed keys.

### Browser Console Demo

Paste this into the browser console on `ghrietn.cybervidya.net`:

```javascript
// Search for hardcoded keys in the bundle
const keyMatch = document.documentElement.innerHTML.match(/cipherkey\s*[:=]\s*"([^"]+)"/);
const ivMatch = document.documentElement.innerHTML.match(/cipheriv\s*[:=]\s*"([^"]+)"/);
console.log('Key:', keyMatch[1]);
console.log('IV:', ivMatch[1]);
```

---

## 📊 Vulnerability Summary

| Finding | Severity | CVSS | Status |
|---------|----------|------|--------|
| Hardcoded Encryption Keys | Critical | 8.1 | ✅ Verified |
| Missing Security Headers | High | 7.4 | ✅ Verified |
| CORS Misconfiguration | High | 7.4 | ✅ Verified |
| Information Disclosure | High | 7.5 | ✅ Verified |
| No Rate Limiting | Medium | 5.3 | ✅ Verified |

---

## 📋 Full Report

See [`SECURITY_REPORT.md`](./SECURITY_REPORT.md) for complete findings, evidence, and remediation steps.

---

## 🛠️ Remediation

### Immediate Actions (24-48 hours)

1. Remove client-side encryption from login flow
2. Add security headers to nginx configuration
3. Restrict CORS to `https://ghrietn.cybervidya.net` only
4. Hide server version with `server_tokens off`

### This Week

1. Implement rate limiting on `/api/auth/*` endpoints
2. Remove internal IPs and emails from frontend code
3. Rotate reCAPTCHA site key

See [`remediation/nginx_config.patch`](./remediation/nginx_config.patch) for ready-to-apply fixes.

---

## 📞 Disclosure

**Researcher:** Siddhant (ETC Student)  
**Institution:** G H Raisoni Institute of Engineering & Technology, Nagpur  
**Date:** May 27, 2026

**Responsible Disclosure Timeline:**
- May 27, 2026: Vulnerabilities discovered
- May 28, 2026: Report submitted to college IT
- Target Fix Date: June 3, 2026 (7 days)

---

## 📚 Methodology

This audit follows:
- OWASP Web Security Testing Guide (WSTG) v4.2
- OWASP API Security Top 10 (2023)
- CVSS v3.1 scoring

**Tools Used:**
- `curl` - HTTP request testing
- `ripgrep` - Source code analysis
- `python3 + pycryptodome` - Encryption validation
- Browser DevTools - Frontend inspection

---

*This assessment was conducted as an educational cybersecurity demonstration to improve institutional security posture.*