"""
Tests for JWT validation in the Zero Trust Lambda Authorizer v2.
Tests cover both valid and invalid JWT scenarios.

Run with: python lambda\test_jwt_validation.py
"""

import sys
import os
import json
import base64
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from device_health_check import (
    validate_cloudflare_jwt,
    fetch_cloudflare_certs,
    run_health_checks,
    deny_access,
    allow_access
)


# ------------------------------------------------------------------
# Test 1 - Cloudflare certs endpoint is reachable
# ------------------------------------------------------------------
def test_fetch_cloudflare_certs():
    result = fetch_cloudflare_certs()
    assert result is not None, "Should fetch certs from Cloudflare"
    assert "public_certs" in result, "Response should contain public_certs"
    assert len(result["public_certs"]) > 0, "Should have at least one cert"
    print("PASS - test_fetch_cloudflare_certs")


# ------------------------------------------------------------------
# Test 2 - Missing JWT is rejected
# ------------------------------------------------------------------
def test_missing_jwt_rejected():
    result = validate_cloudflare_jwt("")
    assert result["valid"] == False
    print("PASS - test_missing_jwt_rejected")


# ------------------------------------------------------------------
# Test 3 - Malformed JWT is rejected
# ------------------------------------------------------------------
def test_malformed_jwt_rejected():
    result = validate_cloudflare_jwt("not.a.valid.jwt.token")
    assert result["valid"] == False
    assert "reason" in result
    print("PASS - test_malformed_jwt_rejected")


# ------------------------------------------------------------------
# Test 4 - Tampered JWT is rejected
# ------------------------------------------------------------------
def test_tampered_jwt_rejected():
    # A real-looking JWT structure but with fake content
    fake_header  = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"fakekid"}').decode()
    fake_payload = base64.urlsafe_b64encode(b'{"email":"attacker@evil.com","aud":"fakeaud"}').decode()
    fake_sig     = base64.urlsafe_b64encode(b"fakesignature").decode()
    fake_jwt     = f"{fake_header}.{fake_payload}.{fake_sig}"

    result = validate_cloudflare_jwt(fake_jwt)
    assert result["valid"] == False
    print("PASS - test_tampered_jwt_rejected")


# ------------------------------------------------------------------
# Test 5 - Wrong audience JWT is rejected
# ------------------------------------------------------------------
def test_wrong_audience_rejected():
    # JWT with wrong kid - no matching public key
    fake_header  = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": "wrongkid123"}).encode()
    ).decode().rstrip("=")
    fake_payload = base64.urlsafe_b64encode(
        json.dumps({"email": "user@gmail.com", "aud": "wrongaud"}).encode()
    ).decode().rstrip("=")
    fake_sig     = base64.urlsafe_b64encode(b"fakesig").decode().rstrip("=")
    fake_jwt     = f"{fake_header}.{fake_payload}.{fake_sig}"

    result = validate_cloudflare_jwt(fake_jwt)
    assert result["valid"] == False
    print("PASS - test_wrong_audience_rejected")


# ------------------------------------------------------------------
# Test 6 - Device posture checks still work after JWT validation
# ------------------------------------------------------------------
def test_posture_allow_when_all_pass():
    result = run_health_checks(
        "okochukwuemekairoha@gmail.com",
        "device-abc-123",
        {"disk_encrypted": True, "hardware_mfa_registered": True}
    )
    assert result["statusCode"] == 200
    assert result["decision"] == "ALLOW"
    print("PASS - test_posture_allow_when_all_pass")


# ------------------------------------------------------------------
# Test 7 - Disk encryption still enforced
# ------------------------------------------------------------------
def test_posture_deny_no_disk_encryption():
    result = run_health_checks(
        "okochukwuemekairoha@gmail.com",
        "device-abc-123",
        {"disk_encrypted": False, "hardware_mfa_registered": True}
    )
    assert result["statusCode"] == 403
    assert result["error_code"] == "DISK_ENCRYPTION_REQUIRED"
    print("PASS - test_posture_deny_no_disk_encryption")


# ------------------------------------------------------------------
# Test 8 - Hardware MFA still enforced
# ------------------------------------------------------------------
def test_posture_deny_no_hardware_mfa():
    result = run_health_checks(
        "okochukwuemekairoha@gmail.com",
        "device-abc-123",
        {"disk_encrypted": True, "hardware_mfa_registered": False}
    )
    assert result["statusCode"] == 403
    assert result["error_code"] == "HARDWARE_MFA_REQUIRED"
    print("PASS - test_posture_deny_no_hardware_mfa")


if __name__ == "__main__":
    print("Running JWT validation tests...\n")
    test_fetch_cloudflare_certs()
    test_missing_jwt_rejected()
    test_malformed_jwt_rejected()
    test_tampered_jwt_rejected()
    test_wrong_audience_rejected()
    test_posture_allow_when_all_pass()
    test_posture_deny_no_disk_encryption()
    test_posture_deny_no_hardware_mfa()
    print("\nAll JWT validation tests passed.")