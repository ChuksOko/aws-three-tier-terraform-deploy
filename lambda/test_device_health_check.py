"""
Unit tests for the Zero Trust Device Health Check Lambda function.
Run with: python -m pytest lambda/test_device_health_check.py -v
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from device_health_check import lambda_handler


# ------------------------------------------------------------------
# Test 1 - Happy path: all checks pass
# ------------------------------------------------------------------
def test_access_granted_when_all_checks_pass():
    event = {
        "user_email": "developer@gmail.com",
        "device_id": "device-abc-123",
        "posture": {
            "disk_encrypted": True,
            "hardware_mfa_registered": True,
            "os_version": "Windows 11",
            "last_seen": "2026-05-08T00:00:00Z"
        }
    }
    result = lambda_handler(event, {})
    assert result["statusCode"] == 200
    assert result["decision"] == "ALLOW"
    assert "disk_encryption" in result["checks_passed"]
    assert "hardware_mfa_registered" in result["checks_passed"]
    print("PASS - test_access_granted_when_all_checks_pass")


# ------------------------------------------------------------------
# Test 2 - Disk encryption missing
# ------------------------------------------------------------------
def test_deny_when_disk_not_encrypted():
    event = {
        "user_email": "developer@gmail.com",
        "device_id": "device-abc-123",
        "posture": {
            "disk_encrypted": False,
            "hardware_mfa_registered": True
        }
    }
    result = lambda_handler(event, {})
    assert result["statusCode"] == 403
    assert result["decision"] == "DENY"
    assert result["error_code"] == "DISK_ENCRYPTION_REQUIRED"
    print("PASS - test_deny_when_disk_not_encrypted")


# ------------------------------------------------------------------
# Test 3 - Hardware MFA not registered
# ------------------------------------------------------------------
def test_deny_when_hardware_mfa_missing():
    event = {
        "user_email": "developer@gmail.com",
        "device_id": "device-abc-123",
        "posture": {
            "disk_encrypted": True,
            "hardware_mfa_registered": False
        }
    }
    result = lambda_handler(event, {})
    assert result["statusCode"] == 403
    assert result["decision"] == "DENY"
    assert result["error_code"] == "HARDWARE_MFA_REQUIRED"
    print("PASS - test_deny_when_hardware_mfa_missing")


# ------------------------------------------------------------------
# Test 4 - Both checks fail (disk checked first)
# ------------------------------------------------------------------
def test_deny_when_both_checks_fail():
    event = {
        "user_email": "developer@gmail.com",
        "device_id": "device-abc-123",
        "posture": {
            "disk_encrypted": False,
            "hardware_mfa_registered": False
        }
    }
    result = lambda_handler(event, {})
    assert result["statusCode"] == 403
    assert result["decision"] == "DENY"
    assert result["error_code"] == "DISK_ENCRYPTION_REQUIRED"
    print("PASS - test_deny_when_both_checks_fail")


# ------------------------------------------------------------------
# Test 5 - Missing email
# ------------------------------------------------------------------
def test_deny_when_email_missing():
    event = {
        "device_id": "device-abc-123",
        "posture": {
            "disk_encrypted": True,
            "hardware_mfa_registered": True
        }
    }
    result = lambda_handler(event, {})
    assert result["statusCode"] == 403
    assert result["error_code"] == "MISSING_IDENTITY"
    print("PASS - test_deny_when_email_missing")


# ------------------------------------------------------------------
# Test 6 - Missing posture data
# ------------------------------------------------------------------
def test_deny_when_posture_missing():
    event = {
        "user_email": "developer@gmail.com",
        "device_id": "device-abc-123"
    }
    result = lambda_handler(event, {})
    assert result["statusCode"] == 403
    assert result["error_code"] == "MISSING_POSTURE_DATA"
    print("PASS - test_deny_when_posture_missing")


if __name__ == "__main__":
    test_access_granted_when_all_checks_pass()
    test_deny_when_disk_not_encrypted()
    test_deny_when_hardware_mfa_missing()
    test_deny_when_both_checks_fail()
    test_deny_when_email_missing()
    test_deny_when_posture_missing()
    print("\nAll tests passed.")