"""
Zero Trust Device Health Check - Lambda Function
=================================================
Enforces device posture requirements before granting access
to the banking API. Two mandatory checks:

  1. Disk encryption must be enabled (BitLocker/FileVault/LUKS)
  2. Hardware MFA token must be registered (FIDO2/YubiKey)

In production this function is configured as an AWS API Gateway
Lambda Authorizer, invoked before every request reaches the
banking API. Device posture data comes from Cloudflare Access
JWT claims or an endpoint agent (CrowdStrike, Jamf, Intune).

Author: Chukwuemeka Oko
Project: aws-three-tier-terraform-deploy - Zero Trust Identity Pivot
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Main Lambda entry point.

    Expected event payload:
    {
        "user_email": "developer@gmail.com",
        "device_id": "device-uuid-here",
        "posture": {
            "disk_encrypted": true,
            "hardware_mfa_registered": true,
            "os_version": "Windows 11",
            "last_seen": "2026-05-08T00:00:00Z"
        }
    }
    """
    logger.info("Device health check invoked: %s", json.dumps(event))

    # ------------------------------------------------------------------
    # Step 1 - Extract and validate request payload
    # ------------------------------------------------------------------
    user_email = event.get("user_email", "").strip().lower()
    device_id  = event.get("device_id", "").strip()
    posture    = event.get("posture", {})

    if not user_email:
        return deny_access(
            user_email="unknown",
            device_id=device_id,
            reason="Missing user_email in request payload",
            code="MISSING_IDENTITY"
        )

    if not device_id:
        return deny_access(
            user_email=user_email,
            device_id="unknown",
            reason="Missing device_id in request payload",
            code="MISSING_DEVICE_ID"
        )

    if not posture:
        return deny_access(
            user_email=user_email,
            device_id=device_id,
            reason="Missing posture data - endpoint agent may not be installed",
            code="MISSING_POSTURE_DATA"
        )

    # ------------------------------------------------------------------
    # Step 2 - Check 1: Disk Encryption
    #
    # Mandatory for PCI-DSS and NDPR compliance.
    # Accepted: BitLocker (Windows), FileVault (Mac), LUKS (Linux)
    # If disk_encrypted is absent or false, access is denied.
    # ------------------------------------------------------------------
    disk_encrypted = posture.get("disk_encrypted", False)

    if not disk_encrypted:
        logger.warning(
            "DEVICE_CHECK_FAILED disk_encryption user=%s device=%s",
            user_email, device_id
        )
        return deny_access(
            user_email=user_email,
            device_id=device_id,
            reason=(
                "Device does not have disk encryption enabled. "
                "Enable BitLocker (Windows), FileVault (Mac), or LUKS (Linux) "
                "before accessing banking infrastructure."
            ),
            code="DISK_ENCRYPTION_REQUIRED"
        )

    logger.info(
        "DEVICE_CHECK_PASSED disk_encryption user=%s device=%s",
        user_email, device_id
    )

    # ------------------------------------------------------------------
    # Step 3 - Check 2: Hardware MFA Token
    #
    # Software TOTP apps (Google Authenticator, Authy) are NOT accepted.
    # Only FIDO2 hardware tokens (YubiKey, Titan Key) are accepted.
    # This check verifies the token is registered, not just that MFA
    # is enabled - a critical distinction for high-security environments.
    # ------------------------------------------------------------------
    hardware_mfa_registered = posture.get("hardware_mfa_registered", False)

    if not hardware_mfa_registered:
        logger.warning(
            "DEVICE_CHECK_FAILED hardware_mfa user=%s device=%s",
            user_email, device_id
        )
        return deny_access(
            user_email=user_email,
            device_id=device_id,
            reason=(
                "No hardware MFA token registered for this user. "
                "Register a FIDO2 hardware token (YubiKey or Google Titan Key) "
                "at your identity provider. Software authenticator apps are not "
                "accepted for banking infrastructure access."
            ),
            code="HARDWARE_MFA_REQUIRED"
        )

    logger.info(
        "DEVICE_CHECK_PASSED hardware_mfa user=%s device=%s",
        user_email, device_id
    )

    # ------------------------------------------------------------------
    # Step 4 - All checks passed - approve access
    # ------------------------------------------------------------------
    logger.info(
        "ACCESS_GRANTED all_checks_passed user=%s device=%s",
        user_email, device_id
    )

    return allow_access(
        user_email=user_email,
        device_id=device_id,
        posture=posture
    )


# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

def allow_access(user_email, device_id, posture):
    """Return 200 approval with full posture summary."""
    return {
        "statusCode": 200,
        "decision": "ALLOW",
        "user_email": user_email,
        "device_id": device_id,
        "checks_passed": [
            "disk_encryption",
            "hardware_mfa_registered"
        ],
        "posture_summary": {
            "disk_encrypted":          posture.get("disk_encrypted"),
            "hardware_mfa_registered": posture.get("hardware_mfa_registered"),
            "os_version":              posture.get("os_version", "unknown"),
            "last_seen":               posture.get("last_seen", "unknown")
        },
        "message": (
            f"Access granted for {user_email}. "
            "Device posture verified: disk encryption enabled, "
            "hardware MFA token registered."
        )
    }


def deny_access(user_email, device_id, reason, code):
    """Return 403 denial with specific reason and remediation guidance."""
    return {
        "statusCode": 403,
        "decision": "DENY",
        "user_email": user_email,
        "device_id": device_id,
        "error_code": code,
        "reason": reason,
        "message": (
            f"Access denied for {user_email}. "
            f"Device posture check failed: {code}. "
            "Contact your security team if you believe this is an error."
        )
    }