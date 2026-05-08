"""
Zero Trust Device Health Check - Lambda Authorizer
===================================================
This function serves dual purpose:
  1. Standalone invocation - returns JSON decision
  2. API Gateway Lambda Authorizer - returns IAM policy

Author: Chukwuemeka Oko
Project: aws-three-tier-terraform-deploy - Zero Trust Identity Pivot
"""

import json
import base64
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Handles both direct invocation and API Gateway authorizer requests.
    API Gateway authorizer events contain a methodArn field.
    """
    logger.info("Event received: %s", json.dumps(event))

    # Detect if called as API Gateway authorizer
    if "methodArn" in event:
        return handle_api_gateway_authorizer(event, context)
    else:
        return handle_direct_invocation(event, context)


def handle_api_gateway_authorizer(event, context):
    """
    Handles API Gateway Lambda authorizer requests.
    Reads device posture from X-Device-Posture header.
    Returns IAM policy allowing or denying access.
    """
    method_arn = event.get("methodArn", "")

    # Extract device posture from header
    headers = event.get("headers", {}) or {}
    posture_header = headers.get("X-Device-Posture", "") or headers.get("x-device-posture", "")

    if not posture_header:
        logger.warning("No X-Device-Posture header found - denying access")
        return generate_policy("anonymous", "Deny", method_arn, {
            "reason": "Missing X-Device-Posture header"
        })

    # Decode base64 posture data
    try:
        posture_json = base64.b64decode(posture_header).decode("utf-8")
        posture_data = json.loads(posture_json)
    except Exception as e:
        logger.error("Failed to decode posture header: %s", str(e))
        return generate_policy("anonymous", "Deny", method_arn, {
            "reason": "Invalid X-Device-Posture header format"
        })

    user_email = posture_data.get("user_email", "unknown")
    device_id  = posture_data.get("device_id", "unknown")
    posture    = posture_data.get("posture", {})

    # Run device health checks
    result = run_health_checks(user_email, device_id, posture)

    if result["statusCode"] == 200:
        logger.info("ACCESS_GRANTED user=%s device=%s", user_email, device_id)
        return generate_policy(user_email, "Allow", method_arn, {
            "user_email": user_email,
            "decision": "ALLOW",
            "checks_passed": "disk_encryption,hardware_mfa"
        })
    else:
        logger.warning(
            "ACCESS_DENIED user=%s device=%s reason=%s",
            user_email, device_id, result.get("error_code")
        )
        return generate_policy(user_email, "Deny", method_arn, {
            "user_email": user_email,
            "decision": "DENY",
            "error_code": result.get("error_code"),
            "reason": result.get("reason")
        })


def handle_direct_invocation(event, context):
    """Handles direct Lambda invocations - returns JSON decision."""
    user_email = event.get("user_email", "").strip().lower()
    device_id  = event.get("device_id", "").strip()
    posture    = event.get("posture", {})

    if not user_email:
        return deny_access("unknown", device_id, "Missing user_email", "MISSING_IDENTITY")
    if not device_id:
        return deny_access(user_email, "unknown", "Missing device_id", "MISSING_DEVICE_ID")
    if not posture:
        return deny_access(user_email, device_id, "Missing posture data", "MISSING_POSTURE_DATA")

    return run_health_checks(user_email, device_id, posture)


def run_health_checks(user_email, device_id, posture):
    """Runs all device health checks and returns decision."""

    # Check 1 - Disk Encryption
    if not posture.get("disk_encrypted", False):
        logger.warning("DEVICE_CHECK_FAILED disk_encryption user=%s device=%s", user_email, device_id)
        return deny_access(
            user_email, device_id,
            "Device does not have disk encryption enabled. "
            "Enable BitLocker (Windows), FileVault (Mac), or LUKS (Linux) "
            "before accessing banking infrastructure.",
            "DISK_ENCRYPTION_REQUIRED"
        )

    logger.info("DEVICE_CHECK_PASSED disk_encryption user=%s device=%s", user_email, device_id)

    # Check 2 - Hardware MFA
    if not posture.get("hardware_mfa_registered", False):
        logger.warning("DEVICE_CHECK_FAILED hardware_mfa user=%s device=%s", user_email, device_id)
        return deny_access(
            user_email, device_id,
            "No hardware MFA token registered. "
            "Register a FIDO2 hardware token (YubiKey or Google Titan Key). "
            "Software authenticator apps are not accepted.",
            "HARDWARE_MFA_REQUIRED"
        )

    logger.info("DEVICE_CHECK_PASSED hardware_mfa user=%s device=%s", user_email, device_id)
    logger.info("ACCESS_GRANTED all_checks_passed user=%s device=%s", user_email, device_id)

    return allow_access(user_email, device_id, posture)


def generate_policy(principal_id, effect, method_arn, context=None):
    """Generates an IAM policy document for API Gateway."""
    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": method_arn
            }]
        }
    }
    if context:
        policy["context"] = context
    logger.info("Generated %s policy for principal=%s", effect, principal_id)
    return policy


def allow_access(user_email, device_id, posture):
    """Returns 200 approval response."""
    return {
        "statusCode": 200,
        "decision": "ALLOW",
        "user_email": user_email,
        "device_id": device_id,
        "checks_passed": ["disk_encryption", "hardware_mfa_registered"],
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
    """Returns 403 denial response."""
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