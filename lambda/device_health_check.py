"""
Zero Trust Device Health Check - Lambda Authorizer with JWT Validation
======================================================================
Version 2.0 - Production-grade JWT validation added

Changes from v1:
  - Validates Cloudflare JWT signature before trusting any request
  - Fetches Cloudflare public keys dynamically from the certs endpoint
  - Extracts user identity from the verified JWT claims
  - Device posture still checked via X-Device-Posture header
  - A forged header with no valid JWT is now rejected at the JWT step

Flow:
  1. Read Cf-Access-Jwt-Assertion header
  2. Fetch Cloudflare public keys from certs endpoint
  3. Verify JWT signature using the correct public key (matched by kid)
  4. Validate JWT audience matches our application AUD tag
  5. Extract user email from verified JWT claims
  6. Run device posture checks (disk encryption + hardware MFA)
  7. Return Allow or Deny IAM policy

Author: Chukwuemeka Oko
Project: aws-three-tier-terraform-deploy - Zero Trust Identity Pivot v2
"""

import json
import base64
import logging
import urllib.request
import urllib.error

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Cloudflare Zero Trust configuration
CLOUDFLARE_TEAM_DOMAIN = "chuksoko.cloudflareaccess.com"
CLOUDFLARE_CERTS_URL   = f"https://{CLOUDFLARE_TEAM_DOMAIN}/cdn-cgi/access/certs"
CLOUDFLARE_AUD         = "0d90066fa1fefca330e64ffe10cd01e0b6b79cdd999ddbc05dff1bb1ccd4918c"


def lambda_handler(event, context):
    """
    Main Lambda entry point.
    Detects whether called as API Gateway authorizer or direct invocation.
    """
    logger.info("Event received: %s", json.dumps(event))

    if "methodArn" in event:
        return handle_api_gateway_authorizer(event, context)
    else:
        return handle_direct_invocation(event, context)


# ------------------------------------------------------------------
# API Gateway Authorizer Handler
# ------------------------------------------------------------------

def handle_api_gateway_authorizer(event, context):
    """
    Handles API Gateway Lambda authorizer requests.

    Step 1: Validate Cloudflare JWT
    Step 2: Run device posture checks
    Step 3: Return IAM policy
    """
    method_arn = event.get("methodArn", "")
    headers    = event.get("headers", {}) or {}

    # Normalise header keys to lowercase for consistent lookup
    headers = {k.lower(): v for k, v in headers.items()}

    # ------------------------------------------------------------------
    # Step 1 - Extract and validate the Cloudflare JWT
    # The JWT is in the Cf-Access-Jwt-Assertion header.
    # Cloudflare attaches this automatically to every authenticated request.
    # Without a valid JWT, any posture header is meaningless - reject immediately.
    # ------------------------------------------------------------------
    jwt_token = headers.get("cf-access-jwt-assertion", "")

    if not jwt_token:
        logger.warning("MISSING_JWT no Cf-Access-Jwt-Assertion header found")
        return generate_policy("anonymous", "Deny", method_arn, {
            "error_code": "MISSING_JWT",
            "reason": "Request did not originate through Cloudflare Access. Direct API access is not permitted."
        })

    jwt_result = validate_cloudflare_jwt(jwt_token)

    if not jwt_result["valid"]:
        logger.warning("INVALID_JWT reason=%s", jwt_result.get("reason"))
        return generate_policy("anonymous", "Deny", method_arn, {
            "error_code": "INVALID_JWT",
            "reason": jwt_result.get("reason", "JWT validation failed")
        })

    # JWT is valid - extract verified user identity
    user_email = jwt_result["claims"].get("email", "unknown")
    logger.info("JWT_VALID user=%s", user_email)

    # ------------------------------------------------------------------
    # Step 2 - Run device posture checks
    # Only reached if JWT is valid - posture header now supplements
    # a cryptographically verified identity, not a spoofable identity.
    # ------------------------------------------------------------------
    posture_header = headers.get("x-device-posture", "")

    if not posture_header:
        logger.warning("MISSING_POSTURE_HEADER user=%s", user_email)
        return generate_policy(user_email, "Deny", method_arn, {
            "error_code": "MISSING_POSTURE_DATA",
            "reason": "Missing X-Device-Posture header. Endpoint agent may not be installed."
        })

    try:
        posture_json = base64.b64decode(posture_header).decode("utf-8")
        posture_data = json.loads(posture_json)
        posture      = posture_data.get("posture", {})
    except Exception as e:
        logger.error("INVALID_POSTURE_HEADER user=%s error=%s", user_email, str(e))
        return generate_policy(user_email, "Deny", method_arn, {
            "error_code": "INVALID_POSTURE_FORMAT",
            "reason": "Could not decode X-Device-Posture header."
        })

    result = run_health_checks(user_email, posture_data.get("device_id", "unknown"), posture)

    if result["statusCode"] == 200:
        logger.info("ACCESS_GRANTED user=%s", user_email)
        return generate_policy(user_email, "Allow", method_arn, {
            "user_email":    user_email,
            "decision":      "ALLOW",
            "jwt_validated": "true",
            "checks_passed": "disk_encryption,hardware_mfa"
        })
    else:
        logger.warning("ACCESS_DENIED user=%s code=%s", user_email, result.get("error_code"))
        return generate_policy(user_email, "Deny", method_arn, {
            "user_email": user_email,
            "decision":   "DENY",
            "error_code": result.get("error_code"),
            "reason":     result.get("reason")
        })


# ------------------------------------------------------------------
# JWT Validation
# ------------------------------------------------------------------

def validate_cloudflare_jwt(token):
    """
    Validates a Cloudflare Access JWT.

    1. Fetches public keys from Cloudflare certs endpoint
    2. Decodes the JWT header to find the key ID (kid)
    3. Matches the kid to the correct public key
    4. Verifies the signature using RS256
    5. Validates the audience claim matches our AUD tag
    6. Returns the verified claims or an error reason
    """
    try:
        import jwt
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.x509 import load_pem_x509_certificate

        # Fetch Cloudflare public keys
        certs_data = fetch_cloudflare_certs()
        if not certs_data:
            return {"valid": False, "reason": "Could not fetch Cloudflare public keys"}

        # Decode JWT header to get kid (key ID)
        header_segment = token.split(".")[0]
        padding = 4 - len(header_segment) % 4
        header_segment += "=" * padding
        header = json.loads(base64.urlsafe_b64decode(header_segment))
        kid = header.get("kid", "")

        logger.info("JWT_KID kid=%s", kid)

        # Find matching public cert by kid
        public_key = None
        for cert_entry in certs_data.get("public_certs", []):
            if cert_entry.get("kid") == kid:
                cert_pem = cert_entry["cert"].encode("utf-8")
                cert     = load_pem_x509_certificate(cert_pem)
                public_key = cert.public_key()
                break

        if not public_key:
            return {"valid": False, "reason": f"No matching public key found for kid={kid}"}

        # Verify JWT signature and claims
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=CLOUDFLARE_AUD,
            options={"verify_exp": True}
        )

        logger.info("JWT_CLAIMS_VERIFIED email=%s aud=%s", claims.get("email"), claims.get("aud"))
        return {"valid": True, "claims": claims}

    except Exception as e:
        logger.error("JWT_VALIDATION_ERROR error=%s", str(e))
        return {"valid": False, "reason": f"JWT validation error: {str(e)}"}


def fetch_cloudflare_certs():
    """Fetches Cloudflare public signing keys from the certs endpoint."""
    try:
        req = urllib.request.Request(
            CLOUDFLARE_CERTS_URL,
            headers={"User-Agent": "zero-trust-lambda/2.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        logger.error("CERTS_FETCH_ERROR error=%s", str(e))
        return None


# ------------------------------------------------------------------
# Device Health Checks
# ------------------------------------------------------------------

def run_health_checks(user_email, device_id, posture):
    """Runs disk encryption and hardware MFA checks."""

    # Check 1 - Disk Encryption
    if not posture.get("disk_encrypted", False):
        logger.warning("DEVICE_CHECK_FAILED disk_encryption user=%s device=%s", user_email, device_id)
        return deny_access(
            user_email, device_id,
            "Device does not have disk encryption enabled. "
            "Enable BitLocker (Windows), FileVault (Mac), or LUKS (Linux).",
            "DISK_ENCRYPTION_REQUIRED"
        )

    logger.info("DEVICE_CHECK_PASSED disk_encryption user=%s", user_email)

    # Check 2 - Hardware MFA
    if not posture.get("hardware_mfa_registered", False):
        logger.warning("DEVICE_CHECK_FAILED hardware_mfa user=%s device=%s", user_email, device_id)
        return deny_access(
            user_email, device_id,
            "No hardware MFA token registered. "
            "Register a FIDO2 hardware token (YubiKey or Google Titan Key).",
            "HARDWARE_MFA_REQUIRED"
        )

    logger.info("DEVICE_CHECK_PASSED hardware_mfa user=%s", user_email)
    logger.info("ACCESS_GRANTED all_checks_passed user=%s", user_email)

    return allow_access(user_email, device_id, posture)


# ------------------------------------------------------------------
# Direct Invocation Handler
# ------------------------------------------------------------------

def handle_direct_invocation(event, context):
    """Handles direct Lambda invocations for testing."""
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


# ------------------------------------------------------------------
# IAM Policy Generator
# ------------------------------------------------------------------

def generate_policy(principal_id, effect, method_arn, context=None):
    """Generates an IAM policy document for API Gateway."""
    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action":   "execute-api:Invoke",
                "Effect":   effect,
                "Resource": method_arn
            }]
        }
    }
    if context:
        policy["context"] = context
    logger.info("POLICY_GENERATED effect=%s principal=%s", effect, principal_id)
    return policy


# ------------------------------------------------------------------
# Response Helpers
# ------------------------------------------------------------------

def allow_access(user_email, device_id, posture):
    return {
        "statusCode": 200,
        "decision":   "ALLOW",
        "user_email": user_email,
        "device_id":  device_id,
        "checks_passed": ["disk_encryption", "hardware_mfa_registered"],
        "message": (
            f"Access granted for {user_email}. "
            "JWT validated. Device posture verified."
        )
    }


def deny_access(user_email, device_id, reason, code):
    return {
        "statusCode": 403,
        "decision":   "DENY",
        "user_email": user_email,
        "device_id":  device_id,
        "error_code": code,
        "reason":     reason,
        "message": (
            f"Access denied for {user_email}. "
            f"Check failed: {code}. "
            "Contact your security team if you believe this is an error."
        )
    }