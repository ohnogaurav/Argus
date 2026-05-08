"""
Password Auditor for CyberOPS.
Analyzes password strength using industry standards.
Returns score/verdict similar to threat_intel pattern.
"""

import re
from typing import Dict

# ── CONFIG ──────────────────────────────────────────────────────────────
SECURITY_ISSUES = {
    "too_short": "Password shorter than 12 chars",
    "no_uppercase": "Missing uppercase letters",
    "no_lowercase": "Missing lowercase letters",
    "no_digits": "Missing numbers",
    "no_special": "Missing special characters",
    "sequential": "Contains sequential characters",
    "repeated": "Contains repeated characters",
    "common": "Common/weak password",
}

# Common weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "dragon", "baseball", "iloveyou",
    "trustno1", "1q2w3e4r", "123123", "admin", "password123",
    "admin123", "root", "toor", "pass", "login", "welcome",
}


def audit_password(password: str) -> dict:
    """
    Audit password strength. Returns dict with:
    - strength: "WEAK" | "FAIR" | "GOOD" | "STRONG"
    - score: 0-100
    - verdict: PASS | FAIL
    - issues: [list of problems]
    - recommendations: [list of tips]
    """
    if not password:
        return {
            "strength": "WEAK",
            "score": 0,
            "verdict": "FAIL",
            "issues": ["Password is empty"],
            "recommendations": ["Enter a password"]
        }

    issues = []
    score = 50  # Start at 50

    # Length check
    if len(password) < 8:
        issues.append(SECURITY_ISSUES["too_short"])
        score -= 20
    elif len(password) < 12:
        score -= 10
    elif len(password) >= 16:
        score += 10

    # Character composition
    if not re.search(r'[A-Z]', password):
        issues.append(SECURITY_ISSUES["no_uppercase"])
        score -= 15
    if not re.search(r'[a-z]', password):
        issues.append(SECURITY_ISSUES["no_lowercase"])
        score -= 15
    if not re.search(r'[0-9]', password):
        issues.append(SECURITY_ISSUES["no_digits"])
        score -= 15
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        issues.append(SECURITY_ISSUES["no_special"])
        score -= 10
    else:
        score += 5

    # Pattern checks
    if re.search(r'(.)\1{2,}', password):  # Repeated chars
        issues.append(SECURITY_ISSUES["repeated"])
        score -= 10

    if re.search(r'(012|123|234|345|456|567|678|789|890|abcd|bcde|cdef)', password):
        issues.append(SECURITY_ISSUES["sequential"])
        score -= 10

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        issues.append(SECURITY_ISSUES["common"])
        score -= 30

    # Clamp score
    score = max(0, min(100, score))

    # Determine strength & verdict
    if score < 40:
        strength = "WEAK"
        verdict = "FAIL"
    elif score < 60:
        strength = "FAIR"
        verdict = "FAIL" if len(issues) > 2 else "PASS"
    elif score < 80:
        strength = "GOOD"
        verdict = "PASS"
    else:
        strength = "STRONG"
        verdict = "PASS"

    # Recommendations
    recommendations = []
    if len(password) < 12:
        recommendations.append("Use at least 12 characters")
    if not re.search(r'[A-Z]', password):
        recommendations.append("Add uppercase letters (A-Z)")
    if not re.search(r'[a-z]', password):
        recommendations.append("Add lowercase letters (a-z)")
    if not re.search(r'[0-9]', password):
        recommendations.append("Add numbers (0-9)")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        recommendations.append("Add special characters (!@#$%^&*)")
    if re.search(r'(.)\1{2,}', password):
        recommendations.append("Avoid repeating characters")
    if re.search(r'(012|123|234|345|456|567|678|789|890|abcd|bcde|cdef)', password):
        recommendations.append("Avoid sequential patterns")

    return {
        "strength": strength,
        "score": score,
        "verdict": verdict,
        "issues": issues,
        "recommendations": recommendations[:3],  # Top 3 recommendations
        "length": len(password),
        "has_uppercase": bool(re.search(r'[A-Z]', password)),
        "has_lowercase": bool(re.search(r'[a-z]', password)),
        "has_digits": bool(re.search(r'[0-9]', password)),
        "has_special": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password)),
    }


def audit_password_pair(password1: str, password2: str) -> dict:
    """
    Check two passwords match + audit. Used for password confirmation.
    Returns audit dict + {"match": bool, "mismatch_error": str}.
    """
    audit = audit_password(password1)

    if password1 != password2:
        audit["match"] = False
        audit["mismatch_error"] = "Passwords do not match"
        audit["verdict"] = "FAIL"
    else:
        audit["match"] = True
        audit["mismatch_error"] = None

    return audit


def get_strength_badge_color(strength: str) -> str:
    """Return CSS color class for strength badge."""
    mapping = {
        "WEAK": "badge-red",
        "FAIR": "badge-yellow",
        "GOOD": "badge-blue",
        "STRONG": "badge-green",
    }
    return mapping.get(strength, "badge-blue")
