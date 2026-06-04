from __future__ import annotations

import math
import re
from dataclasses import dataclass

from scanner.core.models import Severity


@dataclass(frozen=True, slots=True)
class SecretPattern:
    rule_id: str
    secret_type: str
    severity: Severity
    pattern: re.Pattern[str]
    group: int = 0


# These regexes intentionally trade some precision for strong repository coverage.
PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "aws_access_key",
        "AWS Access Key",
        Severity.CRITICAL,
        re.compile(r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b"),
        1,
    ),
    SecretPattern(
        "aws_secret_key",
        "AWS Secret Key",
        Severity.CRITICAL,
        re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}?([A-Za-z0-9/+=]{40})"),
        3,
    ),
    SecretPattern(
        "azure_key",
        "Azure Key",
        Severity.HIGH,
        re.compile(r"(?i)(azure|accountkey|sharedaccesskey).{0,20}?([A-Za-z0-9+/=]{32,88})"),
        2,
    ),
    SecretPattern(
        "google_api_key",
        "Google API Key",
        Severity.CRITICAL,
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        1,
    ),
    SecretPattern(
        "github_token",
        "GitHub Token",
        Severity.CRITICAL,
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82,255})\b"),
        1,
    ),
    SecretPattern(
        "jwt_token",
        "JWT Token",
        Severity.HIGH,
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*\.?[A-Za-z0-9_\-+/=]*)\b"),
        1,
    ),
    SecretPattern(
        "stripe_key",
        "Stripe Key",
        Severity.CRITICAL,
        re.compile(r"\b((?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,99})\b"),
        1,
    ),
    SecretPattern(
        "db_connection_string",
        "Database Connection String",
        Severity.CRITICAL,
        re.compile(
            r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s\"']+)\b"
        ),
        1,
    ),
    SecretPattern(
        "api_key",
        "API Key",
        Severity.HIGH,
        re.compile(
            r"(?i)(?:api[_\- ]?key|token|secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,128})[\"']?"
        ),
        1,
    ),
    SecretPattern(
        "password",
        "Password",
        Severity.HIGH,
        re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"']{8,128})[\"']?"
        ),
        1,
    ),
    SecretPattern(
        "private_key",
        "Private Key",
        Severity.CRITICAL,
        re.compile(r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)"),
        1,
    ),
    SecretPattern(
        "ssh_key",
        "SSH Key",
        Severity.CRITICAL,
        re.compile(r"\b(ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+(?: [^\s]+)?)"),
        1,
    ),
    SecretPattern(
        "bearer_token",
        "Bearer Token",
        Severity.HIGH,
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/=]{16,})\b"),
        1,
    ),
)

HARDCODED_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(?:client_secret|secret|token|password|passwd|pwd|access_key)\b\s*[:=]\s*[\"']([^\"']{10,})[\"']"
)

HIGH_ENTROPY_TOKEN_PATTERN = re.compile(r"\b([A-Za-z0-9+/=_-]{20,})\b")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) / len(value) for char in set(value)}
    return -sum(probability * math.log2(probability) for probability in frequencies.values())
