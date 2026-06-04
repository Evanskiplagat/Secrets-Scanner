from __future__ import annotations

import logging
from pathlib import Path

from scanner.core.models import Detection, Severity
from scanner.detectors.patterns import (
    HARDCODED_CREDENTIAL_PATTERN,
    HIGH_ENTROPY_TOKEN_PATTERN,
    PATTERNS,
    shannon_entropy,
)
from scanner.utils.masking import mask_secret

LOGGER = logging.getLogger(__name__)


def detect_secrets(file_path: Path, content: str) -> list[Detection]:
    detections: list[Detection] = []
    seen: set[tuple[int, str, str]] = set()
    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for rule in PATTERNS:
            for match in rule.pattern.finditer(line):
                secret = match.group(rule.group)
                key = (line_number, rule.rule_id, secret)
                if key in seen:
                    continue
                seen.add(key)
                detections.append(
                    Detection(
                        file_path=file_path,
                        line_number=line_number,
                        secret_type=rule.secret_type,
                        severity=rule.severity,
                        preview=mask_secret(secret),
                        rule_id=rule.rule_id,
                        matched_text=secret,
                    )
                )

        for match in HARDCODED_CREDENTIAL_PATTERN.finditer(line):
            secret = match.group(1)
            if shannon_entropy(secret) < 3.5:
                continue
            key = (line_number, "hardcoded_credential", secret)
            if key in seen:
                continue
            seen.add(key)
            detections.append(
                Detection(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type="Hardcoded Credential",
                    severity=Severity.HIGH,
                    preview=mask_secret(secret),
                    rule_id="hardcoded_credential",
                    matched_text=secret,
                )
            )
        for match in HIGH_ENTROPY_TOKEN_PATTERN.finditer(line):
            secret = match.group(1)
            if secret.startswith(("http", "ssh-rsa", "ssh-ed25519")):
                continue
            if shannon_entropy(secret) < 4.2:
                continue
            key = (line_number, "high_entropy_secret", secret)
            if key in seen:
                continue
            seen.add(key)
            detections.append(
                Detection(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type="High Entropy Secret",
                    severity=Severity.MEDIUM,
                    preview=mask_secret(secret),
                    rule_id="high_entropy_secret",
                    matched_text=secret,
                )
            )

    LOGGER.debug("Detected %s findings in %s", len(detections), file_path)
    return detections

