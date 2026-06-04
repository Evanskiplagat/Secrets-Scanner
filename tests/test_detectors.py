from pathlib import Path

from scanner.detectors.engine import detect_secrets


def test_detects_multiple_secret_types() -> None:
    content = "\n".join(
        [
            'aws_key = "AKIA1234567890ABCDEF"',
            'token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"',
            'password = "Sup3rSecr3tValue"',
        ]
    )

    findings = detect_secrets(Path("config.py"), content)
    types = {finding.secret_type for finding in findings}

    assert "AWS Access Key" in types
    assert "GitHub Token" in types
    assert "Password" in types


def test_masks_secret_values() -> None:
    findings = detect_secrets(Path("app.env"), 'API_KEY="1234567890ABCDEFGHIJ"')
    assert findings
    assert findings[0].preview.startswith("1234")
    assert "*" in findings[0].preview
    assert "ABCDEFGHIJ" not in findings[0].preview


def test_detects_high_entropy_secret() -> None:
    findings = detect_secrets(
        Path("secrets.ts"),
        'const randomToken = "b4A9qL2nP7xT3vK8mJ5sD1fH6rC0wZ";',
    )
    assert any(finding.secret_type == "High Entropy Secret" for finding in findings)
