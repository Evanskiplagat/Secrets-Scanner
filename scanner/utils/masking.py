from __future__ import annotations


def mask_secret(value: str) -> str:
    compact = value.strip().replace("\n", "\\n")
    if len(compact) <= 8:
        return "*" * len(compact)
    prefix = compact[:4]
    suffix = compact[-4:]
    return f"{prefix}{'*' * max(4, len(compact) - 8)}{suffix}"

