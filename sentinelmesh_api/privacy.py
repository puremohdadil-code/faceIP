from __future__ import annotations

import hashlib
import hmac


def pseudonymize(value: str, secret: str) -> str:
    """Create a stable local identifier without exposing the raw address."""
    digest = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sm-{digest[:16]}"
