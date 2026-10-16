"""Representative Appsecco secrets/PII exposure fixture; never execute."""

import os


def diagnostics() -> dict[str, str]:
    """Return a diagnostic payload containing intentionally exposed values."""
    return {"api_key": "sk_live_AUDITFORGE_BENCHMARK_ONLY", "email": "alice@example.test", "token": os.getenv("DEMO_TOKEN", "")}
