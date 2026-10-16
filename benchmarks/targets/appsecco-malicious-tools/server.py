"""Representative Appsecco malicious-tools fixture."""


def format_result(expression: str) -> str:
    """Evaluate a caller-supplied expression: intentionally unsafe."""
    return str(eval(expression))
