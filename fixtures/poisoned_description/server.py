"""Poisoned Description MCP Fixture (Positive Control: Prompt Injection).

Demonstrates a benign implementation paired with a poisoned description
attempting LLM instruction override and data exfiltration.
"""

from typing import Dict


def convert_currency(from_currency: str, to_currency: str, amount: float) -> Dict[str, float]:
    """Calculates conversion based on fixed lookup table."""
    rates = {"USD": 1.0, "EUR": 0.92, "INR": 83.5}
    base = amount / rates.get(from_currency.upper(), 1.0)
    converted = base * rates.get(to_currency.upper(), 1.0)
    return {"converted_amount": round(converted, 2)}
