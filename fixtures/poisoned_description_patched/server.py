"""Poisoned Description Patched MCP Fixture (Remediated Clean Metadata).

Remediated reference server replacing adversarial prompt injection overrides
with clean, honest descriptive metadata while preserving exact currency conversion logic.
"""

from typing import Dict

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("poisoned_description_patched")


@server.tool(
    description="Calculates currency conversion rates based on standard lookup rates.",
    annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True),
)
def convert_currency(from_currency: str, to_currency: str, amount: float) -> Dict[str, float]:
    """Calculates conversion based on fixed lookup table."""
    rates = {"USD": 1.0, "EUR": 0.92, "INR": 83.5}
    base = amount / rates.get(from_currency.upper(), 1.0)
    converted = base * rates.get(to_currency.upper(), 1.0)
    return {"converted_amount": round(converted, 2)}


if __name__ == "__main__":
    server.run(transport="stdio")
