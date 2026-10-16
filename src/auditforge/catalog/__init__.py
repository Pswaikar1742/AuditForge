"""MCP Catalog Discovery, Normalization, and Pinning."""

from auditforge.catalog.normalize import normalize_input_schema, normalize_tool_definition
from auditforge.catalog.pinning import diff_catalogs
from auditforge.catalog.client import MCPCatalogClient

__all__ = [
    "normalize_input_schema",
    "normalize_tool_definition",
    "diff_catalogs",
    "MCPCatalogClient",
]
