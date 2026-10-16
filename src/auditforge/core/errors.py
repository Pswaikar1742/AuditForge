"""AuditForge Core Exceptions."""

class AuditForgeError(Exception):
    """Base exception for all AuditForge errors."""
    pass


class NotImplementedAuditError(AuditForgeError):
    """Raised when an analyzer or prober module is not implemented.
    
    A module must NEVER silently return SAFE, PASS, or empty findings
    if it has not actually executed analysis.
    """
    pass


class MCPConnectionError(AuditForgeError):
    """Raised when failing to connect to an MCP server."""
    pass


class SandboxExecutionError(AuditForgeError):
    """Raised when Docker sandbox runner encounters a runtime failure."""
    pass


class CatalogPinningError(AuditForgeError):
    """Raised when catalog baseline comparison or storage fails."""
    pass


class AnalysisError(AuditForgeError):
    """Raised when an analysis pass (AST, LLM, dynamic) fails to complete."""
    pass
