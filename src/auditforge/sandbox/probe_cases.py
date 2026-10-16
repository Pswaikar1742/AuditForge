"""Safe schema-valid probe case generation."""

from typing import Any, List
import hashlib
from auditforge.core.contracts import ProbeCase, ToolRecord


def generate_probe_cases(tool: ToolRecord) -> List[ProbeCase]:
    """Generate one bounded case using defaults or harmless type values."""
    schema = tool.input_schema or {}
    arguments: dict[str, Any] = {}
    for name, definition in schema.get("properties", {}).items():
        if "default" in definition:
            arguments[name] = definition["default"]
        elif definition.get("type") == "string":
            arguments[name] = "test"
        elif definition.get("type") == "integer":
            arguments[name] = 1
        elif definition.get("type") == "number":
            arguments[name] = 1.0
        elif definition.get("type") == "boolean":
            arguments[name] = False
        elif definition.get("type") == "array":
            arguments[name] = []
        elif definition.get("type") == "object":
            arguments[name] = {}
    digest = hashlib.sha256(tool.name.encode()).hexdigest()[:10]
    return [ProbeCase(case_id=f"probe-{digest}", tool_name=tool.name, input_arguments=arguments,
                      expected_behavior="Completes without external side effects.")]
