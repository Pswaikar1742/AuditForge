"""Safe schema-valid probe case generation."""

import uuid
from typing import Any, Dict, List
from auditforge.core.contracts import ProbeCase, ToolRecord


def _generate_value_for_schema(prop_schema: Dict[str, Any]) -> Any:
    prop_type = prop_schema.get("type", "string")
    if "default" in prop_schema:
        return prop_schema["default"]
    if "enum" in prop_schema and prop_schema["enum"]:
        return prop_schema["enum"][0]

    if prop_type == "string":
        if prop_schema.get("format") == "date":
            return "2026-01-01"
        return "audit_probe_test_val"
    elif prop_type in ("integer", "number"):
        return int(prop_schema.get("minimum", 1))
    elif prop_type == "boolean":
        return True
    elif prop_type == "array":
        item_schema = prop_schema.get("items", {"type": "string"})
        return [_generate_value_for_schema(item_schema)]
    elif prop_type == "object":
        props = prop_schema.get("properties", {})
        return {k: _generate_value_for_schema(v) for k, v in list(props.items())[:3]}
    return "audit_val"


def generate_probe_cases(tool: ToolRecord) -> List[ProbeCase]:
    """Generate safe, schema-valid input probe cases based on tool input_schema."""
    schema = tool.input_schema or {}
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))

    args: Dict[str, Any] = {}
    for param_name, param_def in properties.items():
        if param_name in required or len(args) < 5:
            args[param_name] = _generate_value_for_schema(param_def)

    case_id = f"case-{tool.name}-{uuid.uuid4().hex[:8]}"
    return [
        ProbeCase(
            case_id=case_id,
            tool_name=tool.name,
            input_arguments=args,
            expected_behavior="Normal benign execution within declared capability envelope",
            timeout_seconds=10.0,
        )
    ]
