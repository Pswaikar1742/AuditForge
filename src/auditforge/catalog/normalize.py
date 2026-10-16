"""Tool normalization and canonical representation."""

from typing import Any, Dict
from auditforge.core.contracts import ToolRecord, compute_tool_fingerprint


def normalize_input_schema(raw_schema: Any) -> Dict[str, Any]:
    """Normalize JSON schema ensuring consistent type structure."""
    if not isinstance(raw_schema, dict):
        return {"type": "object", "properties": {}}
    
    schema = dict(raw_schema)
    if "type" not in schema:
        schema["type"] = "object"
    if "properties" not in schema and schema.get("type") == "object":
        schema["properties"] = {}
    return schema


def normalize_tool_definition(raw_tool: Any) -> ToolRecord:
    """Normalize any raw tool representation (dict, MCP SDK Tool, or JSON) into ToolRecord.
    
    Ensures identical definitions produce identical SHA-256 fingerprints across platforms.
    """
    if hasattr(raw_tool, "model_dump"):
        data = raw_tool.model_dump()
    elif hasattr(raw_tool, "__dict__"):
        data = dict(raw_tool.__dict__)
    elif isinstance(raw_tool, dict):
        data = dict(raw_tool)
    else:
        raise ValueError(f"Unsupported tool format: {type(raw_tool)}")

    name = data.get("name", "")
    if not name:
        raise ValueError("Tool definition missing mandatory 'name' field")

    title = data.get("title")
    description = data.get("description") or ""
    
    # Handle both camelCase and snake_case from MCP SDK / raw JSON
    raw_input_schema = data.get("input_schema", data.get("inputSchema", {}))
    input_schema = normalize_input_schema(raw_input_schema)
    
    output_schema = data.get("output_schema", data.get("outputSchema"))
    if output_schema is not None and not isinstance(output_schema, dict):
        output_schema = None
        
    annotations = data.get("annotations")
    if annotations is not None and not isinstance(annotations, dict):
        annotations = None

    icons = data.get("icons")
    if icons is not None and not isinstance(icons, list):
        icons = None

    meta = data.get("meta", data.get("_meta"))
    if meta is not None and not isinstance(meta, dict):
        meta = None

    execution = data.get("execution")
    if execution is not None and not isinstance(execution, dict):
        execution = None

    norm_dict = {
        "annotations": annotations,
        "description": description,
        "execution": execution,
        "icons": icons,
        "input_schema": input_schema,
        "meta": meta,
        "name": name,
        "output_schema": output_schema,
        "title": title,
    }
    fingerprint = compute_tool_fingerprint(norm_dict)

    return ToolRecord(
        name=name,
        title=title,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        icons=icons,
        meta=meta,
        execution=execution,
        fingerprint=fingerprint,
    )
