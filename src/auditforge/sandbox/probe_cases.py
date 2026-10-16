"""Safe schema-valid probe case generation."""

from typing import List
from auditforge.core.contracts import ProbeCase, ToolRecord
from auditforge.core.errors import NotImplementedAuditError


def generate_probe_cases(tool: ToolRecord) -> List[ProbeCase]:
    """Generate safe, schema-valid input probe cases based on tool input_schema.
    
    Implementation assigned to workstream: feat/sandbox-prober-fixtures.
    """
    raise NotImplementedAuditError(
        "Probe case generation is not yet implemented. "
        "Assigned to workstream: feat/sandbox-prober-fixtures."
    )
