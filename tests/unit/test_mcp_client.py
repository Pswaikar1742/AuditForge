import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock
from contextlib import asynccontextmanager

import pytest
from mcp.types import Tool
from auditforge.catalog.client import MCPCatalogClient
from auditforge.catalog.normalize import normalize_tool_definition
from auditforge.catalog.pinning import diff_catalogs
from auditforge.core.contracts import ServerSnapshot, canonical_json
from auditforge.core.errors import MCPConnectionError
from auditforge.storage.database import Database


def test_normalization_hash_and_mutations(tmp_path):
    raw = dict(name='word_count', description='Count', inputSchema={'type': 'object', 'properties': {}},
               outputSchema={'type': 'object'}, title='Counter', annotations={'readOnlyHint': True})
    tool = normalize_tool_definition(Tool(**raw))
    assert tool.fingerprint == hashlib.sha256(canonical_json(tool.model_dump(exclude={'fingerprint'})).encode()).hexdigest()
    assert tool == normalize_tool_definition(dict(reversed(list(Tool(**raw).model_dump().items()))))
    baseline = ServerSnapshot(server_id='fixture', tools={tool.name: tool})
    db = Database(str(tmp_path / 'approval.db'))
    db.save_baseline(baseline)
    for field, value, normalized in [('description', 'Changed', 'description'),
                                     ('inputSchema', {'type': 'object', 'properties': {'new': {'type': 'string'}}}, 'input_schema'),
                                     ('outputSchema', {'type': 'string'}, 'output_schema'),
                                     ('title', 'New title', 'title')]:
        changed = normalize_tool_definition({**raw, field: value})
        current = ServerSnapshot(server_id='fixture', tools={changed.name: changed})
        assert current.catalog_fingerprint != baseline.catalog_fingerprint
        assert normalized in diff_catalogs(baseline, current).modified_tools['word_count']
        db.save_baseline(current)
        assert db.get_baseline('fixture') == baseline


@pytest.mark.asyncio
async def test_pagination_and_duplicate_cursor():
    client = MCPCatalogClient(['unused'])
    session = SimpleNamespace(list_tools=AsyncMock(side_effect=[
        SimpleNamespace(tools=[Tool(name='a', inputSchema={})], next_cursor='page2'),
        SimpleNamespace(tools=[Tool(name='b', inputSchema={})], next_cursor=None)]))
    @asynccontextmanager
    async def connected():
        yield session
    client._session = connected
    assert set((await client.discover_live()).tools) == {'a', 'b'}
    assert session.list_tools.call_args.kwargs['params'].cursor == 'page2'
    session.list_tools.side_effect = [SimpleNamespace(tools=[], next_cursor='same')] * 2
    with pytest.raises(MCPConnectionError, match='cursor'):
        await client.discover_live()


@pytest.mark.asyncio
async def test_missing_command():
    with pytest.raises(MCPConnectionError, match='required'):
        await MCPCatalogClient().discover_live()
