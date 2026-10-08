"""Contract tests: the tools the model receives match the README and the operator confirmation list.

The gateway is started over stdio exactly as deepseek_agent.py starts it, so these tests check what the model
actually gets. Run: python tests/test_tool_contract.py
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import deepseek_agent  # noqa: E402  (importing has no side effects: main() runs only under __main__)

README_TOOLS_HEADING = "## Tools"
README_NEXT_HEADING = "## Quick start"
ACTIVE_GROUP_PREFIX = "**Active**"


def documented_tools() -> dict[str, set[str]]:
    """Tool names per group, read from the Tools table in README.md."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split(README_TOOLS_HEADING, 1)[1].split(README_NEXT_HEADING, 1)[0]
    groups = {}
    for row in section.splitlines():
        if row.startswith("| **"):
            name_cell, tools_cell = row.split("|")[1:3]
            groups[name_cell.strip()] = set(re.findall(r"`([a-z_0-9]+)`", tools_cell))
    return groups


class ToolContractTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        policy = tmp / "policy.json"
        policy.write_text(json.dumps({
            "engagement_id": "CONTRACT-TEST",
            "mode": "read_only",
            "environment": "test",
            "authorized_hosts": ["app.test"],
            "scope_urls": ["https://app.test/"],
            "audit_log": str(tmp / "audit.jsonl"),
            "upstream_sse_url": "http://127.0.0.1:1/",
        }), encoding="utf-8")
        params = StdioServerParameters(
            command=sys.executable, args=[str(ROOT / "server.py")],
            env={**get_default_environment(), "BURP_AGENT_POLICY": str(policy)})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self.tools = (await session.list_tools()).tools

    async def asyncTearDown(self):
        self._tmp.cleanup()

    async def test_harness_receives_exactly_the_documented_tools(self):
        documented = set().union(*documented_tools().values())
        names = {t.name for t in self.tools}
        self.assertEqual(len(self.tools), 34)
        self.assertEqual(names, documented, f"server only: {sorted(names - documented)}, "
                                            f"README only: {sorted(documented - names)}")

    async def test_every_active_tool_requires_operator_confirmation(self):
        active = next(v for g, v in documented_tools().items() if g.startswith(ACTIVE_GROUP_PREFIX))
        self.assertTrue(active)
        self.assertLessEqual(active, deepseek_agent.CONFIRM_TOOLS,
                             f"active tools without confirmation: {sorted(active - deepseek_agent.CONFIRM_TOOLS)}")
        self.assertLessEqual(deepseek_agent.CONFIRM_TOOLS, {t.name for t in self.tools})

    async def test_tool_schemas_can_be_sent_to_the_api(self):
        for tool in self.tools:
            with self.subTest(tool=tool.name):
                self.assertRegex(tool.name, r"^[A-Za-z0-9_-]{1,64}$")
                self.assertTrue((tool.description or "").strip())
                self.assertEqual(tool.inputSchema.get("type"), "object")
                json.dumps(tool.inputSchema)  # the schema is sent as JSON
                for pname, prop in (tool.inputSchema.get("properties") or {}).items():
                    self.assertTrue(any(k in prop for k in ("type", "anyOf", "$ref", "enum", "allOf")),
                                    f"parameter {pname} has no type")


if __name__ == "__main__":
    unittest.main()
