"""Autonomous worker agent executing user tasks via tool calls through the MCP proxy gateway.
Inputs: Task descriptions and MCP tool schemas. Outputs: Completed task results or error handling.
Build plan: Day 1.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from groq import Groq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SERVER_SCRIPT = ROOT_DIR / "downstream" / "sql_server.py"
PROMPT_PATH = ROOT_DIR / "agents" / "prompts" / "worker.md"
ENV_PATH = ROOT_DIR / ".env"


def _load_env() -> dict[str, str]:
    """Load key-value pairs from .env without overriding existing environment variables."""
    env_vars: dict[str, str] = {}
    if ENV_PATH.exists():
        for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env_vars[key.strip()] = value.strip().strip('"').strip("'")

    for key, value in env_vars.items():
        os.environ.setdefault(key, value)
    return env_vars


def _mcp_tools_to_groq(mcp_tools: list[Any]) -> list[dict[str, Any]]:
    """Convert MCP tool definitions to Groq/OpenAI function-calling schema."""
    converted = []
    for tool in mcp_tools:
        raw_schema = getattr(tool, "input_schema", None)
        if not isinstance(raw_schema, dict):
            raw_schema = getattr(tool, "inputSchema", None)
        schema = raw_schema if isinstance(raw_schema, dict) else {"type": "object", "properties": {}}
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": schema,
                },
            }
        )
    return converted


def _extract_tool_text(result: Any) -> str:
    """Safely extract text content from an MCP CallToolResult."""
    if not result or not getattr(result, "content", None):
        return ""
    parts = []
    for item in result.content:
        text = getattr(item, "text", None)
        parts.append(text if text is not None else str(item))
    return "\n".join(parts)


async def smoke_test(server_script: Path | str = DEFAULT_SERVER_SCRIPT) -> dict[str, Any]:
    """Verify MCP server connectivity and basic tool execution without calling an LLM."""
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(server_script).resolve())],
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            tool_names = [t.name for t in tools_resp.tools]

            schema_res = await session.call_tool("get_schema", {})
            sql_res = await session.call_tool(
                "execute_sql",
                {"query": "SELECT id, name, ssn FROM customers LIMIT 2"},
            )
            return {
                "tools": tool_names,
                "schema_preview": _extract_tool_text(schema_res)[:200],
                "sample_query_result": _extract_tool_text(sql_res),
            }


async def run_worker(
    task: str,
    server_script: Path | str = DEFAULT_SERVER_SCRIPT,
    max_turns: int = 10,
) -> dict[str, Any]:
    """Run the Groq-powered worker agent against an MCP server until task completion."""
    _load_env()
    api_key = os.environ.get("GROQ_API_KEY")
    model_name = os.environ.get("MODEL_NAME", "openai/gpt-oss-120b")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set in environment or .env")

    system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
    client = Groq(api_key=api_key)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(server_script).resolve())],
    )

    tool_trace: list[dict[str, Any]] = []

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            groq_tools = _mcp_tools_to_groq(tools_resp.tools)

            messages: list[dict[str, Any]] = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": task},
            ]

            for turn in range(1, max_turns + 1):
                response = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    tools=groq_tools,
                    tool_choice="auto",
                    temperature=0,
                )
                msg = response.choices[0].message

                assistant_entry: dict[str, Any] = {
                    "role": "assistant",
                    "content": msg.content or "",
                }
                if msg.tool_calls:
                    assistant_entry["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                messages.append(assistant_entry)

                if not msg.tool_calls:
                    return {
                        "answer": msg.content or "",
                        "tool_calls": tool_trace,
                        "turns": turn,
                    }

                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    try:
                        tool_args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        tool_args = {}

                    mcp_result = await session.call_tool(tool_name, tool_args)
                    result_text = _extract_tool_text(mcp_result)

                    tool_trace.append(
                        {
                            "tool": tool_name,
                            "arguments": tool_args,
                            "result": result_text,
                        }
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": result_text,
                        }
                    )

            return {
                "answer": "Max turns reached without a final response.",
                "tool_calls": tool_trace,
                "turns": max_turns,
            }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the MCP worker agent.")
    parser.add_argument(
        "task",
        nargs="?",
        default="List all tables and tell me how many customers exist.",
        help="User task for the worker agent to execute.",
    )
    parser.add_argument(
        "--server",
        default=str(DEFAULT_SERVER_SCRIPT),
        help="Path to the MCP server script (downstream or firewall proxy).",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run a direct MCP smoke test without invoking the LLM.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = _parse_args()
    if cli_args.smoke_test:
        output = asyncio.run(smoke_test(cli_args.server))
    else:
        output = asyncio.run(run_worker(cli_args.task, cli_args.server))
    print(json.dumps(output, indent=2))
