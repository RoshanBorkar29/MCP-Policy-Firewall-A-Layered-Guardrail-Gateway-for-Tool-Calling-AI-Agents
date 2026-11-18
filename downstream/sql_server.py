"""Downstream FastMCP server exposing SQLite database operations, CSV export, and email tools.
Inputs: MCP tool call requests (SQL query, export parameters). Outputs: Raw tool execution results.
Build plan: Day 1.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from mcp.server.fastmcp import FastMCP

ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ROOT_DIR / "data" / "synthetic.db"
RESULTS_DIR = ROOT_DIR / "results"
OUTBOX_PATH = RESULTS_DIR / "outbox.log"

mcp = FastMCP("downstream-sql-server")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@mcp.tool()
def get_schema() -> str:
    """Return the CREATE TABLE statements for all tables in the database."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        schema = {row["name"]: row["sql"] for row in rows}
        return json.dumps(schema, indent=2)
    except sqlite3.Error as exc:
        return json.dumps({"error": str(exc)})
    finally:
        conn.close()


@mcp.tool()
def execute_sql(query: str) -> str:
    """Execute any SQL statement against synthetic.db and return results as JSON."""
    conn = _get_conn()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(query)
        except sqlite3.ProgrammingError as exc:
            if "one statement at a time" in str(exc):
                conn.executescript(query)
                conn.commit()
                return json.dumps({"status": "ok", "executed_script": True})
            raise

        if cursor.description is not None:
            rows = [dict(row) for row in cursor.fetchall()]
            return json.dumps({"rows": rows, "row_count": len(rows)})

        conn.commit()
        return json.dumps({"status": "ok", "rows_affected": cursor.rowcount})
    except sqlite3.Error as exc:
        return json.dumps({"error": str(exc)})
    finally:
        conn.close()


@mcp.tool()
def export_csv(query: str, filename: str) -> str:
    """Run a SQL query and write results to a CSV file in results/."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / filename

    conn = _get_conn()
    try:
        cursor = conn.execute(query)
        if cursor.description is None:
            return json.dumps({"error": "Query did not return tabular rows to export."})

        headers = [col[0] for col in cursor.description]
        rows = cursor.fetchall()

        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(list(row))

        return json.dumps(
            {
                "status": "ok",
                "file": str(out_path),
                "rows_exported": len(rows),
            }
        )
    except (sqlite3.Error, OSError) as exc:
        return json.dumps({"error": str(exc)})
    finally:
        conn.close()


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Mock email sender that logs outbound emails to results/outbox.log."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "to": to,
        "subject": subject,
        "body": body,
    }
    try:
        with OUTBOX_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return json.dumps({"status": "sent", "to": to, "subject": subject})
    except OSError as exc:
        return json.dumps({"error": str(exc)})


if __name__ == "__main__":
    mcp.run()
