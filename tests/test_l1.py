"""Unit test suite for Layer 1 SQL AST rule enforcement and sqlglot parsing mechanics.
Inputs: Synthetic test queries (valid, destructive, malformed). Outputs: Pytest test assertion results.
Build plan: Day 2.
"""

from __future__ import annotations

import pytest

from firewall.context import Verdict
from firewall.layers.l1_sql_rules import check_sql


# --- 1. Allowed Safe Queries (Negative class for threat detection) ---


def test_l1_valid_select_simple():
    decision = check_sql("SELECT * FROM customers")
    assert decision.verdict == Verdict.ALLOW
    assert decision.layer == "L1"


def test_l1_valid_select_columns_and_filter():
    decision = check_sql("SELECT id, name, ssn FROM customers WHERE id = 10")
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_select_join():
    query = (
        "SELECT c.name, a.account_number, a.balance "
        "FROM customers c "
        "JOIN accounts a ON c.id = a.customer_id "
        "WHERE a.status = 'active'"
    )
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_select_aggregations_and_group():
    query = (
        "SELECT customer_id, COUNT(*) AS total_accs, SUM(balance) AS total_bal "
        "FROM accounts "
        "GROUP BY customer_id "
        "HAVING COUNT(*) > 1"
    )
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_select_cte():
    query = (
        "WITH active_custs AS ("
        "  SELECT id, name FROM customers WHERE created_at >= '2025-01-01'"
        ") "
        "SELECT * FROM active_custs"
    )
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_select_subquery():
    query = (
        "SELECT name, email FROM customers "
        "WHERE id IN (SELECT customer_id FROM accounts WHERE balance > 10000)"
    )
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_union():
    query = (
        "SELECT name AS entity FROM customers "
        "UNION "
        "SELECT account_number AS entity FROM accounts"
    )
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_select_with_inline_comments():
    query = "SELECT /**/ id, name FROM customers -- fetch customer names\nWHERE id = 5"
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


def test_l1_valid_select_order_and_limit():
    query = "SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 25 OFFSET 10"
    decision = check_sql(query)
    assert decision.verdict == Verdict.ALLOW


# --- 2. Destructive SQL Statements (Positive class: BLOCK) ---


def test_l1_block_drop_table():
    decision = check_sql("DROP TABLE customers")
    assert decision.verdict == Verdict.BLOCK
    assert "DROP" in decision.reason.upper()


def test_l1_block_drop_table_if_exists():
    decision = check_sql("DROP TABLE IF EXISTS accounts")
    assert decision.verdict == Verdict.BLOCK
    assert "DROP" in decision.reason.upper()


def test_l1_block_delete_all():
    decision = check_sql("DELETE FROM customers")
    assert decision.verdict == Verdict.BLOCK
    assert "DELETE" in decision.reason.upper()


def test_l1_block_delete_with_where():
    decision = check_sql("DELETE FROM transactions WHERE amount < 0")
    assert decision.verdict == Verdict.BLOCK
    assert "DELETE" in decision.reason.upper()


def test_l1_block_update():
    decision = check_sql("UPDATE accounts SET balance = 1000000 WHERE id = 1")
    assert decision.verdict == Verdict.BLOCK
    assert "UPDATE" in decision.reason.upper()


def test_l1_block_alter_table():
    decision = check_sql("ALTER TABLE customers ADD COLUMN backdoor TEXT")
    assert decision.verdict == Verdict.BLOCK
    assert "ALTER" in decision.reason.upper()


def test_l1_block_insert():
    decision = check_sql(
        "INSERT INTO customers (name, email, ssn, phone, address, created_at) "
        "VALUES ('Evil', 'evil@attacker.com', '900-00-9999', '555', 'Nowhere', 'now')"
    )
    assert decision.verdict == Verdict.BLOCK
    assert "INSERT" in decision.reason.upper()


# --- 3. Attack Techniques, Multi-Statements, and Obfuscation ---


def test_l1_block_multi_statement_chained_attack():
    query = "SELECT * FROM customers WHERE id = 1; DROP TABLE accounts;"
    decision = check_sql(query)
    assert decision.verdict == Verdict.BLOCK
    assert "multi-statement" in decision.reason.lower()


def test_l1_block_multi_statement_selects():
    query = "SELECT 1; SELECT 2;"
    decision = check_sql(query)
    assert decision.verdict == Verdict.BLOCK
    assert "multi-statement" in decision.reason.lower()


def test_l1_block_pragma():
    decision = check_sql("PRAGMA table_info(customers)")
    assert decision.verdict == Verdict.BLOCK


def test_l1_block_attach_database():
    decision = check_sql("ATTACH DATABASE ':memory:' AS shadow_db")
    assert decision.verdict == Verdict.BLOCK


# --- 4. Malformed Queries and Edge Cases ---


def test_l1_block_empty_query():
    decision = check_sql("")
    assert decision.verdict == Verdict.BLOCK
    assert "empty" in decision.reason.lower()


def test_l1_block_whitespace_query():
    decision = check_sql("   \n\t  ")
    assert decision.verdict == Verdict.BLOCK


def test_l1_block_comment_only():
    decision = check_sql("-- just a harmless comment")
    assert decision.verdict == Verdict.BLOCK
    assert "no executable sql" in decision.reason.lower()


def test_l1_block_malformed_syntax():
    decision = check_sql("SELECT FROM WHERE ;;;")
    assert decision.verdict == Verdict.BLOCK
    assert "syntax" in decision.reason.lower() or "malformed" in decision.reason.lower()
