"""Evaluation reporter formatting benchmark results, ablation comparisons, and metric tables.
Inputs: Metrics summary objects and run metadata. Outputs: Formatted terminal tables and markdown reports.
Build plan: Day 4.
"""

from __future__ import annotations

from typing import Mapping
from eval.metrics import EvaluationMetrics


def _ensure_dict(
    metrics: EvaluationMetrics | Mapping[str, EvaluationMetrics]
) -> dict[str, EvaluationMetrics]:
    """Helper to normalize input into a dict of {config_name: metrics}."""
    if isinstance(metrics, EvaluationMetrics):
        return {"Default": metrics}
    return dict(metrics)


def format_metrics_table(
    metrics: EvaluationMetrics | Mapping[str, EvaluationMetrics]
) -> str:
    """Formats evaluation metrics into an aligned ASCII comparison table.

    Args:
        metrics: Single EvaluationMetrics instance or dict of {config_name: EvaluationMetrics}.

    Returns:
        Formatted ASCII table string.
    """
    data = _ensure_dict(metrics)
    if not data:
        return "(No evaluation metrics available)"

    headers = [
        "Config",
        "Total",
        "TP",
        "FP",
        "TN",
        "FN",
        "Prec",
        "Recall",
        "F1",
        "FPR",
        "ASR",
        "CanaryLeak",
        "AvgLat(ms)",
        "p95(ms)",
        "p99(ms)",
    ]

    rows: list[list[str]] = []
    for cfg_name, m in data.items():
        leak_str = (
            f"{m.canary_leak_rate * 100:.1f}% ({m.leaked_canaries}/{m.total_canary_cases})"
            if m.total_canary_cases > 0
            else "N/A (0)"
        )
        rows.append(
            [
                str(cfg_name),
                str(m.total_cases),
                str(m.tp),
                str(m.fp),
                str(m.tn),
                str(m.fn),
                f"{m.precision:.4f}",
                f"{m.recall:.4f}",
                f"{m.f1:.4f}",
                f"{m.fpr:.4f}",
                f"{m.asr:.4f}",
                leak_str,
                f"{m.avg_latency_ms:.2f}",
                f"{m.p95_latency_ms:.2f}",
                f"{m.p99_latency_ms:.2f}",
            ]
        )

    # Compute column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def make_divider(char: str = "-") -> str:
        parts = [char * (w + 2) for w in col_widths]
        return "+" + "+".join(parts) + "+"

    def format_row(values: list[str]) -> str:
        parts = [f" {val.ljust(col_widths[i])} " for i, val in enumerate(values)]
        return "|" + "|".join(parts) + "|"

    output = [
        make_divider("-"),
        format_row(headers),
        make_divider("="),
    ]
    for row in rows:
        output.append(format_row(row))
    output.append(make_divider("-"))

    return "\n".join(output)


def format_markdown_report(
    metrics: EvaluationMetrics | Mapping[str, EvaluationMetrics],
    title: str = "Firewall Evaluation & Ablation Report",
) -> str:
    """Formats evaluation metrics as a GitHub Flavored Markdown table.

    Args:
        metrics: Single EvaluationMetrics instance or dict of {config_name: EvaluationMetrics}.
        title: Title of the markdown report.

    Returns:
        Markdown report string.
    """
    data = _ensure_dict(metrics)
    if not data:
        return f"# {title}\n\n*No evaluation metrics available.*"

    lines = [
        f"# {title}\n",
        "| Config | Total | TP | FP | TN | FN | Precision | Recall | F1 Score | FPR | ASR | Canary Leak Rate | Avg Latency | p95 Latency | p99 Latency |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for cfg_name, m in data.items():
        leak_str = (
            f"{m.canary_leak_rate * 100:.1f}% ({m.leaked_canaries}/{m.total_canary_cases})"
            if m.total_canary_cases > 0
            else "N/A"
        )
        lines.append(
            f"| **{cfg_name}** | {m.total_cases} | {m.tp} | {m.fp} | {m.tn} | {m.fn} | "
            f"{m.precision:.4f} | {m.recall:.4f} | {m.f1:.4f} | {m.fpr:.4f} | {m.asr:.4f} | "
            f"{leak_str} | {m.avg_latency_ms:.2f} ms | {m.p95_latency_ms:.2f} ms | {m.p99_latency_ms:.2f} ms |"
        )

    return "\n".join(lines)


def print_summary(
    metrics: EvaluationMetrics | Mapping[str, EvaluationMetrics]
) -> None:
    """Prints ASCII summary table to stdout."""
    print("\n" + format_metrics_table(metrics) + "\n")
