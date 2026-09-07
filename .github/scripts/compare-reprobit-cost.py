#!/usr/bin/env python3
"""Print this run's ReproBit intervention cost against the master baseline.

Usage: compare-reprobit-cost.py CURRENT_REPORT_JSON [BASELINE_REPORT_JSON]

The baseline is the report.json of the continuous release, which master
publishes on every verified push, so the output reads "master -> this run"
like the reccmp --diff step next to it. A missing or unreadable baseline is
reported, never fatal: the first master publication has nothing to compare.
The exact verification is the gate; this comparison is informational and
exits 0 once the current report is readable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

MAX_ROWS = 60


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fmt(value: int) -> str:
    return f"{value:,}"


def delta(new: int, old: int) -> str:
    return f"{new - old:+,}" if new != old else "0"


def percent(new: int, old: int) -> str:
    return f" ({(new - old) / old:+.2%})" if old else ""


def by_key(rows: list[dict], key: str) -> dict[str, dict]:
    return {row[key]: row for row in rows}


def scope_label(row: dict) -> str:
    scope = row.get("scope", {})
    parts = [scope.get("target", "?")]
    if scope.get("function"):
        parts.append(scope["function"])
    elif scope.get("translation_unit"):
        parts.append(scope["translation_unit"])
    label = "/".join(parts)
    return label if len(label) <= 72 else label[:69] + "..."


def print_table(title: str, headers: list[str], rows: list[list[str]]) -> None:
    print()
    print(title)
    print("-" * len(title))
    if not rows:
        print("(none)")
        return
    widths = [max(len(cell) for cell in column) for column in zip(headers, *rows)]
    print("  ".join(cell.ljust(width) for cell, width in zip(headers, widths)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)))


def count_rows(old_rows: dict[str, dict], new_rows: dict[str, dict], *, changed_only: bool) -> list[list[str]]:
    rows = []
    for key in sorted(set(old_rows) | set(new_rows)):
        old = old_rows.get(key, {"cost": 0, "interventions": 0})
        new = new_rows.get(key, {"cost": 0, "interventions": 0})
        if changed_only and old["cost"] == new["cost"] and old["interventions"] == new["interventions"]:
            continue
        rows.append([
            key, fmt(old["cost"]), fmt(new["cost"]), delta(new["cost"], old["cost"]),
            f"{old['interventions']} to {new['interventions']} "
            f"({delta(new['interventions'], old['interventions'])})",
        ])
    return rows


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    costs = load(Path(argv[1]))["costs"]
    total = costs["project_total"]
    count = len(costs["interventions"])
    print("ReproBit intervention cost against master")
    print("=========================================")

    baseline = None
    reason = "the continuous release has no report.json yet"
    if len(argv) == 3 and Path(argv[2]).is_file():
        try:
            baseline = load(Path(argv[2]))["costs"]
            baseline["project_total"], baseline["interventions"]
        except (OSError, ValueError, KeyError, TypeError) as error:
            baseline = None
            reason = f"the baseline report could not be read ({error.__class__.__name__})"
    if baseline is None:
        print(
            f"No baseline: {reason}. This run: {fmt(total)} points, "
            f"{count} interventions, cost model v{costs['model_version']}."
        )
        return 0

    old_total = baseline["project_total"]
    old_count = len(baseline["interventions"])
    headline = (
        f"master {fmt(old_total)} points, this run {fmt(total)} points, "
        f"delta {delta(total, old_total)}{percent(total, old_total)}; "
        f"interventions {old_count} to {count} ({delta(count, old_count)})"
    )
    print(headline)
    print(f"::notice title=ReproBit cost::{headline}")
    if baseline["model_version"] != costs["model_version"]:
        print(
            f"::warning title=ReproBit cost::cost model changed from "
            f"v{baseline['model_version']} to v{costs['model_version']}; "
            "totals are not directly comparable"
        )

    print_table("Totals", ["", "master", "this run", "delta"], [
        ["Project total", fmt(old_total), fmt(total), delta(total, old_total) + percent(total, old_total)],
        ["Interventions", str(old_count), str(count), delta(count, old_count)],
        ["Unallocated shared cost", fmt(baseline["unallocated_shared_cost"]),
         fmt(costs["unallocated_shared_cost"]),
         delta(costs["unallocated_shared_cost"], baseline["unallocated_shared_cost"])],
    ])
    columns = ["", "master", "this run", "delta", "interventions"]
    print_table("By target", columns, count_rows(
        by_key(baseline["by_target"], "target"), by_key(costs["by_target"], "target"), changed_only=False))
    print_table("Cost classes that changed", columns, count_rows(
        by_key(baseline["by_class"], "cost_class"), by_key(costs["by_class"], "cost_class"), changed_only=True))

    old_items = by_key(baseline["interventions"], "intervention_id")
    new_items = by_key(costs["interventions"], "intervention_id")
    changes = []
    for item_id in set(old_items) | set(new_items):
        old = old_items.get(item_id)
        new = new_items.get(item_id)
        old_cost = old["cost"] if old else 0
        new_cost = new["cost"] if new else 0
        if old and new and old_cost == new_cost:
            continue
        kind = "added" if old is None else "removed" if new is None else "changed"
        changes.append((abs(new_cost - old_cost), kind, item_id, new or old, old_cost, new_cost))
    changes.sort(key=lambda entry: (-entry[0], entry[2]))
    counts = {kind: sum(1 for entry in changes if entry[1] == kind) for kind in ("added", "removed", "changed")}
    title = f"Intervention changes: {counts['added']} added, {counts['removed']} removed, {counts['changed']} changed"
    if len(changes) > MAX_ROWS:
        title += f" (largest {MAX_ROWS} shown)"
    print_table(title, ["Change", "Intervention", "Class", "Family", "Scope", "master", "this run", "delta"], [
        [kind, item_id, row["cost_class"], row.get("family", ""), scope_label(row),
         fmt(old_cost), fmt(new_cost), delta(new_cost, old_cost)]
        for _, kind, item_id, row, old_cost, new_cost in changes[:MAX_ROWS]
    ])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
