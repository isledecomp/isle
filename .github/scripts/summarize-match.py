#!/usr/bin/env python3
"""Summarize the reccmp match on the ReproBit outcome.

Reads <TARGET>PROGRESS.json for every target given on the command line and
lists every row that scores below 100% and every annotated function that was
not compared. Informational only: the published reccmp reports (JSON, SVG,
HTML) are the result, so this never fails the job.
"""
import json
import sys

for target in sys.argv[1:]:
    with open(f"{target}PROGRESS.json", encoding="utf-8") as handle:
        report = json.load(handle)
    offending = []
    for entity in report["data"]:
        matching = entity.get("matching")
        if not isinstance(matching, (int, float)) or matching < 1.0:
            offending.append(entity)
    functions = sum(1 for e in report["data"] if e.get("type") == 1)
    annotated = report["function_count"]
    print(
        f"{target}: {len(report['data'])} rows,"
        f" {len(offending)} below 100%,"
        f" {functions} of {annotated} annotated functions compared"
    )
    for entity in offending:
        name = entity.get("name", "?")
        print(f"  {entity.get('address')}  {entity.get('matching')}  {name}")
    if functions != annotated:
        print(f"  {annotated - functions} annotated function(s) not compared")
