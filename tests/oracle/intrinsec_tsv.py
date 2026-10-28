"""Intrinsec mplog_parser's CSVs (converted to UTF-8) as the TSV
tests/mplog.rs compares: one line per row, the CSV's name, then its
non-empty columns as name=value, sorted, values trimmed, lists (the
exclusions) joined with "|".
Run: python3 -I intrinsec_tsv.py <dir of *.utf8.csv> > intrinsec-mplog.tsv
"""

import ast
import csv
import pathlib
import sys

lines = []
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.utf8.csv")):
    name = path.name.split(".")[0].removeprefix("MPLog_")
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cells = []
            for key, value in row.items():
                if value.startswith("["):
                    value = "|".join(ast.literal_eval(value))
                value = value.strip()
                if value:
                    cells.append(f"{key}={value}")
            lines.append("\t".join([name] + sorted(cells)))
for line in sorted(lines):
    print(line)
