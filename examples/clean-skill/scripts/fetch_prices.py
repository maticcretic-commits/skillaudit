#!/usr/bin/env python3
"""Print average prices per item from a local wholesale-price CSV.

The CSV needs two columns: `item` and `price`. The file is only
read; nothing is written and nothing leaves the machine.
"""

import argparse
import csv
import sys
from collections import defaultdict


def summarise(path):
    totals = defaultdict(float)
    counts = defaultdict(int)
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                totals[row["item"]] += float(row["price"])
                counts[row["item"]] += 1
            except (KeyError, TypeError, ValueError):
                continue
    return totals, counts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv_path", help="path to the price CSV export")
    args = ap.parse_args()
    totals, counts = summarise(args.csv_path)
    if not counts:
        print("no usable rows found", file=sys.stderr)
        return 1
    for item in sorted(counts):
        avg = totals[item] / counts[item]
        print(f"{item}: average {avg:.2f} over {counts[item]} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
