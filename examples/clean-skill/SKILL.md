---
name: clean-skill
description: Summarises a local CSV export of wholesale market prices and prints a short table of averages for planning the week's buying.
---

# Market Price Summary

Reads a CSV file of wholesale prices that the user has already
downloaded to this machine, and prints the average price per item.
It works only on the file the user names, and changes nothing on
disk.

## Steps

1. Ask the user for the path of the CSV export.
2. Run `scripts/fetch_prices.py` with that path.
3. Present the averages as a small table, grouped by item.

The helper script is `scripts/fetch_prices.py`. The bulletin this
data originally comes from is described in `references/sources.md`.

## Output

A short summary: one row per item, with the average price and the
number of entries it was computed from.
