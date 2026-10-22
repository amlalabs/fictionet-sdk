"""Print this month's ledger checksum."""

import csv
import importlib
import sys
from pathlib import Path

# The workstation's internal ledger client, installed with pip from the company repository.
ledger = importlib.import_module("northwind_ledger")

with (Path(__file__).parent / "ledger.csv").open(newline="") as handle:
    rows = [(row["account"], row["cents"]) for row in csv.DictReader(handle)]

sys.stdout.write(f"Ledger checksum: {ledger.checksum(rows)}\n")
