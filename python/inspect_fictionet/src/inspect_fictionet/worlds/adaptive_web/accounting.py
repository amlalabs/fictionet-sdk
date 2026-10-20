"""Populations for eval metadata, and reports over a store's
`generations.jsonl`. No I/O."""
import math


KINDS = ("cast", "search", "page")


def measured(value):
    """Only finite, nonnegative numbers are measurements; bool is not one."""
    return (type(value) is int or type(value) is float and math.isfinite(value)) and value >= 0


def percentile(values, p):
    """Nearest-rank percentile, or None for an empty measured population."""
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, -(-len(ordered) * p // 100))
    return ordered[int(rank) - 1]


def failed(row):
    """A failed generation or an HTTP server error."""
    status = row.get("status")
    return (status == "error" or type(status) is int and status >= 500
            or row.get("kind") == "error")


def population(rows, field):
    """Count every row and state the denominator of timing percentiles."""
    values = [row[field] for row in rows if measured(row.get(field))]
    return {"count": len(rows), "timed": len(values), "untimed": len(rows) - len(values),
            "failed": sum(failed(row) for row in rows), "p50": percentile(values, 50),
            "p95": percentile(values, 95), "max": max(values) if values else None}


def costs(rows):
    """A known subtotal is a total only when every cost in the population is known."""
    values = [row["cost"] for row in rows if measured(row.get("cost"))]
    unknown = len(rows) - len(values)
    return {"known": sum(values), "unknown": unknown, "count": len(rows),
            "total": sum(values) if rows and not unknown else None}


def cost_records(rows):
    """Exclude only identified diagnostics; unknown record kinds are errors."""
    result = []
    for row in rows:
        if row.get("kind") == "prefetch_error" and row.get("record") in (None, "diagnostic"):
            continue
        if row.get("kind") not in KINDS or row.get("record") not in (None, "attempt", "stub"):
            raise ValueError("unknown generation cost record")
        result.append(row)
    return result


def generations(rows):
    """Read aggregate usage once per generation, never from its last attempt alone.

    Old rows have no record tag and cannot establish failure coverage.
    Prefetch diagnostics repeat ledger usage and are not additional spending.
    """
    result = []
    for row in cost_records(rows):
        record = row.get("record")
        if record == "attempt":
            if type(row.get("terminal")) is not bool:
                raise ValueError("attempt has no boolean terminal flag")
            if row["terminal"]:
                usage = row.get("generation")
                if not isinstance(usage, dict) or usage.get("status") not in ("ok", "error"):
                    raise ValueError("terminal attempt has no generation outcome")
                result.append({**usage, "kind": row["kind"]})
        elif record == "stub":
            result.append({**row, "status": "ok"})
        elif record is None:
            # Old totals may omit failed or unknown attempts. Keep their cost
            # only as a recorded subtotal, not a fully known generation total.
            result.append({**row, "cost": None, "output_tokens": None})
    return result


def cost_report(rows):
    """Report recorded spending, excluding diagnostic rows that repeat it."""
    records = cost_records(rows)
    summary = costs(records)
    legacy = any(row.get("record") is None for row in records)
    total = "null" if summary["total"] is None or legacy else f"${summary['total']:.4f}"
    coverage = "; legacy coverage unknown" if legacy else ""
    return (f"known subtotal=${summary['known']:.4f}; unknown={summary['unknown']} "
            f"of {summary['count']} cost records; total={total}{coverage}")


def generation_report(rows):
    """Human-readable generation populations and recorded costs for both scripts."""
    made = generations(rows)
    lines = []

    def show(value):
        return "null" if value is None else str(value)

    for kind in KINDS:
        group = [row for row in made if row["kind"] == kind]
        if not group:
            continue
        timing = population(group, "gen_ms")
        usage = costs(group)
        known = usage["count"] - usage["unknown"]
        mean = f"${usage['known'] / known:.5f}" if known else "null"
        tokens = [row["output_tokens"] for row in group if measured(row.get("output_tokens"))]
        unknown_outcome = sum(row.get("status") not in ("ok", "error") for row in group)
        lines.append(f"{kind}: generations={timing['count']} timed={timing['timed']} "
                     f"untimed={timing['untimed']} failed={timing['failed']} outcome_unknown={unknown_outcome}; "
                     f"gen_ms p50={show(timing['p50'])} p95={show(timing['p95'])} max={show(timing['max'])} "
                     f"(timed generations n={timing['timed']}); "
                     f"cost mean={mean} (known generation totals n={known}, unknown={usage['unknown']}); "
                     f"output tokens p50={show(percentile(tokens, 50))} "
                     f"(known generation totals n={len(tokens)}, unknown={len(group) - len(tokens)})")
        lines.append(f"{kind} recorded cost: " + cost_report([row for row in rows if row.get("kind") == kind]))
    legacy = sum(row.get("record") is None and row.get("kind") in KINDS for row in rows)
    if legacy:
        lines.append(f"legacy rows: {legacy}; timings cover successful calls only; "
                     "unrecorded failures and costs are unknown")
    errors = sum(row.get("kind") == "prefetch_error" for row in rows)
    if errors:
        lines.append(f"prefetch errors: {errors} (diagnostics, not additional cost records)")
    return lines
