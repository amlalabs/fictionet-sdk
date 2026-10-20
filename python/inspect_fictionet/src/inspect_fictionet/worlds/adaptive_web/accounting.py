"""Timing populations for the score's metadata. No I/O."""
import math


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
