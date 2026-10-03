"""The fictionet-sandbox Helm chart, shipped inside the package."""

from pathlib import Path


def chart_path() -> Path:
    """The directory of the fictionet-sandbox chart that ships with this
    package. It is a copy of `charts/fictionet-sandbox` in the repository,
    so it works wherever the package is installed."""
    return Path(__file__).parent / "chart" / "fictionet-sandbox"
