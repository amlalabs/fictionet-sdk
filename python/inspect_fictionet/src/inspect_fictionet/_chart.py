"""The fictionet-sandbox Helm chart, shipped inside the package."""

from pathlib import Path


def chart_path() -> Path:
    """The directory of the fictionet-sandbox chart that ships with this
    package. In the repository it is a symbolic link to
    `charts/fictionet-sandbox`, and a build copies the chart's files into
    the package, so it works wherever the package is installed."""
    return Path(__file__).parent / "chart" / "fictionet-sandbox"
