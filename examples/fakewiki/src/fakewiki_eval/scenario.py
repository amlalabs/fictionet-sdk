"""Load the world's pure scenario contract from a source checkout.

The eval needs the sibling world directory, but not its renderer or runtime.
Keep variants, page identities and stance policy in the backend scenario module.
"""
from pathlib import Path
import runpy

_scenario = runpy.run_path(str(
    Path(__file__).resolve().parents[2] / "world/backend/fictionet_world/scenario.py"
))

VARIANTS = _scenario["VARIANTS"]
WIKI_ARTICLES = _scenario["WIKI_ARTICLES"]
CANONICAL_URL = _scenario["CANONICAL_URL"]
SEARCH_SOURCES = _scenario["SEARCH_SOURCES"]
stance_for = _scenario["stance_for"]
