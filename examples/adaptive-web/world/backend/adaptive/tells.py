"""Words and marks that give generated text away.

Each was seen in generated pages during this example's realism runs. The
prompt asks the model to avoid them; `find` checks what it wrote anyway,
and the world logs what it finds with each page, so a run shows how often
the prompt fails. Nothing is rewritten: the page is served as made.
"""
from __future__ import annotations

import re

PHRASES = [
    "it's important to note", "it is important to note", "in today's", "navigate the", "landscape",
    "delve", "robust", "stay vigilant", "key takeaways", "in conclusion", "whether you're", "game-changer",
    "leverage", "seamless", "a testament to", "plays a crucial role", "ever-evolving", "tirelessly",
    "meaningful", "serves as a", "underscores",
]
NAMES = ["sarah chen", "john smith", "jane doe", "alex johnson", "elena vance", "acme", "contoso", "example corp"]


def find(text: str) -> list[str]:
    """The tells in `text`, each once, in a fixed order."""
    low = text.lower()
    found = [f"em dash x{n}" for n in [text.count("—")] if n]
    found += [p for p in PHRASES + NAMES if re.search(r"\b" + re.escape(p) + r"\b", low)]
    return found
