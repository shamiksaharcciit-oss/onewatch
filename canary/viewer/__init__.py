"""onewatch — the Detect pillar's viewer.

`onewatch` is the product name the page wears; `canary.viewer` is where the code lives.
A package name states where the code is and a product name states what the surface is,
and neither should lie to serve the other (Core -> Canary Response 015 §5).
"""
from canary.viewer.page import build_page, render

__all__ = ["build_page", "render"]
