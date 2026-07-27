"""The four defense layers.

In Phase 1 every layer is a stub that returns a constant, so the ablation table
has all five columns before any defense is built. Phase 2 onward replaces the
stubs one at a time; the harness never changes.
"""

from __future__ import annotations
