"""Stack composition.

Every one of the four defense layers is real as of Phase 2 — Layer 1
normalization/detection, Layer 2 heuristic signal, Layer 3 intent policy, Layer 4
provenance. This module wires them into the five ablation stacks; the layer
factories keep the composition table readable.
"""

from __future__ import annotations

from collections.abc import Callable

from taintwall.layers.base import Layer, LayerStack
from taintwall.layers.detect_layer import DetectLayer
from taintwall.layers.normalization import NormalizationLayer
from taintwall.layers.policy import PolicyLayer, SessionIntent
from taintwall.layers.provenance_layer import ProvenanceLayer


def tag_layer() -> Layer:
    """Layer 1: normalization + concealment detection (codepoints and markup)."""
    return NormalizationLayer()


def detect_layer() -> Layer:
    """Layer 2: a heuristic injection-likelihood signal. Never gates alone."""
    return DetectLayer()


ABLATION_LABELS: tuple[str, ...] = ("none", "+L1", "+L1L2", "+L1L2L3", "+all")


def build_stack(
    label: str,
    intent: SessionIntent | None = None,
    private_values: frozenset[str] = frozenset(),
) -> LayerStack:
    """Compose a layer stack.

    `intent` configures Layer 3 (defaults to read-only); `private_values`
    configures Layer 4. The `none`, `+L1`, and `+L1L2` stacks use neither.
    """
    session_intent = intent if intent is not None else SessionIntent.read_only()

    def policy_layer() -> Layer:
        return PolicyLayer(session_intent)

    def provenance_layer() -> Layer:
        return ProvenanceLayer(private_values)

    factories: dict[str, tuple[Callable[[], Layer], ...]] = {
        "none": (),
        "+L1": (tag_layer,),
        "+L1L2": (tag_layer, detect_layer),
        "+L1L2L3": (tag_layer, detect_layer, policy_layer),
        "+all": (tag_layer, detect_layer, policy_layer, provenance_layer),
    }
    return LayerStack(label=label, layers=tuple(factory() for factory in factories[label]))
