"""Deterministic local detectors. Detectors find candidates; they never decide actions."""

from ciphergate.detectors.registry import BUILTIN_DETECTOR_IDS, DetectorSet

__all__ = ["BUILTIN_DETECTOR_IDS", "DetectorSet"]
