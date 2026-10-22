"""Normalizer: uniform event schema and masking."""

from .mapper import (
    NormalizationError,
    parse_event_data_xml,
    record_from_line,
    record_from_mapping,
)
from .masking import mask_properties, mask_text
from .schema import LEVEL_LABEL, EventRecord, Level, level_label

__all__ = [
    "LEVEL_LABEL",
    "EventRecord",
    "Level",
    "NormalizationError",
    "level_label",
    "mask_properties",
    "mask_text",
    "parse_event_data_xml",
    "record_from_line",
    "record_from_mapping",
]
