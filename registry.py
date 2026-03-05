"""
Registry for managing vulnerability categories.
"""

from typing import Dict, List, Optional
from models import VulnerabilityCategory


class VulnerabilityRegistry:
    """Central registry of all vulnerability categories."""

    def __init__(self):
        self._categories: Dict[str, VulnerabilityCategory] = {}

    def add_category(self, category: VulnerabilityCategory):
        self._categories[category.id] = category

    def get_category(self, category_id: str) -> Optional[VulnerabilityCategory]:
        return self._categories.get(category_id.upper())

    def list_categories(self) -> List[VulnerabilityCategory]:
        return sorted(self._categories.values(), key=lambda c: c.id)

    def list_ids(self) -> List[str]:
        return sorted(self._categories.keys())

    def __len__(self) -> int:
        return len(self._categories)
