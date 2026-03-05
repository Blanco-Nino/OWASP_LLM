"""
Core data models for the OWASP LLM Top 10 test prompt generator.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TestType(str, Enum):
    """Classifies the nature of the test prompt."""
    DIRECT = "direct"           # Straightforward test of the control
    EVASION = "evasion"         # Attempts to bypass known defenses
    CONTEXTUAL = "contextual"   # Relies on conversational context buildup
    BOUNDARY = "boundary"       # Tests edge cases and boundary conditions


@dataclass
class PromptTemplate:
    """A single test prompt template with metadata."""
    id: str
    name: str
    template: str
    test_type: TestType
    severity: Severity
    description: str
    expected_safe_behavior: str
    variables: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def render(self, variables: Dict[str, str]) -> str:
        """Render the template with the given variables.
        Missing variables are left as placeholders."""
        result = self.template
        for key, value in variables.items():
            result = result.replace(f"{{{key}}}", value)
        return result

    def required_variables(self) -> List[str]:
        """Return variable names found in the template."""
        import re
        return re.findall(r"\{(\w+)\}", self.template)


@dataclass
class VulnerabilityCategory:
    """An OWASP LLM Top 10 vulnerability category with associated templates."""
    id: str               # e.g. "LLM01"
    name: str             # e.g. "Prompt Injection"
    description: str
    references: List[str] = field(default_factory=list)
    templates: List[PromptTemplate] = field(default_factory=list)

    def add_template(self, template: PromptTemplate):
        self.templates.append(template)

    def get_templates_by_type(self, test_type: TestType) -> List[PromptTemplate]:
        return [t for t in self.templates if t.test_type == test_type]

    def get_templates_by_severity(self, severity: Severity) -> List[PromptTemplate]:
        return [t for t in self.templates if t.severity == severity]
