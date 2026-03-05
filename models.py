"""
Core data models for the OWASP LLM Top 10 test prompt generator.
"""

import re
import random
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
    # Alternative phrasings; when randomize=True, one of these may be used instead of template
    template_variants: List[str] = field(default_factory=list)

    def render(self, variables: Dict[str, str], randomize: bool = False) -> str:
        """Render the template with the given variables.
        If randomize=True: may use a template_variant, and expands {choice:a|b|c} to a random option.
        Missing variables are left as placeholders."""
        base = self.template
        if randomize and self.template_variants:
            base = random.choice([self.template] + self.template_variants)
        result = base
        # Expand {choice:option1|option2|option3}: random option if randomize, else first
        def pick_choice(match: re.Match) -> str:
            options = [s.strip() for s in match.group(1).split("|") if s.strip()]
            return random.choice(options) if randomize and options else (options[0] if options else match.group(0))
        result = re.sub(r"\{choice:([^}]+)\}", pick_choice, result)
        for key, value in variables.items():
            result = result.replace(f"{{{key}}}", value)
        return result

    def required_variables(self) -> List[str]:
        """Return variable names found in the template (excludes choice blocks)."""
        return [v for v in re.findall(r"\{(\w+)\}", self.template) if v != "choice"]


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
