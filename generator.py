"""
Prompt generator — renders templates with variable substitution and
optional randomization.
"""

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime, timezone

from models import PromptTemplate, VulnerabilityCategory
from registry import VulnerabilityRegistry


@dataclass
class GeneratedPrompt:
    """A fully rendered test prompt with metadata."""
    category_id: str
    category_name: str
    template_id: str
    template_name: str
    test_type: str
    severity: str
    description: str
    expected_safe_behavior: str
    rendered_prompt: str
    tags: List[str] = field(default_factory=list)


@dataclass
class GenerationResult:
    """Complete output from a generation run."""
    generated_at: str
    total_prompts: int
    categories_tested: List[str]
    prompts: List[GeneratedPrompt] = field(default_factory=list)


# Randomization variants — innocuous wrappers that slightly alter phrasing
_PREFIX_VARIANTS = [
    "",
    "Please ",
    "Could you ",
    "I'd like you to ",
    "Can you help me ",
    "I need to ",
    "Quick question: ",
    "For my research: ",
    "In this scenario: ",
]

_SUFFIX_VARIANTS = [
    "",
    " Thanks.",
    " This is for a security audit.",
    " I need this for testing purposes.",
    " Appreciate your help.",
    " (Confidential.)",
]


def _resolve_variable_pools(variables: Dict[str, str], randomize: bool) -> Dict[str, str]:
    """When randomize is True, values containing '|' are treated as pools; pick one option."""
    if not randomize:
        return variables
    out = {}
    for k, v in variables.items():
        if "|" in str(v):
            parts = [s.strip() for s in v.split("|") if s.strip()]
            out[k] = random.choice(parts) if parts else v
        else:
            out[k] = v
    return out


class PromptGenerator:
    def __init__(self, registry: VulnerabilityRegistry):
        self.registry = registry

    def generate(
        self,
        category_ids: List[str],
        variables: Optional[Dict[str, str]] = None,
        randomize: bool = False,
        max_per_category: Optional[int] = None,
    ) -> GenerationResult:
        variables = variables or {}
        all_prompts: List[GeneratedPrompt] = []

        for cid in category_ids:
            category = self.registry.get_category(cid)
            if category is None:
                print(f"Warning: category '{cid}' not found, skipping.")
                continue

            templates = list(category.templates)

            if randomize:
                random.shuffle(templates)

            if max_per_category and len(templates) > max_per_category:
                templates = templates[:max_per_category]

            for tmpl in templates:
                # When randomize=True, variable values with "|" (e.g. "API keys|passwords") pick one per prompt
                resolved_vars = _resolve_variable_pools(variables, randomize)
                rendered = tmpl.render(resolved_vars, randomize=randomize)

                if randomize:
                    prefix = random.choice(_PREFIX_VARIANTS)
                    suffix = random.choice(_SUFFIX_VARIANTS)
                    rendered = prefix + rendered + suffix

                gp = GeneratedPrompt(
                    category_id=category.id,
                    category_name=category.name,
                    template_id=tmpl.id,
                    template_name=tmpl.name,
                    test_type=tmpl.test_type.value,
                    severity=tmpl.severity.value,
                    description=tmpl.description,
                    expected_safe_behavior=tmpl.expected_safe_behavior,
                    rendered_prompt=rendered.strip(),
                    tags=tmpl.tags,
                )
                all_prompts.append(gp)

        return GenerationResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_prompts=len(all_prompts),
            categories_tested=category_ids,
            prompts=all_prompts,
        )
