"""
Output formatters for rendering generation results.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import asdict

from generator import GenerationResult


class Formatter(ABC):
    @abstractmethod
    def format(self, result: GenerationResult) -> str:
        ...


class JSONFormatter(Formatter):
    def format(self, result: GenerationResult) -> str:
        return json.dumps(asdict(result), indent=2, ensure_ascii=False)


class TextFormatter(Formatter):
    def format(self, result: GenerationResult) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("OWASP LLM Top 10 — Generated Test Prompts")
        lines.append(f"Generated: {result.generated_at}")
        lines.append(f"Total prompts: {result.total_prompts}")
        lines.append(f"Categories: {', '.join(result.categories_tested)}")
        lines.append("=" * 70)

        current_category = None

        for p in result.prompts:
            if p.category_id != current_category:
                current_category = p.category_id
                lines.append("")
                lines.append("-" * 70)
                lines.append(f"  {p.category_id}: {p.category_name}")
                lines.append("-" * 70)

            lines.append("")
            lines.append(f"  [{p.template_id}] {p.template_name}")
            lines.append(f"  Type: {p.test_type}  |  Severity: {p.severity}")
            lines.append(f"  Description: {p.description}")
            lines.append(f"  Expected safe behavior: {p.expected_safe_behavior}")
            if p.tags:
                lines.append(f"  Tags: {', '.join(p.tags)}")
            lines.append("")
            lines.append(f"  PROMPT:")
            for prompt_line in p.rendered_prompt.split("\n"):
                lines.append(f"    {prompt_line}")
            lines.append("")

        return "\n".join(lines)
