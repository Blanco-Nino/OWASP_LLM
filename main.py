#!/usr/bin/env python3
"""
OWASP LLM Top 10 Security Test Prompt Generator

A modular tool for generating adversarial test prompts to evaluate
LLM security controls against the OWASP Top 10 for LLM Applications.

Usage:
    python main.py                  # Interactive menu
    python main.py --list           # List all vulnerability categories
    python main.py --categories LLM01 LLM02 --format json --output results.json
    python main.py --all --format text --randomize
"""

import argparse
import sys
from pathlib import Path
from typing import List

# Ensure the script's directory is first on path so local 'categories' is used
# instead of any installed package with the same name.
_script_dir = Path(__file__).resolve().parent
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))

from registry import VulnerabilityRegistry
from generator import PromptGenerator
from formatters import JSONFormatter, TextFormatter


def build_registry() -> VulnerabilityRegistry:
    """Build and populate the vulnerability registry with all categories."""
    registry = VulnerabilityRegistry()

    # Import and register all built-in vulnerability modules (they live in project root)
    import prompt_injection
    import data_leakage
    import insecure_output
    import training_data_poisoning
    import model_dos
    import supply_chain
    import sensitive_disclosure
    import model_theft
    import excessive_agency
    import overreliance

    modules = [
        prompt_injection,
        data_leakage,
        insecure_output,
        training_data_poisoning,
        model_dos,
        supply_chain,
        sensitive_disclosure,
        model_theft,
        excessive_agency,
        overreliance,
    ]

    for mod in modules:
        category = mod.register()
        registry.add_category(category)

    return registry


def interactive_menu(registry: VulnerabilityRegistry) -> List[str]:
    """Present an interactive menu and return selected category IDs."""
    categories = registry.list_categories()

    print("\n" + "=" * 65)
    print("  OWASP Top 10 for LLM Applications — Test Prompt Generator")
    print("=" * 65)
    print()

    for i, cat in enumerate(categories, 1):
        print(f"  [{i:>2}] {cat.id}: {cat.name}")
        print(f"       {cat.description[:70]}...")
        print()

    print(f"  [ A] Select ALL categories")
    print(f"  [ Q] Quit")
    print()

    selection = input("Select categories (comma-separated numbers, A, or Q): ").strip()

    if selection.upper() == "Q":
        sys.exit(0)

    if selection.upper() == "A":
        return [c.id for c in categories]

    try:
        indices = [int(s.strip()) for s in selection.split(",")]
        selected = []
        for idx in indices:
            if 1 <= idx <= len(categories):
                selected.append(categories[idx - 1].id)
            else:
                print(f"  Warning: index {idx} out of range, skipping.")
        if not selected:
            print("No valid categories selected.")
            sys.exit(1)
        return selected
    except ValueError:
        print("Invalid input. Please enter numbers separated by commas.")
        sys.exit(1)


def interactive_variables() -> dict:
    """Prompt the user for common variable values."""
    print("\n--- Variable Substitution (press Enter to use defaults) ---\n")

    defaults = {
        "target_app": "TargetApp",
        "system_prompt": "You are a helpful assistant.",
        "sensitive_data_type": "API keys",
        "api_endpoint": "https://api.target.com/v1",
        "internal_url": "http://internal-service.local",
        "model_name": "target-model-v1",
        "plugin_name": "example-plugin",
    }

    variables = {}
    for key, default in defaults.items():
        val = input(f"  {key} [{default}]: ").strip()
        variables[key] = val if val else default

    return variables


def main():
    parser = argparse.ArgumentParser(
        description="OWASP LLM Top 10 Security Test Prompt Generator"
    )
    parser.add_argument(
        "--list", action="store_true", help="List all vulnerability categories"
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        metavar="ID",
        help="Category IDs to generate prompts for (e.g., LLM01 LLM02)",
    )
    parser.add_argument(
        "--all", action="store_true", help="Generate prompts for all categories"
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--randomize",
        action="store_true",
        help="Randomize prompt selection and variable insertion",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Max prompts per category (0 = all, default: 0)",
    )
    parser.add_argument(
        "--var",
        nargs=2,
        action="append",
        metavar=("KEY", "VALUE"),
        help="Set a template variable (repeatable). With --randomize, use value1|value2|value3 to pick one per prompt.",
    )

    args = parser.parse_args()

    registry = build_registry()

    # --list: just print categories and exit
    if args.list:
        for cat in registry.list_categories():
            print(f"{cat.id}: {cat.name}")
            print(f"  {cat.description}")
            print(f"  Templates: {len(cat.templates)}")
            print()
        return

    # Determine selected categories
    if args.all:
        selected_ids = [c.id for c in registry.list_categories()]
    elif args.categories:
        selected_ids = [cid.upper() for cid in args.categories]
    else:
        # Interactive mode
        selected_ids = interactive_menu(registry)

    # Gather variables
    if args.var:
        variables = {k: v for k, v in args.var}
    elif not (args.all or args.categories):
        variables = interactive_variables()
    else:
        variables = {}

    # Generate prompts
    generator = PromptGenerator(registry)
    results = generator.generate(
        category_ids=selected_ids,
        variables=variables,
        randomize=args.randomize,
        max_per_category=args.count if args.count > 0 else None,
    )

    # Format output
    if args.format == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    output = formatter.format(results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
