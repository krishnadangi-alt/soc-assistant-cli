# Copilot instructions for soc-assistant-cli

Purpose
- Provide repository-specific guidance for Copilot sessions working on this small SOC assistant CLI.

Build / Test / Lint
- No build step is present. The repository contains a Python CLI (soc.py) and a minimal package.json used for dependency metadata.
- Node: `npm test` runs the placeholder test script (package.json): `npm test` (note: it currently echoes an error by design).
- Python: Run the CLI directly with Python on Windows PowerShell: `python .\soc.py explain "4625"` or `python .\soc.py mitre "<event>"`.
- There are no unit tests or linters configured in this repo. To add them, add a `tests/` folder and update `package.json` or add a tox/pytest configuration.

Running a single behavior-driven command
- Execute the Python CLI for a single scenario: `python .\soc.py explain "4625"` (will print mapping for Event ID 4625).

High-level architecture
- Single-purpose CLI: soc.py is the authoritative entrypoint for functionality. It uses argparse to define three sub-commands: `explain`, `mitre`, and `next`.
- package.json supplies Node dependency metadata (chalk, commander) but there is no Node-based runtime in repository; treat package.json as metadata or future scaffold.
- The Python CLI contains hard-coded event mappings (e.g., Event ID 4625) and placeholder branches for MITRE mapping and investigation steps. New features will typically expand argparse choices and implement handling inside soc.py.

Key conventions and patterns
- CLI surface is driven by argparse choices: when adding features, update the `choices=[...]` list at the top of soc.py and add corresponding branches to the main conditional.
- Event mappings are simple substring checks on the single `input` argument (e.g., `if "4625" in args.input:`). Follow this pattern for quick heuristics; replace with structured parsing when adding more complex parsing.
- Keep Python CLI self-contained: minimal external imports (only argparse); if introducing dependencies, add them to a requirements file and document install steps in README.
- If adding Node-based tooling, synchronize package.json `scripts` and document commands here so Copilot knows canonical commands to run.

Files to check for AI assistant configs
- If present, incorporate the following into these instructions: CLAUDE.md, .cursorrules, .cursor/, AGENTS.md, .windsurfrules, CONVENTIONS.md, AIDER_CONVENTIONS.md, .clinerules. None of these files are present in the repository root currently.

Editing guidance for Copilot
- Prefer small, targeted edits: update argparse choices and corresponding logic in soc.py together.
- When adding tests or linters, include commands in package.json and show examples for running a single test (e.g., `pytest tests/test_event_4625.py`).

Contact / Follow-ups
- After creating features, update this file with any new commands, build steps, or AI-assistant config files added to the repo.
