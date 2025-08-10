# clonelens — detect ABI near-clones & forks (offline)

**clonelens** reads ABI JSONs, builds compact fingerprints from functions/events,
and ranks **near-clone** pairs using a blend of **SimHash** (names/types/flags)
and **selector-set Jaccard** overlap. It’s perfect for quick audits, rug-fork
triage, and CI checks — all offline.

## Why this is useful

- Detects **“same contract, different name”** forks before you list or integrate.
- Surfaces **selector-level overlap**, which is harder to obfuscate than names.
- Generates JSON/CSV you can diff, plus a tiny badge for READMEs/PRs.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
