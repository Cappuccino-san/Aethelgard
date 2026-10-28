# Project Aethelgard v1.0.0

Sovereign Cognitive Twin & Cryptographic Provenance Engine.

What is the significance?

Foundation models are going to get cheaper, better, and more interchangeable. They commoditize. What doesn't commoditize is your context: the decisions you made, why you made them, what you rejected, what you tried, what actually happened when you ran it.

Right now that context is scattered and fragile. It's in chat histories that reset, in markdown notes you forget to update, in Git commits with no reason attached, in your head. A new model starts from zero, guesses at your past, and hallucinates it confidently.

Aethelgard is meant to fix that by keeping one local, verifiable record, and letting any model plug into it.

This is the Gemini-built v1 code, packaged unchanged for Antigravity.

## Open in Antigravity

1. Download the zip and extract it with your operating system (right-click, Extract, or double-click on Mac). Do not run unzip commands in a chat window, those only work in a terminal.
2. In Antigravity, choose Open Folder, then select the extracted `aethelgard` folder.
3. Open a terminal inside Antigravity (Terminal menu, New Terminal) and run the commands below from inside that folder.

## Run the tests

```bash
python3 -m venv .venv
.venv/bin/pip install blake3 cryptography pytest
PYTHONPATH=src .venv/bin/pytest -v
```

On Windows, use `.venv\Scripts\activate` instead of `.venv/bin/`, then `python -m pytest` with `PYTHONPATH=src` set in the same way for your shell.

## Use the CLI

After installing the package, or with PYTHONPATH set:

```bash
twin commit --title "Use SQLite WAL" --context "Local durability" --decision "SQLite 3 in WAL mode"
twin note "First note"
twin rebuild-views
twin verify
```

Default ledger location is `~/.local/share/aethelgard/ledger.db`. Use `--db <path>` to use a different database file.

## Layout

- `src/aethelgard/airlock.py` - secret scrubber
- `src/aethelgard/canonical.py` - RFC 8785 canonical JSON
- `src/aethelgard/ledger.py` - BLAKE3 chain, Ed25519, SQLite WAL ledger
- `src/aethelgard/views.py` - decoupled FTS5 view, rebuildable from the ledger
- `src/aethelgard/cli.py` - `twin` CLI
- `tests/test_aethelgard.py` - 5 tests
